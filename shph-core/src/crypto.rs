//! Cryptographic primitives for SHPH.
//!
//! This module provides identity management, key derivation, and session crypto.

use base64::Engine as _;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::KeyInit;
use ring::rand::SystemRandom;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::{Result, ShphError};
use crate::keystore::compute_fingerprint_hex;

/// X25519 key pair for handshake and session key derivation.
#[derive(Clone)]
pub struct IdentityKeyPair {
    private: StaticSecret,
    public: PublicKey,
}

impl IdentityKeyPair {
    pub fn generate() -> Result<Self> {
        let rng = SystemRandom::new();
        let mut private_bytes = [0u8; 32];
        ring::rand::SecureRandom::fill(&rng, &mut private_bytes)?;
        let private = StaticSecret::from(private_bytes);
        let public = PublicKey::from(&private);
        Ok(Self { private, public })
    }

    pub fn from_private_key(private_bytes: [u8; 32]) -> Self {
        let private = StaticSecret::from(private_bytes);
        let public = PublicKey::from(&private);
        Self { private, public }
    }

    pub fn from_base64(private_b64: &str, public_b64: Option<&str>) -> Result<Self> {
        let private_raw = base64::engine::general_purpose::STANDARD
            .decode(private_b64.as_bytes())
            .map_err(|_| ShphError::Crypto("invalid private key base64".into()))?;
        let private_arr: [u8; 32] = private_raw
            .try_into()
            .map_err(|_| ShphError::Crypto("private key must be 32 bytes".into()))?;
        let pair = Self::from_private_key(private_arr);
        if let Some(public_b64) = public_b64 {
            let expected = base64::engine::general_purpose::STANDARD
                .decode(public_b64.as_bytes())
                .map_err(|_| ShphError::Crypto("invalid public key base64".into()))?;
            if expected.as_slice() != pair.public.as_bytes() {
                return Err(ShphError::Crypto(
                    "public key does not match private key".into(),
                ));
            }
        }
        Ok(pair)
    }

    pub fn public(&self) -> &PublicKey {
        &self.public
    }

    pub fn private_key_bytes(&self) -> [u8; 32] {
        self.private.to_bytes()
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        *self.public.as_bytes()
    }

    pub fn private_key_b64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.private.to_bytes())
    }

    pub fn public_key_b64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.public.as_bytes())
    }

    pub fn fingerprint_hex(&self) -> String {
        compute_fingerprint_hex(self.public.as_bytes())
    }

    pub fn derive_shared(&self, peer_public: &PublicKey) -> [u8; 32] {
        self.private.diffie_hellman(peer_public).to_bytes()
    }

    pub fn sign_handshake(&self, transcript: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"shph-handshake-sign-v1");
        hasher.update(self.public.as_bytes());
        hasher.update(transcript);
        base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
    }

    pub fn verify_handshake_signature(
        &self,
        transcript: &[u8],
        signature_b64: &str,
        peer_public_raw: &[u8; 32],
    ) -> Result<()> {
        let provided = base64::engine::general_purpose::STANDARD
            .decode(signature_b64.as_bytes())
            .map_err(|_| ShphError::Handshake("invalid signature encoding".into()))?;
        let mut hasher = Sha256::new();
        hasher.update(b"shph-handshake-sign-v1");
        hasher.update(peer_public_raw);
        hasher.update(transcript);
        let expected = hasher.finalize();
        if provided.as_slice() != expected.as_slice() {
            return Err(ShphError::Handshake("signature verification failed".into()));
        }
        Ok(())
    }
}

impl zeroize::Zeroize for IdentityKeyPair {
    fn zeroize(&mut self) {
        self.private = StaticSecret::from([0u8; 32]);
    }
}

/// Session keys derived from shared secret.
#[derive(Debug, Clone)]
pub struct SessionKeys {
    pub send_key: [u8; 32],
    pub recv_key: [u8; 32],
    pub send_nonce: u64,
    pub recv_nonce: u64,
}

pub fn hkdf_sha256(input_key: &[u8], info: &[&[u8]], output_len: usize) -> Result<Vec<u8>> {
    let salt = info.iter().fold(Vec::new(), |mut acc, i| {
        acc.extend_from_slice(i);
        acc
    });
    let hkdf = hkdf::Hkdf::<sha2::Sha256>::new(Some(&salt), input_key);
    let mut output = vec![0u8; output_len];
    hkdf.expand(&[], &mut output)
        .map_err(|e| ShphError::Crypto(e.to_string()))?;
    Ok(output)
}

/// ChaCha20-Poly1305 cipher for session encryption.
pub struct SendCipher {
    key: [u8; 32],
    nonce: u64,
}

impl SendCipher {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key, nonce: 0 }
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        use chacha20poly1305::ChaCha20Poly1305;

        let cipher = ChaCha20Poly1305::new_from_slice(&self.key)
            .map_err(|e| ShphError::Crypto(e.to_string()))?;
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..].copy_from_slice(&self.nonce.to_be_bytes());
        let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);
        let mut ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| ShphError::Crypto(e.to_string()))?;
        let mut framed = Vec::with_capacity(12 + ciphertext.len());
        framed.extend_from_slice(&nonce_bytes);
        framed.append(&mut ciphertext);
        self.nonce += 1;
        Ok(framed)
    }
}

pub struct ReceiveCipher {
    key: [u8; 32],
    last_nonce: Option<u64>,
}

impl ReceiveCipher {
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            key,
            // Tracks the highest accepted counter nonce. Because the sender
            // increments its nonce monotonically, any nonce <= the last
            // accepted one is a replay or a stale/out-of-order frame.
            last_nonce: None,
        }
    }

    /// Decrypt a framed ciphertext (12-byte AEAD nonce prefix + ciphertext)
    /// and reject replayed or out-of-order nonces.
    ///
    /// SHPH uses a monotonically increasing 64-bit counter as the AEAD nonce,
    /// so any nonce strictly less-than-or-equal to the highest one already
    /// accepted is treated as a replay and rejected (fail-closed). This makes
    /// capture-and-replay of a prior frame impossible even though the AEAD key
    /// is unchanged.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        use chacha20poly1305::ChaCha20Poly1305;

        let cipher = ChaCha20Poly1305::new_from_slice(&self.key)
            .map_err(|e| ShphError::Crypto(e.to_string()))?;
        if ciphertext.len() < 12 {
            return Err(ShphError::Crypto("ciphertext too short".into()));
        }
        let (nonce_bytes, ciphertext_only) = ciphertext.split_at(12);

        // Anti-replay: the AEAD nonce is a 64-bit big-endian counter in bytes
        // 4..12. Reject replays and stale/out-of-order nonces before
        // attempting decryption (fail-closed).
        let counter = nonce_counter(nonce_bytes)?;
        if self.last_nonce.is_some_and(|last| counter <= last) {
            return Err(ShphError::Crypto("replay or stale nonce rejected".into()));
        }
        self.last_nonce = Some(counter);

        let nonce = chacha20poly1305::Nonce::from_slice(nonce_bytes);
        cipher
            .decrypt(nonce, ciphertext_only)
            .map_err(|e| ShphError::Crypto(e.to_string()))
    }
}

/// Extract the 64-bit AEAD counter nonce from a 12-byte nonce prefix.
/// Bytes 0..4 are zero; bytes 4..12 hold the big-endian counter.
fn nonce_counter(nonce_bytes: &[u8]) -> Result<u64> {
    if nonce_bytes.len() < 12 {
        return Err(ShphError::Crypto("nonce too short".into()));
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&nonce_bytes[4..12]);
    Ok(u64::from_be_bytes(buf))
}

/// Replay window for inbound messages.
pub struct ReplayWindow {
    window: std::collections::HashSet<u64>,
    size: usize,
}

impl ReplayWindow {
    pub fn new(size: usize) -> Self {
        Self {
            window: std::collections::HashSet::new(),
            size,
        }
    }

    pub fn check_and_insert(&mut self, nonce: u64) -> bool {
        if self.window.contains(&nonce) {
            return false;
        }
        self.window.insert(nonce);
        if self.window.len() > self.size {
            self.window.clear();
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::{nonce_counter, ReceiveCipher, SendCipher};

    #[test]
    fn send_and_receive_roundtrip_succeeds() {
        let key = [0x11u8; 32];
        let mut sender = SendCipher::new(key);
        let mut receiver = ReceiveCipher::new(key);
        let frame = sender.encrypt(b"hello").expect("encrypt");
        let plain = receiver.decrypt(&frame).expect("decrypt");
        assert_eq!(plain, b"hello");
    }

    #[test]
    fn replayed_frame_is_rejected_fail_closed() {
        let key = [0x42u8; 32];
        let mut sender = SendCipher::new(key);
        let mut receiver = ReceiveCipher::new(key);

        // Frame 0 (nonce 0).
        let frame0 = sender.encrypt(b"first").expect("encrypt");
        receiver.decrypt(&frame0).expect("first accepted");

        // Replaying the exact same ciphertext (same nonce 0) must be rejected.
        let replay = receiver.decrypt(&frame0);
        assert!(replay.is_err(), "replay must be rejected");
    }

    #[test]
    fn out_of_order_nonce_is_rejected() {
        let key = [0x55u8; 32];
        let mut sender = SendCipher::new(key);
        let mut receiver = ReceiveCipher::new(key);

        // Send frames with nonces 0 then 1; receiver accepts the higher one.
        let _frame0 = sender.encrypt(b"a").expect("encrypt 0");
        let frame1 = sender.encrypt(b"b").expect("encrypt 1");
        // Receiver's first accepted frame is nonce 1 (skipping 0 is allowed for
        // the first frame), but a later attempt at a stale nonce must fail.
        receiver.decrypt(&frame1).expect("accept nonce 1");
        // Now forge a low nonce by re-encrypting with a fresh sender at nonce 0.
        let mut stale_sender = SendCipher::new(key);
        let stale = stale_sender
            .encrypt(b"replay-stale")
            .expect("encrypt stale");
        assert!(
            receiver.decrypt(&stale).is_err(),
            "stale/out-of-order nonce must be rejected"
        );
    }

    #[test]
    fn truncated_ciphertext_is_rejected_fail_closed() {
        let key = [0x77u8; 32];
        let mut receiver = ReceiveCipher::new(key);
        // Fewer than 12 bytes (no full nonce prefix).
        let short = [0u8; 8];
        assert!(receiver.decrypt(&short).is_err());
    }

    #[test]
    fn wrong_key_authentication_fails() {
        let mut sender = SendCipher::new([0x01u8; 32]);
        let mut receiver = ReceiveCipher::new([0x02u8; 32]);
        let frame = sender.encrypt(b"secret").expect("encrypt");
        // AEAD tag will not verify under the wrong key.
        assert!(receiver.decrypt(&frame).is_err());
    }

    #[test]
    fn nonce_counter_extracts_big_endian_counter() {
        // 4 zero bytes + 8-byte big-endian counter == 0x0102.
        let mut bytes = [0u8; 12];
        bytes[11] = 0x02;
        bytes[10] = 0x01;
        assert_eq!(nonce_counter(&bytes).unwrap(), 0x0102);
    }

    #[test]
    fn nonce_counter_rejects_short_input() {
        assert!(nonce_counter(&[0u8; 4]).is_err());
    }
}
