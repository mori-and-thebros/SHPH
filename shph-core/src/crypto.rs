//! Cryptographic primitives for SHPH.
//!
//! This module provides identity management, key derivation, and session crypto.

use base64::Engine as _;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::KeyInit;
use ring::rand::SystemRandom;
use ring::signature::KeyPair as _;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::error::{Result, ShphError};
use crate::keystore::compute_fingerprint_hex;

/// X25519 key pair for handshake and session key derivation, paired with an
/// Ed25519 key pair used to authenticate the handshake transcript.
///
/// The two keys are independent (X25519 for DH, Ed25519 for signatures); both
/// 32-byte seeds are persisted by the keystore. The Ed25519 signature binds the
/// X25519 identity key, the ephemeral key, the nonce, the timestamp, and the
/// Ed25519 public key itself, so the keys cannot be swapped by a MITM.
#[derive(Clone)]
pub struct IdentityKeyPair {
    private: StaticSecret,
    public: PublicKey,
    signing: std::sync::Arc<ring::signature::Ed25519KeyPair>,
    sign_seed: [u8; 32],
}

impl IdentityKeyPair {
    pub fn generate() -> Result<Self> {
        let rng = SystemRandom::new();
        let mut private_bytes = [0u8; 32];
        ring::rand::SecureRandom::fill(&rng, &mut private_bytes)?;
        // Independent Ed25519 signing seed (distinct from the X25519 DH seed).
        let mut sign_seed = [0u8; 32];
        ring::rand::SecureRandom::fill(&rng, &mut sign_seed)?;
        Ok(Self::from_seeds(private_bytes, sign_seed))
    }

    /// Reconstruct from the X25519 DH seed only. The Ed25519 signing seed is
    /// taken as the same bytes (used when an old keystore lacks a separate
    /// signing seed; such identities must be re-`init`ed to sign properly).
    pub fn from_private_key(private_bytes: [u8; 32]) -> Self {
        Self::from_seeds(private_bytes, private_bytes)
    }

    /// Reconstruct from independent X25519 (DH) and Ed25519 (signing) seeds.
    pub fn from_seeds(dh_seed: [u8; 32], sign_seed: [u8; 32]) -> Self {
        let private = StaticSecret::from(dh_seed);
        let public = PublicKey::from(&private);
        let signing = std::sync::Arc::new(
            ring::signature::Ed25519KeyPair::from_seed_unchecked(&sign_seed)
                .expect("any 32 bytes is a valid Ed25519 seed"),
        );
        Self {
            private,
            public,
            signing,
            sign_seed,
        }
    }

    /// The 32-byte Ed25519 signing seed, for keystore persistence.
    pub fn signing_seed(&self) -> [u8; 32] {
        self.sign_seed
    }

    pub fn signing_seed_b64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.sign_seed)
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

    /// Ed25519 signing public key (32 bytes) used to verify handshake
    /// signatures. Distinct from the X25519 DH public key.
    pub fn signing_public_bytes(&self) -> [u8; 32] {
        let p = self.signing.public_key().as_ref();
        let mut out = [0u8; 32];
        let n = p.len().min(32);
        out[..n].copy_from_slice(&p[..n]);
        out
    }

    pub fn signing_public_b64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.signing_public_bytes())
    }

    pub fn fingerprint_hex(&self) -> String {
        compute_fingerprint_hex(self.public.as_bytes())
    }

    pub fn derive_shared(&self, peer_public: &PublicKey) -> [u8; 32] {
        self.private.diffie_hellman(peer_public).to_bytes()
    }

    /// Sign the handshake transcript with the identity's Ed25519 key.
    /// Returns the detached signature, base64-encoded.
    pub fn sign_handshake(&self, transcript: &[u8]) -> String {
        let sig = self.signing.sign(transcript);
        base64::engine::general_purpose::STANDARD.encode(sig)
    }

    /// Verify a peer's Ed25519 handshake signature over `transcript` using the
    /// peer's Ed25519 signing public key (`peer_sign_public`). This is a true
    /// public-key signature: only the holder of the peer's Ed25519 private key
    /// can produce a signature that verifies, giving the handshake real
    /// authentication and MITM resistance.
    pub fn verify_handshake_signature(
        &self,
        transcript: &[u8],
        signature_b64: &str,
        peer_sign_public: &[u8; 32],
    ) -> Result<()> {
        let sig = base64::engine::general_purpose::STANDARD
            .decode(signature_b64.as_bytes())
            .map_err(|_| ShphError::Handshake("invalid signature encoding".into()))?;
        let peer_key =
            ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, peer_sign_public);
        peer_key
            .verify(transcript, &sig)
            .map_err(|_| ShphError::Handshake("signature verification failed".into()))
    }
}

/// Constant-time equality check for secret/credential comparisons.
///
/// Returns `true` iff `a` and `b` are the same length and have identical bytes.
/// The comparison runs in time independent of where (or whether) the first
/// difference occurs, so it does not leak how much of a signature, digest, or
/// fingerprint matched. Unequal lengths are reported as not-equal while still
/// scanning to avoid a length-based timing oracle on the shorter input.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        // Still walk the longer input to avoid leaking the length relationship
        // through early return; the result is fixed (mismatch).
        let longest = if a.len() > b.len() { a } else { b };
        let mut sink = 0u8;
        for &byte in longest {
            sink |= byte;
        }
        let _ = sink;
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

impl zeroize::Zeroize for IdentityKeyPair {
    fn zeroize(&mut self) {
        self.private = StaticSecret::from([0u8; 32]);
        self.sign_seed.zeroize();
    }
}

impl Drop for IdentityKeyPair {
    fn drop(&mut self) {
        // The X25519 `StaticSecret` zeroizes itself on drop; the raw Ed25519
        // signing seed is a plain array we must wipe explicitly so it does not
        // persist in freed heap memory after the identity is discarded.
        self.sign_seed.zeroize();
    }
}

/// Session keys derived from shared secret.
///
/// The symmetric session keys are zeroized on drop so they do not linger in
/// heap memory after the session ends (mitigating core-dump / swap / memory-
/// disclosure exposure of live traffic keys).
#[derive(Debug, Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct SessionKeys {
    #[zeroize(skip)]
    pub send_nonce: u64,
    #[zeroize(skip)]
    pub recv_nonce: u64,
    pub send_key: [u8; 32],
    pub recv_key: [u8; 32],
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

/// Maximum AEAD counter nonce before the session MUST rekey. ChaCha20-Poly1305
/// is safe for 2^32 messages under a single key; SHPH stops at one less than
/// that to make nonce reuse via counter overflow impossible. Hitting this cap
/// fails closed rather than wrapping the counter back to a reused nonce.
pub const AEAD_NONCE_LIMIT: u64 = (1u64 << 32) - 1;

/// ChaCha20-Poly1305 cipher for session encryption.
pub struct SendCipher {
    key: [u8; 32],
    nonce: u64,
}

impl Drop for SendCipher {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl SendCipher {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key, nonce: 0 }
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        use chacha20poly1305::ChaCha20Poly1305;

        // Fail closed before nonce reuse: once the counter reaches the limit,
        // refuse to encrypt further. The caller must establish a new session
        // (new key) rather than letting the 64-bit counter wrap.
        if self.nonce >= AEAD_NONCE_LIMIT {
            return Err(ShphError::Crypto(
                "AEAD nonce limit reached; rekey required to avoid nonce reuse".into(),
            ));
        }

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

impl Drop for ReceiveCipher {
    fn drop(&mut self) {
        self.key.zeroize();
    }
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

/// Sliding anti-replay window over the 64-bit counter nonce space.
///
/// Tracks the highest nonce seen plus a bitmap of the last `size` nonces below
/// it. A nonce is rejected if it equals a previously-seen nonce, or if it falls
/// below the bottom of the window (too old to distinguish from a replay
/// safely). This replaces an earlier implementation that cleared the whole set
/// when it filled, which dropped all protection across the clear boundary (a
/// previously-seen nonce became acceptable again after the clear).
pub struct ReplayWindow {
    /// Highest accepted nonce so far (None until the first valid nonce).
    highest: Option<u64>,
    /// Bitmap of accepted nonces within the window below `highest`. Bit `i`
    /// (counting down from the top) is set when nonce `highest - 1 - i` has
    /// been seen.
    bits: Vec<u64>,
    /// Window width in nonce units (a multiple of 64).
    size: usize,
}

impl ReplayWindow {
    pub fn new(size: usize) -> Self {
        // At least one word (64 nonces) so the window is non-trivial and the
        // word math is sound.
        let size = size.max(64);
        let words = size.div_ceil(64);
        Self {
            highest: None,
            bits: vec![0u64; words],
            size: words * 64,
        }
    }

    /// Record `nonce` if it is fresh; return `true` if accepted, `false` if it
    /// is a replay or falls below the window (too old to track safely).
    pub fn check_and_insert(&mut self, nonce: u64) -> bool {
        match self.highest {
            None => {
                self.highest = Some(nonce);
                true
            }
            Some(highest) => {
                if nonce > highest {
                    // Advance the window. First record the previous highest as
                    // seen (offset 0 == the nonce just below the new highest is
                    // the old highest), then shift the bitmap down by the gap.
                    // A gap larger than the window simply resets the bitmap.
                    let gap = nonce - highest;
                    if gap >= self.size as u64 {
                        self.bits.iter_mut().for_each(|w| *w = 0);
                    } else {
                        self.shift_down(gap as usize);
                        // After shifting, bit index (gap-1) corresponds to the
                        // old highest; mark it seen so it cannot be replayed.
                        let bit_index = (gap - 1) as usize;
                        let word = bit_index / 64;
                        let mask = 1u64 << (bit_index % 64);
                        self.bits[word] |= mask;
                    }
                    self.highest = Some(nonce);
                    true
                } else {
                    // Within or below the window. Reject if stale (at/below
                    // the window bottom) or already seen.
                    let offset = highest - nonce;
                    if offset == 0 || offset > self.size as u64 {
                        return false;
                    }
                    let bit_index = (offset - 1) as usize;
                    let word = bit_index / 64;
                    let mask = 1u64 << (bit_index % 64);
                    if self.bits[word] & mask != 0 {
                        return false;
                    }
                    self.bits[word] |= mask;
                    true
                }
            }
        }
    }

    /// Shift the bitmap down by `gap` positions, dropping the lowest `gap`
    /// nonces (they fall out of the window). Requires `gap < size`.
    fn shift_down(&mut self, gap: usize) {
        let word_shift = gap / 64;
        let bit_shift = gap % 64;
        let words = self.bits.len();
        let mut out = vec![0u64; words];
        if bit_shift == 0 {
            for i in 0..words {
                if i + word_shift < words {
                    out[i + word_shift] = self.bits[i];
                }
            }
        } else {
            for i in 0..words {
                let lo = self.bits[i] << bit_shift;
                if i + word_shift < words {
                    out[i + word_shift] |= lo;
                }
                let hi = self.bits[i] >> (64 - bit_shift);
                if i + word_shift + 1 < words {
                    out[i + word_shift + 1] |= hi;
                }
            }
        }
        self.bits = out;
    }
}

#[cfg(test)]
mod tests {
    use super::{
        constant_time_eq, nonce_counter, IdentityKeyPair, ReceiveCipher, ReplayWindow, SendCipher,
        SessionKeys, AEAD_NONCE_LIMIT,
    };

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

    // --- Crypto-hardening regression tests ---

    #[test]
    fn replay_window_accepts_monotonic_nonces() {
        let mut w = ReplayWindow::new(128);
        assert!(w.check_and_insert(1));
        assert!(w.check_and_insert(2));
        assert!(w.check_and_insert(1_000_000));
    }

    #[test]
    fn replay_window_rejects_exact_replay_within_window() {
        let mut w = ReplayWindow::new(128);
        w.check_and_insert(10);
        w.check_and_insert(20);
        // 10 is below the current highest (20) and within the window, and
        // already seen -> rejected.
        assert!(!w.check_and_insert(10), "replayed nonce must be rejected");
        // A fresh nonce just below the highest, not yet seen, is accepted.
        assert!(
            w.check_and_insert(15),
            "fresh in-window nonce must be accepted"
        );
    }

    #[test]
    fn replay_window_rejects_replay_after_many_advances() {
        // Regression for the old clear-on-full bug: after the window advanced
        // well past an old nonce, replaying that old nonce must STILL be
        // rejected (it is below the window bottom, too old to be safe).
        let mut w = ReplayWindow::new(128);
        let old = 5;
        w.check_and_insert(old);
        // Advance far beyond the window width.
        for n in (old + 1)..(old + 1 + 10_000) {
            assert!(w.check_and_insert(n));
        }
        assert!(
            !w.check_and_insert(old),
            "old nonce below window must be rejected even after many advances"
        );
    }

    #[test]
    fn replay_window_rejects_zero_offset_duplicate_at_highest() {
        let mut w = ReplayWindow::new(128);
        w.check_and_insert(42);
        // Equal to highest -> duplicate, rejected.
        assert!(!w.check_and_insert(42));
    }

    #[test]
    fn send_cipher_fails_closed_at_nonce_limit() {
        let mut sender = SendCipher::new([0x77u8; 32]);
        // Fast-forward the counter to the limit.
        sender.nonce = AEAD_NONCE_LIMIT;
        let res = sender.encrypt(b"one-too-many");
        assert!(
            res.is_err(),
            "encrypt must fail closed at the nonce limit to prevent nonce reuse"
        );
    }

    #[test]
    fn send_cipher_encrypts_just_below_limit() {
        let mut sender = SendCipher::new([0x88u8; 32]);
        sender.nonce = AEAD_NONCE_LIMIT - 1;
        // The last allowed encryption (nonce = LIMIT-1) must succeed; the next
        // would hit the guard.
        assert!(sender.encrypt(b"last-one").is_ok());
        assert!(sender.encrypt(b"overflow").is_err());
    }

    #[test]
    fn constant_time_eq_matches_semantics() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(!constant_time_eq(b"abcd", b"abc"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn constant_time_eq_rejects_prefix() {
        // A matching prefix must not be reported as equal.
        assert!(!constant_time_eq(b"signature-v1", b"signature-v2"));
    }

    #[test]
    fn send_cipher_zeroizes_key_on_drop() {
        // Wrap in ManuallyDrop so we control when Drop runs, then read the key
        // field directly (tests are in-module, so private fields are visible).
        use std::mem::ManuallyDrop;
        use std::ptr;
        let mut cipher = ManuallyDrop::new(SendCipher::new([0xABu8; 32]));
        assert_eq!(cipher.key, [0xABu8; 32]);
        // Run Drop in place on the contained value.
        unsafe { ptr::drop_in_place(&mut *cipher) };
        assert_eq!(cipher.key, [0u8; 32]);
        // Drop already ran; forget so it does not run a second time.
        let _inner = ManuallyDrop::into_inner(cipher);
        std::mem::forget(_inner);
    }

    #[test]
    fn receive_cipher_zeroizes_key_on_drop() {
        use std::mem::ManuallyDrop;
        use std::ptr;
        let mut cipher = ManuallyDrop::new(ReceiveCipher::new([0xCDu8; 32]));
        assert_eq!(cipher.key, [0xCDu8; 32]);
        unsafe { ptr::drop_in_place(&mut *cipher) };
        assert_eq!(cipher.key, [0u8; 32]);
        let _inner = ManuallyDrop::into_inner(cipher);
        std::mem::forget(_inner);
    }

    #[test]
    fn session_keys_zeroizes_on_drop() {
        use std::mem::ManuallyDrop;
        use std::ptr;
        let mut sk = ManuallyDrop::new(SessionKeys {
            send_key: [0x11u8; 32],
            recv_key: [0x22u8; 32],
            send_nonce: 7,
            recv_nonce: 3,
        });
        assert_eq!(sk.send_key, [0x11u8; 32]);
        unsafe { ptr::drop_in_place(&mut *sk) };
        assert_eq!(sk.send_key, [0u8; 32]);
        assert_eq!(sk.recv_key, [0u8; 32]);
        let _inner = ManuallyDrop::into_inner(sk);
        std::mem::forget(_inner);
    }

    #[test]
    fn identity_keypair_zeroizes_sign_seed_on_drop() {
        use std::mem::ManuallyDrop;
        use std::ptr;
        let seed = [0xFEu8; 32];
        let mut id = ManuallyDrop::new(IdentityKeyPair::from_private_key(seed));
        assert_eq!(id.sign_seed, [0xFEu8; 32]);
        unsafe { ptr::drop_in_place(&mut *id) };
        assert_eq!(id.sign_seed, [0u8; 32]);
        let _inner = ManuallyDrop::into_inner(id);
        std::mem::forget(_inner);
    }
}
