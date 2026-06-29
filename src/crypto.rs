//! Cryptographic primitives for SHPH.
//!
//! Implements X25519 key exchange, HKDF key derivation, and ChaCha20-Poly1305 encryption.

use chacha20poly1305::aead::{Aead, NewAead, Nonce};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use ring::rand::{SecureRandom, SystemRandom};
use sha2::Sha256;
use x25519_dalek::PublicKey;
use x25519_dalek::SecretKey;
use x25519_dalek::SharedSecret;
use zeroize::Zeroize;

use crate::error::{Result, ShphError};

/// X25519 key pair for Noise handshake
pub struct IdentityKeyPair {
    private: SecretKey,
    public: PublicKey,
}

impl IdentityKeyPair {
    pub fn generate() -> Result<Self> {
        let mut csprng = SystemRandom::new();
        let private = SecretKey::generate(&mut csprng)?;
        let public = PublicKey::from(&private);
        Ok(Self { private, public })
    }

    pub fn public(&self) -> &PublicKey {
        &self.public
    }

    pub fn derive_shared(&self, peer_public: &PublicKey) -> Result<SharedSecret> {
        Ok(self.private.derive(peer_public))
    }
}

impl zeroize::Zeroize for IdentityKeyPair {
    fn zeroize(&mut self) {
        self.private.as_mut().zeroize();
    }
}

/// Session keys derived from shared secret using HKDF
pub struct SessionKeys {
    pub send_key: [u8; 32],
    pub recv_key: [u8; 32],
    pub send_nonce: u64,
    pub recv_nonce: u64,
}

impl SessionKeys {
    pub fn derive(shared_secret: &SharedSecret) -> Self {
        let mut okm = [0u8; 64];
        let hkdf = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
        hkdf.expand(b"shph key derivation", &mut okm).unwrap();
        
        let mut send_key = [0u8; 32];
        let mut recv_key = [0u8; 32];
        send_key.copy_from_slice(&okm[0..32]);
        recv_key.copy_from_slice(&okm[32..64]);
        
        Self {
            send_key,
            recv_key,
            send_nonce: 0,
            recv_nonce: 0,
        }
    }
}

/// ChaCha20-Poly1305 cipher for session encryption
pub struct SendCipher {
    cipher: ChaCha20Poly1305,
    nonce: u64,
}

impl SendCipher {
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new_from_slice(&key),
            nonce: 0,
        }
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = Nonce::from_slice(&self.nonce.to_be_bytes());
        let ciphertext = self.cipher.encrypt(nonce, plaintext)
            .map_err(|e| ShphError::Crypto(e.to_string()))?;
        self.nonce += 1;
        Ok(ciphertext)
    }
}

pub struct ReceiveCipher {
    cipher: ChaCha20Poly1305,
    replay_window: ReplayWindow,
}

impl ReceiveCipher {
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new_from_slice(&key),
            replay_window: ReplayWindow::new(1024),
        }
    }

    pub fn decrypt(&mut self, nonce: u64, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if !self.replay_window.check_and_insert(nonce) {
            return Err(ShphError::Protocol("nonce replay detected".to_string()));
        }
        let nonce_bytes = Nonce::from_slice(&nonce.to_be_bytes());
        self.cipher.decrypt(nonce_bytes, ciphertext)
            .map_err(|e| ShphError::Crypto(e.to_string()))
    }
}

/// Replay window for inbound messages
pub struct ReplayWindow {
    window: std::collections::HashSet<u64>,
    size: usize,
}

impl ReplayWindow {
    pub fn new(size: usize) -> Self {
        Self { window: std::collections::HashSet::new(), size }
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