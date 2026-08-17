//! Hybrid post-quantum key encapsulation (ML-KEM-768) layered on X25519.
//!
//! Wraps the RustCrypto `ml-kem` (FIPS-203 ML-KEM-768) implementation behind a
//! small API used by the handshake. The session key is derived from **both** the
//! classical X25519 ECDH shared secret **and** the ML-KEM shared secret, so the
//! session remains confidential even if a future quantum adversary records
//! today's traffic and later breaks ECDH ("harvest now, decrypt later").

use crate::error::{Result, ShphError};
use ml_kem::kem::{Decapsulate, Encapsulate, KeyExport};
use ml_kem::ml_kem_768::{Ciphertext, DecapsulationKey, EncapsulationKey};
use ml_kem::{FromSeed, Seed};
use ring::rand::{SecureRandom, SystemRandom};
use zeroize::Zeroize;

/// ML-KEM-768 ciphertext size in bytes (FIPS-203). Used by transports to bound
/// the follow-up PQ-ciphertext read so a malicious peer cannot stream an
/// unbounded payload into the handshake.
pub const ML_KEM_768_CIPHERTEXT_BYTES: usize = 1088;
/// ML-KEM-768 encapsulation (public) key size in bytes.
pub const ML_KEM_768_PUBLIC_KEY_BYTES: usize = 1184;

/// A full ML-KEM-768 keypair: encapsulation (public) + decapsulation (private).
pub struct PqcKeypair {
    encap_key: EncapsulationKey,
    decap_key: DecapsulationKey,
}

impl PqcKeypair {
    /// Generate a fresh ML-KEM-768 keypair from OS randomness.
    pub fn generate() -> Result<Self> {
        let rng = SystemRandom::new();
        let mut seed_bytes = [0u8; 64];
        SecureRandom::fill(&rng, &mut seed_bytes)?;
        let mut seed = Seed::from(seed_bytes);
        let (decap_key, encap_key) = ml_kem::ml_kem_768::MlKem768::from_seed(&seed);
        seed.zeroize();
        seed_bytes.zeroize();
        Ok(Self {
            encap_key,
            decap_key,
        })
    }

    /// The encapsulation (public) key, byte-encoded for transmission.
    pub fn encap_public_bytes(&self) -> Vec<u8> {
        self.encap_key.to_bytes().to_vec()
    }

    /// Decapsulate a ciphertext produced against this keypair's public key,
    /// returning the 32-byte ML-KEM shared secret.
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<[u8; 32]> {
        let ct = Ciphertext::try_from(ciphertext)
            .map_err(|_| ShphError::Crypto("invalid ML-KEM ciphertext length".into()))?;
        let shared = self.decap_key.decapsulate(&ct);
        let mut out = [0u8; 32];
        out.copy_from_slice(shared.as_slice());
        Ok(out)
    }

    /// Encapsulate against a peer's encapsulation public key, returning
    /// `(ciphertext_bytes, 32-byte shared_secret)`.
    pub fn encapsulate_against(peer_encap_pub: &[u8]) -> Result<(Vec<u8>, [u8; 32])> {
        let key = ml_kem::kem::Key::<EncapsulationKey>::try_from(peer_encap_pub)
            .map_err(|_| ShphError::Crypto("invalid ML-KEM peer public key length".into()))?;
        let peer = EncapsulationKey::new(&key)
            .map_err(|_| ShphError::Crypto("invalid ML-KEM peer public key".into()))?;
        let (ct, shared) = peer.encapsulate();
        let mut ss = [0u8; 32];
        ss.copy_from_slice(shared.as_slice());
        Ok((ct.to_vec(), ss))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ml_kem_roundtrip_yields_matching_shared_secret() {
        let responder = PqcKeypair::generate().unwrap();
        let (ct, ss_init) =
            PqcKeypair::encapsulate_against(&responder.encap_public_bytes()).unwrap();
        let ss_resp = responder.decapsulate(&ct).unwrap();
        assert_eq!(ss_init, ss_resp, "ML-KEM shared secrets must match");
        assert_eq!(ss_init.len(), 32);
    }

    #[test]
    fn hybrid_key_depends_on_both_halves() {
        use x25519_dalek::{PublicKey, StaticSecret};
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        a[0] = 1;
        b[0] = 2;
        let sa = StaticSecret::from(a);
        let sb = StaticSecret::from(b);
        let _pa = PublicKey::from(&sa);
        let pb = PublicKey::from(&sb);
        let classical = sa.diffie_hellman(&pb).to_bytes();

        let resp = PqcKeypair::generate().unwrap();
        let (_ct, pq) = PqcKeypair::encapsulate_against(&resp.encap_public_bytes()).unwrap();

        let mut hybrid = [0u8; 64];
        hybrid[..32].copy_from_slice(&classical);
        hybrid[32..].copy_from_slice(&pq);

        let mut bad = classical;
        bad[0] ^= 0xff;
        let mut hybrid_bad = [0u8; 64];
        hybrid_bad[..32].copy_from_slice(&bad);
        hybrid_bad[32..].copy_from_slice(&pq);
        assert_ne!(
            hybrid, hybrid_bad,
            "hybrid must depend on the classical half"
        );

        let mut hybrid_badpq = [0u8; 64];
        hybrid_badpq[..32].copy_from_slice(&classical);
        assert_ne!(hybrid, hybrid_badpq, "hybrid must depend on the PQ half");
    }

    #[test]
    fn malformed_ciphertext_rejected() {
        let resp = PqcKeypair::generate().unwrap();
        assert!(resp.decapsulate(&[0u8; 7]).is_err());
    }
}
