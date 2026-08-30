use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ring::{
    rand::SystemRandom,
    signature::{self, Ed25519KeyPair, KeyPair, UnparsedPublicKey},
};
use std::{
    collections::{HashMap, VecDeque},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;

pub const CAPABILITY_VERSION: &str = "phantom-one.1";
const SIGNING_DOMAIN: &[u8] = b"SHPH-EDGE-CAPABILITY/PHANTOM-ONE/1\0";
const NONCE_LEN: usize = 16;
const MAX_TOKEN_LEN: usize = 4096;
const MAX_AUDIENCE_LEN: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityClaims {
    pub audience: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub nonce: [u8; NONCE_LEN],
}

impl CapabilityClaims {
    pub fn new(
        audience: impl Into<String>,
        issued_at: u64,
        expires_at: u64,
        nonce: [u8; 16],
    ) -> Self {
        Self {
            audience: audience.into(),
            issued_at,
            expires_at,
            nonce,
        }
    }

    pub fn validate_shape(&self, now: u64, max_lifetime: Duration) -> Result<(), CapabilityError> {
        if self.audience.is_empty() || self.audience.len() > MAX_AUDIENCE_LEN {
            return Err(CapabilityError::InvalidAudience);
        }
        if !self.audience.is_ascii()
            || self
                .audience
                .bytes()
                .any(|b| b <= 0x20 || b == b'/' || b == b'\\')
        {
            return Err(CapabilityError::InvalidAudience);
        }
        if self.expires_at <= self.issued_at {
            return Err(CapabilityError::InvalidLifetime);
        }
        if self.expires_at - self.issued_at > max_lifetime.as_secs() {
            return Err(CapabilityError::LifetimeTooLong);
        }
        if now < self.issued_at {
            return Err(CapabilityError::NotYetValid);
        }
        if now >= self.expires_at {
            return Err(CapabilityError::Expired);
        }
        Ok(())
    }

    fn encode(&self) -> Result<Vec<u8>, CapabilityError> {
        let audience = self.audience.as_bytes();
        if audience.len() > u8::MAX as usize {
            return Err(CapabilityError::InvalidAudience);
        }
        let mut out = Vec::with_capacity(1 + audience.len() + 8 + 8 + NONCE_LEN);
        out.push(audience.len() as u8);
        out.extend_from_slice(audience);
        out.extend_from_slice(&self.issued_at.to_be_bytes());
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        out.extend_from_slice(&self.nonce);
        Ok(out)
    }

    fn decode(payload: &[u8]) -> Result<Self, CapabilityError> {
        if payload.len() < 1 + 8 + 8 + NONCE_LEN {
            return Err(CapabilityError::Malformed);
        }
        let audience_len = payload[0] as usize;
        let expected = 1 + audience_len + 8 + 8 + NONCE_LEN;
        if audience_len == 0 || audience_len > MAX_AUDIENCE_LEN || expected != payload.len() {
            return Err(CapabilityError::Malformed);
        }
        let audience = std::str::from_utf8(&payload[1..1 + audience_len])
            .map_err(|_| CapabilityError::Malformed)?
            .to_owned();
        let mut cursor = 1 + audience_len;
        let issued_at = u64::from_be_bytes(
            payload[cursor..cursor + 8]
                .try_into()
                .map_err(|_| CapabilityError::Malformed)?,
        );
        cursor += 8;
        let expires_at = u64::from_be_bytes(
            payload[cursor..cursor + 8]
                .try_into()
                .map_err(|_| CapabilityError::Malformed)?,
        );
        cursor += 8;
        let nonce: [u8; NONCE_LEN] = payload[cursor..]
            .try_into()
            .map_err(|_| CapabilityError::Malformed)?;
        Ok(Self::new(audience, issued_at, expires_at, nonce))
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CapabilityError {
    #[error("capability token is malformed")]
    Malformed,
    #[error("capability token has an invalid signature")]
    InvalidSignature,
    #[error("capability audience is invalid")]
    InvalidAudience,
    #[error("capability lifetime is invalid")]
    InvalidLifetime,
    #[error("capability lifetime exceeds the configured bound")]
    LifetimeTooLong,
    #[error("capability is not yet valid")]
    NotYetValid,
    #[error("capability is expired")]
    Expired,
    #[error("capability audience does not match this edge")]
    AudienceMismatch,
    #[error("capability nonce has already been used")]
    Replay,
    #[error("capability signing key is invalid")]
    InvalidSigningKey,
}

#[derive(Debug)]
pub struct CapabilityIssuer {
    key_pair: Ed25519KeyPair,
    max_lifetime: Duration,
}

impl CapabilityIssuer {
    pub fn from_pkcs8(pkcs8: &[u8], max_lifetime: Duration) -> Result<Self, CapabilityError> {
        let key_pair =
            Ed25519KeyPair::from_pkcs8(pkcs8).map_err(|_| CapabilityError::InvalidSigningKey)?;
        Ok(Self {
            key_pair,
            max_lifetime,
        })
    }

    pub fn generate(max_lifetime: Duration) -> Result<(Self, Vec<u8>), CapabilityError> {
        let rng = SystemRandom::new();
        let document =
            Ed25519KeyPair::generate_pkcs8(&rng).map_err(|_| CapabilityError::InvalidSigningKey)?;
        let issuer = Self::from_pkcs8(document.as_ref(), max_lifetime)?;
        Ok((issuer, document.as_ref().to_vec()))
    }

    pub fn public_key(&self) -> [u8; 32] {
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(self.key_pair.public_key().as_ref());
        public_key
    }

    pub fn issue(&self, claims: &CapabilityClaims) -> Result<String, CapabilityError> {
        let now = claims.issued_at;
        claims.validate_shape(now, self.max_lifetime)?;
        let payload = claims.encode()?;
        let signing_input = signing_input(&payload);
        let signature = self.key_pair.sign(&signing_input);
        Ok(format!(
            "{CAPABILITY_VERSION}.{}.{}",
            URL_SAFE_NO_PAD.encode(payload),
            URL_SAFE_NO_PAD.encode(signature.as_ref())
        ))
    }
}

#[derive(Debug)]
pub struct CapabilityVerifier {
    public_key: [u8; 32],
    audience: String,
    max_lifetime: Duration,
    clock_skew: Duration,
}

impl CapabilityVerifier {
    pub fn new(
        public_key: [u8; 32],
        audience: impl Into<String>,
        max_lifetime: Duration,
        clock_skew: Duration,
    ) -> Result<Self, CapabilityError> {
        let audience = audience.into();
        let shape = CapabilityClaims::new(audience.clone(), 1, 2, [0; 16]);
        shape
            .validate_shape(1, max_lifetime)
            .map_err(|_| CapabilityError::InvalidAudience)?;
        Ok(Self {
            public_key,
            audience,
            max_lifetime,
            clock_skew,
        })
    }

    pub fn verify(
        &self,
        token: &str,
        now: u64,
        replay: &mut ReplayCache,
    ) -> Result<CapabilityClaims, CapabilityError> {
        if token.len() > MAX_TOKEN_LEN {
            return Err(CapabilityError::Malformed);
        }
        let Some(encoded) = token.strip_prefix(&format!("{CAPABILITY_VERSION}.")) else {
            return Err(CapabilityError::Malformed);
        };
        let Some((payload_b64, signature_b64)) = encoded.split_once('.') else {
            return Err(CapabilityError::Malformed);
        };
        let payload = URL_SAFE_NO_PAD
            .decode(payload_b64)
            .map_err(|_| CapabilityError::Malformed)?;
        let signature_bytes = URL_SAFE_NO_PAD
            .decode(signature_b64)
            .map_err(|_| CapabilityError::Malformed)?;
        if signature_bytes.len() != 64 {
            return Err(CapabilityError::Malformed);
        }
        UnparsedPublicKey::new(&signature::ED25519, self.public_key)
            .verify(&signing_input(&payload), &signature_bytes)
            .map_err(|_| CapabilityError::InvalidSignature)?;
        let claims = CapabilityClaims::decode(&payload)?;
        if claims.audience != self.audience {
            return Err(CapabilityError::AudienceMismatch);
        }
        let lower = now.saturating_sub(self.clock_skew.as_secs());
        let upper = now.saturating_add(self.clock_skew.as_secs());
        if claims.issued_at > upper {
            return Err(CapabilityError::NotYetValid);
        }
        if claims.expires_at <= lower {
            return Err(CapabilityError::Expired);
        }
        let lifetime = claims
            .expires_at
            .checked_sub(claims.issued_at)
            .ok_or(CapabilityError::InvalidLifetime)?;
        if lifetime == 0 {
            return Err(CapabilityError::InvalidLifetime);
        }
        if lifetime > self.max_lifetime.as_secs() {
            return Err(CapabilityError::LifetimeTooLong);
        }
        if !replay.insert(claims.nonce, claims.expires_at, now) {
            return Err(CapabilityError::Replay);
        }
        Ok(claims)
    }
}

fn signing_input(payload: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(SIGNING_DOMAIN.len() + payload.len());
    input.extend_from_slice(SIGNING_DOMAIN);
    input.extend_from_slice(payload);
    input
}

#[derive(Debug)]
pub struct ReplayCache {
    capacity: usize,
    entries: HashMap<[u8; NONCE_LEN], u64>,
    order: VecDeque<([u8; NONCE_LEN], u64)>,
}

impl ReplayCache {
    pub fn new(capacity: usize) -> Result<Self, CapabilityError> {
        if capacity == 0 {
            return Err(CapabilityError::Malformed);
        }
        Ok(Self {
            capacity,
            entries: HashMap::with_capacity(capacity),
            order: VecDeque::with_capacity(capacity),
        })
    }

    pub fn insert(&mut self, nonce: [u8; NONCE_LEN], expires_at: u64, now: u64) -> bool {
        self.prune(now);
        if self.entries.contains_key(&nonce) {
            return false;
        }
        while self.entries.len() >= self.capacity {
            if let Some((old_nonce, _)) = self.order.pop_front() {
                self.entries.remove(&old_nonce);
            } else {
                break;
            }
        }
        self.entries.insert(nonce, expires_at);
        self.order.push_back((nonce, expires_at));
        true
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn prune(&mut self, now: u64) {
        while let Some((nonce, expires_at)) = self.order.front().copied() {
            if expires_at > now {
                break;
            }
            self.order.pop_front();
            self.entries.remove(&nonce);
        }
    }
}

pub fn unix_now() -> Result<u64, CapabilityError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .map_err(|_| CapabilityError::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issuer_verifier() -> (CapabilityIssuer, CapabilityVerifier) {
        let (issuer, _) = CapabilityIssuer::generate(Duration::from_secs(60)).expect("key");
        let verifier = CapabilityVerifier::new(
            issuer.public_key(),
            "edge-a",
            Duration::from_secs(60),
            Duration::ZERO,
        )
        .expect("verifier");
        (issuer, verifier)
    }

    fn claims(nonce: u8) -> CapabilityClaims {
        CapabilityClaims::new("edge-a", 100, 120, [nonce; NONCE_LEN])
    }

    #[test]
    fn round_trip_signature_and_parsing() {
        let (issuer, verifier) = issuer_verifier();
        let token = issuer.issue(&claims(1)).expect("token");
        let mut replay = ReplayCache::new(4).expect("cache");
        assert_eq!(
            verifier.verify(&token, 110, &mut replay).expect("claims"),
            claims(1)
        );
    }

    #[test]
    fn rejects_tampering_expiry_audience_and_replay() {
        let (issuer, verifier) = issuer_verifier();
        let mut replay = ReplayCache::new(4).expect("cache");
        let token = issuer.issue(&claims(2)).expect("token");
        assert_eq!(
            verifier.verify(&token, 120, &mut replay),
            Err(CapabilityError::Expired)
        );
        assert!(verifier.verify(&token, 110, &mut replay).is_ok());
        assert_eq!(
            verifier.verify(&token, 110, &mut replay),
            Err(CapabilityError::Replay)
        );

        let other = CapabilityClaims::new("other", 100, 120, [3; NONCE_LEN]);
        let other_token = issuer.issue(&other).expect("token");
        assert_eq!(
            verifier.verify(&other_token, 110, &mut replay),
            Err(CapabilityError::AudienceMismatch)
        );
    }

    #[test]
    fn cache_is_bounded_and_prunes() {
        let mut cache = ReplayCache::new(2).expect("cache");
        assert!(cache.insert([1; 16], 10, 0));
        assert!(cache.insert([2; 16], 11, 0));
        assert!(!cache.insert([1; 16], 10, 0));
        assert!(cache.insert([3; 16], 12, 0));
        assert_eq!(cache.len(), 2);
        assert!(cache.insert([1; 16], 10, 12));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn verifier_rejects_expiry_before_issue_without_panicking() {
        let (issuer, _) = issuer_verifier();
        let verifier = CapabilityVerifier::new(
            issuer.public_key(),
            "edge-a",
            Duration::from_secs(60),
            Duration::from_secs(30),
        )
        .expect("verifier");
        let claims = CapabilityClaims::new("edge-a", 120, 100, [9; NONCE_LEN]);
        let token = format!(
            "{CAPABILITY_VERSION}.{}.{}",
            URL_SAFE_NO_PAD.encode(claims.encode().expect("claims")),
            URL_SAFE_NO_PAD.encode(
                issuer
                    .key_pair
                    .sign(&signing_input(&claims.encode().expect("claims")))
                    .as_ref()
            )
        );
        let mut replay = ReplayCache::new(4).expect("cache");
        assert_eq!(
            verifier.verify(&token, 120, &mut replay),
            Err(CapabilityError::InvalidLifetime)
        );
    }
}
