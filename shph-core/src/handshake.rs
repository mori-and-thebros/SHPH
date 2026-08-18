//! Handshake protocol for session establishment.

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};
use x25519_dalek::PublicKey;
use zeroize::Zeroizing;

use crate::crypto::{constant_time_eq, hkdf_sha256_into, IdentityKeyPair, SessionKeys};
use crate::error::{Result, ShphError};
use crate::keystore::compute_fingerprint_hex;

const HANDSHAKE_VERSION: u8 = 5;
const MAX_SIGNED_PAYLOAD_BYTES: usize = 1_400;
pub const MAX_HANDSHAKE_FRAME_TAIL_BYTES: usize = 64;

/// Maximum number of configured peer pins accepted by a handshake policy.
///
/// Every candidate is checked against an authenticated hello, so leaving this
/// vector unbounded would make a caller-supplied policy an avoidable CPU/memory
/// amplification surface.
pub const MAX_PEER_PINS: usize = 4_096;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HandshakeProfile {
    #[default]
    SecureDefault,
    ClassicalLab,
}

impl HandshakeProfile {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SecureDefault => "secure-default",
            Self::ClassicalLab => "classical-lab",
        }
    }

    pub const fn protocol_tag(self) -> &'static str {
        match self {
            Self::SecureDefault => "shph/5/secure-default",
            Self::ClassicalLab => "shph/5/classical-lab",
        }
    }

    pub const fn uses_pqc(self) -> bool {
        matches!(self, Self::SecureDefault)
    }
}

impl FromStr for HandshakeProfile {
    type Err = ShphError;

    fn from_str(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "secure-default" | "secure_default" | "secure" => Ok(Self::SecureDefault),
            "classical-lab" | "classical_lab" | "classical" => Ok(Self::ClassicalLab),
            _ => Err(ShphError::InvalidArgument(format!(
                "unsupported handshake profile: {value}"
            ))),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hello {
    pub proto: String,
    pub profile: HandshakeProfile,
    pub identity_pub_b64: String,
    /// Ed25519 signing public key (base64). Bound into the signed payload so a
    /// MITM cannot swap it for a different signing key.
    pub sign_pub_b64: String,
    /// ML-KEM-768 encapsulation public key (base64) for the hybrid PQ key exchange.
    pub pqc_pub_b64: Option<String>,
    /// ML-KEM-768 ciphertext (base64) the sender produced against the peer's PQ
    /// public key. Both sides decapsulate the peer's ciphertext against their
    /// own PQ key, giving a shared PQ secret combined with X25519 ECDH.
    pub pqc_ct_b64: Option<String>,
    pub ephemeral_pub_b64: String,
    pub nonce_b64: String,
    pub timestamp_secs: u64,
    pub sig: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeVersion {
    V2,
}

impl HandshakeVersion {
    pub fn as_u8(&self) -> u8 {
        match self {
            HandshakeVersion::V2 => HANDSHAKE_VERSION,
        }
    }
}

pub struct HandshakeMaterial {
    pub local_ephemeral: IdentityKeyPair,
    pub local_nonce: [u8; 32],
    pub profile: HandshakeProfile,
    pub local_pqc: Option<crate::pqc::PqcKeypair>,
    pub local_hello: Hello,
    /// Hybrid ML-KEM-768 shared secret, populated by [`finalize_initiator_pq`]
    /// (initiator) or [`absorb_responder_pq`] (responder) before key derivation.
    /// `None` here blocks derivation, preventing a silent classical downgrade.
    pub pq_shared: Option<Zeroizing<[u8; 32]>>,
    /// The exact ML-KEM ciphertext that produced `pq_shared`. This public
    /// handshake value is included in the KDF transcript so both sides bind
    /// their derived keys to the same encapsulation exchange.
    pub pq_ciphertext: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct HandshakeState {
    pub peer_fingerprint_hex: String,
    pub peer_identity_pubkey_b64: String,
    pub peer_signing_pubkey_b64: String,
    pub session_keys: SessionKeys,
    pub transcript_hash_hex: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeRole {
    Initiator,
    Responder,
}

/// Resolve the directional role deterministically from the two authenticated
/// peer IDs. This keeps both sides on the same send/receive mapping if both
/// peers initiate at the same time.
pub fn deterministic_role(local_identity: &[u8; 32], peer_identity: &[u8; 32]) -> HandshakeRole {
    if local_identity <= peer_identity {
        HandshakeRole::Initiator
    } else {
        HandshakeRole::Responder
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerPin {
    pub identity_public: [u8; 32],
    pub signing_public: [u8; 32],
}

impl PeerPin {
    pub const fn new(identity_public: [u8; 32], signing_public: [u8; 32]) -> Self {
        Self {
            identity_public,
            signing_public,
        }
    }

    pub fn for_identity(identity: &IdentityKeyPair) -> Self {
        Self::new(identity.public_key_bytes(), identity.signing_public_bytes())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerPolicy {
    pins: Vec<PeerPin>,
    allow_any: bool,
}

impl PeerPolicy {
    pub fn new(pins: Vec<PeerPin>) -> Result<Self> {
        if pins.is_empty() {
            return Err(ShphError::Auth("peer policy cannot be empty".into()));
        }
        if pins.len() > MAX_PEER_PINS {
            return Err(ShphError::Auth(format!(
                "peer policy exceeds the {MAX_PEER_PINS}-pin safety limit"
            )));
        }
        Ok(Self {
            pins,
            allow_any: false,
        })
    }

    pub fn single(pin: PeerPin) -> Self {
        Self {
            pins: vec![pin],
            allow_any: false,
        }
    }

    /// Create a temporary bootstrap policy for an explicit TOFU enrollment.
    ///
    /// Callers must persist and pin the authenticated peer before accepting
    /// another connection. This is intentionally not exposed through the
    /// ordinary configuration parser.
    pub fn allow_any() -> Self {
        Self {
            pins: Vec::new(),
            allow_any: true,
        }
    }

    pub fn pins(&self) -> &[PeerPin] {
        &self.pins
    }

    fn allows(&self, identity_public: &[u8; 32], signing_public: &[u8; 32]) -> bool {
        self.allow_any
            || self.pins.iter().any(|pin| {
                constant_time_eq(&pin.identity_public, identity_public)
                    && constant_time_eq(&pin.signing_public, signing_public)
            })
    }
}

pub fn build_hello(local_identity: &IdentityKeyPair) -> Result<HandshakeMaterial> {
    build_hello_with_profile(local_identity, HandshakeProfile::SecureDefault)
}

pub fn build_hello_with_profile(
    local_identity: &IdentityKeyPair,
    profile: HandshakeProfile,
) -> Result<HandshakeMaterial> {
    let local_ephemeral = IdentityKeyPair::generate()?;
    let rng = ring::rand::SystemRandom::new();
    let mut local_nonce = [0u8; 32];
    ring::rand::SecureRandom::fill(&rng, &mut local_nonce)?;
    let timestamp_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ShphError::Handshake("system clock before unix epoch".into()))?
        .as_secs();

    let sign_pub = local_identity.signing_public_bytes();
    let local_pqc = if profile.uses_pqc() {
        Some(crate::pqc::PqcKeypair::generate()?)
    } else {
        None
    };
    let pqc_pub = local_pqc.as_ref().map(|pqc| pqc.encap_public_bytes());
    // The PQ ciphertext each side sends is computed against the peer's PQ public
    // key, which is only known after the hellos are exchanged. It is filled in
    // during verify_and_derive; the hello carries an empty placeholder here.
    let mut signed_payload = [0u8; MAX_SIGNED_PAYLOAD_BYTES];
    let mut signed_len = 0;
    append_signed_part(
        &mut signed_payload,
        &mut signed_len,
        profile.protocol_tag().as_bytes(),
    )?;
    append_signed_part(
        &mut signed_payload,
        &mut signed_len,
        local_identity.public().as_bytes(),
    )?;
    append_signed_part(&mut signed_payload, &mut signed_len, &sign_pub)?;
    if let Some(pqc_pub) = &pqc_pub {
        append_signed_part(&mut signed_payload, &mut signed_len, pqc_pub)?;
    }
    append_signed_part(
        &mut signed_payload,
        &mut signed_len,
        local_ephemeral.public().as_bytes(),
    )?;
    append_signed_part(&mut signed_payload, &mut signed_len, &local_nonce)?;
    append_signed_part(
        &mut signed_payload,
        &mut signed_len,
        &timestamp_secs.to_be_bytes(),
    )?;
    let sig = local_identity.sign_handshake(&signed_payload[..signed_len]);

    let local_hello = Hello {
        proto: profile.protocol_tag().to_string(),
        profile,
        identity_pub_b64: base64::engine::general_purpose::STANDARD
            .encode(local_identity.public().as_bytes()),
        sign_pub_b64: base64::engine::general_purpose::STANDARD.encode(sign_pub),
        pqc_pub_b64: pqc_pub
            .as_ref()
            .map(|pqc_pub| base64::engine::general_purpose::STANDARD.encode(pqc_pub)),
        // Filled in by verify_and_derive once the peer PQ key is known.
        pqc_ct_b64: None,
        ephemeral_pub_b64: base64::engine::general_purpose::STANDARD
            .encode(local_ephemeral.public().as_bytes()),
        nonce_b64: base64::engine::general_purpose::STANDARD.encode(local_nonce),
        timestamp_secs,
        sig,
    };

    Ok(HandshakeMaterial {
        local_ephemeral,
        local_nonce,
        profile,
        local_pqc,
        local_hello,
        pq_shared: None,
        pq_ciphertext: None,
    })
}

/// Serialize the outer hello frame with a bounded, randomized whitespace tail.
///
/// The tail is deliberately valid JSON whitespace so existing newline- and
/// datagram-delimited transports can parse the canonical hello without a
/// second framing format. Its length and byte values are randomized by the
/// core layer, making the initial envelope size non-deterministic while
/// keeping the authenticated hello fields unchanged.
pub fn serialize_hello_frame(hello: &Hello) -> Result<Vec<u8>> {
    let rng = ring::rand::SystemRandom::new();
    let mut random = [0u8; 1];
    ring::rand::SecureRandom::fill(&rng, &mut random)?;
    let padding_len = usize::from(random[0]) % (MAX_HANDSHAKE_FRAME_TAIL_BYTES + 1);
    serialize_hello_frame_with_padding_len(hello, padding_len)
}

/// Serialize a hello with an explicit tail length for deterministic tests and
/// transport-level size-bound checks.
pub fn serialize_hello_frame_with_padding_len(
    hello: &Hello,
    padding_len: usize,
) -> Result<Vec<u8>> {
    if padding_len > MAX_HANDSHAKE_FRAME_TAIL_BYTES {
        return Err(ShphError::Protocol(
            "handshake frame tail exceeds size limit".into(),
        ));
    }
    let mut payload = serde_json::to_vec(hello).map_err(ShphError::Serialization)?;
    if padding_len == 0 {
        return Ok(payload);
    }

    let rng = ring::rand::SystemRandom::new();
    let mut random_tail = [0u8; MAX_HANDSHAKE_FRAME_TAIL_BYTES];
    ring::rand::SecureRandom::fill(&rng, &mut random_tail)?;
    payload.reserve(padding_len);
    for random in random_tail.into_iter().take(padding_len) {
        // JSON permits only space, tab, CR, and LF after a value. Avoid LF/CR
        // because TCP uses LF as the outer line delimiter.
        payload.push(if random & 1 == 0 { b' ' } else { b'\t' });
    }
    Ok(payload)
}

pub fn verify_and_derive(
    local_identity: &IdentityKeyPair,
    material: &HandshakeMaterial,
    peer_hello: &Hello,
    initiator: bool,
    policy: &PeerPolicy,
) -> Result<HandshakeState> {
    verify_and_derive_with_profile(local_identity, material, peer_hello, initiator, policy)
}

pub fn verify_hello_signature(
    local_identity: &IdentityKeyPair,
    material: &HandshakeMaterial,
    peer_hello: &Hello,
    policy: &PeerPolicy,
) -> Result<()> {
    validate_local_material(local_identity, material)?;
    let profile = material.profile;
    if peer_hello.profile != profile || peer_hello.proto != profile.protocol_tag() {
        return Err(ShphError::Handshake("protocol mismatch".into()));
    }
    if material.local_hello.proto != profile.protocol_tag()
        || material.local_hello.profile != profile
    {
        return Err(ShphError::Handshake(
            "local protocol profile mismatch".into(),
        ));
    }
    if peer_hello.pqc_ct_b64.is_some() {
        return Err(ShphError::Handshake(
            "peer PQ ciphertext must be sent as a separate handshake frame".into(),
        ));
    }

    let peer_identity_raw = decode_32(&peer_hello.identity_pub_b64, "peer identity")?;
    let peer_ephemeral_raw = decode_32(&peer_hello.ephemeral_pub_b64, "peer ephemeral")?;
    let peer_nonce = decode_32(&peer_hello.nonce_b64, "peer nonce")?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ShphError::Handshake("system clock before unix epoch".into()))?
        .as_secs();
    if now.abs_diff(peer_hello.timestamp_secs) > 300 {
        return Err(ShphError::Handshake("peer timestamp out of window".into()));
    }

    let peer_sign_public = decode_32(&peer_hello.sign_pub_b64, "peer signing key")?;
    let peer_pqc_pub = peer_hello
        .pqc_pub_b64
        .as_deref()
        .map(|value| b64_decode(value, "peer PQ public key"))
        .transpose()?;
    if profile.uses_pqc() != peer_pqc_pub.is_some() {
        return Err(ShphError::Handshake(
            "peer post-quantum profile material mismatch".into(),
        ));
    }
    if let Some(peer_pqc_pub) = &peer_pqc_pub {
        if peer_pqc_pub.len() != crate::ML_KEM_768_PUBLIC_KEY_BYTES {
            return Err(ShphError::Handshake(format!(
                "peer PQ public key must be {} bytes",
                crate::ML_KEM_768_PUBLIC_KEY_BYTES
            )));
        }
    }

    let mut signed_payload = [0u8; MAX_SIGNED_PAYLOAD_BYTES];
    let mut signed_len = 0;
    append_signed_part(
        &mut signed_payload,
        &mut signed_len,
        profile.protocol_tag().as_bytes(),
    )?;
    append_signed_part(&mut signed_payload, &mut signed_len, &peer_identity_raw)?;
    append_signed_part(&mut signed_payload, &mut signed_len, &peer_sign_public)?;
    if let Some(peer_pqc_pub) = &peer_pqc_pub {
        append_signed_part(&mut signed_payload, &mut signed_len, peer_pqc_pub)?;
    }
    append_signed_part(&mut signed_payload, &mut signed_len, &peer_ephemeral_raw)?;
    append_signed_part(&mut signed_payload, &mut signed_len, &peer_nonce)?;
    append_signed_part(
        &mut signed_payload,
        &mut signed_len,
        &peer_hello.timestamp_secs.to_be_bytes(),
    )?;
    local_identity.verify_handshake_signature(
        &signed_payload[..signed_len],
        &peer_hello.sig,
        &peer_sign_public,
    )?;
    if !policy.allows(&peer_identity_raw, &peer_sign_public) {
        return Err(ShphError::Auth(
            "peer identity and signing key are not pinned".into(),
        ));
    }
    Ok(())
}

fn validate_local_material(
    local_identity: &IdentityKeyPair,
    material: &HandshakeMaterial,
) -> Result<()> {
    let profile = material.profile;
    if material.local_hello.proto != profile.protocol_tag()
        || material.local_hello.profile != profile
    {
        return Err(ShphError::Handshake(
            "local protocol profile mismatch".into(),
        ));
    }

    let local_identity_raw = decode_32(&material.local_hello.identity_pub_b64, "local identity")?;
    if !constant_time_eq(&local_identity_raw, &local_identity.public_key_bytes()) {
        return Err(ShphError::Handshake(
            "local hello identity does not match the configured identity".into(),
        ));
    }

    let local_sign_public = decode_32(&material.local_hello.sign_pub_b64, "local signing key")?;
    if !constant_time_eq(&local_sign_public, &local_identity.signing_public_bytes()) {
        return Err(ShphError::Handshake(
            "local hello signing key does not match the configured identity".into(),
        ));
    }

    let local_ephemeral_raw =
        decode_32(&material.local_hello.ephemeral_pub_b64, "local ephemeral")?;
    if !constant_time_eq(
        &local_ephemeral_raw,
        &material.local_ephemeral.public_key_bytes(),
    ) {
        return Err(ShphError::Handshake(
            "local hello ephemeral key does not match handshake material".into(),
        ));
    }

    let local_nonce = decode_32(&material.local_hello.nonce_b64, "local nonce")?;
    if !constant_time_eq(&local_nonce, &material.local_nonce) {
        return Err(ShphError::Handshake(
            "local hello nonce does not match handshake material".into(),
        ));
    }

    if profile.uses_pqc() {
        let local_pqc = material
            .local_pqc
            .as_ref()
            .ok_or_else(|| ShphError::Handshake("missing local PQ keypair".into()))?;
        let encoded_public = material
            .local_hello
            .pqc_pub_b64
            .as_deref()
            .ok_or_else(|| ShphError::Handshake("missing local PQ public key".into()))?;
        let local_pqc_public = b64_decode(encoded_public, "local PQ public key")?;
        if local_pqc_public != local_pqc.encap_public_bytes() {
            return Err(ShphError::Handshake(
                "local hello PQ key does not match handshake material".into(),
            ));
        }
    } else if material.local_pqc.is_some()
        || material.local_hello.pqc_pub_b64.is_some()
        || material.pq_shared.is_some()
        || material.pq_ciphertext.is_some()
        || material.local_hello.pqc_ct_b64.is_some()
    {
        return Err(ShphError::Handshake(
            "classical profile contains post-quantum material".into(),
        ));
    }

    let local_pqc_public = material
        .local_hello
        .pqc_pub_b64
        .as_deref()
        .map(|encoded| b64_decode(encoded, "local PQ public key"))
        .transpose()?;
    let mut signed_payload = [0u8; MAX_SIGNED_PAYLOAD_BYTES];
    let mut signed_len = 0;
    append_signed_part(
        &mut signed_payload,
        &mut signed_len,
        profile.protocol_tag().as_bytes(),
    )?;
    append_signed_part(&mut signed_payload, &mut signed_len, &local_identity_raw)?;
    append_signed_part(&mut signed_payload, &mut signed_len, &local_sign_public)?;
    if let Some(local_pqc_public) = local_pqc_public.as_deref() {
        append_signed_part(&mut signed_payload, &mut signed_len, local_pqc_public)?;
    }
    append_signed_part(&mut signed_payload, &mut signed_len, &local_ephemeral_raw)?;
    append_signed_part(&mut signed_payload, &mut signed_len, &local_nonce)?;
    append_signed_part(
        &mut signed_payload,
        &mut signed_len,
        &material.local_hello.timestamp_secs.to_be_bytes(),
    )?;
    local_identity.verify_handshake_signature(
        &signed_payload[..signed_len],
        &material.local_hello.sig,
        &local_sign_public,
    )?;

    if let Some(encoded_ciphertext) = material.local_hello.pqc_ct_b64.as_deref() {
        let ciphertext = b64_decode(encoded_ciphertext, "local PQ ciphertext")?;
        if material.pq_ciphertext.as_deref() != Some(ciphertext.as_slice()) {
            return Err(ShphError::Handshake(
                "local hello PQ ciphertext does not match handshake material".into(),
            ));
        }
    }
    Ok(())
}

pub fn verify_and_derive_with_profile(
    local_identity: &IdentityKeyPair,
    material: &HandshakeMaterial,
    peer_hello: &Hello,
    initiator: bool,
    policy: &PeerPolicy,
) -> Result<HandshakeState> {
    verify_hello_signature(local_identity, material, peer_hello, policy)?;
    let profile = material.profile;
    if peer_hello.profile != profile || peer_hello.proto != profile.protocol_tag() {
        return Err(ShphError::Handshake("protocol mismatch".into()));
    }
    if material.local_hello.proto != profile.protocol_tag()
        || material.local_hello.profile != profile
    {
        return Err(ShphError::Handshake(
            "local protocol profile mismatch".into(),
        ));
    }

    let peer_identity_raw = decode_32(&peer_hello.identity_pub_b64, "peer identity")?;
    let peer_ephemeral_raw = decode_32(&peer_hello.ephemeral_pub_b64, "peer ephemeral")?;
    let peer_nonce = decode_32(&peer_hello.nonce_b64, "peer nonce")?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ShphError::Handshake("system clock before unix epoch".into()))?
        .as_secs();
    let skew = now.abs_diff(peer_hello.timestamp_secs);
    if skew > 300 {
        return Err(ShphError::Handshake("peer timestamp out of window".into()));
    }

    let peer_sign_public = decode_32(&peer_hello.sign_pub_b64, "peer signing key")?;
    let peer_pqc_pub = peer_hello
        .pqc_pub_b64
        .as_deref()
        .map(|value| b64_decode(value, "peer PQ public key"))
        .transpose()?;
    if profile.uses_pqc() != peer_pqc_pub.is_some() {
        return Err(ShphError::Handshake(
            "peer post-quantum profile material mismatch".into(),
        ));
    }
    let mut signed_payload = [0u8; MAX_SIGNED_PAYLOAD_BYTES];
    let mut signed_len = 0;
    append_signed_part(
        &mut signed_payload,
        &mut signed_len,
        profile.protocol_tag().as_bytes(),
    )?;
    append_signed_part(&mut signed_payload, &mut signed_len, &peer_identity_raw)?;
    append_signed_part(&mut signed_payload, &mut signed_len, &peer_sign_public)?;
    if let Some(peer_pqc_pub) = &peer_pqc_pub {
        append_signed_part(&mut signed_payload, &mut signed_len, peer_pqc_pub)?;
    }
    append_signed_part(&mut signed_payload, &mut signed_len, &peer_ephemeral_raw)?;
    append_signed_part(&mut signed_payload, &mut signed_len, &peer_nonce)?;
    append_signed_part(
        &mut signed_payload,
        &mut signed_len,
        &peer_hello.timestamp_secs.to_be_bytes(),
    )?;
    local_identity.verify_handshake_signature(
        &signed_payload[..signed_len],
        &peer_hello.sig,
        &peer_sign_public,
    )?;

    let peer_ephemeral = PublicKey::from(peer_ephemeral_raw);
    let ecdh_shared = material.local_ephemeral.derive_shared(&peer_ephemeral);
    if ecdh_shared == [0u8; 32] {
        return Err(ShphError::Handshake(
            "peer X25519 public key produced an all-zero shared secret".into(),
        ));
    }

    // Hybrid post-quantum key exchange (ML-KEM-768). The INITIATOR encapsulates
    // against the responder's PQ public key, producing (ciphertext, shared);
    // the RESPONDER decapsulates that ciphertext to recover the same shared
    // secret. The `initiator` flag selects the role. The resulting PQ shared
    // secret is combined with the X25519 ECDH shared secret and fed to HKDF, so
    // the session key stays confidential even against a future quantum adversary
    // that recorded this exchange and later breaks ECDH.
    // Hybrid post-quantum shared secret (ML-KEM-768). The transport layer is
    // responsible for performing the encapsulate/decapsulate round trip and
    // passing the resulting 32-byte secret here. Refusing `None` hardens
    // against a silent downgrade to classical-only ECDH: if a peer strips the
    // PQ ciphertext the handshake fails closed instead of deriving a key that a
    // future quantum adversary could break from a transcript recording.
    let pq_shared = if profile.uses_pqc() {
        Some(material.pq_shared.as_ref().ok_or_else(|| {
            ShphError::Handshake("missing post-quantum shared secret (downgrade blocked)".into())
        })?)
    } else {
        if material.pq_shared.is_some() {
            return Err(ShphError::Handshake(
                "classical lab profile cannot carry post-quantum material".into(),
            ));
        }
        None
    };
    let pq_ciphertext = if profile.uses_pqc() {
        let ciphertext = material.pq_ciphertext.as_deref().ok_or_else(|| {
            ShphError::Handshake(
                "missing post-quantum ciphertext binding (downgrade blocked)".into(),
            )
        })?;
        if ciphertext.len() != crate::ML_KEM_768_CIPHERTEXT_BYTES {
            return Err(ShphError::Handshake(
                "invalid post-quantum ciphertext binding length".into(),
            ));
        }
        Some(ciphertext)
    } else {
        None
    };

    let mut shared = zeroize::Zeroizing::new([0u8; 64]);
    shared[..32].copy_from_slice(&ecdh_shared);
    if let Some(pq_shared) = pq_shared {
        shared[32..].copy_from_slice(pq_shared.as_ref());
    }

    let local_identity_raw = decode_32(&material.local_hello.identity_pub_b64, "local identity")?;
    let local_sign_public = decode_32(&material.local_hello.sign_pub_b64, "local signing key")?;
    let local_ephemeral_raw =
        decode_32(&material.local_hello.ephemeral_pub_b64, "local ephemeral")?;
    let local_pqc_pub = material
        .local_hello
        .pqc_pub_b64
        .as_deref()
        .map(|value| b64_decode(value, "local PQ public key"))
        .transpose()?;

    let (first_identity, second_identity) = if local_identity_raw <= peer_identity_raw {
        (&local_identity_raw, &peer_identity_raw)
    } else {
        (&peer_identity_raw, &local_identity_raw)
    };
    let (first_signing, second_signing) = if local_identity_raw <= peer_identity_raw {
        (&local_sign_public, &peer_sign_public)
    } else {
        (&peer_sign_public, &local_sign_public)
    };
    let (first_ephemeral, second_ephemeral) = if local_identity_raw <= peer_identity_raw {
        (&local_ephemeral_raw, &peer_ephemeral_raw)
    } else {
        (&peer_ephemeral_raw, &local_ephemeral_raw)
    };
    let (first_nonce, second_nonce) = if local_identity_raw <= peer_identity_raw {
        (&material.local_nonce, &peer_nonce)
    } else {
        (&peer_nonce, &material.local_nonce)
    };
    let (first_timestamp, second_timestamp) = if local_identity_raw <= peer_identity_raw {
        (
            material.local_hello.timestamp_secs,
            peer_hello.timestamp_secs,
        )
    } else {
        (
            peer_hello.timestamp_secs,
            material.local_hello.timestamp_secs,
        )
    };
    let (first_pqc_pub, second_pqc_pub) = if local_identity_raw <= peer_identity_raw {
        (local_pqc_pub.as_deref(), peer_pqc_pub.as_deref())
    } else {
        (peer_pqc_pub.as_deref(), local_pqc_pub.as_deref())
    };

    let mut transcript_hasher = Sha256::new();
    update_transcript_field(
        &mut transcript_hasher,
        b"domain",
        b"shph/handshake-transcript-v2",
    );
    update_transcript_field(
        &mut transcript_hasher,
        b"protocol",
        profile.protocol_tag().as_bytes(),
    );
    update_transcript_field(
        &mut transcript_hasher,
        b"profile",
        profile.as_str().as_bytes(),
    );
    update_transcript_field(
        &mut transcript_hasher,
        b"initiator-identity",
        if initiator {
            &local_identity_raw
        } else {
            &peer_identity_raw
        },
    );
    update_transcript_field(&mut transcript_hasher, b"peer-a-identity", first_identity);
    update_transcript_field(&mut transcript_hasher, b"peer-a-signing", first_signing);
    update_transcript_optional_field(&mut transcript_hasher, b"peer-a-pqc", first_pqc_pub);
    update_transcript_field(&mut transcript_hasher, b"peer-a-ephemeral", first_ephemeral);
    update_transcript_field(&mut transcript_hasher, b"peer-a-nonce", first_nonce);
    update_transcript_u64(&mut transcript_hasher, b"peer-a-timestamp", first_timestamp);
    update_transcript_field(&mut transcript_hasher, b"peer-b-identity", second_identity);
    update_transcript_field(&mut transcript_hasher, b"peer-b-signing", second_signing);
    update_transcript_optional_field(&mut transcript_hasher, b"peer-b-pqc", second_pqc_pub);
    update_transcript_field(
        &mut transcript_hasher,
        b"peer-b-ephemeral",
        second_ephemeral,
    );
    update_transcript_field(&mut transcript_hasher, b"peer-b-nonce", second_nonce);
    update_transcript_u64(
        &mut transcript_hasher,
        b"peer-b-timestamp",
        second_timestamp,
    );
    update_transcript_optional_field(&mut transcript_hasher, b"pqc-ciphertext", pq_ciphertext);
    let transcript_hash = transcript_hasher.finalize();

    // The transport role remains authoritative for one-sided client/server
    // sessions: it determines which cipher is used on the connected socket.
    // `deterministic_role` is exposed for simultaneous-open orchestration,
    // where both peers must first agree which connection survives.
    let direction = if initiator {
        [b"initiator".as_slice(), b"responder".as_slice()]
    } else {
        [b"responder".as_slice(), b"initiator".as_slice()]
    };

    // Wrap HKDF outputs in `Zeroizing` so the raw key material is wiped when
    // these bindings go out of scope, rather than lingering in freed heap
    // memory until the page is reused.
    let mut send_key = [0u8; 32];
    hkdf_sha256_into(
        &shared[..if profile.uses_pqc() { 64 } else { 32 }],
        &[
            b"shph-session-v2",
            profile.protocol_tag().as_bytes(),
            &transcript_hash,
            direction[0],
        ],
        &mut send_key,
    )?;
    let mut recv_key = [0u8; 32];
    hkdf_sha256_into(
        &shared[..if profile.uses_pqc() { 64 } else { 32 }],
        &[
            b"shph-session-v2",
            profile.protocol_tag().as_bytes(),
            &transcript_hash,
            direction[1],
        ],
        &mut recv_key,
    )?;

    Ok(HandshakeState {
        peer_fingerprint_hex: compute_fingerprint_hex(&peer_identity_raw),
        peer_identity_pubkey_b64: base64::engine::general_purpose::STANDARD
            .encode(peer_identity_raw),
        peer_signing_pubkey_b64: base64::engine::general_purpose::STANDARD.encode(peer_sign_public),
        session_keys: SessionKeys {
            send_key,
            recv_key,
            send_nonce: 0,
            recv_nonce: 0,
        },
        transcript_hash_hex: hex::encode(transcript_hash),
    })
}

fn append_signed_part(
    buffer: &mut [u8; MAX_SIGNED_PAYLOAD_BYTES],
    length: &mut usize,
    part: &[u8],
) -> Result<()> {
    let end = length
        .checked_add(part.len())
        .ok_or_else(|| ShphError::Handshake("signed payload length overflow".into()))?;
    if end > buffer.len() {
        return Err(ShphError::Handshake(
            "signed payload exceeds handshake limit".into(),
        ));
    }
    buffer[*length..end].copy_from_slice(part);
    *length = end;
    Ok(())
}

/// Initiator half of the hybrid PQ exchange.
///
/// After receiving the responder's hello, the initiator encapsulates against the
/// responder's PQ public key. Returns the ciphertext bytes the transport must
/// deliver to the responder as a follow-up handshake message, and stashes the
/// derived PQ shared secret onto `material` so the subsequent
/// [`verify_and_derive_with_pq`] call can consume it.
pub fn finalize_initiator_pq(
    local_identity: &IdentityKeyPair,
    material: &mut HandshakeMaterial,
    peer_hello: &Hello,
    policy: &PeerPolicy,
) -> Result<Vec<u8>> {
    if !material.profile.uses_pqc() {
        return Err(ShphError::Handshake(
            "classical lab profile does not use post-quantum exchange".into(),
        ));
    }
    verify_hello_signature(local_identity, material, peer_hello, policy)?;
    let peer_pqc_pub = b64_decode(
        peer_hello
            .pqc_pub_b64
            .as_deref()
            .ok_or_else(|| ShphError::Handshake("missing peer PQ public key".into()))?,
        "peer PQ public key",
    )?;
    let (ct, ss) = crate::pqc::PqcKeypair::encapsulate_against(&peer_pqc_pub)?;
    // Record the ciphertext we are sending so the transcript/inspection stays
    // consistent, and remember the shared secret for verify_and_derive_with_pq.
    material.local_hello.pqc_ct_b64 = Some(base64::engine::general_purpose::STANDARD.encode(&ct));
    material.pq_shared = Some(Zeroizing::new(ss));
    material.pq_ciphertext = Some(ct.clone());
    Ok(ct)
}

/// Responder half of the hybrid PQ exchange.
///
/// The responder receives the initiator's PQ ciphertext (delivered by the
/// transport as a follow-up message). The peer hello signature and configured
/// identity/signing-key policy are checked before decapsulation, so callers
/// cannot accidentally spend ML-KEM work on an unauthorized peer.
pub fn absorb_responder_pq(
    local_identity: &IdentityKeyPair,
    material: &mut HandshakeMaterial,
    peer_hello: &Hello,
    peer_ct: &[u8],
    policy: &PeerPolicy,
) -> Result<()> {
    verify_hello_signature(local_identity, material, peer_hello, policy)?;
    absorb_responder_pq_unverified(material, peer_ct)
}

fn absorb_responder_pq_unverified(material: &mut HandshakeMaterial, peer_ct: &[u8]) -> Result<()> {
    if !material.profile.uses_pqc() {
        return Err(ShphError::Handshake(
            "classical lab profile does not use post-quantum exchange".into(),
        ));
    }
    let ss = material
        .local_pqc
        .as_ref()
        .ok_or_else(|| ShphError::Handshake("missing local PQ keypair".into()))?
        .decapsulate(peer_ct)?;
    material.pq_shared = Some(Zeroizing::new(ss));
    material.pq_ciphertext = Some(peer_ct.to_vec());
    Ok(())
}

fn decode_32(input_b64: &str, what: &str) -> Result<[u8; 32]> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(input_b64.as_bytes())
        .map_err(|_| ShphError::Handshake(format!("invalid {what} encoding")))?;
    raw.try_into()
        .map_err(|_| ShphError::Handshake(format!("{what} must be 32 bytes")))
}

fn b64_decode(input_b64: &str, what: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(input_b64.as_bytes())
        .map_err(|_| ShphError::Handshake(format!("invalid {what} encoding")))
}

fn update_transcript_field(hasher: &mut Sha256, label: &[u8], value: &[u8]) {
    hasher.update((label.len() as u32).to_be_bytes());
    hasher.update(label);
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn update_transcript_optional_field(hasher: &mut Sha256, label: &[u8], value: Option<&[u8]>) {
    update_transcript_field(hasher, label, &[if value.is_some() { 1u8 } else { 0u8 }]);
    if let Some(value) = value {
        update_transcript_field(hasher, label, value);
    }
}

fn update_transcript_u64(hasher: &mut Sha256, label: &[u8], value: u64) {
    update_transcript_field(hasher, label, &value.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::{
        build_hello_with_profile, serialize_hello_frame, serialize_hello_frame_with_padding_len,
        verify_hello_signature, HandshakeProfile, PeerPin, PeerPolicy,
        MAX_HANDSHAKE_FRAME_TAIL_BYTES, MAX_PEER_PINS,
    };
    use crate::crypto::IdentityKeyPair;
    use base64::Engine as _;

    #[test]
    fn hello_frame_tail_is_bounded_random_whitespace() {
        let identity = IdentityKeyPair::generate().expect("identity");
        let material =
            build_hello_with_profile(&identity, HandshakeProfile::ClassicalLab).expect("hello");
        let canonical = serde_json::to_vec(&material.local_hello).expect("canonical hello");
        let framed = serialize_hello_frame_with_padding_len(&material.local_hello, 17)
            .expect("padded hello");

        assert_eq!(&framed[..canonical.len()], canonical.as_slice());
        assert_eq!(framed.len(), canonical.len() + 17);
        assert!(framed[canonical.len()..]
            .iter()
            .all(u8::is_ascii_whitespace));
        assert_eq!(
            serde_json::from_slice::<super::Hello>(&framed)
                .expect("parse padded hello")
                .proto,
            material.local_hello.proto
        );
    }

    #[test]
    fn hello_frame_random_tail_stays_within_bound() {
        let identity = IdentityKeyPair::generate().expect("identity");
        let material =
            build_hello_with_profile(&identity, HandshakeProfile::ClassicalLab).expect("hello");
        let canonical_len = serde_json::to_vec(&material.local_hello)
            .expect("canonical hello")
            .len();

        for _ in 0..64 {
            let framed = serialize_hello_frame(&material.local_hello).expect("random hello");
            assert!(
                (canonical_len..=canonical_len + MAX_HANDSHAKE_FRAME_TAIL_BYTES)
                    .contains(&framed.len())
            );
            serde_json::from_slice::<super::Hello>(&framed).expect("parse random hello");
        }
    }

    #[test]
    fn peer_policy_bounds_configured_pin_count() {
        let pin = PeerPin::new([1u8; 32], [2u8; 32]);
        assert!(PeerPolicy::new(vec![pin; MAX_PEER_PINS]).is_ok());
        assert!(PeerPolicy::new(vec![pin; MAX_PEER_PINS + 1]).is_err());
    }

    #[test]
    fn bootstrap_peer_policy_accepts_one_unpinned_identity() {
        let policy = PeerPolicy::allow_any();
        assert!(policy.allows(&[7u8; 32], &[9u8; 32]));
        assert!(policy.pins().is_empty());
    }

    #[test]
    fn hello_verification_rejects_mismatched_local_identity_material() {
        let local = IdentityKeyPair::generate().expect("local identity");
        let peer = IdentityKeyPair::generate().expect("peer identity");
        let mut local_material =
            build_hello_with_profile(&local, HandshakeProfile::ClassicalLab).expect("hello");
        let peer_material =
            build_hello_with_profile(&peer, HandshakeProfile::ClassicalLab).expect("peer hello");
        local_material.local_hello.identity_pub_b64 =
            peer_material.local_hello.identity_pub_b64.clone();
        let policy = PeerPolicy::single(PeerPin::for_identity(&peer));
        assert!(verify_hello_signature(
            &local,
            &local_material,
            &peer_material.local_hello,
            &policy
        )
        .is_err());
    }

    #[test]
    fn hello_verification_rejects_inline_pq_ciphertext_metadata() {
        let local = IdentityKeyPair::generate().expect("local identity");
        let peer = IdentityKeyPair::generate().expect("peer identity");
        let local_material =
            build_hello_with_profile(&local, HandshakeProfile::ClassicalLab).expect("hello");
        let mut peer_material =
            build_hello_with_profile(&peer, HandshakeProfile::ClassicalLab).expect("peer hello");
        peer_material.local_hello.pqc_ct_b64 = Some("not-a-frame".into());
        let policy = PeerPolicy::single(PeerPin::for_identity(&peer));
        assert!(verify_hello_signature(
            &local,
            &local_material,
            &peer_material.local_hello,
            &policy
        )
        .is_err());
    }

    #[test]
    fn hello_verification_rejects_malformed_pq_public_key_length() {
        let local = IdentityKeyPair::generate().expect("local identity");
        let peer = IdentityKeyPair::generate().expect("peer identity");
        let local_material =
            build_hello_with_profile(&local, HandshakeProfile::SecureDefault).expect("hello");
        let mut peer_material =
            build_hello_with_profile(&peer, HandshakeProfile::SecureDefault).expect("peer hello");
        peer_material.local_hello.pqc_pub_b64 =
            Some(base64::engine::general_purpose::STANDARD.encode([0u8; 1]));
        let policy = PeerPolicy::single(PeerPin::for_identity(&peer));
        assert!(verify_hello_signature(
            &local,
            &local_material,
            &peer_material.local_hello,
            &policy
        )
        .is_err());
    }
}
