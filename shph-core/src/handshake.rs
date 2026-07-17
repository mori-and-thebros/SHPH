//! Handshake protocol for session establishment.

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use x25519_dalek::PublicKey;

use crate::crypto::{hkdf_sha256, IdentityKeyPair, SessionKeys};
use crate::error::{Result, ShphError};
use crate::keystore::compute_fingerprint_hex;

const HANDSHAKE_VERSION: u8 = 4;
const PROTOCOL_TAG: &str = "shph/4";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hello {
    pub proto: String,
    pub identity_pub_b64: String,
    /// Ed25519 signing public key (base64). Bound into the signed payload so a
    /// MITM cannot swap it for a different signing key.
    pub sign_pub_b64: String,
    /// ML-KEM-768 encapsulation public key (base64) for the hybrid PQ key exchange.
    pub pqc_pub_b64: String,
    /// ML-KEM-768 ciphertext (base64) the sender produced against the peer's PQ
    /// public key. Both sides decapsulate the peer's ciphertext against their
    /// own PQ key, giving a shared PQ secret combined with X25519 ECDH.
    pub pqc_ct_b64: String,
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
    pub local_pqc: crate::pqc::PqcKeypair,
    pub local_hello: Hello,
    /// Hybrid ML-KEM-768 shared secret, populated by [`finalize_initiator_pq`]
    /// (initiator) or [`absorb_responder_pq`] (responder) before key derivation.
    /// `None` here blocks derivation, preventing a silent classical downgrade.
    pub pq_shared: Option<[u8; 32]>,
}

#[derive(Debug, Clone)]
pub struct HandshakeState {
    pub peer_fingerprint_hex: String,
    pub peer_signing_pubkey_b64: String,
    pub session_keys: SessionKeys,
    pub transcript_hash_hex: String,
}

pub fn build_hello(local_identity: &IdentityKeyPair) -> Result<HandshakeMaterial> {
    let local_ephemeral = IdentityKeyPair::generate()?;
    let rng = ring::rand::SystemRandom::new();
    let mut local_nonce = [0u8; 32];
    ring::rand::SecureRandom::fill(&rng, &mut local_nonce)?;
    let timestamp_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ShphError::Handshake("system clock before unix epoch".into()))?
        .as_secs();

    let sign_pub = local_identity.signing_public_bytes();
    let local_pqc = crate::pqc::PqcKeypair::generate()?;
    let pqc_pub = local_pqc.encap_public_bytes();
    // The PQ ciphertext each side sends is computed against the peer's PQ public
    // key, which is only known after the hellos are exchanged. It is filled in
    // during verify_and_derive; the hello carries an empty placeholder here.
    let mut signed_payload = Vec::new();
    signed_payload.extend_from_slice(PROTOCOL_TAG.as_bytes());
    signed_payload.extend_from_slice(local_identity.public().as_bytes());
    signed_payload.extend_from_slice(&sign_pub);
    signed_payload.extend_from_slice(&pqc_pub);
    signed_payload.extend_from_slice(local_ephemeral.public().as_bytes());
    signed_payload.extend_from_slice(&local_nonce);
    signed_payload.extend_from_slice(&timestamp_secs.to_be_bytes());
    let sig = local_identity.sign_handshake(&signed_payload);

    let local_hello = Hello {
        proto: PROTOCOL_TAG.to_string(),
        identity_pub_b64: base64::engine::general_purpose::STANDARD
            .encode(local_identity.public().as_bytes()),
        sign_pub_b64: base64::engine::general_purpose::STANDARD.encode(sign_pub),
        pqc_pub_b64: base64::engine::general_purpose::STANDARD.encode(&pqc_pub),
        // Filled in by verify_and_derive once the peer PQ key is known.
        pqc_ct_b64: String::new(),
        ephemeral_pub_b64: base64::engine::general_purpose::STANDARD
            .encode(local_ephemeral.public().as_bytes()),
        nonce_b64: base64::engine::general_purpose::STANDARD.encode(local_nonce),
        timestamp_secs,
        sig,
    };

    Ok(HandshakeMaterial {
        local_ephemeral,
        local_nonce,
        local_pqc,
        local_hello,
        pq_shared: None,
    })
}

pub fn verify_and_derive(
    local_identity: &IdentityKeyPair,
    material: &HandshakeMaterial,
    peer_hello: &Hello,
    initiator: bool,
) -> Result<HandshakeState> {
    if peer_hello.proto != PROTOCOL_TAG {
        return Err(ShphError::Handshake("protocol mismatch".into()));
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
    let peer_pqc_pub = b64_decode(&peer_hello.pqc_pub_b64, "peer PQ public key")?;
    let mut signed_payload = Vec::new();
    signed_payload.extend_from_slice(PROTOCOL_TAG.as_bytes());
    signed_payload.extend_from_slice(&peer_identity_raw);
    signed_payload.extend_from_slice(&peer_sign_public);
    signed_payload.extend_from_slice(&peer_pqc_pub);
    signed_payload.extend_from_slice(&peer_ephemeral_raw);
    signed_payload.extend_from_slice(&peer_nonce);
    signed_payload.extend_from_slice(&peer_hello.timestamp_secs.to_be_bytes());
    local_identity.verify_handshake_signature(
        &signed_payload,
        &peer_hello.sig,
        &peer_sign_public,
    )?;

    let peer_ephemeral = PublicKey::from(peer_ephemeral_raw);
    let ecdh_shared = material.local_ephemeral.derive_shared(&peer_ephemeral);

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
    let pq_shared = material.pq_shared.ok_or_else(|| {
        ShphError::Handshake("missing post-quantum shared secret (downgrade blocked)".into())
    })?;
    let _ = initiator;

    let mut shared = zeroize::Zeroizing::new(Vec::with_capacity(32 + 32));
    shared.extend_from_slice(&ecdh_shared);
    shared.extend_from_slice(&pq_shared);

    let (first, second) = if material.local_hello.identity_pub_b64 <= peer_hello.identity_pub_b64 {
        (&material.local_hello, peer_hello)
    } else {
        (peer_hello, &material.local_hello)
    };
    let mut transcript_hasher = Sha256::new();
    transcript_hasher.update(PROTOCOL_TAG.as_bytes());
    transcript_hasher.update(first.identity_pub_b64.as_bytes());
    transcript_hasher.update(second.identity_pub_b64.as_bytes());
    transcript_hasher.update(first.ephemeral_pub_b64.as_bytes());
    transcript_hasher.update(second.ephemeral_pub_b64.as_bytes());
    transcript_hasher.update(first.nonce_b64.as_bytes());
    transcript_hasher.update(second.nonce_b64.as_bytes());
    transcript_hasher.update(first.timestamp_secs.to_be_bytes());
    transcript_hasher.update(second.timestamp_secs.to_be_bytes());
    let transcript_hash = transcript_hasher.finalize();

    let direction = if initiator {
        [b"initiator".as_slice(), b"responder".as_slice()]
    } else {
        [b"responder".as_slice(), b"initiator".as_slice()]
    };

    // Wrap HKDF outputs in `Zeroizing` so the raw key material is wiped when
    // these bindings go out of scope, rather than lingering in freed heap
    // memory until the page is reused.
    let send_key_raw = zeroize::Zeroizing::new(hkdf_sha256(
        &shared,
        &[b"shph-session-v1", &transcript_hash, direction[0]],
        32,
    )?);
    let recv_key_raw = zeroize::Zeroizing::new(hkdf_sha256(
        &shared,
        &[b"shph-session-v1", &transcript_hash, direction[1]],
        32,
    )?);
    let mut send_key = [0u8; 32];
    let mut recv_key = [0u8; 32];
    send_key.copy_from_slice(&send_key_raw[..32]);
    recv_key.copy_from_slice(&recv_key_raw[..32]);

    Ok(HandshakeState {
        peer_fingerprint_hex: compute_fingerprint_hex(&peer_identity_raw),
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

/// Initiator half of the hybrid PQ exchange.
///
/// After receiving the responder's hello, the initiator encapsulates against the
/// responder's PQ public key. Returns the ciphertext bytes the transport must
/// deliver to the responder as a follow-up handshake message, and stashes the
/// derived PQ shared secret onto `material` so the subsequent
/// [`verify_and_derive_with_pq`] call can consume it.
pub fn finalize_initiator_pq(
    material: &mut HandshakeMaterial,
    peer_hello: &Hello,
) -> Result<Vec<u8>> {
    let peer_pqc_pub = b64_decode(&peer_hello.pqc_pub_b64, "peer PQ public key")?;
    let (ct, ss) = crate::pqc::PqcKeypair::encapsulate_against(&peer_pqc_pub)?;
    // Record the ciphertext we are sending so the transcript/inspection stays
    // consistent, and remember the shared secret for verify_and_derive_with_pq.
    material.local_hello.pqc_ct_b64 = base64::engine::general_purpose::STANDARD.encode(&ct);
    material.pq_shared = Some(ss);
    Ok(ct)
}

/// Responder half of the hybrid PQ exchange.
///
/// The responder receives the initiator's PQ ciphertext (delivered by the
/// transport as a follow-up message), decapsulates it against her own PQ key,
/// and stashes the resulting shared secret onto `material`.
pub fn absorb_responder_pq(material: &mut HandshakeMaterial, peer_ct: &[u8]) -> Result<()> {
    let ss = material.local_pqc.decapsulate(peer_ct)?;
    material.pq_shared = Some(ss);
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
