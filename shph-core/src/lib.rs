//! SHPH Core - Core types, error handling, and shared utilities for SHPH VPN.

pub mod crypto;
pub mod error;
pub mod framing;
pub mod handshake;
pub mod keystore;
pub mod metrics;
pub mod net;
pub mod pqc;
pub mod roadmap;
pub mod stealth;

pub use crypto::{
    hkdf_sha256_into, IdentityKeyPair, ReceiveCipher, ReplayWindow, SendCipher, SessionKeys,
};
pub use error::{Result, ShphError};
pub use framing::{
    decode_cell, decode_cell_payload, encode_cell, encode_chaff_cell, encode_data_cell, ShroudCell,
    SHROUD_FRAME_CHAFF, SHROUD_FRAME_DATA, SHROUD_FRAME_HEADER,
};
pub use handshake::{
    absorb_responder_pq, build_hello, build_hello_with_profile, finalize_initiator_pq,
    verify_and_derive, verify_and_derive_with_profile, verify_hello_signature, HandshakeMaterial,
    HandshakeProfile, HandshakeState, HandshakeVersion, Hello, PeerPin, PeerPolicy,
};
pub use keystore::{
    compute_fingerprint_hex, enforce_owner_only_file_permissions, ensure_not_reparse_point,
    Contact, KeyStore, KeyStoreConfig,
};
pub use metrics::{MetricsCollector, MetricsSnapshot};
pub use net::{Endpoint, TransportType, TunnelConfig};
pub use pqc::{PqcKeypair, ML_KEM_768_CIPHERTEXT_BYTES, ML_KEM_768_PUBLIC_KEY_BYTES};
pub use roadmap::{
    append_ratchet_audit_event, offline_spool_path, read_ratchet_audit_events,
    recover_secret_from_shares, serialize_shamir_share, split_secret, validate_identity_provider,
    validate_roadmap, validate_transport_adapter, DataMuleConfig, DataMuleEnvelope,
    IdentityProviderConfig, OfflineMeshConfig, OfflineMeshEnvelope, PqcConfig, RatchetAuditPolicy,
    RatchetAuditRecord, RoadmapConfig, ShamirPolicy, ShamirShare, ShamirThresholdError,
    ShamirWarning, TransportAdapterConfig,
};
pub use stealth::{
    profiles, shroud_profile_by_name, shroud_profile_by_selection, stealth_profile_by_name,
    stealth_profiles, ChunkDistribution, MorphProfile, ShroudProfile, StealthProfile,
    TlsCamouflage, BALANCED, BULK, CAMOUFLAGE, EXTREME_LAB, LOW_LATENCY, MIMICRY_LAB,
    RANDOMIZED_LAB, STEADY,
};
