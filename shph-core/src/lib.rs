//! SHPH Core - Core types, error handling, and shared utilities for SHPH VPN.

pub mod crypto;
pub mod error;
pub mod framing;
pub mod handshake;
pub mod keystore;
pub mod metrics;
pub mod net;
pub mod roadmap;
pub mod stealth;

pub use crypto::{IdentityKeyPair, ReceiveCipher, ReplayWindow, SendCipher, SessionKeys};
pub use error::{Result, ShphError};
pub use framing::{decode_cell, encode_cell, ShroudCell};
pub use handshake::{
    build_hello, verify_and_derive, HandshakeMaterial, HandshakeState, HandshakeVersion, Hello,
};
pub use keystore::{compute_fingerprint_hex, Contact, KeyStore, KeyStoreConfig};
pub use metrics::{MetricsCollector, MetricsSnapshot};
pub use net::{Endpoint, TransportType, TunnelConfig};
pub use roadmap::{
    append_ratchet_audit_event, offline_spool_path, read_ratchet_audit_events,
    serialize_shamir_share, validate_transport_adapter, DataMuleConfig, DataMuleEnvelope,
    IdentityProviderConfig, OfflineMeshConfig, OfflineMeshEnvelope, PqcConfig, RatchetAuditPolicy,
    RatchetAuditRecord, RoadmapConfig, ShamirPolicy, ShamirShare, ShamirThresholdError,
    ShamirWarning, TransportAdapterConfig,
};
pub use stealth::{
    profiles, stealth_profiles, ChunkDistribution, MorphProfile, ShroudProfile, StealthProfile,
    TlsCamouflage, BALANCED, BULK, CAMOUFLAGE, LOW_LATENCY, MIMICRY_LAB, STEADY,
};
