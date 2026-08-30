//! Phantom One owned-domain edge relay.
//!
//! The edge only authenticates a short-lived capability and forwards opaque
//! bytes. It never parses, decrypts, or otherwise interprets SHPH payloads.

#![forbid(unsafe_code)]

pub mod capability;
pub mod carrier;
pub mod config;
pub mod file;
pub mod frontdoor;
pub mod logging;
pub mod relay;

pub use capability::{
    CapabilityClaims, CapabilityError, CapabilityIssuer, CapabilityVerifier, ReplayCache,
    CAPABILITY_VERSION,
};
pub use carrier::{
    validate_h2_uri, validate_h2_uri_with_path, Carrier, CarrierError, CarrierKind, Http2Carrier,
    OpaqueStream, UnsupportedCarrier, H2_PATH, MAX_CAPABILITY_TOKEN_FILE_BYTES,
};
pub use config::{EdgeConfig, EdgeConfigError, Limits, SocksConfig};
pub use frontdoor::{FrontDoor, FrontDoorDecision, FrontDoorResponse};
pub use logging::{MetadataEvent, RedactedMetadata};
pub use relay::{pipe_opaque, RelayError};

#[cfg(feature = "http3")]
pub use carrier::Http3Carrier;
