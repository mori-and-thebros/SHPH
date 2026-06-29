//! Error types for SHPH.

use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ShphError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Cryptographic error: {0}")]
    Crypto(String),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Handshake failed: {0}")]
    Handshake(String),

    #[error("Authentication failed: {0}")]
    Auth(String),

    #[error("TUN device error: {0}")]
    Tun(String),

    #[error("Transport error: {0}")]
    Transport(String),

    #[error("Obfuscation error: {0}")]
    Obfuscation(String),

    #[error("Stealth/profile error: {0}")]
    Stealth(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

    #[error("Not connected")]
    NotConnected,

    #[error("Already connected")]
    AlreadyConnected,

    #[error("Connection closed")]
    ConnectionClosed,

    #[error("Timeout")]
    Timeout,

    #[error("Resource exhausted: {0}")]
    ResourceExhausted(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Unsupported operation: {0}")]
    Unsupported(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, ShphError>;