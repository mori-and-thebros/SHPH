use http::Uri;
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, path::PathBuf, time::Duration};
use thiserror::Error;

const MAX_CONFIG_BYTES: usize = 64 * 1024;
pub const DEFAULT_RELAY_PATH: &str = "/phantom-one/v1";
pub const MAX_RELAY_PATH_BYTES: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeConfig {
    pub listen: SocketAddr,
    pub backend: String,
    pub audience: String,
    pub public_key: String,
    #[serde(default = "default_relay_path")]
    pub relay_path: String,
    #[serde(default)]
    pub tls: TlsConfig,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub socks: SocksConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    pub cert: Option<PathBuf>,
    pub key: Option<PathBuf>,
    pub ca: Option<PathBuf>,
    #[serde(default = "default_server_name")]
    pub server_name: String,
}

fn default_server_name() -> String {
    "edge.invalid".to_owned()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    #[serde(default = "default_max_token")]
    pub max_token_bytes: usize,
    #[serde(default = "default_max_body")]
    pub max_stream_bytes: u64,
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    #[serde(default = "default_replay_capacity")]
    pub replay_capacity: usize,
    #[serde(default = "default_max_lifetime")]
    pub max_capability_lifetime_secs: u64,
    #[serde(default = "default_clock_skew")]
    pub clock_skew_secs: u64,
    #[serde(default = "default_connect_timeout")]
    pub backend_connect_timeout_ms: u64,
    #[serde(default = "default_idle_timeout")]
    pub backend_idle_timeout_ms: u64,
    #[serde(default = "default_tls_handshake_timeout")]
    pub tls_handshake_timeout_ms: u64,
    #[serde(default = "default_max_streams_per_connection")]
    pub max_streams_per_connection: u32,
    #[serde(default = "default_max_http2_connections")]
    pub max_http2_connections: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_token_bytes: default_max_token(),
            max_stream_bytes: default_max_body(),
            max_connections: default_max_connections(),
            replay_capacity: default_replay_capacity(),
            max_capability_lifetime_secs: default_max_lifetime(),
            clock_skew_secs: default_clock_skew(),
            backend_connect_timeout_ms: default_connect_timeout(),
            backend_idle_timeout_ms: default_idle_timeout(),
            tls_handshake_timeout_ms: default_tls_handshake_timeout(),
            max_streams_per_connection: default_max_streams_per_connection(),
            max_http2_connections: default_max_http2_connections(),
        }
    }
}

fn default_max_token() -> usize {
    4096
}
fn default_max_body() -> u64 {
    64 * 1024 * 1024
}
fn default_max_connections() -> usize {
    1024
}
fn default_replay_capacity() -> usize {
    16 * 1024
}
fn default_max_lifetime() -> u64 {
    300
}
fn default_clock_skew() -> u64 {
    5
}
fn default_connect_timeout() -> u64 {
    5000
}
fn default_idle_timeout() -> u64 {
    30_000
}
fn default_tls_handshake_timeout() -> u64 {
    5000
}
fn default_max_streams_per_connection() -> u32 {
    128
}
fn default_max_http2_connections() -> usize {
    4
}

impl Limits {
    pub fn validate(&self) -> Result<(), EdgeConfigError> {
        if !(64..=4096).contains(&self.max_token_bytes)
            || self.max_stream_bytes == 0
            || self.max_stream_bytes > 1024 * 1024 * 1024
            || !(1..=100_000).contains(&self.max_connections)
            || !(1..=1_000_000).contains(&self.replay_capacity)
            || !(1..=3600).contains(&self.max_capability_lifetime_secs)
            || self.clock_skew_secs > 300
            || !(100..=60_000).contains(&self.backend_connect_timeout_ms)
            || !(100..=600_000).contains(&self.backend_idle_timeout_ms)
            || !(100..=60_000).contains(&self.tls_handshake_timeout_ms)
            || !(1..=1024).contains(&self.max_streams_per_connection)
            || !(1..=64).contains(&self.max_http2_connections)
        {
            return Err(EdgeConfigError::InvalidLimits);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SocksConfig {
    #[serde(default = "default_socks_listen")]
    pub listen: SocketAddr,
    #[serde(default = "default_socks_connections")]
    pub max_connections: usize,
}

impl Default for SocksConfig {
    fn default() -> Self {
        Self {
            listen: default_socks_listen(),
            max_connections: default_socks_connections(),
        }
    }
}

fn default_socks_listen() -> SocketAddr {
    "127.0.0.1:10808".parse().expect("literal socket address")
}
fn default_socks_connections() -> usize {
    128
}

impl EdgeConfig {
    pub fn from_toml_bytes(bytes: &[u8]) -> Result<Self, EdgeConfigError> {
        if bytes.len() > MAX_CONFIG_BYTES {
            return Err(EdgeConfigError::TooLarge);
        }
        let source = std::str::from_utf8(bytes).map_err(|_| EdgeConfigError::Malformed)?;
        let config: Self = toml::from_str(source).map_err(|_| EdgeConfigError::Malformed)?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), EdgeConfigError> {
        let backend = self
            .backend
            .parse::<SocketAddr>()
            .map_err(|_| EdgeConfigError::InvalidBackend)?;
        if backend.port() == 0 || backend.ip().is_unspecified() {
            return Err(EdgeConfigError::InvalidBackend);
        }
        if self.audience.is_empty()
            || self.audience.len() > 64
            || !self.audience.is_ascii()
            || self
                .audience
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        {
            return Err(EdgeConfigError::InvalidAudience);
        }
        validate_relay_path(&self.relay_path)?;
        if self.tls.cert.is_some() != self.tls.key.is_some() {
            return Err(EdgeConfigError::IncompleteTls);
        }
        if ((self.tls.cert.is_some() || self.tls.key.is_some()) && self.tls.server_name.is_empty())
            || self.tls.server_name.len() > 253
            || !self.tls.server_name.is_ascii()
            || self
                .tls
                .server_name
                .bytes()
                .any(|byte| byte <= 0x20 || byte == 0x7f || byte == b'/' || byte == b'@')
        {
            return Err(EdgeConfigError::InvalidServerName);
        }
        if !self.socks.listen.ip().is_loopback()
            || self.socks.max_connections == 0
            || self.socks.max_connections > 10_000
        {
            return Err(EdgeConfigError::InvalidLimits);
        }
        self.limits.validate()
    }

    pub fn max_lifetime(&self) -> Duration {
        Duration::from_secs(self.limits.max_capability_lifetime_secs)
    }

    pub fn backend_connect_timeout(&self) -> Duration {
        Duration::from_millis(self.limits.backend_connect_timeout_ms)
    }

    pub fn backend_idle_timeout(&self) -> Duration {
        Duration::from_millis(self.limits.backend_idle_timeout_ms)
    }

    pub fn tls_handshake_timeout(&self) -> Duration {
        Duration::from_millis(self.limits.tls_handshake_timeout_ms)
    }
}

fn default_relay_path() -> String {
    DEFAULT_RELAY_PATH.to_owned()
}

pub fn validate_relay_path(path: &str) -> Result<(), EdgeConfigError> {
    if path.is_empty()
        || path.len() > MAX_RELAY_PATH_BYTES
        || !path.is_ascii()
        || !path.starts_with('/')
        || path.bytes().any(|byte| {
            byte <= 0x20 || byte == 0x7f || byte == b'?' || byte == b'#' || byte == b'\\'
        })
    {
        return Err(EdgeConfigError::InvalidRelayPath);
    }

    let uri = path
        .parse::<Uri>()
        .map_err(|_| EdgeConfigError::InvalidRelayPath)?;
    if uri.path() != path || uri.query().is_some() {
        return Err(EdgeConfigError::InvalidRelayPath);
    }
    Ok(())
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum EdgeConfigError {
    #[error("configuration is larger than 64 KiB")]
    TooLarge,
    #[error("configuration is malformed")]
    Malformed,
    #[error("backend must be a numeric socket address")]
    InvalidBackend,
    #[error("audience is invalid")]
    InvalidAudience,
    #[error("TLS certificate and key must be configured together")]
    IncompleteTls,
    #[error("TLS server name is invalid")]
    InvalidServerName,
    #[error("HTTP/2 relay path is invalid")]
    InvalidRelayPath,
    #[error("one or more configured limits are outside the safe bounds")]
    InvalidLimits,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_are_bounded() {
        assert!(Limits::default().validate().is_ok());
        let limits = Limits {
            max_stream_bytes: 0,
            ..Default::default()
        };
        assert_eq!(limits.validate(), Err(EdgeConfigError::InvalidLimits));
    }

    #[test]
    fn timeout_and_stream_limits_are_bounded() {
        for invalid in [
            Limits {
                backend_idle_timeout_ms: 99,
                ..Default::default()
            },
            Limits {
                backend_idle_timeout_ms: 600_001,
                ..Default::default()
            },
            Limits {
                tls_handshake_timeout_ms: 99,
                ..Default::default()
            },
            Limits {
                max_streams_per_connection: 0,
                ..Default::default()
            },
            Limits {
                max_streams_per_connection: 1025,
                ..Default::default()
            },
            Limits {
                max_http2_connections: 0,
                ..Default::default()
            },
            Limits {
                max_http2_connections: 65,
                ..Default::default()
            },
        ] {
            assert_eq!(invalid.validate(), Err(EdgeConfigError::InvalidLimits));
        }
    }

    #[test]
    fn config_requires_numeric_backend_and_paired_tls() {
        let source = br#"
listen = "127.0.0.1:8443"
backend = "backend.example:443"
audience = "edge-a"
public_key = "AA"
"#;
        assert_eq!(
            EdgeConfig::from_toml_bytes(source),
            Err(EdgeConfigError::InvalidBackend)
        );
    }

    #[test]
    fn config_rejects_unusable_backend_addresses() {
        for backend in ["0.0.0.0:443", "127.0.0.1:0"] {
            let source = format!(
                r#"
listen = "127.0.0.1:8443"
backend = "{backend}"
audience = "edge-a"
public_key = "AA"
"#
            );
            assert_eq!(
                EdgeConfig::from_toml_bytes(source.as_bytes()),
                Err(EdgeConfigError::InvalidBackend),
                "{backend} must be rejected"
            );
        }
    }

    #[test]
    fn config_rejects_whitespace_in_audience_and_invalid_tls_server_name() {
        let audience = br#"
listen = "127.0.0.1:8443"
backend = "127.0.0.1:443"
audience = "edge a"
public_key = "AA"
"#;
        assert_eq!(
            EdgeConfig::from_toml_bytes(audience),
            Err(EdgeConfigError::InvalidAudience)
        );

        let server_name = br#"
listen = "127.0.0.1:8443"
backend = "127.0.0.1:443"
audience = "edge-a"
public_key = "AA"

[tls]
server_name = ""
cert = "/etc/shph-edge/server.crt"
key = "/etc/shph-edge/server.key"
"#;
        assert_eq!(
            EdgeConfig::from_toml_bytes(server_name),
            Err(EdgeConfigError::InvalidServerName)
        );
    }

    #[test]
    fn config_accepts_and_validates_a_custom_relay_path() {
        let source = br#"
listen = "127.0.0.1:8443"
backend = "127.0.0.1:443"
audience = "edge-a"
public_key = "AA"
relay_path = "/owned/relay-v2"
"#;
        let config = EdgeConfig::from_toml_bytes(source).expect("custom path");
        assert_eq!(config.relay_path, "/owned/relay-v2");
    }

    #[test]
    fn relay_path_rejects_queries_controls_and_oversized_values() {
        for invalid in [
            "",
            "phantom-one/v1",
            "/phantom-one/v1?probe=1",
            "/phantom-one/\nv1",
            "/phantom-one/v1#fragment",
            &format!("/{}", "x".repeat(MAX_RELAY_PATH_BYTES)),
        ] {
            assert_eq!(
                validate_relay_path(invalid),
                Err(EdgeConfigError::InvalidRelayPath),
                "{invalid:?} must be rejected"
            );
        }
    }

    #[test]
    fn config_rejects_public_unauthenticated_socks_listener() {
        let source = br#"
listen = "127.0.0.1:8443"
backend = "127.0.0.1:443"
audience = "edge-a"
public_key = "AA"

[socks]
listen = "0.0.0.0:10808"
"#;
        assert_eq!(
            EdgeConfig::from_toml_bytes(source),
            Err(EdgeConfigError::InvalidLimits)
        );
    }

    #[test]
    fn config_rejects_invalid_tls_server_name() {
        let source = br#"
listen = "127.0.0.1:8443"
backend = "127.0.0.1:443"
audience = "edge-a"
public_key = "AA"

[tls]
server_name = "edge.example/path"
"#;
        assert_eq!(
            EdgeConfig::from_toml_bytes(source),
            Err(EdgeConfigError::InvalidServerName)
        );
    }
}
