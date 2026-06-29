//! Configuration management for SHPH.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

use crate::error::{ConfigError, Result};
pub use shph_core::roadmap::{
    IdentityProviderConfig, PqcConfig, RatchetAuditConfig, RoadmapConfig, ShamirConfig,
    TransportAdapterConfig,
};

pub mod error;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub interface_name: String,
    pub local_endpoint: String,
    pub peers: Vec<PeerConfig>,
    pub obfuscation: Option<ObfuscationConfig>,
    pub stealth: Option<StealthConfig>,
    pub roadmap: Option<RoadmapConfig>,
    pub control_plane: Option<ControlPlaneConfig>,
    pub session: Option<SessionConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerConfig {
    pub alias: String,
    pub endpoint: String,
    pub pubkey: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObfuscationConfig {
    pub mode: ObfuscationMode,
    pub shadowsocks: Option<ShadowsocksConfig>,
    pub tls: Option<TlsConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObfuscationMode {
    Direct,
    Shadowsocks,
    Tls,
    H3,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowsocksConfig {
    pub server: String,
    pub method: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    pub server_name: String,
    pub ca_cert: Option<String>,
    pub pin_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StealthConfig {
    pub profile: String,
    pub shroud_profile: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlPlaneConfig {
    pub apply_routes: Option<bool>,
    pub route_cidrs: Option<Vec<String>>,
    pub apply_dns: Option<bool>,
    pub dns_servers: Option<Vec<String>>,
    pub dry_run: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    pub role: SessionRole,
    pub bind: Option<String>,
    pub peer: Option<String>,
    pub timeout_secs: Option<u64>,
    pub reconnect: Option<ReconnectConfig>,
    pub startup_payload: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconnectConfig {
    pub enabled: Option<bool>,
    pub max_attempts: Option<u32>,
    pub initial_delay_ms: Option<u64>,
    pub max_delay_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SessionRole {
    Listen,
    Connect,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            interface_name: "shph0".to_string(),
            local_endpoint: "0.0.0.0:51820".to_string(),
            peers: Vec::new(),
            obfuscation: None,
            stealth: None,
            roadmap: None,
            control_plane: None,
            session: None,
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let contents = fs::read_to_string(path).map_err(ConfigError::Io)?;
        toml::from_str(&contents).map_err(ConfigError::Parse)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let contents = toml::to_string_pretty(self).map_err(ConfigError::Serialize)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(ConfigError::Io)?;
        }
        fs::write(path, contents).map_err(ConfigError::Io)?;
        Ok(())
    }

    pub fn default_config_path() -> std::path::PathBuf {
        let home = home::home_dir().unwrap_or_else(|| std::path::PathBuf::from("."));
        home.join(".shph").join("config.toml")
    }
}

#[cfg(test)]
mod tests {
    use super::{Config, SessionRole};

    #[test]
    fn parse_session_reconnect_and_control_plane() {
        let input = r#"
interface_name = "shph0"
local_endpoint = "0.0.0.0:51820"
peers = []

[control_plane]
apply_routes = true
route_cidrs = ["10.10.0.0/16", "172.20.0.0/16"]
apply_dns = true
dns_servers = ["1.1.1.1", "9.9.9.9"]
dry_run = true

[session]
role = "connect"
peer = "127.0.0.1:7231"
timeout_secs = 8

[session.reconnect]
enabled = true
max_attempts = 3
initial_delay_ms = 250
max_delay_ms = 2000
"#;

        let cfg = toml::from_str::<Config>(input).expect("parse config");
        let session = cfg.session.expect("session config");
        assert_eq!(session.role, SessionRole::Connect);
        let reconnect = session.reconnect.expect("reconnect config");
        assert_eq!(reconnect.enabled, Some(true));
        assert_eq!(reconnect.max_attempts, Some(3));
        assert_eq!(reconnect.initial_delay_ms, Some(250));
        assert_eq!(reconnect.max_delay_ms, Some(2000));

        let cp = cfg.control_plane.expect("control plane config");
        assert_eq!(cp.apply_routes, Some(true));
        assert_eq!(
            cp.route_cidrs,
            Some(vec![
                "10.10.0.0/16".to_string(),
                "172.20.0.0/16".to_string()
            ])
        );
        assert_eq!(cp.apply_dns, Some(true));
        assert_eq!(
            cp.dns_servers,
            Some(vec!["1.1.1.1".to_string(), "9.9.9.9".to_string()])
        );
        assert_eq!(cp.dry_run, Some(true));
    }
}
