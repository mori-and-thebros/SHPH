//! Configuration management for SHPH.

use serde::de::Error as _;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::net::IpAddr;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{ConfigError, Result};
pub use shph_core::roadmap::{
    IdentityProviderConfig, PqcConfig, RatchetAuditConfig, RoadmapConfig, ShamirConfig,
    TransportAdapterConfig,
};
pub use shph_core::HandshakeProfile;
use shph_core::{ensure_no_reparse_components, open_readonly_no_reparse};

static CONFIG_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);
const MAX_CONFIG_BYTES: u64 = 1 << 20;
const MAX_PEERS: usize = 1024;
const MAX_LIST_ENTRIES: usize = 1024;
const MAX_DNS_SERVERS: usize = 32;
const MAX_ALIAS_BYTES: usize = 128;
const MAX_ENDPOINT_BYTES: usize = 512;
const MAX_PROFILE_BYTES: usize = 64;
const MAX_STARTUP_PAYLOAD_BYTES: usize = 64 * 1024;

pub mod error;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct PeerConfig {
    pub alias: String,
    pub endpoint: String,
    pub pubkey: String,
    #[serde(default)]
    pub sign_pubkey: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct ShadowsocksConfig {
    pub server: String,
    pub method: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    pub server_name: String,
    pub ca_cert: Option<String>,
    pub pin_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StealthConfig {
    pub profile: String,
    pub shroud_profile: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlPlaneConfig {
    /// Apply `interface_cidr` to the configured TUN interface.
    pub apply_interface_address: Option<bool>,
    /// Local layer-3 address and prefix for the configured TUN interface.
    pub interface_cidr: Option<String>,
    pub apply_routes: Option<bool>,
    pub route_cidrs: Option<Vec<String>>,
    /// Routes that must remain on the original network underlay while a
    /// SOCKS-backed session installs a default route through SHPH.
    #[serde(default)]
    pub underlay_bypass_cidrs: Option<Vec<String>>,
    pub apply_dns: Option<bool>,
    pub dns_servers: Option<Vec<String>>,
    pub dry_run: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionConfig {
    pub role: SessionRole,
    pub bind: Option<String>,
    pub peer: Option<String>,
    /// Optional transport endpoint override. `peer` remains the identity and
    /// peer-policy selector; this endpoint is used only for connection setup.
    #[serde(default)]
    pub transport_peer: Option<String>,
    pub timeout_secs: Option<u64>,
    #[serde(default)]
    pub handshake_profile: Option<HandshakeProfile>,
    /// Optional outbound underlay adapter, for example
    /// `socks5://127.0.0.1:10808`. Direct TCP is the default.
    #[serde(default)]
    pub underlay: Option<String>,
    /// Out-of-band trusted standards-QUIC server certificate path.
    #[serde(default)]
    pub quic_cert: Option<String>,
    /// Owner-only standards-QUIC server private-key path.
    #[serde(default)]
    pub quic_key: Option<String>,
    /// Select the separate Phantom One morphology envelope.
    #[serde(default)]
    pub phantom_one: bool,
    /// Phantom One profile name. The CLI validates the six supported tiers.
    #[serde(default = "default_phantom_one_profile")]
    pub phantom_one_profile: String,
    pub reconnect: Option<ReconnectConfig>,
    pub startup_payload: Option<String>,
}

fn default_phantom_one_profile() -> String {
    "medium".to_owned()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
        ensure_no_reparse_components(path).map_err(|error| {
            ConfigError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                error.to_string(),
            ))
        })?;
        let file = open_config_readonly(path).map_err(ConfigError::Io)?;
        let metadata = file.metadata().map_err(ConfigError::Io)?;
        if metadata.len() > MAX_CONFIG_BYTES {
            return Err(ConfigError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("configuration exceeds {MAX_CONFIG_BYTES} bytes"),
            )));
        }
        let mut bytes = Vec::new();
        file.take(MAX_CONFIG_BYTES.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(ConfigError::Io)?;
        if bytes.len() as u64 > MAX_CONFIG_BYTES {
            return Err(ConfigError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("configuration exceeds {MAX_CONFIG_BYTES} bytes"),
            )));
        }
        let contents = String::from_utf8(bytes).map_err(|err| {
            ConfigError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("configuration is not valid UTF-8: {err}"),
            ))
        })?;
        Self::parse(&contents)
    }

    pub fn parse(contents: &str) -> Result<Self> {
        let mut document: toml::Value = toml::from_str(contents).map_err(ConfigError::Parse)?;
        let mut migrated = false;
        let legacy_profile = document
            .get("stealth")
            .and_then(toml::Value::as_table)
            .and_then(|stealth| stealth.get("shroud_profile"))
            .and_then(toml::Value::as_str)
            .unwrap_or("medium")
            .to_ascii_lowercase();

        if let Some(session) = document
            .get_mut("session")
            .and_then(toml::Value::as_table_mut)
        {
            if let Some(old_value) = session.remove("shroud_version") {
                let old_version = old_value.as_str().ok_or_else(|| {
                    ConfigError::Parse(toml::de::Error::custom(
                        "session.shroud_version must be the string 2.0 or 2.1",
                    ))
                })?;
                let migrated_phantom_one = match old_version {
                    "2.0" => false,
                    "2.1" => true,
                    _ => {
                        return Err(ConfigError::Parse(toml::de::Error::custom(
                            "session.shroud_version must be 2.0 or 2.1",
                        )))
                    }
                };

                if let Some(configured) = session.get("phantom_one").and_then(toml::Value::as_bool)
                {
                    if configured != migrated_phantom_one {
                        return Err(ConfigError::Parse(toml::de::Error::custom(
                            "session.shroud_version conflicts with session.phantom_one",
                        )));
                    }
                } else {
                    session.insert(
                        "phantom_one".into(),
                        toml::Value::Boolean(migrated_phantom_one),
                    );
                }

                if migrated_phantom_one && !session.contains_key("phantom_one_profile") {
                    let profile = match legacy_profile.as_str() {
                        "low-latency" => "low",
                        "balanced" => "medium",
                        "bulk" => "high",
                        "tuned" | "optimized" | "optimized-medium" => "tuned-medium",
                        "optimized-low" => "tuned-low",
                        "optimized-high" => "tuned-high",
                        "low" | "medium" | "high" | "tuned-low" | "tuned-medium" | "tuned-high" => {
                            legacy_profile.as_str()
                        }
                        _ => "medium",
                    };
                    session.insert("phantom_one_profile".into(), profile.into());
                }
                migrated = true;
            }
        }

        if migrated {
            eprintln!(
                "Warning: migrated session.shroud_version in memory; the configuration file was not rewritten"
            );
        }

        let config: Self = document.try_into().map_err(ConfigError::Parse)?;
        config.validate()?;
        Ok(config)
    }

    /// Validate the complete configuration before any session or host
    /// mutation is attempted.
    ///
    /// Parsing TOML only proves that the document has the right types. This
    /// second boundary checks sizes, endpoint shapes, cross-field
    /// requirements, and privileged control-plane inputs in one place so
    /// callers cannot accidentally skip the same safety checks.
    pub fn validate(&self) -> Result<()> {
        validate_interface_name(&self.interface_name)?;
        validate_endpoint("local_endpoint", &self.local_endpoint)?;

        if self.peers.len() > MAX_PEERS {
            return Err(ConfigError::Invalid(format!(
                "peers exceeds the maximum of {MAX_PEERS} entries"
            )));
        }
        let mut aliases = HashSet::with_capacity(self.peers.len());
        for peer in &self.peers {
            validate_text("peer alias", &peer.alias, MAX_ALIAS_BYTES, false)?;
            if !aliases.insert(peer.alias.to_ascii_lowercase()) {
                return Err(ConfigError::Invalid(format!(
                    "peer aliases must be unique: {}",
                    peer.alias
                )));
            }
            validate_endpoint("peer endpoint", &peer.endpoint)?;
            validate_key_text("peer public key", &peer.pubkey)?;
            if let Some(sign_pubkey) = &peer.sign_pubkey {
                validate_key_text("peer signing public key", sign_pubkey)?;
            }
        }

        if let Some(obfuscation) = &self.obfuscation {
            if let Some(shadowsocks) = &obfuscation.shadowsocks {
                validate_endpoint("obfuscation.shadowsocks.server", &shadowsocks.server)?;
                validate_text(
                    "obfuscation.shadowsocks.method",
                    &shadowsocks.method,
                    MAX_PROFILE_BYTES,
                    false,
                )?;
                validate_text(
                    "obfuscation.shadowsocks.password",
                    &shadowsocks.password,
                    MAX_STARTUP_PAYLOAD_BYTES,
                    false,
                )?;
            }
            if let Some(tls) = &obfuscation.tls {
                validate_dns_name("obfuscation.tls.server_name", &tls.server_name)?;
                if let Some(ca_cert) = &tls.ca_cert {
                    validate_path_text("obfuscation.tls.ca_cert", ca_cert)?;
                }
                if let Some(pin) = &tls.pin_sha256 {
                    validate_text("obfuscation.tls.pin_sha256", pin, 128, false)?;
                }
            }
        }

        if let Some(stealth) = &self.stealth {
            validate_text(
                "stealth.profile",
                &stealth.profile,
                MAX_PROFILE_BYTES,
                false,
            )?;
            validate_text(
                "stealth.shroud_profile",
                &stealth.shroud_profile,
                MAX_PROFILE_BYTES,
                false,
            )?;
        }

        if let Some(control) = &self.control_plane {
            validate_control_plane(control)?;
        }

        if let Some(session) = &self.session {
            validate_session(session)?;
        }

        Ok(())
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        self.validate()?;
        let contents = toml::to_string_pretty(self).map_err(ConfigError::Serialize)?;
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            ensure_no_reparse_components(parent).map_err(|error| {
                ConfigError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    error.to_string(),
                ))
            })?;
            fs::create_dir_all(parent).map_err(ConfigError::Io)?;
            ensure_no_reparse_components(parent).map_err(|error| {
                ConfigError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    error.to_string(),
                ))
            })?;
        }
        ensure_no_reparse_components(path).map_err(|error| {
            ConfigError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                error.to_string(),
            ))
        })?;
        let (mut file, tmp) = create_config_temp_file(path)?;
        if let Err(err) = restrict_config_perms(&tmp).map_err(ConfigError::Io) {
            drop(file);
            let _ = fs::remove_file(&tmp);
            return Err(err);
        }
        if let Err(err) = file.write_all(contents.as_bytes()).map_err(ConfigError::Io) {
            drop(file);
            let _ = fs::remove_file(&tmp);
            return Err(err);
        }
        if let Err(err) = file.sync_all().map_err(ConfigError::Io) {
            drop(file);
            let _ = fs::remove_file(&tmp);
            return Err(err);
        }
        drop(file);
        if let Some(parent) = path.parent() {
            let result = ensure_no_reparse_components(parent).map_err(|error| {
                ConfigError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    error.to_string(),
                ))
            });
            if let Err(error) = result {
                let _ = fs::remove_file(&tmp);
                return Err(error);
            }
        }
        let result = ensure_no_reparse_components(path).map_err(|error| {
            ConfigError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                error.to_string(),
            ))
        });
        if let Err(error) = result {
            let _ = fs::remove_file(&tmp);
            return Err(error);
        }
        if let Err(err) = persist_config_over(&tmp, path).map_err(ConfigError::Io) {
            let _ = fs::remove_file(&tmp);
            return Err(err);
        }
        sync_parent_dir(path).map_err(ConfigError::Io)?;
        Ok(())
    }

    pub fn default_config_path() -> std::path::PathBuf {
        let home = home::home_dir().unwrap_or_else(|| std::path::PathBuf::from("."));
        home.join(".shph").join("config.toml")
    }
}

fn validate_interface_name(value: &str) -> Result<()> {
    validate_text("interface_name", value, 15, false)?;
    if !value.chars().all(|character| {
        character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.' | ':')
    }) {
        return Err(ConfigError::Invalid(
            "interface_name contains unsupported characters".into(),
        ));
    }
    Ok(())
}

fn validate_text(label: &str, value: &str, max_bytes: usize, allow_empty: bool) -> Result<()> {
    if (!allow_empty && value.is_empty())
        || value.len() > max_bytes
        || !value.is_ascii()
        || value
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(ConfigError::Invalid(format!(
            "{label} must be non-empty ASCII text of at most {max_bytes} bytes without whitespace or control characters"
        )));
    }
    Ok(())
}

fn validate_path_text(label: &str, value: &str) -> Result<()> {
    if value.is_empty() || value.len() > MAX_ENDPOINT_BYTES || value.contains('\0') {
        return Err(ConfigError::Invalid(format!(
            "{label} is empty or too long"
        )));
    }
    Ok(())
}

fn validate_key_text(label: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 512
        || !value.is_ascii()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
    {
        return Err(ConfigError::Invalid(format!(
            "{label} must be bounded ASCII text without whitespace"
        )));
    }
    Ok(())
}

fn validate_endpoint(label: &str, value: &str) -> Result<()> {
    if value.len() > MAX_ENDPOINT_BYTES
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        || value.contains('@')
        || value.contains('/')
    {
        return Err(ConfigError::Invalid(format!(
            "{label} is not a valid host:port"
        )));
    }
    let endpoint = shph_core::Endpoint::parse(value)
        .map_err(|error| ConfigError::Invalid(format!("{label}: {error}")))?;
    if endpoint.host.is_empty() || endpoint.host.len() > MAX_ENDPOINT_BYTES {
        return Err(ConfigError::Invalid(format!(
            "{label} host is empty or too long"
        )));
    }
    Ok(())
}

fn validate_dns_name(label: &str, value: &str) -> Result<()> {
    validate_text(label, value, 253, false)?;
    if value.starts_with('.') || value.ends_with('.') || value.contains("..") {
        return Err(ConfigError::Invalid(format!(
            "{label} is not a valid DNS name"
        )));
    }
    Ok(())
}

fn validate_cidr(label: &str, value: &str) -> Result<()> {
    let (address, prefix) = value
        .split_once('/')
        .ok_or_else(|| ConfigError::Invalid(format!("{label} must be an IP/prefix")))?;
    let ip = address
        .parse::<IpAddr>()
        .map_err(|_| ConfigError::Invalid(format!("{label} has an invalid IP address")))?;
    let prefix = prefix
        .parse::<u8>()
        .map_err(|_| ConfigError::Invalid(format!("{label} has an invalid prefix")))?;
    let maximum = if ip.is_ipv4() { 32 } else { 128 };
    if prefix > maximum {
        return Err(ConfigError::Invalid(format!(
            "{label} has an invalid CIDR prefix; maximum is /{maximum}"
        )));
    }
    Ok(())
}

fn validate_single_host_cidr(label: &str, value: &str) -> Result<()> {
    validate_cidr(label, value)?;
    let (address, prefix) = value
        .split_once('/')
        .ok_or_else(|| ConfigError::Invalid(format!("{label} must be an IP/prefix")))?;
    let ip = address
        .parse::<IpAddr>()
        .map_err(|_| ConfigError::Invalid(format!("{label} has an invalid IP address")))?;
    let expected = if ip.is_ipv4() { 32 } else { 128 };
    if prefix != expected.to_string() {
        return Err(ConfigError::Invalid(format!(
            "{label} must be a single-host route"
        )));
    }
    if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() {
        return Err(ConfigError::Invalid(format!(
            "{label} must be a unicast, non-loopback address"
        )));
    }
    Ok(())
}

fn validate_list<T>(label: &str, values: Option<&Vec<T>>, maximum: usize) -> Result<()> {
    if values.is_some_and(|values| values.len() > maximum) {
        return Err(ConfigError::Invalid(format!(
            "{label} exceeds the maximum of {maximum} entries"
        )));
    }
    Ok(())
}

fn validate_control_plane(control: &ControlPlaneConfig) -> Result<()> {
    if control.apply_interface_address.unwrap_or(false) {
        let cidr = control.interface_cidr.as_deref().ok_or_else(|| {
            ConfigError::Invalid(
                "apply_interface_address=true requires control_plane.interface_cidr".into(),
            )
        })?;
        validate_cidr("control_plane.interface_cidr", cidr)?;
    } else if let Some(cidr) = &control.interface_cidr {
        validate_cidr("control_plane.interface_cidr", cidr)?;
    }

    validate_list(
        "control_plane.route_cidrs",
        control.route_cidrs.as_ref(),
        MAX_LIST_ENTRIES,
    )?;
    if let Some(routes) = &control.route_cidrs {
        for route in routes {
            validate_cidr("control_plane.route_cidrs entry", route)?;
        }
    }
    validate_list(
        "control_plane.underlay_bypass_cidrs",
        control.underlay_bypass_cidrs.as_ref(),
        MAX_LIST_ENTRIES,
    )?;
    if let Some(routes) = &control.underlay_bypass_cidrs {
        for route in routes {
            validate_single_host_cidr("control_plane.underlay_bypass_cidrs entry", route)?;
        }
    }

    validate_list(
        "control_plane.dns_servers",
        control.dns_servers.as_ref(),
        MAX_DNS_SERVERS,
    )?;
    if control.apply_dns.unwrap_or(false) && control.dns_servers.as_ref().is_none_or(Vec::is_empty)
    {
        return Err(ConfigError::Invalid(
            "apply_dns=true requires at least one DNS server".into(),
        ));
    }
    if let Some(servers) = &control.dns_servers {
        for server in servers {
            let ip = server.parse::<IpAddr>().map_err(|_| {
                ConfigError::Invalid(format!(
                    "control_plane.dns_servers entry is not an IP address: {server}"
                ))
            })?;
            if ip.is_unspecified() || ip.is_multicast() {
                return Err(ConfigError::Invalid(
                    "control_plane.dns_servers entries must be unicast addresses".into(),
                ));
            }
        }
    }
    Ok(())
}

fn validate_session(session: &SessionConfig) -> Result<()> {
    match session.role {
        SessionRole::Listen => {
            if let Some(bind) = &session.bind {
                validate_endpoint("session.bind", bind)?;
            }
        }
        SessionRole::Connect => {
            let peer = session.peer.as_deref().ok_or_else(|| {
                ConfigError::Invalid("connect sessions require session.peer".into())
            })?;
            validate_endpoint("session.peer", peer)?;
        }
    }
    if let Some(transport_peer) = &session.transport_peer {
        validate_endpoint("session.transport_peer", transport_peer)?;
    }
    if let Some(timeout) = session.timeout_secs {
        if !(1..=3600).contains(&timeout) {
            return Err(ConfigError::Invalid(
                "session.timeout_secs must be between 1 and 3600".into(),
            ));
        }
    }
    if let Some(underlay) = &session.underlay {
        let value = underlay.trim();
        if value != "direct" {
            let proxy = value
                .strip_prefix("socks5://")
                .or_else(|| value.strip_prefix("socks5h://"))
                .ok_or_else(|| {
                    ConfigError::Invalid(
                        "session.underlay must be direct or socks5://host:port".into(),
                    )
                })?;
            validate_endpoint("session.underlay proxy", proxy)?;
        }
    }
    if let Some(cert) = &session.quic_cert {
        validate_path_text("session.quic_cert", cert)?;
    }
    if let Some(key) = &session.quic_key {
        validate_path_text("session.quic_key", key)?;
    }
    validate_text(
        "session.phantom_one_profile",
        &session.phantom_one_profile,
        MAX_PROFILE_BYTES,
        false,
    )?;
    if let Some(reconnect) = &session.reconnect {
        if reconnect.enabled.unwrap_or(false) && reconnect.max_attempts.unwrap_or(0) == 0 {
            return Err(ConfigError::Invalid(
                "enabled reconnect requires max_attempts greater than zero".into(),
            ));
        }
        if let Some(attempts) = reconnect.max_attempts {
            if attempts > 100 {
                return Err(ConfigError::Invalid(
                    "session.reconnect.max_attempts cannot exceed 100".into(),
                ));
            }
        }
        if let Some(delay) = reconnect.initial_delay_ms {
            if !(1..=60_000).contains(&delay) {
                return Err(ConfigError::Invalid(
                    "session.reconnect.initial_delay_ms must be between 1 and 60000".into(),
                ));
            }
        }
        if let Some(delay) = reconnect.max_delay_ms {
            if !(1..=300_000).contains(&delay) {
                return Err(ConfigError::Invalid(
                    "session.reconnect.max_delay_ms must be between 1 and 300000".into(),
                ));
            }
        }
        if let (Some(initial), Some(maximum)) = (reconnect.initial_delay_ms, reconnect.max_delay_ms)
        {
            if maximum < initial {
                return Err(ConfigError::Invalid(
                    "session.reconnect.max_delay_ms must be >= initial_delay_ms".into(),
                ));
            }
        }
    }
    if let Some(payload) = &session.startup_payload {
        if payload.len() > MAX_STARTUP_PAYLOAD_BYTES {
            return Err(ConfigError::Invalid(format!(
                "session.startup_payload exceeds {MAX_STARTUP_PAYLOAD_BYTES} bytes"
            )));
        }
    }
    Ok(())
}

fn open_config_readonly(path: &Path) -> std::io::Result<std::fs::File> {
    let file = open_readonly_no_reparse(path).map_err(|error| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, error.to_string())
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = file.metadata()?.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "configuration file is group/other accessible (mode {mode:o}); refusing to load"
                ),
            ));
        }
    }
    #[cfg(not(unix))]
    shph_core::enforce_owner_only_file_permissions(path).map_err(|error| {
        std::io::Error::new(std::io::ErrorKind::PermissionDenied, error.to_string())
    })?;
    Ok(file)
}

fn create_config_temp_file(path: &Path) -> Result<(std::fs::File, std::path::PathBuf)> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let filename = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("config.toml");
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ConfigError::Io(std::io::Error::other("system clock before unix epoch")))?
        .as_nanos();

    for attempt in 0..32 {
        let counter = CONFIG_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp = parent.join(format!(
            ".{filename}.tmp-{}-{timestamp}-{counter}-{attempt}",
            std::process::id()
        ));
        match OpenOptions::new().create_new(true).write(true).open(&tmp) {
            Ok(file) => return Ok((file, tmp)),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(ConfigError::Io(err)),
        }
    }

    Err(ConfigError::Io(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "unable to allocate a unique config temp file",
    )))
}

fn persist_config_over(tmp: &Path, path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        fs::rename(tmp, path)
    }
    #[cfg(not(unix))]
    {
        persist_config_over_windows(tmp, path)
    }
}

fn sync_parent_dir(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::File::open(parent)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

fn restrict_config_perms(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    {
        shph_core::enforce_owner_only_file_permissions(path).map_err(|error| {
            std::io::Error::new(std::io::ErrorKind::PermissionDenied, error.to_string())
        })?;
    }
    Ok(())
}

#[cfg(windows)]
fn wide_path(path: &Path) -> std::io::Result<Vec<u16>> {
    use std::os::windows::ffi::OsStrExt;
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide.contains(&0) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "configuration path contains an embedded NUL",
        ));
    }
    wide.push(0);
    Ok(wide)
}

#[cfg(windows)]
fn persist_config_over_windows(tmp: &Path, path: &Path) -> std::io::Result<()> {
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, ReplaceFileW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
        REPLACEFILE_WRITE_THROUGH,
    };

    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "refusing to replace a symlinked configuration",
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let tmp_w = wide_path(tmp)?;
    let path_w = wide_path(path)?;
    let result = if path.exists() {
        unsafe {
            ReplaceFileW(
                path_w.as_ptr(),
                tmp_w.as_ptr(),
                std::ptr::null(),
                REPLACEFILE_WRITE_THROUGH,
                std::ptr::null(),
                std::ptr::null(),
            )
        }
    } else {
        unsafe {
            MoveFileExW(
                tmp_w.as_ptr(),
                path_w.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        }
    };
    if result == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Config, SessionRole, MAX_CONFIG_BYTES};
    use std::fs;

    #[test]
    fn parse_session_reconnect_and_control_plane() {
        let input = r#"
interface_name = "shph0"
local_endpoint = "0.0.0.0:51820"
peers = []

[control_plane]
apply_routes = true
route_cidrs = ["10.10.0.0/16", "172.20.0.0/16"]
underlay_bypass_cidrs = ["198.51.100.10/32"]
apply_dns = true
dns_servers = ["1.1.1.1", "9.9.9.9"]
dry_run = true

[session]
role = "connect"
peer = "127.0.0.1:7231"
transport_peer = "127.0.0.1:8443"
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
        assert_eq!(session.peer.as_deref(), Some("127.0.0.1:7231"));
        assert_eq!(session.transport_peer.as_deref(), Some("127.0.0.1:8443"));
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
        assert_eq!(
            cp.underlay_bypass_cidrs,
            Some(vec!["198.51.100.10/32".to_string()])
        );
        assert_eq!(cp.apply_dns, Some(true));
        assert_eq!(
            cp.dns_servers,
            Some(vec!["1.1.1.1".to_string(), "9.9.9.9".to_string()])
        );
        assert_eq!(cp.dry_run, Some(true));
    }

    #[test]
    fn session_handshake_profile_defaults_to_secure_default() {
        let cfg = toml::from_str::<Config>(
            r#"
interface_name = "shph0"
local_endpoint = "0.0.0.0:51820"
peers = []

[session]
role = "connect"
peer = "127.0.0.1:7000"
"#,
        )
        .expect("parse config");
        assert_eq!(cfg.session.unwrap().handshake_profile, None);
    }

    #[test]
    fn session_handshake_profile_parses_classical_lab() {
        let cfg = toml::from_str::<Config>(
            r#"
interface_name = "shph0"
local_endpoint = "0.0.0.0:51820"
peers = []

[session]
role = "connect"
handshake_profile = "classical-lab"
"#,
        )
        .expect("parse config");
        assert_eq!(
            cfg.session.unwrap().handshake_profile,
            Some(shph_core::HandshakeProfile::ClassicalLab)
        );
    }

    #[test]
    fn parse_migrates_legacy_shroud_version_in_memory() {
        let input = r#"
interface_name = "shph0"
local_endpoint = "0.0.0.0:51820"
peers = []

[stealth]
profile = "steady"
shroud_profile = "tuned-high"

[session]
role = "connect"
peer = "127.0.0.1:7000"
shroud_version = "2.1"
"#;

        let cfg = Config::parse(input).expect("parse migrated config");
        let session = cfg.session.as_ref().expect("session");
        assert!(session.phantom_one);
        assert_eq!(session.phantom_one_profile, "tuned-high");
        assert!(!input.contains("phantom_one ="));
    }

    #[test]
    fn parse_migrates_legacy_shroud_two_without_phantom_one() {
        let input = r#"
interface_name = "shph0"
local_endpoint = "0.0.0.0:51820"
peers = []

[session]
role = "listen"
bind = "0.0.0.0:7000"
shroud_version = "2.0"
"#;

        let cfg = Config::parse(input).expect("parse migrated config");
        let session = cfg.session.as_ref().expect("session");
        assert!(!session.phantom_one);
        assert_eq!(session.phantom_one_profile, "medium");
        let canonical = toml::to_string_pretty(&cfg).expect("serialize canonical config");
        assert!(canonical.contains("phantom_one = false"));
        assert!(canonical.contains("phantom_one_profile = \"medium\""));
        assert!(!canonical.contains("shroud_version"));
    }

    #[test]
    fn parse_rejects_conflicting_legacy_and_new_morphology() {
        let input = r#"
interface_name = "shph0"
local_endpoint = "0.0.0.0:51820"
peers = []

[session]
role = "connect"
peer = "127.0.0.1:7000"
shroud_version = "2.0"
phantom_one = true
"#;

        assert!(Config::parse(input).is_err());
    }

    #[test]
    fn parse_rejects_unknown_top_level_and_privileged_control_plane_fields() {
        let top_level = r#"
interface_name = "shph0"
local_endpoint = "127.0.0.1:1"
peers = []
interafce_name = "typo"
"#;
        assert!(Config::parse(top_level).is_err());

        let control_plane = r#"
interface_name = "shph0"
local_endpoint = "127.0.0.1:1"
peers = []

[control_plane]
apply_routes = true
route_cidrss = ["10.0.0.0/24"]
"#;
        assert!(Config::parse(control_plane).is_err());
    }

    #[test]
    fn validate_rejects_duplicate_peers_and_missing_connect_peer() {
        let duplicate = r#"
interface_name = "shph0"
local_endpoint = "0.0.0.0:51820"
peers = [
  { alias = "ALPHA", endpoint = "127.0.0.1:7000", pubkey = "AA" },
  { alias = "alpha", endpoint = "127.0.0.1:7001", pubkey = "BB" }
]
"#;
        assert!(Config::parse(duplicate)
            .expect_err("duplicate peer aliases must fail")
            .to_string()
            .contains("peer aliases must be unique"));

        let missing_peer = r#"
interface_name = "shph0"
local_endpoint = "0.0.0.0:51820"
peers = []

[session]
role = "connect"
"#;
        assert!(Config::parse(missing_peer)
            .expect_err("connect peer is required")
            .to_string()
            .contains("session.peer"));
    }

    #[test]
    fn validate_rejects_unsafe_control_plane_combinations() {
        let missing_dns = r#"
interface_name = "shph0"
local_endpoint = "0.0.0.0:51820"
peers = []

[control_plane]
apply_dns = true
"#;
        assert!(Config::parse(missing_dns)
            .expect_err("DNS apply without servers must fail")
            .to_string()
            .contains("apply_dns"));

        let broad_bypass = r#"
interface_name = "shph0"
local_endpoint = "0.0.0.0:51820"
peers = []

[control_plane]
underlay_bypass_cidrs = ["198.51.100.0/24"]
"#;
        assert!(Config::parse(broad_bypass)
            .expect_err("bypass route must be single-host")
            .to_string()
            .contains("single-host"));
    }

    #[cfg(unix)]
    #[test]
    fn save_does_not_follow_predictable_temp_symlink() {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join(format!(
            "shph-config-temp-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        fs::create_dir_all(&root).expect("mkdir");
        let target = root.join("victim");
        let config = root.join("config.toml");
        let predictable_tmp = root.join("config.tmp");
        fs::write(&target, b"must remain unchanged").expect("victim");
        symlink(&target, &predictable_tmp).expect("temp symlink");

        Config::default().save(&config).expect("save config");

        assert_eq!(
            fs::read_to_string(&target).expect("read victim"),
            "must remain unchanged"
        );
        assert!(config.exists());
        assert!(predictable_tmp.exists());
        fs::remove_dir_all(root).ok();
    }

    #[cfg(unix)]
    #[test]
    fn save_refuses_symlinked_parent_directory() {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join(format!(
            "shph-config-parent-symlink-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let real = root.join("real");
        let link = root.join("link");
        fs::create_dir_all(&real).expect("mkdir");
        symlink(&real, &link).expect("symlink");

        assert!(Config::default().save(&link.join("config.toml")).is_err());
        assert!(!real.join("config.toml").exists());
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn load_rejects_oversized_configuration() {
        let root = std::env::temp_dir().join(format!(
            "shph-config-oversized-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        fs::create_dir_all(&root).expect("mkdir");
        let path = root.join("config.toml");
        fs::write(&path, vec![b'x'; (MAX_CONFIG_BYTES + 1) as usize]).expect("write");

        assert!(Config::load(&path).is_err());
        fs::remove_dir_all(root).ok();
    }

    #[cfg(unix)]
    #[test]
    fn load_refuses_final_component_symlink() {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join(format!(
            "shph-config-symlink-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        fs::create_dir_all(&root).expect("mkdir");
        let target = root.join("target.toml");
        let link = root.join("config.toml");
        fs::write(&target, "interface_name = \"shph0\"\n").expect("target");
        symlink(&target, &link).expect("symlink");

        assert!(Config::load(&link).is_err());
        fs::remove_dir_all(root).ok();
    }

    #[cfg(unix)]
    #[test]
    fn load_requires_owner_only_permissions() {
        use std::fs::Permissions;
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!(
            "shph-config-perms-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        fs::create_dir_all(&root).expect("mkdir");
        let path = root.join("config.toml");
        fs::write(
            &path,
            "interface_name = \"shph0\"\nlocal_endpoint = \"127.0.0.1:1\"\npeers = []\n",
        )
        .expect("write config");

        for mode in [0o644, 0o640] {
            fs::set_permissions(&path, Permissions::from_mode(mode)).expect("set leaky mode");
            assert!(
                Config::load(&path).is_err(),
                "mode {mode:o} must be rejected"
            );
        }

        fs::set_permissions(&path, Permissions::from_mode(0o600)).expect("set owner-only mode");
        assert!(Config::load(&path).is_ok(), "0600 must be accepted");
        fs::remove_dir_all(root).ok();
    }
}
