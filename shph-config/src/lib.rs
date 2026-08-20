//! Configuration management for SHPH.

use serde::{Deserialize, Serialize};
use std::fs;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{ConfigError, Result};
use shph_core::ensure_no_reparse_components;
pub use shph_core::roadmap::{
    IdentityProviderConfig, PqcConfig, RatchetAuditConfig, RoadmapConfig, ShamirConfig,
    TransportAdapterConfig,
};
pub use shph_core::HandshakeProfile;

static CONFIG_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);
const MAX_CONFIG_BYTES: u64 = 1 << 20;

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
    pub reconnect: Option<ReconnectConfig>,
    pub startup_payload: Option<String>,
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
        toml::from_str(contents).map_err(ConfigError::Parse)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
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

fn open_config_readonly(path: &Path) -> std::io::Result<std::fs::File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        if !file.metadata()?.file_type().is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "configuration path must reference a regular file",
            ));
        }
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
        Ok(file)
    }
    #[cfg(not(unix))]
    {
        shph_core::ensure_not_reparse_point(path).map_err(|error| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, error.to_string())
        })?;
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "refusing to load a symlinked configuration",
            ));
        }
        shph_core::enforce_owner_only_file_permissions(path).map_err(|error| {
            std::io::Error::new(std::io::ErrorKind::PermissionDenied, error.to_string())
        })?;
        let file = std::fs::File::open(path)?;
        if !file.metadata()?.file_type().is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "configuration path must reference a regular file",
            ));
        }
        Ok(file)
    }
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
