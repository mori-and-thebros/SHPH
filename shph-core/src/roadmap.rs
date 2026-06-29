//! Roadmap hardening primitives and optional adapter configuration models.

use base64::Engine as _;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{Result, ShphError};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TransportAdapterConfig {
    #[default]
    Tcp,
    OfflineMesh {
        #[serde(default)]
        node_id: String,
        #[serde(default)]
        peer_id: String,
        #[serde(default)]
        spool_dir: String,
        #[serde(default = "default_poll_interval_ms")]
        poll_interval_ms: u64,
        #[serde(default = "default_max_idle_entries")]
        max_idle_entries: u32,
    },
    DataMule {
        #[serde(default)]
        inbox_dir: String,
        #[serde(default)]
        outbox_dir: String,
        #[serde(default = "default_poll_interval_ms")]
        poll_interval_ms: u64,
        #[serde(default = "default_max_file_bytes")]
        max_file_bytes: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfflineMeshConfig {
    pub node_id: String,
    pub peer_id: String,
    pub spool_dir: String,
    pub poll_interval_ms: u64,
    pub max_idle_entries: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataMuleConfig {
    pub inbox_dir: String,
    pub outbox_dir: String,
    pub poll_interval_ms: u64,
    pub max_file_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportAdapterConfigContainer {
    pub transport: TransportAdapterConfig,
}

fn default_poll_interval_ms() -> u64 {
    250
}

fn default_max_idle_entries() -> u32 {
    1024
}

fn default_max_file_bytes() -> u64 {
    32 * 1024
}

impl TransportAdapterConfig {
    pub fn as_offline_mesh(&self) -> Option<OfflineMeshConfig> {
        match self {
            Self::OfflineMesh {
                node_id,
                peer_id,
                spool_dir,
                poll_interval_ms,
                max_idle_entries,
            } => Some(OfflineMeshConfig {
                node_id: node_id.clone(),
                peer_id: peer_id.clone(),
                spool_dir: spool_dir.clone(),
                poll_interval_ms: *poll_interval_ms,
                max_idle_entries: *max_idle_entries,
            }),
            _ => None,
        }
    }

    pub fn as_data_mule(&self) -> Option<DataMuleConfig> {
        match self {
            Self::DataMule {
                inbox_dir,
                outbox_dir,
                poll_interval_ms,
                max_file_bytes,
            } => Some(DataMuleConfig {
                inbox_dir: inbox_dir.clone(),
                outbox_dir: outbox_dir.clone(),
                poll_interval_ms: *poll_interval_ms,
                max_file_bytes: *max_file_bytes,
            }),
            _ => None,
        }
    }

    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Tcp => Ok(()),
            Self::OfflineMesh {
                node_id,
                peer_id,
                spool_dir,
                poll_interval_ms,
                ..
            } => {
                if node_id.trim().is_empty() || peer_id.trim().is_empty() {
                    return Err(ShphError::Config(
                        "offline-mesh node_id/peer_id required".into(),
                    ));
                }
                if node_id == peer_id {
                    return Err(ShphError::Config(
                        "offline-mesh node_id and peer_id must differ".into(),
                    ));
                }
                if spool_dir.trim().is_empty() {
                    return Err(ShphError::Config("offline-mesh spool_dir required".into()));
                }
                if *poll_interval_ms == 0 {
                    return Err(ShphError::Config(
                        "poll interval must be greater than zero".into(),
                    ));
                }
                Ok(())
            }
            Self::DataMule {
                inbox_dir,
                outbox_dir,
                poll_interval_ms,
                max_file_bytes,
                ..
            } => {
                if inbox_dir.trim().is_empty() || outbox_dir.trim().is_empty() {
                    return Err(ShphError::Config(
                        "data-mule inbox and outbox required".into(),
                    ));
                }
                if inbox_dir == outbox_dir {
                    return Err(ShphError::Config(
                        "data-mule inbox and outbox must differ".into(),
                    ));
                }
                if *poll_interval_ms == 0 {
                    return Err(ShphError::Config(
                        "poll interval must be greater than zero".into(),
                    ));
                }
                if *max_file_bytes == 0 {
                    return Err(ShphError::Config(
                        "data-mule max_file_bytes must be greater than zero".into(),
                    ));
                }
                Ok(())
            }
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum IdentityProviderConfig {
    #[default]
    Software,
    HsmPkcs11 {
        #[serde(default)]
        module_path: String,
        #[serde(default)]
        token_label: String,
        #[serde(default)]
        slot: u64,
        #[serde(default)]
        key_label: String,
    },
    YubikeyPiv {
        #[serde(default)]
        slot: String,
        #[serde(default)]
        pin: Option<String>,
    },
    TpmBinding {
        #[serde(default)]
        aik_key_handle: String,
        #[serde(default)]
        pcr_profile: Option<String>,
    },
}

impl IdentityProviderConfig {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Software => Ok(()),
            Self::HsmPkcs11 {
                module_path,
                token_label,
                key_label,
                ..
            } => {
                if module_path.trim().is_empty()
                    || token_label.trim().is_empty()
                    || key_label.trim().is_empty()
                {
                    Err(ShphError::Config(
                        "HSM PKCS#11 config requires module_path, token_label, and key_label"
                            .into(),
                    ))
                } else {
                    Ok(())
                }
            }
            Self::YubikeyPiv { slot, .. } => {
                if slot.trim().is_empty() {
                    Err(ShphError::Config("YubikeyPiv slot required".into()))
                } else {
                    Ok(())
                }
            }
            Self::TpmBinding { aik_key_handle, .. } => {
                if aik_key_handle.trim().is_empty() {
                    Err(ShphError::Config("TPM aik_key_handle required".into()))
                } else {
                    Ok(())
                }
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PqcConfig {
    pub enabled: bool,
    #[serde(default = "default_transition_label")]
    pub transition_label: String,
    #[serde(default = "default_hybrid_context")]
    pub hybrid_context: String,
    #[serde(default = "default_kem_tag")]
    pub kem_tag: String,
}

fn default_transition_label() -> String {
    "shph-hybrid-v1".to_string()
}

fn default_hybrid_context() -> String {
    "shph-pqc-kem".to_string()
}

fn default_kem_tag() -> String {
    "mlkem768".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShamirConfig {
    pub enabled: bool,
    #[serde(default)]
    pub threshold: usize,
    #[serde(default)]
    pub shares: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RatchetAuditConfig {
    #[serde(default)]
    pub journal_path: String,
    #[serde(default)]
    pub max_entries: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RoadmapConfig {
    #[serde(default)]
    pub transport: TransportAdapterConfig,
    #[serde(default)]
    pub identity: IdentityProviderConfig,
    #[serde(default)]
    pub pqc: PqcConfig,
    #[serde(default)]
    pub shamir: ShamirConfig,
    #[serde(default)]
    pub ratchet_audit: RatchetAuditConfig,
}

impl Default for PqcConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            transition_label: default_transition_label(),
            hybrid_context: default_hybrid_context(),
            kem_tag: default_kem_tag(),
        }
    }
}

impl Default for ShamirConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            threshold: 2,
            shares: 3,
        }
    }
}

impl Default for RatchetAuditConfig {
    fn default() -> Self {
        Self {
            journal_path: "~/.shph/ratchet_audit.jsonl".into(),
            max_entries: 2048,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfflineMeshEnvelope {
    pub session_id: String,
    pub from: String,
    pub to: String,
    pub created_at_unix_ms: u64,
    pub sequence: u64,
    pub ciphertext_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataMuleEnvelope {
    pub envelope_id: String,
    pub created_at_unix_ms: u64,
    pub from_node: String,
    pub to_node: String,
    pub ciphertext_b64: String,
    pub nonce_b64: String,
}

#[derive(Debug)]
pub enum ShamirError {
    InvalidPolicy,
    TooFewShares,
    BadShareCount,
    DecodeFailed,
}

impl std::fmt::Display for ShamirError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPolicy => write!(f, "invalid Shamir policy"),
            Self::TooFewShares => write!(f, "insufficient Shamir shares"),
            Self::BadShareCount => write!(f, "shamir share payload mismatch"),
            Self::DecodeFailed => write!(f, "shamir decode failed"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShamirShare {
    pub index: u8,
    pub payload_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RatchetAuditRecord {
    pub ts_ms: u64,
    pub local_fingerprint: String,
    pub peer_fingerprint: String,
    pub transcript_hash: String,
    pub role: String,
    pub transport: String,
}

pub fn validate_transport_adapter(config: &TransportAdapterConfig) -> Result<()> {
    config.validate()
}

pub fn validate_identity_provider(config: &IdentityProviderConfig) -> Result<()> {
    config.validate()
}

pub fn validate_roadmap(config: &RoadmapConfig) -> Result<()> {
    config.transport.validate()?;
    config.identity.validate()?;
    validate_shamir_config(&config.shamir)?;
    Ok(())
}

pub fn validate_shamir_config(cfg: &ShamirConfig) -> Result<()> {
    if cfg.enabled && (cfg.threshold == 0 || cfg.shares == 0 || cfg.threshold > cfg.shares) {
        return Err(ShphError::Config("invalid Shamir policy".into()));
    }
    Ok(())
}

pub fn offline_mesh_envelope_path(base_dir: &str, session_id: &str) -> PathBuf {
    Path::new(base_dir).join(format!("shph-session-{session_id}.json"))
}

pub fn offline_spool_path(base_dir: &str, session_id: &str) -> PathBuf {
    offline_mesh_envelope_path(base_dir, session_id)
}

pub fn data_mule_inbox_path(inbox_dir: &str, peer: &str, envelope_id: &str) -> PathBuf {
    Path::new(inbox_dir)
        .join(peer)
        .join(format!("{}.shph", sanitize_filename(envelope_id)))
}

pub fn offline_session_id(node_a: &str, node_b: &str) -> String {
    let mut nodes = [node_a, node_b];
    nodes.sort_unstable();
    format!("{}:{}", nodes[0], nodes[1])
}

pub fn map_pqc_context(cfg: &PqcConfig) -> Vec<(String, String)> {
    vec![
        ("enabled".into(), cfg.enabled.to_string()),
        ("transition_label".into(), cfg.transition_label.to_string()),
        ("hybrid_context".into(), cfg.hybrid_context.to_string()),
        ("kem_tag".into(), cfg.kem_tag.to_string()),
    ]
}

pub fn append_ratchet_audit_event(
    policy: &RatchetAuditConfig,
    local_fingerprint: String,
    peer_fingerprint: String,
    transcript_hash: String,
    role: &str,
    transport: &str,
) -> Result<()> {
    let max_entries = policy.max_entries.max(1);
    let path = expand_path(&policy.journal_path);
    let ts_ms = now_unix_ms()?;
    let record = RatchetAuditRecord {
        ts_ms,
        local_fingerprint,
        peer_fingerprint,
        transcript_hash,
        role: role.to_string(),
        transport: transport.to_string(),
    };
    write_jsonl_line(&path, &record)?;
    prune_jsonl(&path, max_entries)?;
    Ok(())
}

pub fn read_ratchet_audit_events(policy: &RatchetAuditConfig) -> Result<Vec<RatchetAuditRecord>> {
    let path = expand_path(&policy.journal_path);
    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(ShphError::Io(err)),
    };
    let mut entries = Vec::new();
    for line in BufReader::new(file).lines() {
        let line = line.map_err(ShphError::Io)?;
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(record) = serde_json::from_str::<RatchetAuditRecord>(&line) {
            entries.push(record);
        }
    }
    Ok(entries)
}

pub fn split_secret(secret: &[u8], cfg: &ShamirConfig) -> Result<Vec<ShamirShare>> {
    if !cfg.enabled {
        return Ok(Vec::new());
    }
    if cfg.threshold == 0 || cfg.shares == 0 || cfg.threshold > cfg.shares || cfg.shares > 255 {
        return Err(ShphError::from(ShamirError::InvalidPolicy));
    }

    let mut rng = rand::thread_rng();
    let prime = 257u64;
    let mut rows: Vec<Vec<u16>> = vec![Vec::with_capacity(secret.len()); cfg.shares];
    for &byte in secret {
        let mut coeffs = vec![byte as u64];
        for _ in 1..cfg.threshold {
            coeffs.push((rng.next_u64() % (prime - 2)) + 1);
        }
        for x in 1..=(cfg.shares as u64) {
            let value = gf_eval(&coeffs, x, prime) as u16;
            rows[(x - 1) as usize].push(value);
        }
    }

    let shares = rows
        .into_iter()
        .enumerate()
        .map(|(idx, row)| ShamirShare {
            index: (idx + 1) as u8,
            payload_b64: encode_u16_array(&row),
        })
        .collect();
    Ok(shares)
}

pub fn recover_secret_from_shares(shares: &[ShamirShare], cfg: &ShamirConfig) -> Result<Vec<u8>> {
    if !cfg.enabled {
        return Ok(Vec::new());
    }
    if shares.len() < cfg.threshold {
        return Err(ShphError::from(ShamirError::TooFewShares));
    }
    if cfg.threshold == 0 {
        return Err(ShphError::from(ShamirError::InvalidPolicy));
    }

    let mut decoded: Vec<(u64, Vec<u16>)> = Vec::with_capacity(cfg.threshold);
    let mut lens = BTreeSet::new();

    for share in shares.iter().take(cfg.threshold) {
        let values = decode_u16_array(&share.payload_b64)
            .map_err(|_| ShphError::from(ShamirError::DecodeFailed))?;
        if share.index == 0 {
            return Err(ShphError::from(ShamirError::BadShareCount));
        }
        lens.insert(values.len());
        decoded.push((share.index as u64, values));
    }
    if lens.len() != 1 {
        return Err(ShphError::from(ShamirError::BadShareCount));
    }

    let secret_len = decoded
        .first()
        .map(|(_, values)| values.len())
        .ok_or_else(|| ShphError::from(ShamirError::DecodeFailed))?;

    let mut out = Vec::with_capacity(secret_len);
    for byte_index in 0..secret_len {
        let mut points = Vec::with_capacity(cfg.threshold);
        for (x, values) in decoded.iter().take(cfg.threshold) {
            points.push((*x, values[byte_index] as u64));
        }
        let secret_byte = gf_lagrange_origin(&points, 257) as u8;
        out.push(secret_byte);
    }
    Ok(out)
}

pub fn serialize_shamir_share(values: &[u16]) -> String {
    encode_u16_array(values)
}

fn now_unix_ms() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ShphError::Internal("system time before unix epoch".into()))?
        .as_millis() as u64)
}

fn expand_path(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return Path::new(&home).join(rest);
        }
        if let Ok(profile) = std::env::var("USERPROFILE") {
            return Path::new(&profile).join(rest);
        }
    }
    Path::new(path).to_path_buf()
}

fn write_jsonl_line(path: &Path, record: &RatchetAuditRecord) -> Result<()> {
    let line = serde_json::to_string(record).map_err(ShphError::Serialization)?;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(ShphError::Io)?;
        }
    }
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(ShphError::Io)?;
    writeln!(f, "{line}").map_err(ShphError::Io)?;
    Ok(())
}

fn prune_jsonl(path: &Path, max_entries: usize) -> Result<()> {
    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(ShphError::Io(err)),
    };
    let mut records = Vec::new();
    for line in BufReader::new(file).lines() {
        let line = line.map_err(ShphError::Io)?;
        if line.trim().is_empty() {
            continue;
        }
        let record = serde_json::from_str::<RatchetAuditRecord>(&line)
            .map_err(|e| ShphError::Protocol(format!("invalid audit entry: {e}")))?;
        records.push(record);
    }
    if records.len() <= max_entries {
        return Ok(());
    }
    let drop_n = records.len() - max_entries;
    let records = records.split_off(drop_n);
    let mut f = OpenOptions::new()
        .write(true)
        .truncate(true)
        .create(true)
        .open(path)
        .map_err(ShphError::Io)?;
    for record in records {
        let line = serde_json::to_string(&record).map_err(ShphError::Serialization)?;
        writeln!(f, "{line}").map_err(ShphError::Io)?;
    }
    Ok(())
}

fn sanitize_filename(input: &str) -> String {
    input
        .chars()
        .map(|ch| match ch {
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            _ => ch,
        })
        .collect()
}

fn encode_u16_array(values: &[u16]) -> String {
    let mut raw = Vec::with_capacity(values.len() * 2);
    for value in values {
        raw.extend_from_slice(&value.to_le_bytes());
    }
    base64::engine::general_purpose::STANDARD.encode(raw)
}

fn decode_u16_array(raw_b64: &str) -> Result<Vec<u16>> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(raw_b64)
        .map_err(|_| ShphError::Protocol("invalid share payload".into()))?;
    if raw.len() % 2 != 0 {
        return Err(ShphError::Protocol("invalid share payload length".into()));
    }
    let mut values = Vec::with_capacity(raw.len() / 2);
    for bytes in raw.chunks_exact(2) {
        values.push(u16::from_le_bytes([bytes[0], bytes[1]]));
    }
    Ok(values)
}

fn gf_eval(coeffs: &[u64], x: u64, p: u64) -> u64 {
    let mut result = 0u64;
    for &coef in coeffs.iter().rev() {
        result = (result * x + coef) % p;
    }
    result
}

fn gf_inv(x: u64, p: u64) -> u64 {
    let mut t = 0i64;
    let mut new_t = 1i64;
    let mut r = p as i64;
    let mut new_r = x as i64;
    while new_r != 0 {
        let quotient = r / new_r;
        let temp_t = t - quotient * new_t;
        t = new_t;
        new_t = temp_t;
        let temp_r = r - quotient * new_r;
        r = new_r;
        new_r = temp_r;
    }
    if r != 1 {
        return 0;
    }
    if t < 0 {
        (t + p as i64) as u64
    } else {
        t as u64
    }
}

fn gf_lagrange_origin(points: &[(u64, u64)], prime: u64) -> u64 {
    let mut out = 0u64;
    for (i, (xi, yi)) in points.iter().enumerate() {
        let mut num = 1u64;
        let mut den = 1u64;
        for (j, (xj, _)) in points.iter().enumerate() {
            if i == j {
                continue;
            }
            num = (num * (prime + prime.wrapping_sub(*xj % prime)) % prime) % prime;
            den = (den * ((prime + xi - xj) % prime)) % prime;
        }
        let lag = (num * gf_inv(den, prime)) % prime;
        out = (out + yi * lag) % prime;
    }
    out % prime
}

pub type ShamirPolicy = ShamirConfig;
pub type RatchetAuditPolicy = RatchetAuditConfig;
pub type ShamirThresholdError = ShamirError;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShamirWarning {
    pub code: u8,
    pub message: String,
}

impl From<ShamirError> for ShphError {
    fn from(err: ShamirError) -> Self {
        match err {
            ShamirError::InvalidPolicy => ShphError::Config("invalid Shamir policy".into()),
            ShamirError::TooFewShares => ShphError::Config("insufficient Shamir shares".into()),
            ShamirError::BadShareCount => ShphError::Protocol("invalid Shamir share count".into()),
            ShamirError::DecodeFailed => {
                ShphError::Protocol("failed to decode Shamir share".into())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_roadmap_defaults_and_transport_variants() {
        let cfg = RoadmapConfig::default();
        assert!(cfg.transport.validate().is_ok());
        assert!(validate_roadmap(&cfg).is_ok());

        let offline = TransportAdapterConfig::OfflineMesh {
            node_id: "node-a".to_string(),
            peer_id: "node-b".to_string(),
            spool_dir: "/tmp/shph-offline".to_string(),
            poll_interval_ms: 250,
            max_idle_entries: 42,
        };
        assert!(offline.validate().is_ok());
        let data_mule = TransportAdapterConfig::DataMule {
            inbox_dir: "/tmp/in".to_string(),
            outbox_dir: "/tmp/out".to_string(),
            poll_interval_ms: 250,
            max_file_bytes: 4096,
        };
        assert!(data_mule.validate().is_ok());
    }

    #[test]
    fn validate_shamir_roundtrip_when_enabled() {
        let cfg = ShamirConfig {
            enabled: true,
            threshold: 2,
            shares: 3,
        };
        let secret = b"vpn-routing-key";
        let shares = split_secret(secret, &cfg).expect("split");
        assert_eq!(shares.len(), 3);
        let recovered = recover_secret_from_shares(&shares[..2], &cfg).expect("recover");
        assert_eq!(recovered, secret);
    }

    #[test]
    fn offline_spool_path_is_stable() {
        let got = offline_spool_path("/tmp/spool", "alice:bob");
        assert!(got.ends_with("shph-session-alice:bob.json"));
    }
}
