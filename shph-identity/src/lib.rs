//! Experimental SHPH identity records and provider-independent discovery.
//!
//! This crate is intentionally outside `shph-core` and `shph-transport`.
//! Providers are untrusted distribution mechanisms only: a record is useful
//! only after this crate verifies SHPH's own signature and freshness rules.
//! The direct handshake path has no dependency on this crate or on a provider.
//! The current provider trait is in-process and therefore limited to trusted
//! local implementations; third-party plugins require a process/RPC boundary.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use shph_core::{IdentityKeyPair, PeerPin};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

pub const IDENTITY_RECORD_VERSION: u16 = 1;
pub const DISCOVERY_PLUGIN_API_VERSION: u16 = 1;
pub const MAX_RECORD_BYTES: usize = 64 * 1024;
pub const MAX_KEYS: usize = 32;
pub const MAX_ENDPOINTS: usize = 32;
pub const MAX_CAPABILITIES: usize = 64;
pub const MAX_PROVIDER_RECORDS: usize = 1_024;
pub const MAX_PROVIDER_ENTRIES: usize = MAX_PROVIDER_RECORDS * 4;
pub const MAX_DISCOVERY_PROVIDERS: usize = 64;
pub const MAX_TOTAL_CANDIDATES: usize = 4_096;
pub const MAX_PLUGIN_CAPABILITIES: usize = 16;
pub const MAX_STRING_BYTES: usize = 256;
pub const MAX_ALGORITHM_BYTES: usize = 96;
pub const MAX_PUBLIC_KEY_BYTES: usize = 8 * 1024;
pub const DEFAULT_CLOCK_SKEW_SECS: u64 = 300;
pub const MAX_CLOCK_SKEW_SECS: u64 = 24 * 60 * 60;
pub const MAX_RECORD_LIFETIME_SECS: u64 = 90 * 24 * 60 * 60;
pub const IDENTITY_ID_DOMAIN: &[u8] = b"shph/identity-id/v1";
pub const RECORD_DOMAIN: &[u8] = b"shph/identity-record/v1";

pub const PROFILE_ED25519: &str = "ed25519";
pub const PROFILE_HYBRID_ED25519_ML_DSA_65: &str = "hybrid-ed25519+ml-dsa-65";
pub const PROFILE_ML_DSA_44: &str = "ml-dsa-44";
pub const PROFILE_ML_DSA_65: &str = "ml-dsa-65";
pub const PROFILE_ML_DSA_87: &str = "ml-dsa-87";
pub const PROFILE_SLH_DSA_SHAKE_128S: &str = "slh-dsa-shake-128s";
pub const PROFILE_SLH_DSA_SHAKE_128F: &str = "slh-dsa-shake-128f";

pub const ALGORITHM_ED25519: &str = "ed25519";
pub const ALGORITHM_X25519: &str = "x25519";
pub const ALGORITHM_ML_KEM_768: &str = "ml-kem-768";
pub const ALGORITHM_ML_DSA_44: &str = "ml-dsa-44";
pub const ALGORITHM_ML_DSA_65: &str = "ml-dsa-65";
pub const ALGORITHM_ML_DSA_87: &str = "ml-dsa-87";
pub const ALGORITHM_SLH_DSA_SHAKE_128S: &str = "slh-dsa-shake-128s";
pub const ALGORITHM_SLH_DSA_SHAKE_128F: &str = "slh-dsa-shake-128f";

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("invalid identity record: {0}")]
    InvalidRecord(String),

    #[error("record signature is invalid")]
    InvalidSignature,

    #[error("unsupported identity signature profile or algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("record is not yet valid")]
    NotYetValid,

    #[error("record is expired")]
    Expired,

    #[error("record was rolled back or replayed")]
    Replay,

    #[error("conflicting valid records at sequence {sequence}")]
    Conflict { sequence: u64 },

    #[error("no valid record was found")]
    NotFound,

    #[error("discovery provider unavailable: {0}")]
    ProviderUnavailable(String),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

pub type Result<T> = std::result::Result<T, IdentityError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Hash32(pub [u8; 32]);

pub type IdentityId = Hash32;
pub type KeyId = Hash32;
pub type RecordHash = Hash32;

impl Hash32 {
    pub const ZERO: Self = Self([0u8; 32]);

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn parse_hex(value: &str) -> Result<Self> {
        if value.len() != 64 || value.bytes().any(|byte| byte.is_ascii_uppercase()) {
            return Err(IdentityError::InvalidRecord(
                "hash must be exactly 64 lowercase hexadecimal characters".into(),
            ));
        }
        let bytes = hex::decode(value)
            .map_err(|_| IdentityError::InvalidRecord("hash must be lowercase hex".into()))?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| IdentityError::InvalidRecord("hash must be exactly 32 bytes".into()))?;
        Ok(Self(bytes))
    }
}

impl std::fmt::Display for Hash32 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.hex())
    }
}

impl Serialize for Hash32 {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.hex())
    }
}

impl<'de> Deserialize<'de> for Hash32 {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if value.len() != 64 || value.bytes().any(|byte| byte.is_ascii_uppercase()) {
            return Err(serde::de::Error::custom(
                "hash must be exactly 64 lowercase hexadecimal characters",
            ));
        }
        let bytes = hex::decode(&value).map_err(serde::de::Error::custom)?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("hash must be exactly 32 bytes"))?;
        Ok(Self(bytes))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AlgorithmId(String);

impl AlgorithmId {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_token("algorithm", &value, MAX_ALGORITHM_BYTES)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn ed25519() -> Self {
        Self(ALGORITHM_ED25519.into())
    }

    pub fn x25519() -> Self {
        Self(ALGORITHM_X25519.into())
    }

    pub fn ml_kem_768() -> Self {
        Self(ALGORITHM_ML_KEM_768.into())
    }

    pub fn ml_dsa_65() -> Self {
        Self(ALGORITHM_ML_DSA_65.into())
    }
}

impl std::fmt::Display for AlgorithmId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SignatureProfile(String);

impl SignatureProfile {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_token("signature profile", &value, MAX_ALGORITHM_BYTES)?;
        Ok(Self(value))
    }

    pub fn ed25519() -> Self {
        Self(PROFILE_ED25519.into())
    }

    pub fn hybrid_ed25519_ml_dsa_65() -> Self {
        Self(PROFILE_HYBRID_ED25519_ML_DSA_65.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_pqc(&self) -> bool {
        self.as_str() != PROFILE_ED25519
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyRole {
    RootSigning,
    OperationalSigning,
    IdentityBinding,
    KeyEstablishment,
    RecoverySigning,
}

impl KeyRole {
    fn code(self) -> u8 {
        match self {
            Self::RootSigning => 1,
            Self::OperationalSigning => 2,
            Self::IdentityBinding => 3,
            Self::KeyEstablishment => 4,
            Self::RecoverySigning => 5,
        }
    }

    fn accepts_record_signature(self) -> bool {
        matches!(self, Self::RootSigning | Self::RecoverySigning)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityKey {
    pub key_id: KeyId,
    pub role: KeyRole,
    pub algorithm: AlgorithmId,
    #[serde(with = "base64_bytes")]
    pub public_key: Vec<u8>,
    pub not_before: u64,
    pub not_after: u64,
    #[serde(default)]
    pub previous_key_id: Option<KeyId>,
}

impl IdentityKey {
    pub fn new(
        role: KeyRole,
        algorithm: AlgorithmId,
        public_key: Vec<u8>,
        not_before: u64,
        not_after: u64,
        previous_key_id: Option<KeyId>,
    ) -> Result<Self> {
        validate_key_material(&algorithm, &public_key)?;
        if not_after < not_before {
            return Err(IdentityError::InvalidRecord(
                "identity key expires before it becomes valid".into(),
            ));
        }
        let key_id = derive_key_id(role, &algorithm, &public_key);
        if previous_key_id == Some(key_id) {
            return Err(IdentityError::InvalidRecord(
                "identity key cannot supersede itself".into(),
            ));
        }
        Ok(Self {
            key_id,
            role,
            algorithm,
            public_key,
            not_before,
            not_after,
            previous_key_id,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityEndpoint {
    pub transport: String,
    pub address: String,
    #[serde(default)]
    pub priority: u16,
}

impl IdentityEndpoint {
    pub fn new(
        transport: impl Into<String>,
        address: impl Into<String>,
        priority: u16,
    ) -> Result<Self> {
        let endpoint = Self {
            transport: transport.into(),
            address: address.into(),
            priority,
        };
        validate_endpoint(&endpoint)?;
        Ok(endpoint)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordSignature {
    pub key_id: KeyId,
    pub algorithm: AlgorithmId,
    #[serde(with = "base64_bytes")]
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum RecordStatus {
    #[default]
    Active,
    Revoked {
        revoked_at: u64,
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityRecord {
    pub version: u16,
    pub subject: IdentityId,
    pub signature_profile: SignatureProfile,
    pub sequence: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    #[serde(default)]
    pub previous_record: Option<RecordHash>,
    #[serde(default)]
    pub status: RecordStatus,
    pub keys: Vec<IdentityKey>,
    #[serde(default)]
    pub endpoints: Vec<IdentityEndpoint>,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub signatures: Vec<RecordSignature>,
}

#[derive(Debug, Clone, Copy)]
pub struct VerificationPolicy {
    pub now_secs: u64,
    pub clock_skew_secs: u64,
    pub expected_subject: Option<IdentityId>,
    pub require_pqc_signature: bool,
}

impl VerificationPolicy {
    pub fn at(now_secs: u64) -> Self {
        Self {
            now_secs,
            clock_skew_secs: DEFAULT_CLOCK_SKEW_SECS,
            expected_subject: None,
            require_pqc_signature: false,
        }
    }
}

impl Default for VerificationPolicy {
    fn default() -> Self {
        Self::at(now_unix_secs())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerificationResult {
    pub subject: IdentityId,
    pub pqc_authenticated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublishReceipt {
    pub record_hash: RecordHash,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolution {
    pub record: IdentityRecord,
    pub record_hash: RecordHash,
    pub providers_consulted: usize,
    pub invalid_candidates: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryPluginDescriptor {
    pub api_version: u16,
    pub plugin_id: String,
    pub provider_kind: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
}

impl DiscoveryPluginDescriptor {
    pub fn new(
        plugin_id: impl Into<String>,
        provider_kind: impl Into<String>,
        capabilities: Vec<String>,
    ) -> Result<Self> {
        let descriptor = Self {
            api_version: DISCOVERY_PLUGIN_API_VERSION,
            plugin_id: plugin_id.into(),
            provider_kind: provider_kind.into(),
            capabilities,
        };
        descriptor.validate()?;
        Ok(descriptor)
    }

    pub fn minimal(plugin_id: impl Into<String>) -> Self {
        Self {
            api_version: DISCOVERY_PLUGIN_API_VERSION,
            plugin_id: plugin_id.into(),
            provider_kind: "unknown".into(),
            capabilities: Vec::new(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.api_version != DISCOVERY_PLUGIN_API_VERSION {
            return Err(IdentityError::InvalidRecord(format!(
                "unsupported discovery plugin API version {}",
                self.api_version
            )));
        }
        validate_token("plugin id", &self.plugin_id, MAX_STRING_BYTES)?;
        validate_token("provider kind", &self.provider_kind, MAX_STRING_BYTES)?;
        if self.capabilities.len() > MAX_PLUGIN_CAPABILITIES {
            return Err(IdentityError::InvalidRecord(format!(
                "plugin exposes more than {MAX_PLUGIN_CAPABILITIES} capabilities"
            )));
        }
        let mut capabilities = BTreeSet::new();
        for capability in &self.capabilities {
            validate_token("plugin capability", capability, MAX_STRING_BYTES)?;
            if !capabilities.insert(capability) {
                return Err(IdentityError::InvalidRecord(
                    "plugin descriptor contains duplicate capabilities".into(),
                ));
            }
        }
        Ok(())
    }
}

/// An in-process discovery provider.
///
/// Implementations are trusted code in the current prototype. The resolver
/// catches panics and bounds returned data, but it cannot sandbox a provider,
/// interrupt a hung call, or prevent arbitrary process I/O. Third-party or
/// remote plugins must use a process/RPC boundary before being registered here.
pub trait DiscoveryProvider: Send + Sync {
    fn provider_id(&self) -> &str;
    /// Plugin metadata is descriptive only and never grants trust.
    fn descriptor(&self) -> DiscoveryPluginDescriptor {
        DiscoveryPluginDescriptor::minimal(self.provider_id())
    }
    fn publish(&self, record: &IdentityRecord) -> Result<PublishReceipt>;
    fn fetch(&self, subject: &IdentityId) -> Result<Vec<IdentityRecord>>;
}

static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone)]
pub struct LocalDirectoryProvider {
    root: PathBuf,
    provider_id: String,
}

impl LocalDirectoryProvider {
    pub fn new(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        if root.as_os_str().is_empty() {
            return Err(IdentityError::InvalidRecord(
                "local provider root cannot be empty".into(),
            ));
        }
        ensure_no_symlink_components(&root)?;
        if let Ok(metadata) = fs::symlink_metadata(&root) {
            if !metadata.is_dir() {
                return Err(IdentityError::InvalidRecord(
                    "local provider root must be a directory".into(),
                ));
            }
        }
        Ok(Self {
            root,
            provider_id: "local-directory".into(),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn subject_dir(&self, subject: &IdentityId) -> PathBuf {
        self.root.join(subject.hex())
    }

    fn record_path(&self, record: &IdentityRecord, hash: &RecordHash) -> PathBuf {
        self.subject_dir(&record.subject).join(format!(
            "{:020}-{}.json",
            record.sequence,
            hash.hex()
        ))
    }
}

impl DiscoveryProvider for LocalDirectoryProvider {
    fn provider_id(&self) -> &str {
        &self.provider_id
    }

    fn descriptor(&self) -> DiscoveryPluginDescriptor {
        DiscoveryPluginDescriptor::new(
            self.provider_id.clone(),
            "local-filesystem",
            vec![
                "publication".into(),
                "retrieval".into(),
                "self-hosted".into(),
            ],
        )
        .expect("static local-directory plugin descriptor")
    }

    fn publish(&self, record: &IdentityRecord) -> Result<PublishReceipt> {
        record.validate_structure()?;
        let bytes = record.to_json_bytes()?;
        let hash = record.record_hash()?;
        let directory = self.subject_dir(&record.subject);
        ensure_no_symlink_components(&self.root)?;
        if !self.root.exists() {
            fs::create_dir_all(&self.root)?;
        }
        ensure_no_symlink_components(&self.root)?;
        ensure_directory(&directory)?;
        let path = self.record_path(record, &hash);
        ensure_no_symlink_components(&path)?;

        let parent = path
            .parent()
            .ok_or_else(|| IdentityError::InvalidRecord("provider path has no parent".into()))?;
        let filename = path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| IdentityError::InvalidRecord("provider filename is not UTF-8".into()))?;
        let temp = parent.join(format!(
            ".{filename}.tmp.{}-{}",
            std::process::id(),
            TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temp)?;
        if let Err(error) = file.write_all(&bytes).and_then(|_| file.sync_all()) {
            drop(file);
            let _ = fs::remove_file(&temp);
            return Err(IdentityError::Io(error));
        }
        drop(file);
        match fs::hard_link(&temp, &path) {
            Ok(()) => {
                let _ = fs::remove_file(&temp);
                Ok(PublishReceipt { record_hash: hash })
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let _ = fs::remove_file(&temp);
                ensure_no_symlink_components(&path)?;
                let existing = read_bounded_file(&path, MAX_RECORD_BYTES)?;
                if existing != bytes {
                    return Err(IdentityError::Conflict {
                        sequence: record.sequence,
                    });
                }
                Ok(PublishReceipt { record_hash: hash })
            }
            Err(error) => {
                let _ = fs::remove_file(&temp);
                Err(IdentityError::Io(error))
            }
        }
    }

    fn fetch(&self, subject: &IdentityId) -> Result<Vec<IdentityRecord>> {
        ensure_no_symlink_components(&self.root)?;
        let directory = self.subject_dir(subject);
        ensure_no_symlink_components(&directory)?;
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => {
                return Err(IdentityError::ProviderUnavailable(format!(
                    "{}: {error}",
                    self.provider_id
                )))
            }
        };

        let mut records = Vec::new();
        for (index, entry) in entries.enumerate() {
            if index >= MAX_PROVIDER_ENTRIES {
                return Err(IdentityError::ProviderUnavailable(format!(
                    "{} returned too many directory entries",
                    self.provider_id
                )));
            }
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            if entry.file_type()?.is_symlink() {
                continue;
            }
            if ensure_no_symlink_components(&path).is_err() {
                continue;
            }
            let metadata = entry.metadata()?;
            if metadata.len() > MAX_RECORD_BYTES as u64 {
                continue;
            }
            if records.len() >= MAX_PROVIDER_RECORDS {
                return Err(IdentityError::ProviderUnavailable(format!(
                    "{} returned too many records",
                    self.provider_id
                )));
            }
            let bytes = match read_bounded_file(&path, MAX_RECORD_BYTES) {
                Ok(bytes) => bytes,
                Err(error) if error.kind() == io::ErrorKind::InvalidData => continue,
                Err(error) => return Err(IdentityError::Io(error)),
            };
            if let Ok(record) = IdentityRecord::from_json_bytes(&bytes) {
                if record.subject == *subject {
                    records.push(record);
                }
            }
        }
        Ok(records)
    }
}

#[derive(Debug, Default)]
pub struct DiscoveryResolver {
    accepted: HashMap<IdentityId, AcceptedRecord>,
}

#[derive(Debug, Clone, Copy)]
struct AcceptedRecord {
    sequence: u64,
    hash: RecordHash,
}

impl DiscoveryResolver {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn resolve(
        &mut self,
        subject: &IdentityId,
        providers: &[&dyn DiscoveryProvider],
        policy: VerificationPolicy,
    ) -> Result<Resolution> {
        if providers.len() > MAX_DISCOVERY_PROVIDERS {
            return Err(IdentityError::InvalidRecord(format!(
                "resolution requested with more than {MAX_DISCOVERY_PROVIDERS} providers"
            )));
        }
        if policy.clock_skew_secs > MAX_CLOCK_SKEW_SECS {
            return Err(IdentityError::InvalidRecord(
                "verification clock skew exceeds the safety limit".into(),
            ));
        }

        let mut candidates = Vec::new();
        let mut provider_failures = 0usize;
        for provider in providers {
            let (provider_id, descriptor) = match catch_unwind(AssertUnwindSafe(|| {
                (provider.provider_id().to_owned(), provider.descriptor())
            })) {
                Ok(value) => value,
                Err(_) => {
                    provider_failures += 1;
                    continue;
                }
            };
            if descriptor.validate().is_err() || descriptor.plugin_id != provider_id {
                provider_failures += 1;
                continue;
            }
            let fetched = match catch_unwind(AssertUnwindSafe(|| provider.fetch(subject))) {
                Ok(result) => result,
                Err(_) => {
                    provider_failures += 1;
                    continue;
                }
            };
            match fetched {
                Ok(records) if records.len() > MAX_PROVIDER_RECORDS => {
                    provider_failures += 1;
                }
                Ok(records)
                    if candidates.len().saturating_add(records.len()) > MAX_TOTAL_CANDIDATES =>
                {
                    provider_failures += 1;
                }
                Ok(records) => candidates.extend(records),
                Err(_) => provider_failures += 1,
            }
        }
        if candidates.is_empty() {
            if !providers.is_empty() && provider_failures == providers.len() {
                return Err(IdentityError::ProviderUnavailable(
                    "all configured discovery providers failed".into(),
                ));
            }
            return Err(IdentityError::NotFound);
        }

        let mut invalid_candidates = 0usize;
        let mut valid_by_sequence: BTreeMap<u64, BTreeMap<RecordHash, IdentityRecord>> =
            BTreeMap::new();
        for record in candidates {
            if record.subject != *subject {
                invalid_candidates += 1;
                continue;
            }
            if record.verify(policy).is_err() {
                invalid_candidates += 1;
                continue;
            }
            let hash = record.record_hash()?;
            valid_by_sequence
                .entry(record.sequence)
                .or_default()
                .entry(hash)
                .or_insert(record);
        }

        let Some((sequence, records)) = valid_by_sequence.iter().next_back() else {
            return Err(IdentityError::NotFound);
        };
        if records.len() > 1 {
            return Err(IdentityError::Conflict {
                sequence: *sequence,
            });
        }
        let (record_hash, record) = records
            .iter()
            .next()
            .expect("records was checked to contain one entry");

        if let Some(previous) = self.accepted.get(subject) {
            if *sequence < previous.sequence {
                return Err(IdentityError::Replay);
            }
            if *sequence == previous.sequence {
                if *record_hash == previous.hash {
                    return Ok(Resolution {
                        record: record.clone(),
                        record_hash: *record_hash,
                        providers_consulted: providers.len(),
                        invalid_candidates,
                    });
                }
                return Err(IdentityError::Conflict {
                    sequence: *sequence,
                });
            }
            if *sequence != previous.sequence.saturating_add(1)
                || record.previous_record != Some(previous.hash)
            {
                return Err(IdentityError::Replay);
            }
        } else if *sequence != 1 {
            return Err(IdentityError::Replay);
        }

        self.accepted.insert(
            *subject,
            AcceptedRecord {
                sequence: *sequence,
                hash: *record_hash,
            },
        );
        Ok(Resolution {
            record: record.clone(),
            record_hash: *record_hash,
            providers_consulted: providers.len(),
            invalid_candidates,
        })
    }
}

impl IdentityRecord {
    /// Build an initial record. Non-initial records must be created with
    /// [`Self::from_current_identity_with_previous`] so the continuity link
    /// cannot be omitted accidentally.
    pub fn from_current_identity(
        identity: &IdentityKeyPair,
        sequence: u64,
        issued_at: u64,
        expires_at: u64,
        endpoints: Vec<IdentityEndpoint>,
        capabilities: Vec<String>,
    ) -> Result<Self> {
        Self::from_current_identity_with_previous(
            identity,
            sequence,
            issued_at,
            expires_at,
            None,
            endpoints,
            capabilities,
        )
    }

    /// Build and sign a record that explicitly continues `previous_record`.
    pub fn from_current_identity_with_previous(
        identity: &IdentityKeyPair,
        sequence: u64,
        issued_at: u64,
        expires_at: u64,
        previous_record: Option<RecordHash>,
        endpoints: Vec<IdentityEndpoint>,
        capabilities: Vec<String>,
    ) -> Result<Self> {
        let root_public = identity.signing_public_bytes().to_vec();
        let identity_binding = identity.public_key_bytes().to_vec();
        let subject = derive_identity_id(&root_public);
        let root = IdentityKey::new(
            KeyRole::RootSigning,
            AlgorithmId::ed25519(),
            root_public,
            issued_at,
            expires_at,
            None,
        )?;
        let binding = IdentityKey::new(
            KeyRole::IdentityBinding,
            AlgorithmId::x25519(),
            identity_binding,
            issued_at,
            expires_at,
            None,
        )?;
        let mut record = Self {
            version: IDENTITY_RECORD_VERSION,
            subject,
            signature_profile: SignatureProfile::ed25519(),
            sequence,
            issued_at,
            expires_at,
            previous_record,
            status: RecordStatus::Active,
            keys: vec![root, binding],
            endpoints,
            capabilities,
            signatures: Vec::new(),
        };
        record.sign_with_identity(identity)?;
        Ok(record)
    }

    pub fn validate_structure(&self) -> Result<()> {
        if self.version != IDENTITY_RECORD_VERSION {
            return Err(IdentityError::InvalidRecord(format!(
                "unsupported record version {}",
                self.version
            )));
        }
        if self.sequence == 0 {
            return Err(IdentityError::InvalidRecord(
                "record sequence must start at one".into(),
            ));
        }
        if self.sequence == 1 && self.previous_record.is_some() {
            return Err(IdentityError::InvalidRecord(
                "initial record cannot reference a previous record".into(),
            ));
        }
        if self.sequence > 1 && self.previous_record.is_none() {
            return Err(IdentityError::InvalidRecord(
                "non-initial record must reference a previous record".into(),
            ));
        }
        if self.expires_at <= self.issued_at {
            return Err(IdentityError::InvalidRecord(
                "record expiration must be after issuance".into(),
            ));
        }
        if self.expires_at.saturating_sub(self.issued_at) > MAX_RECORD_LIFETIME_SECS {
            return Err(IdentityError::InvalidRecord(
                "record lifetime exceeds the safety limit".into(),
            ));
        }
        validate_token(
            "signature profile",
            self.signature_profile.as_str(),
            MAX_ALGORITHM_BYTES,
        )?;

        if self.keys.is_empty() || self.keys.len() > MAX_KEYS {
            return Err(IdentityError::InvalidRecord(format!(
                "record must contain between one and {MAX_KEYS} keys"
            )));
        }
        let mut key_ids = BTreeSet::new();
        let mut root_keys = 0usize;
        for key in &self.keys {
            validate_key_material(&key.algorithm, &key.public_key)?;
            if key.key_id != derive_key_id(key.role, &key.algorithm, &key.public_key) {
                return Err(IdentityError::InvalidRecord(format!(
                    "key id does not match {} key material",
                    key.role_string()
                )));
            }
            if key.not_after < key.not_before {
                return Err(IdentityError::InvalidRecord(
                    "key expiration precedes key activation".into(),
                ));
            }
            if key.previous_key_id == Some(key.key_id) {
                return Err(IdentityError::InvalidRecord(
                    "key cannot supersede itself".into(),
                ));
            }
            if !key_ids.insert(key.key_id) {
                return Err(IdentityError::InvalidRecord(
                    "record contains duplicate key ids".into(),
                ));
            }
            if key.role == KeyRole::RootSigning {
                root_keys += 1;
            }
        }
        if root_keys != 1 {
            return Err(IdentityError::InvalidRecord(
                "record must contain exactly one root signing key".into(),
            ));
        }
        self.validate_subject_binding()?;
        if self.endpoints.len() > MAX_ENDPOINTS {
            return Err(IdentityError::InvalidRecord(format!(
                "record contains more than {MAX_ENDPOINTS} endpoints"
            )));
        }
        let mut endpoint_ids = BTreeSet::new();
        for endpoint in &self.endpoints {
            validate_endpoint(endpoint)?;
            if !endpoint_ids.insert((
                endpoint.transport.clone(),
                endpoint.address.clone(),
                endpoint.priority,
            )) {
                return Err(IdentityError::InvalidRecord(
                    "record contains duplicate endpoints".into(),
                ));
            }
        }
        if self.capabilities.len() > MAX_CAPABILITIES {
            return Err(IdentityError::InvalidRecord(format!(
                "record contains more than {MAX_CAPABILITIES} capabilities"
            )));
        }
        let mut capabilities = BTreeSet::new();
        for capability in &self.capabilities {
            validate_token("capability", capability, MAX_STRING_BYTES)?;
            if !capabilities.insert(capability.clone()) {
                return Err(IdentityError::InvalidRecord(
                    "record contains duplicate capabilities".into(),
                ));
            }
        }
        match &self.status {
            RecordStatus::Active => {}
            RecordStatus::Revoked { revoked_at, reason } => {
                if *revoked_at < self.issued_at || *revoked_at > self.expires_at {
                    return Err(IdentityError::InvalidRecord(
                        "revocation timestamp is outside the record lifetime".into(),
                    ));
                }
                validate_text("revocation reason", reason, MAX_STRING_BYTES)?;
            }
        }
        if self.signatures.is_empty() {
            return Err(IdentityError::InvalidRecord(
                "record must contain at least one signature".into(),
            ));
        }
        let mut signature_ids = BTreeSet::new();
        let root_key_id = self
            .keys
            .iter()
            .find(|key| key.role == KeyRole::RootSigning)
            .map(|key| key.key_id)
            .ok_or_else(|| IdentityError::InvalidRecord("record has no root signing key".into()))?;
        let mut has_root_signature = false;
        for signature in &self.signatures {
            if signature.signature.is_empty() || signature.signature.len() > MAX_PUBLIC_KEY_BYTES {
                return Err(IdentityError::InvalidRecord(
                    "record signature has an invalid size".into(),
                ));
            }
            validate_token(
                "signature algorithm",
                signature.algorithm.as_str(),
                MAX_ALGORITHM_BYTES,
            )?;
            if !signature_ids.insert((signature.key_id, signature.algorithm.clone())) {
                return Err(IdentityError::InvalidRecord(
                    "record contains duplicate signatures".into(),
                ));
            }
            let key = self
                .keys
                .iter()
                .find(|key| key.key_id == signature.key_id)
                .ok_or_else(|| {
                    IdentityError::InvalidRecord(
                        "record signature references an unknown key".into(),
                    )
                })?;
            if key.algorithm != signature.algorithm || !key.role.accepts_record_signature() {
                return Err(IdentityError::InvalidRecord(
                    "record signature key is not authorized for record signing".into(),
                ));
            }
            if signature.key_id == root_key_id {
                has_root_signature = true;
            }
        }
        if !has_root_signature {
            return Err(IdentityError::InvalidRecord(
                "record must include a signature by the root signing key".into(),
            ));
        }
        Ok(())
    }

    pub fn sign_with_identity(&mut self, identity: &IdentityKeyPair) -> Result<()> {
        if self.signature_profile.as_str() != PROFILE_ED25519 {
            return Err(IdentityError::UnsupportedAlgorithm(
                self.signature_profile.as_str().into(),
            ));
        }
        if !self.signatures.is_empty() {
            return Err(IdentityError::InvalidRecord(
                "record is already signed".into(),
            ));
        }
        let signing_public = identity.signing_public_bytes();
        let root_key = self
            .keys
            .iter()
            .find(|key| {
                key.role == KeyRole::RootSigning
                    && key.algorithm.as_str() == ALGORITHM_ED25519
                    && key.public_key.as_slice() == signing_public
            })
            .ok_or_else(|| {
                IdentityError::InvalidRecord(
                    "identity signing key is not the record's root signing key".into(),
                )
            })?;
        let payload = self.canonical_payload()?;
        let keypair =
            ring::signature::Ed25519KeyPair::from_seed_unchecked(&identity.signing_seed())
                .map_err(|_| IdentityError::InvalidSignature)?;
        let signature = keypair.sign(&payload);
        self.signatures.push(RecordSignature {
            key_id: root_key.key_id,
            algorithm: AlgorithmId::ed25519(),
            signature: signature.as_ref().to_vec(),
        });
        Ok(())
    }

    pub fn verify(&self, policy: VerificationPolicy) -> Result<VerificationResult> {
        if policy.clock_skew_secs > MAX_CLOCK_SKEW_SECS {
            return Err(IdentityError::InvalidRecord(
                "verification clock skew exceeds the safety limit".into(),
            ));
        }
        self.validate_structure()?;
        let root_key = self
            .keys
            .iter()
            .find(|key| key.role == KeyRole::RootSigning)
            .ok_or_else(|| IdentityError::InvalidRecord("record has no root signing key".into()))?;
        if self.subject != derive_identity_id(&root_key.public_key) {
            return Err(IdentityError::InvalidRecord(
                "record subject is not bound to the root signing key".into(),
            ));
        }
        if let Some(expected) = policy.expected_subject {
            if expected != self.subject {
                return Err(IdentityError::InvalidRecord(
                    "record subject does not match the expected identity".into(),
                ));
            }
        }
        if self.issued_at > policy.now_secs.saturating_add(policy.clock_skew_secs) {
            return Err(IdentityError::NotYetValid);
        }
        if self.expires_at.saturating_add(policy.clock_skew_secs) < policy.now_secs {
            return Err(IdentityError::Expired);
        }
        if self.signature_profile.as_str() != PROFILE_ED25519 {
            return Err(IdentityError::UnsupportedAlgorithm(
                self.signature_profile.as_str().into(),
            ));
        }
        let payload = self.canonical_payload()?;
        let mut valid_ed25519 = false;
        for signature in &self.signatures {
            let key = self
                .keys
                .iter()
                .find(|key| key.key_id == signature.key_id)
                .ok_or_else(|| {
                    IdentityError::InvalidRecord(
                        "record signature references an unknown key".into(),
                    )
                })?;
            if key.not_before > self.issued_at || key.not_after < self.issued_at {
                return Err(IdentityError::InvalidRecord(
                    "record signature key was not valid when the record was issued".into(),
                ));
            }
            if key.not_before > policy.now_secs.saturating_add(policy.clock_skew_secs) {
                return Err(IdentityError::NotYetValid);
            }
            if key.not_after.saturating_add(policy.clock_skew_secs) < policy.now_secs {
                return Err(IdentityError::Expired);
            }
            match signature.algorithm.as_str() {
                ALGORITHM_ED25519 => {
                    if key.public_key.len() != 32 || signature.signature.len() != 64 {
                        return Err(IdentityError::InvalidRecord(
                            "Ed25519 record signature has the wrong size".into(),
                        ));
                    }
                    let verifier = ring::signature::UnparsedPublicKey::new(
                        &ring::signature::ED25519,
                        &key.public_key,
                    );
                    verifier
                        .verify(&payload, &signature.signature)
                        .map_err(|_| IdentityError::InvalidSignature)?;
                    valid_ed25519 = true;
                }
                other => return Err(IdentityError::UnsupportedAlgorithm(other.into())),
            }
        }
        if !valid_ed25519 {
            return Err(IdentityError::InvalidSignature);
        }
        if policy.require_pqc_signature {
            return Err(IdentityError::UnsupportedAlgorithm(
                "a post-quantum signature is required by policy".into(),
            ));
        }
        Ok(VerificationResult {
            subject: self.subject,
            pqc_authenticated: false,
        })
    }

    pub fn to_peer_pin(&self, policy: VerificationPolicy) -> Result<PeerPin> {
        self.verify(policy)?;
        if !matches!(self.status, RecordStatus::Active) {
            return Err(IdentityError::InvalidRecord(
                "revoked identity cannot produce a peer pin".into(),
            ));
        }
        let identity_keys: Vec<&IdentityKey> = self
            .keys
            .iter()
            .filter(|key| {
                key.role == KeyRole::IdentityBinding
                    && key.algorithm.as_str() == ALGORITHM_X25519
                    && key_valid_for_record_and_policy(key, self.issued_at, policy)
            })
            .collect();
        let identity_key = match identity_keys.as_slice() {
            [key] => *key,
            [] => {
                return Err(IdentityError::InvalidRecord(
                    "record has no currently valid X25519 identity binding".into(),
                ))
            }
            _ => {
                return Err(IdentityError::InvalidRecord(
                    "record has ambiguous current X25519 identity bindings".into(),
                ))
            }
        };
        let operational_keys: Vec<&IdentityKey> = self
            .keys
            .iter()
            .filter(|key| {
                key.role == KeyRole::OperationalSigning
                    && key.algorithm.as_str() == ALGORITHM_ED25519
                    && key_valid_for_record_and_policy(key, self.issued_at, policy)
            })
            .collect();
        if !operational_keys.is_empty() {
            return Err(IdentityError::InvalidRecord(
                "record contains a current operational signing key that shph-core cannot emit in a handshake; pin generation requires the root signing key".into(),
            ));
        }
        let signing_key = self
            .keys
            .iter()
            .find(|key| {
                key.role == KeyRole::RootSigning
                    && key.algorithm.as_str() == ALGORITHM_ED25519
                    && key_valid_for_record_and_policy(key, self.issued_at, policy)
            })
            .ok_or_else(|| {
                IdentityError::InvalidRecord(
                    "record has no currently valid Ed25519 handshake signing key".into(),
                )
            })?;
        let identity_public: [u8; 32] =
            identity_key.public_key.as_slice().try_into().map_err(|_| {
                IdentityError::InvalidRecord("X25519 binding must be 32 bytes".into())
            })?;
        let signing_public: [u8; 32] =
            signing_key.public_key.as_slice().try_into().map_err(|_| {
                IdentityError::InvalidRecord("Ed25519 signing key must be 32 bytes".into())
            })?;
        Ok(PeerPin::new(identity_public, signing_public))
    }

    pub fn record_hash(&self) -> Result<RecordHash> {
        self.validate_structure()?;
        let payload = self.canonical_payload()?;
        let mut hasher = Sha256::new();
        hasher.update(RECORD_DOMAIN);
        append_bytes(&mut hasher, &payload);
        let mut signatures = self.signatures.clone();
        signatures.sort_by(|left, right| {
            left.key_id
                .cmp(&right.key_id)
                .then_with(|| left.algorithm.cmp(&right.algorithm))
                .then_with(|| left.signature.cmp(&right.signature))
        });
        append_u32(&mut hasher, signatures.len() as u32);
        for signature in signatures {
            hasher.update(signature.key_id.0);
            append_string(&mut hasher, signature.algorithm.as_str());
            append_bytes(&mut hasher, &signature.signature);
        }
        Ok(Hash32(hasher.finalize().into()))
    }

    pub fn to_json_bytes(&self) -> Result<Vec<u8>> {
        self.validate_structure()?;
        let bytes = serde_json::to_vec_pretty(self)?;
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(IdentityError::InvalidRecord(
                "serialized record exceeds the safety limit".into(),
            ));
        }
        Ok(bytes)
    }

    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(IdentityError::InvalidRecord(
                "serialized record exceeds the safety limit".into(),
            ));
        }
        let record: Self = serde_json::from_slice(bytes)?;
        record.validate_structure()?;
        Ok(record)
    }

    fn canonical_payload(&self) -> Result<Vec<u8>> {
        self.validate_structure_without_signatures()?;
        let mut out = Vec::new();
        out.extend_from_slice(RECORD_DOMAIN);
        append_u16_vec(&mut out, self.version);
        out.extend_from_slice(self.subject.as_bytes());
        append_string_vec(&mut out, self.signature_profile.as_str());
        append_u64_vec(&mut out, self.sequence);
        append_u64_vec(&mut out, self.issued_at);
        append_u64_vec(&mut out, self.expires_at);
        match self.previous_record {
            Some(hash) => {
                out.push(1);
                out.extend_from_slice(hash.as_bytes());
            }
            None => out.push(0),
        }
        match &self.status {
            RecordStatus::Active => out.push(0),
            RecordStatus::Revoked { revoked_at, reason } => {
                out.push(1);
                append_u64_vec(&mut out, *revoked_at);
                append_string_vec(&mut out, reason);
            }
        }

        let mut keys = self.keys.clone();
        keys.sort_by(|left, right| {
            left.key_id
                .cmp(&right.key_id)
                .then_with(|| left.role.cmp(&right.role))
                .then_with(|| left.algorithm.cmp(&right.algorithm))
        });
        append_u32_vec(&mut out, keys.len() as u32);
        for key in keys {
            out.push(key.role.code());
            append_string_vec(&mut out, key.algorithm.as_str());
            out.extend_from_slice(key.key_id.as_bytes());
            append_bytes_vec(&mut out, &key.public_key);
            append_u64_vec(&mut out, key.not_before);
            append_u64_vec(&mut out, key.not_after);
            match key.previous_key_id {
                Some(key_id) => {
                    out.push(1);
                    out.extend_from_slice(key_id.as_bytes());
                }
                None => out.push(0),
            }
        }

        let mut endpoints = self.endpoints.clone();
        endpoints.sort_by(|left, right| {
            left.transport
                .cmp(&right.transport)
                .then_with(|| left.address.cmp(&right.address))
                .then_with(|| left.priority.cmp(&right.priority))
        });
        append_u32_vec(&mut out, endpoints.len() as u32);
        for endpoint in endpoints {
            append_string_vec(&mut out, &endpoint.transport);
            append_string_vec(&mut out, &endpoint.address);
            append_u16_vec(&mut out, endpoint.priority);
        }

        let mut capabilities = self.capabilities.clone();
        capabilities.sort();
        append_u32_vec(&mut out, capabilities.len() as u32);
        for capability in capabilities {
            append_string_vec(&mut out, &capability);
        }
        Ok(out)
    }

    fn validate_structure_without_signatures(&self) -> Result<()> {
        if self.version != IDENTITY_RECORD_VERSION {
            return Err(IdentityError::InvalidRecord(format!(
                "unsupported record version {}",
                self.version
            )));
        }
        if self.sequence == 0 {
            return Err(IdentityError::InvalidRecord(
                "record sequence must start at one".into(),
            ));
        }
        if self.sequence == 1 && self.previous_record.is_some() {
            return Err(IdentityError::InvalidRecord(
                "initial record cannot reference a previous record".into(),
            ));
        }
        if self.sequence > 1 && self.previous_record.is_none() {
            return Err(IdentityError::InvalidRecord(
                "non-initial record must reference a previous record".into(),
            ));
        }
        if self.expires_at <= self.issued_at {
            return Err(IdentityError::InvalidRecord(
                "record expiration must be after issuance".into(),
            ));
        }
        if self.expires_at.saturating_sub(self.issued_at) > MAX_RECORD_LIFETIME_SECS {
            return Err(IdentityError::InvalidRecord(
                "record lifetime exceeds the safety limit".into(),
            ));
        }
        validate_token(
            "signature profile",
            self.signature_profile.as_str(),
            MAX_ALGORITHM_BYTES,
        )?;
        if self.keys.is_empty() || self.keys.len() > MAX_KEYS {
            return Err(IdentityError::InvalidRecord(format!(
                "record must contain between one and {MAX_KEYS} keys"
            )));
        }
        let mut key_ids = BTreeSet::new();
        let mut root_keys = 0usize;
        for key in &self.keys {
            validate_key_material(&key.algorithm, &key.public_key)?;
            if key.key_id != derive_key_id(key.role, &key.algorithm, &key.public_key) {
                return Err(IdentityError::InvalidRecord(format!(
                    "key id does not match {} key material",
                    key.role_string()
                )));
            }
            if key.not_after < key.not_before {
                return Err(IdentityError::InvalidRecord(
                    "key expiration precedes key activation".into(),
                ));
            }
            if key.previous_key_id == Some(key.key_id) {
                return Err(IdentityError::InvalidRecord(
                    "key cannot supersede itself".into(),
                ));
            }
            if !key_ids.insert(key.key_id) {
                return Err(IdentityError::InvalidRecord(
                    "record contains duplicate key ids".into(),
                ));
            }
            if key.role == KeyRole::RootSigning {
                root_keys += 1;
            }
        }
        if root_keys != 1 {
            return Err(IdentityError::InvalidRecord(
                "record must contain exactly one root signing key".into(),
            ));
        }
        self.validate_subject_binding()?;
        if self.endpoints.len() > MAX_ENDPOINTS {
            return Err(IdentityError::InvalidRecord(format!(
                "record contains more than {MAX_ENDPOINTS} endpoints"
            )));
        }
        let mut endpoint_ids = BTreeSet::new();
        for endpoint in &self.endpoints {
            validate_endpoint(endpoint)?;
            if !endpoint_ids.insert((
                endpoint.transport.clone(),
                endpoint.address.clone(),
                endpoint.priority,
            )) {
                return Err(IdentityError::InvalidRecord(
                    "record contains duplicate endpoints".into(),
                ));
            }
        }
        if self.capabilities.len() > MAX_CAPABILITIES {
            return Err(IdentityError::InvalidRecord(format!(
                "record contains more than {MAX_CAPABILITIES} capabilities"
            )));
        }
        let mut capabilities = BTreeSet::new();
        for capability in &self.capabilities {
            validate_token("capability", capability, MAX_STRING_BYTES)?;
            if !capabilities.insert(capability.clone()) {
                return Err(IdentityError::InvalidRecord(
                    "record contains duplicate capabilities".into(),
                ));
            }
        }
        match &self.status {
            RecordStatus::Active => {}
            RecordStatus::Revoked { revoked_at, reason } => {
                if *revoked_at < self.issued_at || *revoked_at > self.expires_at {
                    return Err(IdentityError::InvalidRecord(
                        "revocation timestamp is outside the record lifetime".into(),
                    ));
                }
                validate_text("revocation reason", reason, MAX_STRING_BYTES)?;
            }
        }
        Ok(())
    }

    fn validate_subject_binding(&self) -> Result<()> {
        let root_key = self
            .keys
            .iter()
            .find(|key| key.role == KeyRole::RootSigning)
            .ok_or_else(|| IdentityError::InvalidRecord("record has no root signing key".into()))?;
        if self.subject != derive_identity_id(&root_key.public_key) {
            return Err(IdentityError::InvalidRecord(
                "record subject is not bound to the root signing key".into(),
            ));
        }
        Ok(())
    }
}

impl IdentityKey {
    fn role_string(&self) -> &'static str {
        match self.role {
            KeyRole::RootSigning => "root-signing",
            KeyRole::OperationalSigning => "operational-signing",
            KeyRole::IdentityBinding => "identity-binding",
            KeyRole::KeyEstablishment => "key-establishment",
            KeyRole::RecoverySigning => "recovery-signing",
        }
    }
}

pub fn derive_identity_id(root_public_key: &[u8]) -> IdentityId {
    let mut hasher = Sha256::new();
    hasher.update(IDENTITY_ID_DOMAIN);
    append_bytes(&mut hasher, root_public_key);
    Hash32(hasher.finalize().into())
}

pub fn derive_key_id(role: KeyRole, algorithm: &AlgorithmId, public_key: &[u8]) -> KeyId {
    let mut hasher = Sha256::new();
    hasher.update(b"shph/key-id/v1");
    hasher.update([role.code()]);
    append_string(&mut hasher, algorithm.as_str());
    append_bytes(&mut hasher, public_key);
    Hash32(hasher.finalize().into())
}

fn validate_key_material(algorithm: &AlgorithmId, public_key: &[u8]) -> Result<()> {
    validate_token("algorithm", algorithm.as_str(), MAX_ALGORITHM_BYTES)?;
    if public_key.is_empty() || public_key.len() > MAX_PUBLIC_KEY_BYTES {
        return Err(IdentityError::InvalidRecord(
            "public key has an invalid size".into(),
        ));
    }
    if matches!(algorithm.as_str(), ALGORITHM_ED25519 | ALGORITHM_X25519) && public_key.len() != 32
    {
        return Err(IdentityError::InvalidRecord(format!(
            "{algorithm} public key must be 32 bytes"
        )));
    }
    Ok(())
}

fn key_valid_for_record_and_policy(
    key: &IdentityKey,
    issued_at: u64,
    policy: VerificationPolicy,
) -> bool {
    key.not_before <= issued_at
        && key.not_after >= issued_at
        && key.not_before <= policy.now_secs
        && key.not_after >= policy.now_secs
}

fn validate_endpoint(endpoint: &IdentityEndpoint) -> Result<()> {
    validate_token("transport", &endpoint.transport, MAX_STRING_BYTES)?;
    validate_text("endpoint address", &endpoint.address, MAX_STRING_BYTES)?;
    Ok(())
}

fn validate_token(label: &str, value: &str, max_bytes: usize) -> Result<()> {
    if value.is_empty() || value.len() > max_bytes {
        return Err(IdentityError::InvalidRecord(format!(
            "{label} is empty or exceeds {max_bytes} bytes"
        )));
    }
    if !value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'+' | b':')
    }) {
        return Err(IdentityError::InvalidRecord(format!(
            "{label} contains unsupported characters"
        )));
    }
    Ok(())
}

fn validate_text(label: &str, value: &str, max_bytes: usize) -> Result<()> {
    if value.is_empty() || value.len() > max_bytes || value.chars().any(char::is_control) {
        return Err(IdentityError::InvalidRecord(format!(
            "{label} is empty, too long, or contains control characters"
        )));
    }
    Ok(())
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn append_u32(hasher: &mut Sha256, value: u32) {
    hasher.update(value.to_be_bytes());
}

fn append_string(hasher: &mut Sha256, value: &str) {
    append_bytes(hasher, value.as_bytes());
}

fn append_bytes(hasher: &mut Sha256, value: &[u8]) {
    append_u32(hasher, value.len() as u32);
    hasher.update(value);
}

fn append_u16_vec(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn append_u32_vec(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn append_u64_vec(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn append_string_vec(out: &mut Vec<u8>, value: &str) {
    append_bytes_vec(out, value.as_bytes());
}

fn append_bytes_vec(out: &mut Vec<u8>, value: &[u8]) {
    append_u32_vec(out, value.len() as u32);
    out.extend_from_slice(value);
}

fn ensure_directory(path: &Path) -> io::Result<()> {
    ensure_no_symlink_components(path)?;
    match fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    ensure_no_symlink_components(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotADirectory,
            format!("{} is not a directory", path.display()),
        ));
    }
    Ok(())
}

fn read_bounded_file(path: &Path, max_bytes: usize) -> io::Result<Vec<u8>> {
    let file = open_readonly(path)?;
    let mut bytes = Vec::new();
    file.take((max_bytes as u64).saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file exceeds the configured record size limit",
        ));
    }
    Ok(bytes)
}

fn open_readonly(path: &Path) -> io::Result<fs::File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        if !file.metadata()?.file_type().is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "provider record path must reference a regular file",
            ));
        }
        Ok(file)
    }
    #[cfg(not(unix))]
    {
        shph_core::ensure_not_reparse_point(path)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "refusing to read a symlinked provider file",
            ));
        }
        let file = OpenOptions::new().read(true).open(path)?;
        if !file.metadata()?.file_type().is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "provider record path must reference a regular file",
            ));
        }
        Ok(file)
    }
}

fn ensure_no_symlink_components(path: &Path) -> io::Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => current.push(prefix.as_os_str()),
            Component::RootDir => current.push(Path::new(std::path::MAIN_SEPARATOR_STR)),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "provider paths cannot contain parent-directory components",
                ));
            }
            Component::Normal(value) => current.push(value),
        }
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "refusing to traverse symlink component {}",
                        current.display()
                    ),
                ));
            }
            Ok(_) =>
            {
                #[cfg(windows)]
                if let Err(error) = shph_core::ensure_not_reparse_point(&current) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        error.to_string(),
                    ));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

mod base64_bytes {
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&base64::engine::general_purpose::STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        base64::engine::general_purpose::STANDARD
            .decode(value.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shph_core::{KeyStore, KeyStoreConfig, PeerPolicy};
    use std::sync::Arc;

    fn identity() -> IdentityKeyPair {
        KeyStore::new(KeyStoreConfig::default())
            .expect("keystore")
            .identity
    }

    fn record(identity: &IdentityKeyPair, now: u64) -> IdentityRecord {
        IdentityRecord::from_current_identity(
            identity,
            1,
            now.saturating_sub(10),
            now + 3_600,
            vec![IdentityEndpoint::new("tcp", "198.51.100.10:51820", 10).expect("endpoint")],
            vec!["transport:tcp".into(), "kem:ml-kem-768".into()],
        )
        .expect("record")
    }

    #[test]
    fn signed_record_round_trips_and_maps_to_existing_peer_pin() {
        let now = 1_800_000_000;
        let identity = identity();
        let record = record(&identity, now);
        let bytes = record.to_json_bytes().expect("json");
        let decoded = IdentityRecord::from_json_bytes(&bytes).expect("decode");
        let result = decoded.verify(VerificationPolicy::at(now)).expect("verify");
        assert_eq!(result.subject, decoded.subject);
        assert!(!result.pqc_authenticated);
        let pin = decoded
            .to_peer_pin(VerificationPolicy::at(now))
            .expect("peer pin");
        assert_eq!(pin, PeerPin::for_identity(&identity));
    }

    #[test]
    fn canonical_signature_rejects_endpoint_substitution() {
        let now = 1_800_000_000;
        let identity = identity();
        let mut record = record(&identity, now);
        record.endpoints[0].address = "203.0.113.77:443".into();
        assert!(matches!(
            record.verify(VerificationPolicy::at(now)),
            Err(IdentityError::InvalidSignature)
        ));
    }

    #[test]
    fn canonical_payload_is_independent_of_collection_order() {
        let now = 1_800_000_000;
        let identity = identity();
        let record = record(&identity, now);
        let mut reordered = record.clone();
        reordered.keys.reverse();
        reordered.endpoints.reverse();
        reordered.capabilities.reverse();
        reordered
            .verify(VerificationPolicy::at(now))
            .expect("reordered record");
        assert_eq!(
            reordered.record_hash().expect("reordered hash"),
            record.record_hash().expect("original hash")
        );
    }

    #[test]
    fn malformed_and_oversized_records_are_rejected() {
        assert!(IdentityRecord::from_json_bytes(br#"{"version":1}"#).is_err());
        assert!(IdentityRecord::from_json_bytes(&vec![b'x'; MAX_RECORD_BYTES + 1]).is_err());

        let now = 1_800_000_000;
        let identity = identity();
        let record = record(&identity, now);
        let mut value = serde_json::to_value(record).expect("value");
        value
            .as_object_mut()
            .expect("record object")
            .insert("unexpected".into(), serde_json::Value::Null);
        let bytes = serde_json::to_vec(&value).expect("json");
        assert!(IdentityRecord::from_json_bytes(&bytes).is_err());
    }

    #[test]
    fn unsupported_pqc_profiles_fail_closed_instead_of_downgrading() {
        let now = 1_800_000_000;
        let identity = identity();
        let mut record = record(&identity, now);
        record.signature_profile = SignatureProfile::hybrid_ed25519_ml_dsa_65();
        assert!(matches!(
            record.verify(VerificationPolicy::at(now)),
            Err(IdentityError::UnsupportedAlgorithm(_))
        ));
    }

    #[test]
    fn local_provider_is_idempotent_and_content_addressed() {
        let now = 1_800_000_000;
        let identity = identity();
        let record = record(&identity, now);
        let root = std::env::temp_dir().join(format!(
            "shph-identity-provider-{}-{}",
            std::process::id(),
            now
        ));
        let provider = LocalDirectoryProvider::new(&root).expect("provider");
        let first = provider.publish(&record).expect("publish");
        let second = provider.publish(&record).expect("republish");
        assert_eq!(first, second);
        let fetched = provider.fetch(&record.subject).expect("fetch");
        assert_eq!(fetched.len(), 1);
        assert_eq!(fetched[0].record_hash().expect("hash"), first.record_hash);
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn provider_descriptor_is_explicit_and_bounded() {
        let root =
            std::env::temp_dir().join(format!("shph-identity-plugin-{}", std::process::id()));
        let provider = LocalDirectoryProvider::new(&root).expect("provider");
        let descriptor = provider.descriptor();
        assert_eq!(descriptor.api_version, DISCOVERY_PLUGIN_API_VERSION);
        assert_eq!(descriptor.plugin_id, "local-directory");
        assert_eq!(descriptor.provider_kind, "local-filesystem");
        assert!(descriptor.capabilities.contains(&"self-hosted".into()));
        assert!(
            DiscoveryPluginDescriptor::new("invalid/plugin", "local-filesystem", Vec::new())
                .is_err()
        );
    }

    #[test]
    fn resolver_rejects_same_sequence_conflicts() {
        let now = 1_800_000_000;
        let identity = identity();
        let first = record(&identity, now);
        let root = std::env::temp_dir().join(format!(
            "shph-identity-conflict-{}-{}",
            std::process::id(),
            now
        ));
        let provider = LocalDirectoryProvider::new(&root).expect("provider");
        let mut conflict = first.clone();
        conflict.endpoints[0].address = "203.0.113.77:443".into();
        conflict.signatures.clear();
        conflict
            .sign_with_identity(&identity)
            .expect("sign conflict");
        provider.publish(&first).expect("publish first");
        provider.publish(&conflict).expect("publish conflict");
        let mut resolver = DiscoveryResolver::new();
        let providers: [&dyn DiscoveryProvider; 1] = [&provider];
        assert!(matches!(
            resolver.resolve(&first.subject, &providers, VerificationPolicy::at(now)),
            Err(IdentityError::Conflict { sequence: 1 })
        ));
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn resolver_rejects_sequence_rollback() {
        let now = 1_800_000_000;
        let identity = identity();
        let first = record(&identity, now);
        let root = std::env::temp_dir().join(format!(
            "shph-identity-rollback-{}-{}",
            std::process::id(),
            now
        ));
        let provider = LocalDirectoryProvider::new(&root).expect("provider");
        provider.publish(&first).expect("publish first");
        let mut resolver = DiscoveryResolver::new();
        let providers: [&dyn DiscoveryProvider; 1] = [&provider];
        resolver
            .resolve(&first.subject, &providers, VerificationPolicy::at(now))
            .expect("first resolution");

        let mut second = first.clone();
        second.sequence = 2;
        second.previous_record = Some(first.record_hash().expect("first hash"));
        second.signatures.clear();
        second.sign_with_identity(&identity).expect("sign second");
        provider.publish(&second).expect("publish second");
        resolver
            .resolve(&first.subject, &providers, VerificationPolicy::at(now))
            .expect("second resolution");

        let mut rollback = first.clone();
        rollback.endpoints[0].priority = 20;
        rollback.signatures.clear();
        rollback
            .sign_with_identity(&identity)
            .expect("sign rollback");
        let rollback_root = std::env::temp_dir().join(format!(
            "shph-identity-rollback-only-{}-{}",
            std::process::id(),
            now
        ));
        let rollback_provider =
            LocalDirectoryProvider::new(&rollback_root).expect("rollback provider");
        rollback_provider
            .publish(&rollback)
            .expect("publish conflicting old record");
        let rollback_providers: [&dyn DiscoveryProvider; 1] = [&rollback_provider];
        assert!(matches!(
            resolver.resolve(
                &first.subject,
                &rollback_providers,
                VerificationPolicy::at(now)
            ),
            Err(IdentityError::Replay)
        ));
        fs::remove_dir_all(root).ok();
        fs::remove_dir_all(rollback_root).ok();
    }

    #[test]
    fn resolver_rejects_unanchored_initial_update() {
        let now = 1_800_000_000;
        let identity = identity();
        let mut skipped = record(&identity, now);
        skipped.sequence = 2;
        skipped.previous_record = Some(Hash32([0x55; 32]));
        skipped.signatures.clear();
        skipped
            .sign_with_identity(&identity)
            .expect("sign skipped update");

        let root = std::env::temp_dir().join(format!(
            "shph-identity-unanchored-{}-{}",
            std::process::id(),
            now
        ));
        let provider = LocalDirectoryProvider::new(&root).expect("provider");
        provider.publish(&skipped).expect("publish skipped update");
        let mut resolver = DiscoveryResolver::new();
        let providers: [&dyn DiscoveryProvider; 1] = [&provider];
        assert!(matches!(
            resolver.resolve(&skipped.subject, &providers, VerificationPolicy::at(now)),
            Err(IdentityError::Replay)
        ));
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn resolver_ignores_malformed_provider_entries() {
        let now = 1_800_000_000;
        let identity = identity();
        let record = record(&identity, now);
        let root = std::env::temp_dir().join(format!(
            "shph-identity-poison-{}-{}",
            std::process::id(),
            now
        ));
        let provider = LocalDirectoryProvider::new(&root).expect("provider");
        provider.publish(&record).expect("publish");
        let directory = root.join(record.subject.hex());
        fs::write(
            directory.join("poison.json"),
            br#"{"version":1,"keys":"not-a-list"}"#,
        )
        .expect("write poison");
        let fetched = provider.fetch(&record.subject).expect("fetch");
        assert_eq!(fetched.len(), 1);
        assert_eq!(
            fetched[0].record_hash().expect("hash"),
            record.record_hash().expect("hash")
        );
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn resolver_handles_provider_failure_without_affecting_direct_core_use() {
        struct FailingProvider;
        impl DiscoveryProvider for FailingProvider {
            fn provider_id(&self) -> &str {
                "failing"
            }

            fn publish(&self, _record: &IdentityRecord) -> Result<PublishReceipt> {
                Err(IdentityError::ProviderUnavailable("offline".into()))
            }

            fn fetch(&self, _subject: &IdentityId) -> Result<Vec<IdentityRecord>> {
                Err(IdentityError::ProviderUnavailable("offline".into()))
            }
        }

        let now = 1_800_000_000;
        let identity = Arc::new(identity());
        let record = record(&identity, now);
        let failing = FailingProvider;
        let mut resolver = DiscoveryResolver::new();
        let providers: [&dyn DiscoveryProvider; 1] = [&failing];
        assert!(matches!(
            resolver.resolve(&record.subject, &providers, VerificationPolicy::at(now)),
            Err(IdentityError::ProviderUnavailable(_))
        ));
        let _ = PeerPolicy::single(PeerPin::for_identity(&identity));
    }

    #[test]
    fn resolver_uses_valid_provider_when_another_provider_is_unavailable() {
        struct FailingProvider;
        impl DiscoveryProvider for FailingProvider {
            fn provider_id(&self) -> &str {
                "failing"
            }

            fn publish(&self, _record: &IdentityRecord) -> Result<PublishReceipt> {
                Err(IdentityError::ProviderUnavailable("offline".into()))
            }

            fn fetch(&self, _subject: &IdentityId) -> Result<Vec<IdentityRecord>> {
                Err(IdentityError::ProviderUnavailable("offline".into()))
            }
        }

        let now = 1_800_000_000;
        let identity = identity();
        let record = record(&identity, now);
        let root = std::env::temp_dir().join(format!(
            "shph-identity-fallback-{}-{}",
            std::process::id(),
            now
        ));
        let local = LocalDirectoryProvider::new(&root).expect("provider");
        local.publish(&record).expect("publish");
        let failing = FailingProvider;
        let mut resolver = DiscoveryResolver::new();
        let providers: [&dyn DiscoveryProvider; 2] = [&local, &failing];
        let resolution = resolver
            .resolve(&record.subject, &providers, VerificationPolicy::at(now))
            .expect("fallback resolution");
        assert_eq!(resolution.record_hash, record.record_hash().expect("hash"));
        assert_eq!(resolution.providers_consulted, 2);
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn resolver_bounds_provider_count_and_candidate_amplification() {
        struct ManyProvider {
            record: IdentityRecord,
        }

        impl DiscoveryProvider for ManyProvider {
            fn provider_id(&self) -> &str {
                "many"
            }

            fn fetch(&self, _subject: &IdentityId) -> Result<Vec<IdentityRecord>> {
                Ok(std::iter::repeat_n(self.record.clone(), MAX_PROVIDER_RECORDS + 1).collect())
            }

            fn publish(&self, _record: &IdentityRecord) -> Result<PublishReceipt> {
                Err(IdentityError::ProviderUnavailable("read-only".into()))
            }
        }

        let now = 1_800_000_000;
        let identity = identity();
        let record = record(&identity, now);
        let many = ManyProvider {
            record: record.clone(),
        };
        let mut resolver = DiscoveryResolver::new();
        let providers: [&dyn DiscoveryProvider; 1] = [&many];
        assert!(matches!(
            resolver.resolve(&record.subject, &providers, VerificationPolicy::at(now)),
            Err(IdentityError::ProviderUnavailable(_))
        ));

        let too_many: Vec<&dyn DiscoveryProvider> =
            std::iter::repeat_n(&many as &dyn DiscoveryProvider, MAX_DISCOVERY_PROVIDERS + 1)
                .collect();
        assert!(matches!(
            resolver.resolve(&record.subject, &too_many, VerificationPolicy::at(now)),
            Err(IdentityError::InvalidRecord(_))
        ));
    }

    #[test]
    fn resolver_rejects_plugin_descriptor_identity_mismatch() {
        struct MismatchedDescriptor;
        impl DiscoveryProvider for MismatchedDescriptor {
            fn provider_id(&self) -> &str {
                "actual-provider"
            }

            fn descriptor(&self) -> DiscoveryPluginDescriptor {
                DiscoveryPluginDescriptor::new(
                    "different-provider",
                    "test",
                    vec!["retrieval".into()],
                )
                .expect("descriptor")
            }

            fn publish(&self, _record: &IdentityRecord) -> Result<PublishReceipt> {
                Err(IdentityError::ProviderUnavailable("read-only".into()))
            }

            fn fetch(&self, _subject: &IdentityId) -> Result<Vec<IdentityRecord>> {
                Ok(Vec::new())
            }
        }

        let provider = MismatchedDescriptor;
        let mut resolver = DiscoveryResolver::new();
        let subject = IdentityId::ZERO;
        let providers: [&dyn DiscoveryProvider; 1] = [&provider];
        assert!(matches!(
            resolver.resolve(&subject, &providers, VerificationPolicy::default()),
            Err(IdentityError::ProviderUnavailable(_))
        ));
    }

    #[test]
    fn expired_and_revoked_records_cannot_be_used_as_peer_pins() {
        let now = 1_800_000_000;
        let identity = identity();
        let expired = IdentityRecord::from_current_identity(
            &identity,
            1,
            now - 3_600,
            now - 1_000,
            Vec::new(),
            Vec::new(),
        )
        .expect("expired record");
        assert!(matches!(
            expired.verify(VerificationPolicy::at(now)),
            Err(IdentityError::Expired)
        ));

        let mut revoked = record(&identity, now);
        revoked.status = RecordStatus::Revoked {
            revoked_at: now - 5,
            reason: "test revocation".into(),
        };
        revoked.signatures.clear();
        revoked.sign_with_identity(&identity).expect("sign revoked");
        revoked
            .verify(VerificationPolicy::at(now))
            .expect("revocation is authenticated");
        assert!(matches!(
            revoked.to_peer_pin(VerificationPolicy::at(now)),
            Err(IdentityError::InvalidRecord(_))
        ));
    }

    #[test]
    fn signing_key_validity_is_enforced() {
        let now = 1_800_000_000;
        let identity = identity();
        let mut record = record(&identity, now);
        let root = record
            .keys
            .iter_mut()
            .find(|key| key.role == KeyRole::RootSigning)
            .expect("root key");
        root.not_before = now + 600;
        record.signatures.clear();
        record.sign_with_identity(&identity).expect("resign");
        assert!(matches!(
            record.verify(VerificationPolicy::at(now)),
            Err(IdentityError::InvalidRecord(_))
        ));
    }

    #[test]
    fn record_subject_is_bound_to_the_root_signing_key() {
        let now = 1_800_000_000;
        let identity = identity();
        let mut record = record(&identity, now);
        record.subject = Hash32([0xA5; 32]);
        record.signatures.clear();
        assert!(matches!(
            record.sign_with_identity(&identity),
            Err(IdentityError::InvalidRecord(_))
        ));
    }

    #[test]
    fn recovery_signature_alone_cannot_authorize_a_record() {
        let now = 1_800_000_000;
        let signing_identity = identity();
        let recovery = identity();
        let mut record = record(&signing_identity, now);
        let recovery_key = IdentityKey::new(
            KeyRole::RecoverySigning,
            AlgorithmId::ed25519(),
            recovery.signing_public_bytes().to_vec(),
            record.issued_at,
            record.expires_at,
            None,
        )
        .expect("recovery key");
        record.keys.push(recovery_key.clone());
        record.signatures.clear();
        let payload = record.canonical_payload().expect("payload");
        let keypair =
            ring::signature::Ed25519KeyPair::from_seed_unchecked(&recovery.signing_seed())
                .expect("recovery keypair");
        let signature = keypair.sign(&payload);
        record.signatures.push(RecordSignature {
            key_id: recovery_key.key_id,
            algorithm: AlgorithmId::ed25519(),
            signature: signature.as_ref().to_vec(),
        });
        assert!(matches!(
            record.verify(VerificationPolicy::at(now)),
            Err(IdentityError::InvalidRecord(_))
        ));
    }

    #[test]
    fn peer_pin_rejects_an_expired_identity_binding() {
        let now = 1_800_000_000;
        let signing_identity = identity();
        let mut record = record(&signing_identity, now);
        let binding = record
            .keys
            .iter_mut()
            .find(|key| key.role == KeyRole::IdentityBinding)
            .expect("binding key");
        binding.not_before = now - 1_000;
        binding.not_after = now - 1;
        record.signatures.clear();
        record
            .sign_with_identity(&signing_identity)
            .expect("resign");
        assert!(matches!(
            record.to_peer_pin(VerificationPolicy::at(now)),
            Err(IdentityError::InvalidRecord(_))
        ));
    }

    #[test]
    fn peer_pin_rejects_ambiguous_current_identity_bindings() {
        let now = 1_800_000_000;
        let signing_identity = identity();
        let second_identity = identity();
        let mut record = record(&signing_identity, now);
        record.keys.push(
            IdentityKey::new(
                KeyRole::IdentityBinding,
                AlgorithmId::x25519(),
                second_identity.public_key_bytes().to_vec(),
                record.issued_at,
                record.expires_at,
                None,
            )
            .expect("second binding key"),
        );
        record.signatures.clear();
        record
            .sign_with_identity(&signing_identity)
            .expect("resign");
        assert!(matches!(
            record.to_peer_pin(VerificationPolicy::at(now)),
            Err(IdentityError::InvalidRecord(_))
        ));
    }

    #[test]
    fn peer_pin_ignores_an_expired_operational_signing_key() {
        let now = 1_800_000_000;
        let signing_identity = identity();
        let operational = identity();
        let mut record = record(&signing_identity, now);
        record.keys.push(
            IdentityKey::new(
                KeyRole::OperationalSigning,
                AlgorithmId::ed25519(),
                operational.signing_public_bytes().to_vec(),
                now - 1_000,
                now - 1,
                None,
            )
            .expect("operational key"),
        );
        record.signatures.clear();
        record
            .sign_with_identity(&signing_identity)
            .expect("resign");
        let pin = record
            .to_peer_pin(VerificationPolicy::at(now))
            .expect("fallback to root signing key");
        assert_eq!(pin, PeerPin::for_identity(&signing_identity));
    }

    #[test]
    fn peer_pin_rejects_a_current_operational_signing_key_until_handshake_support_exists() {
        let now = 1_800_000_000;
        let signing_identity = identity();
        let operational = identity();
        let mut record = record(&signing_identity, now);
        record.keys.push(
            IdentityKey::new(
                KeyRole::OperationalSigning,
                AlgorithmId::ed25519(),
                operational.signing_public_bytes().to_vec(),
                now - 1_000,
                now + 1_000,
                None,
            )
            .expect("operational key"),
        );
        record.signatures.clear();
        record
            .sign_with_identity(&signing_identity)
            .expect("resign");
        assert!(matches!(
            record.to_peer_pin(VerificationPolicy::at(now)),
            Err(IdentityError::InvalidRecord(message))
                if message.contains("shph-core cannot emit")
        ));
    }

    #[test]
    fn resolver_contains_panicking_plugins() {
        struct PanickingProvider;
        impl DiscoveryProvider for PanickingProvider {
            fn provider_id(&self) -> &str {
                "panicking"
            }

            fn descriptor(&self) -> DiscoveryPluginDescriptor {
                panic!("plugin panic")
            }

            fn publish(&self, _record: &IdentityRecord) -> Result<PublishReceipt> {
                Err(IdentityError::ProviderUnavailable("read-only".into()))
            }

            fn fetch(&self, _subject: &IdentityId) -> Result<Vec<IdentityRecord>> {
                panic!("plugin panic")
            }
        }

        let now = 1_800_000_000;
        let identity = identity();
        let record = record(&identity, now);
        let root = std::env::temp_dir().join(format!(
            "shph-identity-panic-plugin-{}-{}",
            std::process::id(),
            now
        ));
        let local = LocalDirectoryProvider::new(&root).expect("provider");
        local.publish(&record).expect("publish");
        let panicking = PanickingProvider;
        let providers: [&dyn DiscoveryProvider; 2] = [&panicking, &local];
        let mut resolver = DiscoveryResolver::new();
        let resolution = resolver
            .resolve(&record.subject, &providers, VerificationPolicy::at(now))
            .expect("healthy provider should still resolve");
        assert_eq!(resolution.record_hash, record.record_hash().expect("hash"));
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn provider_file_reads_are_bounded() {
        let root =
            std::env::temp_dir().join(format!("shph-identity-bounded-read-{}", std::process::id()));
        fs::create_dir_all(&root).expect("root");
        let path = root.join("oversized.json");
        fs::write(&path, vec![b'x'; MAX_RECORD_BYTES + 1]).expect("oversized file");
        assert!(matches!(
            read_bounded_file(&path, MAX_RECORD_BYTES),
            Err(error) if error.kind() == io::ErrorKind::InvalidData
        ));
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn provider_rejects_parent_directory_components() {
        let root = std::env::temp_dir()
            .join(format!("shph-identity-parent-{}", std::process::id()))
            .join("..")
            .join("escape");
        assert!(LocalDirectoryProvider::new(root).is_err());
    }

    #[test]
    fn initial_record_cannot_skip_a_previous_record() {
        let now = 1_800_000_000;
        let identity = identity();
        let mut record = record(&identity, now);
        record.previous_record = Some(Hash32([0x11; 32]));
        record.signatures.clear();
        assert!(matches!(
            record.sign_with_identity(&identity),
            Err(IdentityError::InvalidRecord(_))
        ));
    }

    #[test]
    fn non_initial_record_requires_a_previous_record() {
        let now = 1_800_000_000;
        let identity = identity();
        let mut record = record(&identity, now);
        record.sequence = 2;
        assert!(matches!(
            record.validate_structure(),
            Err(IdentityError::InvalidRecord(_))
        ));
    }

    #[test]
    fn update_constructor_requires_and_binds_previous_record() {
        let now = 1_800_000_000;
        let identity = identity();
        let first = record(&identity, now);
        let second = IdentityRecord::from_current_identity_with_previous(
            &identity,
            2,
            now,
            now + 3_600,
            Some(first.record_hash().expect("first hash")),
            Vec::new(),
            Vec::new(),
        )
        .expect("linked update");
        assert_eq!(
            second.previous_record,
            Some(first.record_hash().expect("first hash"))
        );
        assert!(second.verify(VerificationPolicy::at(now)).is_ok());
    }

    #[test]
    fn verification_rejects_unbounded_clock_skew() {
        let now = 1_800_000_000;
        let identity = identity();
        let record = record(&identity, now);
        let mut policy = VerificationPolicy::at(now);
        policy.clock_skew_secs = MAX_CLOCK_SKEW_SECS + 1;
        assert!(matches!(
            record.verify(policy),
            Err(IdentityError::InvalidRecord(_))
        ));
    }

    #[test]
    fn sequence_updates_require_previous_record_hash() {
        let now = 1_800_000_000;
        let signing_identity = identity();
        let first = record(&signing_identity, now);
        let root = std::env::temp_dir().join(format!(
            "shph-identity-chain-{}-{}",
            std::process::id(),
            now
        ));
        let provider = LocalDirectoryProvider::new(&root).expect("provider");
        provider.publish(&first).expect("publish first");
        let mut resolver = DiscoveryResolver::new();
        let providers: [&dyn DiscoveryProvider; 1] = [&provider];
        resolver
            .resolve(&first.subject, &providers, VerificationPolicy::at(now))
            .expect("first resolution");

        let mut forged_next = first.clone();
        forged_next.sequence = 3;
        forged_next.previous_record = Some(Hash32([0x44; 32]));
        let replacement_identity = identity();
        let replacement_binding = IdentityKey::new(
            KeyRole::IdentityBinding,
            AlgorithmId::x25519(),
            replacement_identity.public_key_bytes().to_vec(),
            forged_next.issued_at,
            forged_next.expires_at,
            None,
        )
        .expect("replacement binding");
        let binding = forged_next
            .keys
            .iter_mut()
            .find(|key| key.role == KeyRole::IdentityBinding)
            .expect("binding key");
        *binding = replacement_binding;
        forged_next.signatures.clear();
        forged_next
            .sign_with_identity(&signing_identity)
            .expect("sign forged next");
        provider.publish(&forged_next).expect("publish forged next");
        assert!(matches!(
            resolver.resolve(&first.subject, &providers, VerificationPolicy::at(now)),
            Err(IdentityError::Replay)
        ));
        fs::remove_dir_all(root).ok();
    }
}
