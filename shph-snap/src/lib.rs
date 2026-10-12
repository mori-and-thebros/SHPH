//! Versioned, local SNAP path profiles and deterministic candidate planning.
//!
//! This crate owns policy only. It does not open sockets or alter SHPH peer
//! identity policy; callers must authenticate every selected candidate using
//! the existing SHPH session handshake.

use rand::{Rng, RngCore};
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::net::IpAddr;
use thiserror::Error;

pub const PROFILE_VERSION: u32 = 1;
pub const MAX_PROFILE_BYTES: usize = 1024 * 1024;
pub const MAX_DIRECT_ENDPOINTS: usize = 16;
pub const MAX_BRIDGES: usize = 32;
pub const MAX_RETRY_ROUNDS: u32 = 12;
pub const MAX_RETRY_ATTEMPTS: u32 = 1024;
pub const MAX_ROUTE_HOPS: usize = 8;

const DEFAULT_ADAPTER_ORDER: &[&str] = &[
    "direct-tcp",
    "bridge-onion-tcp",
    "bridge-tls",
    "bridge-ws",
    "edge-relay",
    "shroud-tcp",
    "mesh-dtn-local",
    "mule-usb",
];

// Keep the Python SNAP default ranking intact. SHPH-native extensions remain
// valid adapters, but without an explicit adapter_order they tie after the
// Python defaults and retain profile insertion order.
const KNOWN_ADAPTERS: &[&str] = &[
    "direct-tcp",
    "bridge-onion-tcp",
    "bridge-tls",
    "bridge-ws",
    "shroud-tcp",
    "mesh-dtn-local",
    "mule-usb",
    "edge-relay",
    "quic",
    "quic-standard",
    "offline-mesh",
    "data-mule",
];

/// Match Python SNAP's adapter-specific connection budgets when a candidate
/// does not declare its own timeout.
pub fn adapter_default_timeout_sec(adapter: &str) -> Option<f64> {
    match adapter.trim().to_ascii_lowercase().as_str() {
        "bridge-ws" | "shroud-tcp" => Some(12.0),
        _ => None,
    }
}

#[derive(Debug, Error)]
pub enum SnapError {
    #[error("invalid SNAP profile: {0}")]
    Invalid(String),
    #[error("unsupported SNAP profile format: {0}")]
    UnsupportedFormat(String),
    #[error("SNAP profile exceeds the {MAX_PROFILE_BYTES}-byte limit")]
    TooLarge,
    #[error("failed to parse SNAP JSON profile: {0}")]
    Json(#[from] serde_json::Error),
    #[error("failed to parse SNAP TOML profile: {0}")]
    Toml(#[from] toml::de::Error),
}

pub type Result<T> = std::result::Result<T, SnapError>;

/// JSON objects with duplicate member names have parser-dependent meaning.
/// Keep profile parsing deterministic by rejecting duplicates before converting
/// to `serde_json::Value`, whose map representation would otherwise keep only
/// the last value.
struct StrictJsonValue(Value);

impl<'de> Deserialize<'de> for StrictJsonValue {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictJsonVisitor)
    }
}

struct StrictJsonVisitor;

impl<'de> Visitor<'de> for StrictJsonVisitor {
    type Value = StrictJsonValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value with unique object keys")
    }

    fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::Null))
    }

    fn visit_bool<E>(self, value: bool) -> std::result::Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> std::result::Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> std::result::Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> std::result::Result<Self::Value, E>
    where
        E: de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(|number| StrictJsonValue(Value::Number(number)))
            .ok_or_else(|| E::custom("JSON number must be finite"))
    }

    fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> std::result::Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::String(value)))
    }

    fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(StrictJsonValue(value)) = sequence.next_element()? {
            values.push(value);
        }
        Ok(StrictJsonValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut object: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = serde_json::Map::new();
        while let Some(key) = object.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom(format!(
                    "duplicate JSON object key: {key}"
                )));
            }
            let StrictJsonValue(value) = object.next_value()?;
            values.insert(key, value);
        }
        Ok(StrictJsonValue(Value::Object(values)))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileFormat {
    Json,
    Toml,
}

impl ProfileFormat {
    pub fn from_path(path: &std::path::Path) -> Result<Self> {
        match path
            .extension()
            .and_then(std::ffi::OsStr::to_str)
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            Some("json") => Ok(Self::Json),
            Some("toml") => Ok(Self::Toml),
            Some(extension) => Err(SnapError::UnsupportedFormat(extension.to_owned())),
            None => Err(SnapError::UnsupportedFormat("missing extension".into())),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SnapMode {
    #[default]
    Auto,
    DirectOnly,
    BridgesOnly,
    OnionOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RoundOrder {
    #[default]
    Stable,
    Rotate,
    Shuffle,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportPreferences {
    #[serde(default = "default_adapter_order")]
    pub adapter_order: Vec<String>,
}

impl Default for TransportPreferences {
    fn default() -> Self {
        Self {
            adapter_order: default_adapter_order(),
        }
    }
}

fn default_adapter_order() -> Vec<String> {
    DEFAULT_ADAPTER_ORDER
        .iter()
        .map(|name| (*name).to_owned())
        .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetryPolicy {
    #[serde(default = "default_rounds")]
    pub rounds: u32,
    #[serde(default = "default_backoff_base")]
    pub backoff_base_sec: f64,
    #[serde(default = "default_backoff_max")]
    pub backoff_max_sec: f64,
    #[serde(default = "default_jitter")]
    pub jitter_ratio: f64,
    #[serde(default)]
    pub round_order: RoundOrder,
    #[serde(default)]
    pub shuffle_seed: Option<u64>,
    #[serde(default)]
    pub max_total_attempts: u32,
    #[serde(default)]
    pub max_elapsed_sec: f64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            rounds: default_rounds(),
            backoff_base_sec: default_backoff_base(),
            backoff_max_sec: default_backoff_max(),
            jitter_ratio: default_jitter(),
            round_order: RoundOrder::default(),
            shuffle_seed: None,
            max_total_attempts: 0,
            max_elapsed_sec: 0.0,
        }
    }
}

fn default_rounds() -> u32 {
    1
}

fn default_backoff_base() -> f64 {
    0.6
}

fn default_backoff_max() -> f64 {
    8.0
}

fn default_jitter() -> f64 {
    0.15
}

impl RetryPolicy {
    pub fn validate(&self) -> Result<()> {
        if !(1..=MAX_RETRY_ROUNDS).contains(&self.rounds) {
            return Err(SnapError::Invalid(format!(
                "retry_policy.rounds must be between 1 and {MAX_RETRY_ROUNDS}"
            )));
        }
        validate_range(
            "retry_policy.backoff_base_sec",
            self.backoff_base_sec,
            0.0,
            120.0,
        )?;
        validate_range(
            "retry_policy.backoff_max_sec",
            self.backoff_max_sec,
            0.0,
            120.0,
        )?;
        if self.backoff_max_sec < self.backoff_base_sec {
            return Err(SnapError::Invalid(
                "retry_policy.backoff_max_sec must be >= backoff_base_sec".into(),
            ));
        }
        validate_range("retry_policy.jitter_ratio", self.jitter_ratio, 0.0, 0.5)?;
        if self.max_total_attempts > MAX_RETRY_ATTEMPTS {
            return Err(SnapError::Invalid(format!(
                "retry_policy.max_total_attempts must not exceed {MAX_RETRY_ATTEMPTS}"
            )));
        }
        validate_range(
            "retry_policy.max_elapsed_sec",
            self.max_elapsed_sec,
            0.0,
            3600.0,
        )?;
        if self.shuffle_seed.is_some_and(|seed| seed > 2_147_483_647) {
            return Err(SnapError::Invalid(
                "retry_policy.shuffle_seed must not exceed 2147483647".into(),
            ));
        }
        Ok(())
    }

    pub fn attempt_limit(&self, candidate_count: usize) -> usize {
        let computed = candidate_count.saturating_mul(self.rounds as usize);
        if self.max_total_attempts == 0 {
            computed
        } else {
            computed.min(self.max_total_attempts as usize)
        }
    }

    pub fn ordered_round<T: Clone>(&self, candidates: &[T], round_index: u32) -> Vec<T> {
        if candidates.len() <= 1 {
            return candidates.to_vec();
        }
        match self.round_order {
            RoundOrder::Stable => candidates.to_vec(),
            RoundOrder::Rotate => {
                let offset = round_index.saturating_sub(1) as usize % candidates.len();
                candidates[offset..]
                    .iter()
                    .chain(candidates[..offset].iter())
                    .cloned()
                    .collect()
            }
            RoundOrder::Shuffle => {
                let seed = self
                    .shuffle_seed
                    .unwrap_or_else(|| rand::thread_rng().gen_range(0..2_147_483_647));
                let mut ordered = candidates.to_vec();
                python_seeded_shuffle(&mut ordered, seed.wrapping_add(round_index as u64));
                ordered
            }
        }
    }

    pub fn backoff_after_round(&self, completed_round: u32, random_unit: f64) -> f64 {
        if completed_round == 0 || completed_round >= self.rounds {
            return 0.0;
        }
        let exponent = completed_round.saturating_sub(1).min(31);
        let base = (self.backoff_base_sec * 2_f64.powi(exponent as i32)).min(self.backoff_max_sec);
        if self.jitter_ratio == 0.0 {
            return base;
        }
        let unit = random_unit.clamp(0.0, 1.0);
        (base + (unit * 2.0 - 1.0) * base * self.jitter_ratio).clamp(0.0, self.backoff_max_sec)
    }
}

/// Reproduce Python's `random.Random(seed).shuffle` for portable seeded SNAP
/// profiles. Python uses MT19937 and rejection sampling in `_randbelow`; using
/// Rust's default RNG here would make the same profile order candidates
/// differently in the two implementations.
fn python_seeded_shuffle<T>(values: &mut [T], seed: u64) {
    let mut random = PythonMt19937::new(seed);
    for index in (1..values.len()).rev() {
        let selected = random.randbelow(index + 1);
        values.swap(index, selected);
    }
}

struct PythonMt19937 {
    state: [u32; 624],
    index: usize,
}

impl PythonMt19937 {
    fn new(seed: u64) -> Self {
        let mut random = Self {
            state: [0; 624],
            index: 624,
        };
        random.state[0] = 19_650_218;
        for index in 1..624 {
            let previous = random.state[index - 1];
            random.state[index] = 1_812_433_253_u32
                .wrapping_mul(previous ^ (previous >> 30))
                .wrapping_add(index as u32);
        }

        let mut key = vec![seed as u32];
        if seed >> 32 != 0 {
            key.push((seed >> 32) as u32);
        }
        let mut state_index = 1usize;
        let mut key_index = 0usize;
        for _ in 0..624.max(key.len()) {
            let previous = random.state[state_index - 1];
            random.state[state_index] = (random.state[state_index]
                ^ (previous ^ (previous >> 30)).wrapping_mul(1_664_525))
            .wrapping_add(key[key_index])
            .wrapping_add(key_index as u32);
            state_index += 1;
            key_index += 1;
            if state_index >= 624 {
                random.state[0] = random.state[623];
                state_index = 1;
            }
            if key_index >= key.len() {
                key_index = 0;
            }
        }
        for _ in 0..623 {
            let previous = random.state[state_index - 1];
            random.state[state_index] = (random.state[state_index]
                ^ (previous ^ (previous >> 30)).wrapping_mul(1_566_083_941))
            .wrapping_sub(state_index as u32);
            state_index += 1;
            if state_index >= 624 {
                random.state[0] = random.state[623];
                state_index = 1;
            }
        }
        random.state[0] = 0x8000_0000;
        random
    }

    fn randbelow(&mut self, upper_bound: usize) -> usize {
        let bits = usize::BITS - upper_bound.leading_zeros();
        loop {
            let value = (self.next_u32() >> (32 - bits)) as usize;
            if value < upper_bound {
                return value;
            }
        }
    }

    fn next_u32(&mut self) -> u32 {
        if self.index >= 624 {
            self.twist();
        }
        let mut value = self.state[self.index];
        self.index += 1;
        value ^= value >> 11;
        value ^= (value << 7) & 0x9d2c_5680;
        value ^= (value << 15) & 0xefc6_0000;
        value ^= value >> 18;
        value
    }

    fn twist(&mut self) {
        for index in 0..(624 - 397) {
            let value = (self.state[index] & 0x8000_0000) | (self.state[index + 1] & 0x7fff_ffff);
            self.state[index] = self.state[index + 397]
                ^ (value >> 1)
                ^ if value & 1 == 0 { 0 } else { 0x9908_b0df };
        }
        for index in (624 - 397)..623 {
            let value = (self.state[index] & 0x8000_0000) | (self.state[index + 1] & 0x7fff_ffff);
            self.state[index] = self.state[index - (624 - 397)]
                ^ (value >> 1)
                ^ if value & 1 == 0 { 0 } else { 0x9908_b0df };
        }
        let value = (self.state[623] & 0x8000_0000) | (self.state[0] & 0x7fff_ffff);
        self.state[623] =
            self.state[396] ^ (value >> 1) ^ if value & 1 == 0 { 0 } else { 0x9908_b0df };
        self.index = 0;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectEndpoint {
    pub ip: String,
    pub port: u16,
    #[serde(default = "default_tcp")]
    pub transport: String,
    #[serde(default = "default_direct_adapter")]
    pub adapter: String,
    #[serde(default)]
    pub tls_enabled: bool,
    #[serde(default)]
    pub sni: Option<String>,
    #[serde(default)]
    pub edge_label: Option<String>,
    #[serde(default = "default_priority")]
    pub priority: u16,
    #[serde(default = "default_weight")]
    pub weight: u16,
    #[serde(default)]
    pub timeout_sec: Option<f64>,
    #[serde(default)]
    pub allowed_fallback: Vec<String>,
}

fn default_tcp() -> String {
    "tcp".into()
}

fn default_direct_adapter() -> String {
    "direct-tcp".into()
}

fn default_priority() -> u16 {
    100
}

fn default_weight() -> u16 {
    100
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bridge {
    #[serde(default)]
    pub label: String,
    pub ip: String,
    pub port: u16,
    #[serde(default)]
    pub key_file: Option<String>,
    #[serde(default)]
    pub route_file: Option<String>,
    #[serde(default = "default_onion_transport")]
    pub transport: String,
    #[serde(default = "default_onion_adapter")]
    pub adapter: String,
    #[serde(default)]
    pub tls_enabled: bool,
    #[serde(default)]
    pub sni: Option<String>,
    #[serde(default)]
    pub edge_label: Option<String>,
    #[serde(default = "default_priority")]
    pub priority: u16,
    #[serde(default = "default_weight")]
    pub weight: u16,
    #[serde(default)]
    pub timeout_sec: Option<f64>,
    #[serde(default)]
    pub allowed_fallback: Vec<String>,
    #[serde(default)]
    pub tls_ca_file: Option<String>,
    #[serde(default)]
    pub tls_cert_sha256: Option<String>,
    #[serde(default)]
    pub ws_path: Option<String>,
    #[serde(default)]
    pub shroud_profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_service_contract: Option<OperatorServiceContract>,
}

/// Operator supplied authorization metadata for a network bridge or relay.
/// This is an explicit declaration, not independent proof that the service is
/// owned or authorized.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorServiceContract {
    pub owner: String,
    pub service_id: String,
    pub authorization_ref: String,
}

impl OperatorServiceContract {
    fn validate(&self) -> Result<()> {
        validate_text("operator_service_contract.owner", &self.owner, 128)?;
        validate_text(
            "operator_service_contract.service_id",
            &self.service_id,
            128,
        )?;
        validate_text(
            "operator_service_contract.authorization_ref",
            &self.authorization_ref,
            128,
        )
    }
}

fn default_onion_transport() -> String {
    "onion-tcp".into()
}

fn default_onion_adapter() -> String {
    "bridge-onion-tcp".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeProfile {
    pub host: String,
    pub port: u16,
    #[serde(default = "default_true")]
    pub tls_required: bool,
    #[serde(default)]
    pub notes: String,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapProfile {
    #[serde(default = "default_version")]
    pub version: u32,
    #[serde(default = "default_profile_name")]
    pub profile_name: String,
    #[serde(default)]
    pub mode: SnapMode,
    pub peer_alias: String,
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_sec: f64,
    #[serde(default)]
    pub direct_endpoints: Vec<DirectEndpoint>,
    #[serde(default)]
    pub bridges: Vec<Bridge>,
    #[serde(default)]
    pub retry_policy: RetryPolicy,
    #[serde(default)]
    pub edge_profiles: BTreeMap<String, EdgeProfile>,
    #[serde(default)]
    pub transport_preferences: TransportPreferences,
}

fn default_version() -> u32 {
    PROFILE_VERSION
}

fn default_profile_name() -> String {
    "default".into()
}

fn default_connect_timeout() -> f64 {
    8.0
}

impl SnapProfile {
    pub fn parse(bytes: &[u8], format: ProfileFormat) -> Result<Self> {
        if bytes.len() > MAX_PROFILE_BYTES {
            return Err(SnapError::TooLarge);
        }
        let text = std::str::from_utf8(bytes)
            .map_err(|_| SnapError::Invalid("profile must be UTF-8".into()))?;
        let mut value = match format {
            ProfileFormat::Json => serde_json::from_str::<StrictJsonValue>(text)?.0,
            ProfileFormat::Toml => {
                let parsed = toml::from_str::<toml::Value>(text)?;
                serde_json::to_value(parsed)?
            }
        };
        normalize_python_profile(&mut value)?;
        let profile: Self = serde_json::from_value(value)?;
        profile.validate()?;
        Ok(profile)
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != PROFILE_VERSION {
            return Err(SnapError::Invalid(format!(
                "unsupported profile version {}; expected {PROFILE_VERSION}",
                self.version
            )));
        }
        validate_text("profile_name", &self.profile_name, 128)?;
        validate_text("peer_alias", &self.peer_alias, 128)?;
        validate_range("connect_timeout_sec", self.connect_timeout_sec, 0.2, 60.0)?;
        self.retry_policy.validate()?;
        match self.mode {
            SnapMode::DirectOnly if self.direct_endpoints.is_empty() => {
                return Err(SnapError::Invalid(
                    "direct-only mode requires at least one direct_endpoints entry".into(),
                ));
            }
            SnapMode::BridgesOnly | SnapMode::OnionOnly if self.bridges.is_empty() => {
                return Err(SnapError::Invalid(format!(
                    "{} mode requires at least one bridge entry",
                    match self.mode {
                        SnapMode::BridgesOnly => "bridges-only",
                        SnapMode::OnionOnly => "onion-only",
                        _ => unreachable!(),
                    }
                )));
            }
            _ => {}
        }
        if self.direct_endpoints.len() > MAX_DIRECT_ENDPOINTS {
            return Err(SnapError::Invalid(format!(
                "direct_endpoints supports at most {MAX_DIRECT_ENDPOINTS} entries"
            )));
        }
        if self.bridges.len() > MAX_BRIDGES {
            return Err(SnapError::Invalid(format!(
                "bridges supports at most {MAX_BRIDGES} entries"
            )));
        }
        validate_adapter_order(&self.transport_preferences.adapter_order)?;

        let mut bridge_labels = BTreeSet::new();
        for bridge in &self.bridges {
            bridge.validate(&self.edge_profiles, &mut bridge_labels)?;
        }
        for endpoint in &self.direct_endpoints {
            endpoint.validate()?;
        }
        for (label, edge) in &self.edge_profiles {
            validate_text("edge profile label", label, 128)?;
            validate_host("edge profile host", &edge.host)?;
            validate_port("edge profile port", edge.port)?;
            if edge.notes.len() > 2048 || edge.notes.chars().any(char::is_control) {
                return Err(SnapError::Invalid(format!(
                    "edge_profiles[{label}].notes is invalid"
                )));
            }
        }

        self.validate_fallback_graph()?;
        Ok(())
    }

    /// Verify that every network bridge or relay carries an explicit
    /// operator ownership and authorization declaration. Profiles without
    /// external adapters remain valid without this metadata.
    pub fn validate_operator_service_contracts(&self) -> Result<()> {
        for bridge in &self.bridges {
            let local_adapter = matches!(bridge.adapter.as_str(), "mesh-dtn-local" | "mule-usb");
            if !local_adapter && bridge.operator_service_contract.is_none() {
                return Err(SnapError::Invalid(format!(
                    "bridge '{}' requires operator_service_contract",
                    bridge.label
                )));
            }
        }
        Ok(())
    }

    fn validate_fallback_graph(&self) -> Result<()> {
        let mut candidates = Vec::new();
        candidates.extend(
            self.direct_endpoints
                .iter()
                .map(|item| (item.adapter.as_str(), item.allowed_fallback.as_slice())),
        );
        candidates.extend(
            self.bridges
                .iter()
                .map(|item| (item.adapter.as_str(), item.allowed_fallback.as_slice())),
        );
        let available: BTreeSet<&str> = candidates.iter().map(|(adapter, _)| *adapter).collect();
        let edges: Vec<Vec<usize>> = candidates
            .iter()
            .enumerate()
            .map(|(current_index, (_, allowed))| {
                if allowed.is_empty() {
                    return Ok(Vec::new());
                }
                for name in *allowed {
                    if !available.contains(name.as_str()) {
                        return Err(SnapError::Invalid(format!(
                            "allowed_fallback references adapter absent from profile: {name}"
                        )));
                    }
                }
                let matches: Vec<usize> = candidates
                    .iter()
                    .enumerate()
                    .filter_map(|(index, (candidate_adapter, _))| {
                        (index != current_index
                            && allowed.iter().any(|name| name == candidate_adapter))
                        .then_some(index)
                    })
                    .collect();
                if matches.is_empty() {
                    return Err(SnapError::Invalid(
                        "allowed_fallback does not resolve to another candidate".into(),
                    ));
                }
                Ok(matches)
            })
            .collect::<Result<_>>()?;

        fn visit(index: usize, edges: &[Vec<usize>], marks: &mut [u8]) -> bool {
            match marks[index] {
                1 => return true,
                2 => return false,
                _ => {}
            }
            marks[index] = 1;
            for next in &edges[index] {
                if visit(*next, edges, marks) {
                    return true;
                }
            }
            marks[index] = 2;
            false
        }

        let mut marks = vec![0; candidates.len()];
        for index in 0..candidates.len() {
            if visit(index, &edges, &mut marks) {
                return Err(SnapError::Invalid(
                    "allowed_fallback graph must be acyclic".into(),
                ));
            }
        }
        Ok(())
    }

    pub fn profile_hash(&self) -> String {
        let canonical = serde_json::to_vec(self).unwrap_or_default();
        hex::encode(Sha256::digest(canonical))
    }

    /// Build a deterministic plan without probing configured endpoints.
    pub fn plan(&self, peer_host: &str, peer_port: u16) -> Result<SnapPlan> {
        self.validate()?;
        validate_host("peer endpoint host", peer_host)?;
        validate_port("peer endpoint port", peer_port)?;

        let include_direct = matches!(self.mode, SnapMode::Auto | SnapMode::DirectOnly);
        let include_bridges = matches!(
            self.mode,
            SnapMode::Auto | SnapMode::BridgesOnly | SnapMode::OnionOnly
        );
        let mut candidates = Vec::new();
        let mut insertion = 0usize;

        if include_direct {
            if self.direct_endpoints.is_empty() {
                candidates.push(SnapCandidate::new(
                    CandidateKind::Direct,
                    "direct-tcp".into(),
                    "tcp".into(),
                    peer_host.to_owned(),
                    peer_port,
                    "profile_direct_endpoint".into(),
                    100,
                    100,
                    None,
                    Vec::new(),
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    insertion,
                ));
            } else {
                for endpoint in &self.direct_endpoints {
                    insertion += 1;
                    candidates.push(SnapCandidate::new(
                        CandidateKind::Direct,
                        endpoint.adapter.clone(),
                        endpoint.transport.clone(),
                        endpoint.ip.clone(),
                        endpoint.port,
                        "profile_direct_endpoint".into(),
                        endpoint.priority,
                        endpoint.weight,
                        endpoint.timeout_sec,
                        endpoint.allowed_fallback.clone(),
                        None,
                        None,
                        endpoint.tls_enabled.then_some(true),
                        endpoint.sni.clone(),
                        None,
                        None,
                        None,
                        None,
                        insertion,
                    ));
                }
            }
        }

        if include_bridges {
            for bridge in &self.bridges {
                insertion += 1;
                let edge = bridge
                    .edge_label
                    .as_ref()
                    .and_then(|label| self.edge_profiles.get(label));
                let (target_host, target_port) = if bridge.adapter == "bridge-onion-tcp" {
                    (peer_host.to_owned(), peer_port)
                } else if let Some(edge) = edge {
                    (edge.host.clone(), edge.port)
                } else {
                    (peer_host.to_owned(), peer_port)
                };
                candidates.push(
                    SnapCandidate::new(
                        CandidateKind::Bridge,
                        bridge.adapter.clone(),
                        bridge.transport.clone(),
                        target_host,
                        target_port,
                        format!("bridge:{}", bridge.label),
                        bridge.priority,
                        bridge.weight,
                        bridge.timeout_sec,
                        bridge.allowed_fallback.clone(),
                        bridge.edge_label.clone(),
                        bridge.route_file.clone(),
                        Some(bridge.tls_enabled),
                        bridge.sni.clone(),
                        bridge.tls_ca_file.clone(),
                        bridge.tls_cert_sha256.clone(),
                        bridge.ws_path.clone(),
                        bridge.shroud_profile.clone(),
                        insertion,
                    )
                    .with_relay(bridge.ip.clone(), bridge.port, bridge.key_file.clone())
                    .with_operator_service_contract(bridge.operator_service_contract.clone()),
                );
            }
        }

        let adapter_rank: HashMap<&str, usize> = self
            .transport_preferences
            .adapter_order
            .iter()
            .enumerate()
            .map(|(index, name)| (name.as_str(), index))
            .collect();
        candidates.sort_by_key(|candidate| {
            (
                candidate.priority,
                adapter_rank
                    .get(candidate.adapter.as_str())
                    .copied()
                    .unwrap_or(usize::MAX),
                std::cmp::Reverse(candidate.weight),
                candidate.insertion_index,
            )
        });
        for candidate in &mut candidates {
            candidate.candidate_id = candidate.compute_id();
        }
        Ok(SnapPlan {
            profile_name: self.profile_name.clone(),
            profile_hash: self.profile_hash(),
            peer_alias: self.peer_alias.clone(),
            connect_timeout_sec: self.connect_timeout_sec,
            retry_policy: self.retry_policy.clone(),
            attempt_limit: self.retry_policy.attempt_limit(candidates.len()),
            candidates,
        })
    }
}

/// Apply the string/list normalization used by Python SNAP before Rust's
/// strict, unknown-field-rejecting deserialization. Keeping this at the format
/// boundary lets JSON and TOML profiles share the same behavior.
fn normalize_python_profile(value: &mut Value) -> Result<()> {
    let root = value
        .as_object_mut()
        .ok_or_else(|| SnapError::Invalid("profile root must be an object".into()))?;
    trim_string(root.get_mut("profile_name"));
    trim_string(root.get_mut("peer_alias"));
    lowercase_string(root.get_mut("mode"));

    if root.get("direct_endpoints").is_some_and(Value::is_null) {
        root.insert("direct_endpoints".into(), Value::Array(Vec::new()));
    }
    if root.get("bridges").is_some_and(Value::is_null) {
        root.insert("bridges".into(), Value::Array(Vec::new()));
    }
    if root.get("edge_profiles").is_some_and(Value::is_null) {
        root.insert("edge_profiles".into(), Value::Object(Default::default()));
    }
    if root.get("retry_policy").is_some_and(Value::is_null) {
        root.insert("retry_policy".into(), Value::Object(Default::default()));
    }

    let mut normalized_edges = serde_json::Map::new();
    if let Some(edges) = root.get_mut("edge_profiles").and_then(Value::as_object_mut) {
        for (label, edge) in std::mem::take(edges) {
            let label = label.trim().to_owned();
            if normalized_edges.contains_key(&label) {
                return Err(SnapError::Invalid(
                    "edge profile labels collide after whitespace normalization".into(),
                ));
            }
            let mut edge = edge;
            if let Some(edge) = edge.as_object_mut() {
                trim_string(edge.get_mut("host"));
                trim_string(edge.get_mut("notes"));
            }
            normalized_edges.insert(label, edge);
        }
    }
    if let Some(edges) = root.get_mut("edge_profiles") {
        if edges.is_object() {
            *edges = Value::Object(normalized_edges);
        }
    }

    if root
        .get("transport_preferences")
        .is_some_and(Value::is_null)
    {
        root.insert(
            "transport_preferences".into(),
            Value::Object(Default::default()),
        );
    }
    let preferences = root
        .entry("transport_preferences")
        .or_insert_with(|| Value::Object(Default::default()));
    if let Some(preferences) = preferences.as_object_mut() {
        if preferences
            .get("adapter_order")
            .is_some_and(|value| value.is_null() || value.as_str() == Some(""))
        {
            preferences.insert("adapter_order".into(), Value::Array(Vec::new()));
        }
        let mut order = Vec::new();
        let mut seen = BTreeSet::new();
        let order_has_python_compatible_shape = preferences
            .get("adapter_order")
            .is_none_or(|value| value.is_null() || value.as_str() == Some("") || value.is_array());
        if order_has_python_compatible_shape {
            if let Some(items) = preferences
                .get_mut("adapter_order")
                .and_then(Value::as_array_mut)
            {
                for item in items.iter_mut() {
                    lowercase_string(Some(item));
                    if let Some(name) = item.as_str() {
                        if seen.insert(name.to_owned()) {
                            order.push(Value::String(name.to_owned()));
                        }
                    } else {
                        order.push(item.clone());
                    }
                }
            }
            for adapter in DEFAULT_ADAPTER_ORDER {
                if seen.insert((*adapter).to_owned()) {
                    order.push(Value::String((*adapter).to_owned()));
                }
            }
            preferences.insert("adapter_order".into(), Value::Array(order));
        }
    }

    if let Some(retry) = root.get_mut("retry_policy").and_then(Value::as_object_mut) {
        lowercase_string(retry.get_mut("round_order"));
    }

    normalize_candidate_list(root.get_mut("direct_endpoints"), false)?;
    normalize_candidate_list(root.get_mut("bridges"), true)?;
    Ok(())
}

fn normalize_candidate_list(value: Option<&mut Value>, is_bridge: bool) -> Result<()> {
    let Some(Value::Array(items)) = value else {
        return Ok(());
    };
    let mut normalized = Vec::with_capacity(items.len());
    let mut direct_keys = BTreeSet::new();
    for (index, item) in std::mem::take(items).into_iter().enumerate() {
        let mut item = item;
        let Some(fields) = item.as_object_mut() else {
            normalized.push(item);
            continue;
        };
        canonicalize_ip_value(fields.get_mut("ip"));
        lowercase_string(fields.get_mut("transport"));
        lowercase_string(fields.get_mut("adapter"));
        for key in [
            "label",
            "key_file",
            "route_file",
            "sni",
            "edge_label",
            "tls_ca_file",
            "ws_path",
            "shroud_profile",
            "tls_cert_sha256",
        ] {
            trim_string(fields.get_mut(key));
        }
        if let Some(pin) = fields
            .get("tls_cert_sha256")
            .and_then(Value::as_str)
            .map(str::to_ascii_lowercase)
        {
            fields.insert("tls_cert_sha256".into(), Value::String(pin));
        }
        if let Some(fallback) = fields.get_mut("allowed_fallback") {
            if fallback.is_null() || fallback.as_str() == Some("") {
                *fallback = Value::Array(Vec::new());
            } else if let Some(items) = fallback.as_array_mut() {
                let mut seen = BTreeSet::new();
                let mut values = Vec::with_capacity(items.len());
                for mut name in std::mem::take(items) {
                    lowercase_string(Some(&mut name));
                    if let Some(text) = name.as_str() {
                        if seen.insert(text.to_owned()) {
                            values.push(Value::String(text.to_owned()));
                        }
                    } else {
                        values.push(name);
                    }
                }
                *fallback = Value::Array(values);
            }
        }
        if is_bridge {
            let label = fields
                .get("label")
                .and_then(Value::as_str)
                .filter(|label| !label.is_empty())
                .map(str::to_owned)
                .unwrap_or_else(|| format!("bridge-{}", index + 1));
            fields.insert("label".into(), Value::String(label));
        } else if let (Some(ip), Some(port), Some(transport)) = (
            fields.get("ip").and_then(Value::as_str),
            fields.get("port").and_then(Value::as_u64),
            fields
                .get("transport")
                .and_then(Value::as_str)
                .or(Some("tcp")),
        ) {
            if !direct_keys.insert((transport.to_owned(), ip.to_owned(), port)) {
                continue;
            }
        }
        normalized.push(item);
    }
    *items = normalized;
    Ok(())
}

fn trim_string(value: Option<&mut Value>) {
    let Some(Value::String(text)) = value else {
        return;
    };
    let normalized = text.trim().to_owned();
    if normalized.is_empty() {
        *value.expect("value was matched") = Value::Null;
    } else {
        *text = normalized;
    }
}

fn lowercase_string(value: Option<&mut Value>) {
    let Some(Value::String(text)) = value else {
        return;
    };
    *text = text.trim().to_ascii_lowercase();
}

fn canonicalize_ip_value(value: Option<&mut Value>) {
    let Some(Value::String(text)) = value else {
        return;
    };
    let candidate = text.trim().trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = candidate.parse::<IpAddr>() {
        *text = ip.to_string();
    } else {
        *text = candidate.to_owned();
    }
}

impl DirectEndpoint {
    fn validate(&self) -> Result<()> {
        validate_ip("direct endpoint ip", &self.ip)?;
        validate_port("direct endpoint port", self.port)?;
        validate_adapter(&self.adapter)?;
        let expected_transport = match self.adapter.as_str() {
            "direct-tcp" => "tcp",
            "quic" => "quic",
            "quic-standard" => "quic-standard",
            "offline-mesh" => "offline-mesh",
            "data-mule" => "data-mule",
            _ => {
                return Err(SnapError::Invalid(format!(
                    "direct_endpoints adapter '{}' is not a SHPH direct transport",
                    self.adapter
                )))
            }
        };
        if self.transport != expected_transport {
            return Err(SnapError::Invalid(format!(
                "direct_endpoints adapter '{}' requires transport '{}'",
                self.adapter, expected_transport
            )));
        }
        if self.tls_enabled || self.sni.is_some() || self.edge_label.is_some() {
            return Err(SnapError::Invalid(
                "direct endpoints cannot configure TLS, SNI, or edge_label".into(),
            ));
        }
        validate_priority_weight(self.priority, self.weight)?;
        validate_optional_timeout("direct endpoint timeout_sec", self.timeout_sec)?;
        validate_fallback_names(&self.allowed_fallback)
    }
}

impl Bridge {
    fn validate(
        &self,
        edge_profiles: &BTreeMap<String, EdgeProfile>,
        labels: &mut BTreeSet<String>,
    ) -> Result<()> {
        validate_text("bridge label", &self.label, 128)?;
        if !labels.insert(self.label.clone()) {
            return Err(SnapError::Invalid(format!(
                "duplicate bridge label: {}",
                self.label
            )));
        }
        validate_ip("bridge ip", &self.ip)?;
        validate_port("bridge port", self.port)?;
        let expected_transport = match self.adapter.as_str() {
            "quic" => "quic",
            "quic-standard" => "quic-standard",
            "offline-mesh" => "offline-mesh",
            "data-mule" => "data-mule",
            _ => "onion-tcp",
        };
        if self.transport != expected_transport {
            return Err(SnapError::Invalid(format!(
                "bridge adapter '{}' requires transport '{}'",
                self.adapter, expected_transport
            )));
        }
        validate_adapter(&self.adapter)?;
        if self.adapter == "direct-tcp" {
            return Err(SnapError::Invalid(
                "bridge adapter cannot be direct-tcp".into(),
            ));
        }
        if matches!(
            self.adapter.as_str(),
            "bridge-onion-tcp"
                | "bridge-tls"
                | "bridge-ws"
                | "shroud-tcp"
                | "edge-relay"
                | "mesh-dtn-local"
                | "mule-usb"
        ) && self.key_file.is_none()
        {
            return Err(SnapError::Invalid(format!(
                "{} requires key_file in a Python-compatible SNAP profile",
                self.adapter
            )));
        }
        validate_priority_weight(self.priority, self.weight)?;
        validate_optional_timeout("bridge timeout_sec", self.timeout_sec)?;
        validate_fallback_names(&self.allowed_fallback)?;

        if self.adapter == "bridge-onion-tcp" {
            if self.edge_label.is_some() || self.tls_enabled || self.sni.is_some() {
                return Err(SnapError::Invalid(
                    "bridge-onion-tcp cannot configure TLS, SNI, or edge_label".into(),
                ));
            }
            if self.key_file.is_none() {
                return Err(SnapError::Invalid(
                    "bridge-onion-tcp requires key_file".into(),
                ));
            }
        }
        let requires_tls = matches!(
            self.adapter.as_str(),
            "bridge-tls" | "bridge-ws" | "shroud-tcp" | "edge-relay"
        );
        if requires_tls && (!self.tls_enabled || self.sni.as_deref().is_none_or(str::is_empty)) {
            return Err(SnapError::Invalid(format!(
                "{} requires tls_enabled=true and a non-empty sni",
                self.adapter
            )));
        }
        if let Some(label) = &self.edge_label {
            if !edge_profiles.contains_key(label) {
                return Err(SnapError::Invalid(format!(
                    "edge_label references an unknown edge profile: {label}"
                )));
            }
        } else if requires_tls {
            return Err(SnapError::Invalid(format!(
                "{} requires edge_label",
                self.adapter
            )));
        }
        if self.adapter == "bridge-ws" && self.ws_path.is_none() {
            return Err(SnapError::Invalid("bridge-ws requires ws_path".into()));
        }
        if let Some(path) = &self.ws_path {
            validate_ws_path(path)?;
            if !matches!(self.adapter.as_str(), "bridge-ws" | "shroud-tcp") {
                return Err(SnapError::Invalid(
                    "ws_path is only valid for bridge-ws or shroud-tcp".into(),
                ));
            }
        }
        if let Some(profile) = &self.shroud_profile {
            if self.adapter != "shroud-tcp"
                || !matches!(
                    profile.as_str(),
                    "low-latency"
                        | "balanced"
                        | "bulk"
                        | "interactive"
                        | "stealth-safe"
                        | "default"
                        | "bulk-transfer"
                )
            {
                return Err(SnapError::Invalid(
                    "invalid shroud_profile for this bridge".into(),
                ));
            }
        }
        if let Some(contract) = &self.operator_service_contract {
            if matches!(self.adapter.as_str(), "mesh-dtn-local" | "mule-usb") {
                return Err(SnapError::Invalid(
                    "operator_service_contract is only valid for network bridges and relays".into(),
                ));
            }
            contract.validate()?;
        }
        if let Some(pin) = &self.tls_cert_sha256 {
            if pin.len() != 64 || !pin.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(SnapError::Invalid(
                    "tls_cert_sha256 must be a 64-character SHA-256 hex value".into(),
                ));
            }
        }
        if self.tls_ca_file.is_some() && !self.tls_enabled {
            return Err(SnapError::Invalid(
                "tls_ca_file requires tls_enabled=true".into(),
            ));
        }
        for (name, file) in [
            ("key_file", self.key_file.as_deref()),
            ("route_file", self.route_file.as_deref()),
            ("tls_ca_file", self.tls_ca_file.as_deref()),
        ] {
            if let Some(file) = file {
                validate_text(name, file, 4096)?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CandidateKind {
    Direct,
    Bridge,
}

#[derive(Debug, Clone, Serialize)]
pub struct SnapCandidate {
    pub kind: CandidateKind,
    pub adapter: String,
    pub transport: String,
    pub target_host: String,
    pub target_port: u16,
    pub source: String,
    pub priority: u16,
    pub weight: u16,
    pub timeout_sec: Option<f64>,
    pub allowed_fallback: Vec<String>,
    pub edge_label: Option<String>,
    pub route_file: Option<String>,
    pub tls_enabled: Option<bool>,
    pub sni: Option<String>,
    pub tls_ca_file: Option<String>,
    pub tls_cert_sha256: Option<String>,
    pub ws_path: Option<String>,
    pub shroud_profile: Option<String>,
    pub relay_ip: Option<String>,
    pub relay_port: Option<u16>,
    pub key_file: Option<String>,
    #[serde(skip_serializing)]
    pub operator_service_contract: Option<OperatorServiceContract>,
    #[serde(skip_serializing)]
    candidate_id: String,
    #[serde(skip)]
    insertion_index: usize,
}

impl SnapCandidate {
    #[allow(clippy::too_many_arguments)]
    fn new(
        kind: CandidateKind,
        adapter: String,
        transport: String,
        target_host: String,
        target_port: u16,
        source: String,
        priority: u16,
        weight: u16,
        timeout_sec: Option<f64>,
        allowed_fallback: Vec<String>,
        edge_label: Option<String>,
        route_file: Option<String>,
        tls_enabled: Option<bool>,
        sni: Option<String>,
        tls_ca_file: Option<String>,
        tls_cert_sha256: Option<String>,
        ws_path: Option<String>,
        shroud_profile: Option<String>,
        insertion_index: usize,
    ) -> Self {
        Self {
            kind,
            adapter,
            transport,
            target_host,
            target_port,
            source,
            priority,
            weight,
            timeout_sec,
            allowed_fallback,
            edge_label,
            route_file,
            tls_enabled,
            sni,
            tls_ca_file,
            tls_cert_sha256,
            ws_path,
            shroud_profile,
            relay_ip: None,
            relay_port: None,
            key_file: None,
            operator_service_contract: None,
            candidate_id: String::new(),
            insertion_index,
        }
    }

    fn with_relay(mut self, ip: String, port: u16, key_file: Option<String>) -> Self {
        self.relay_ip = Some(ip);
        self.relay_port = Some(port);
        self.key_file = key_file;
        self
    }

    fn with_operator_service_contract(mut self, contract: Option<OperatorServiceContract>) -> Self {
        self.operator_service_contract = contract;
        self
    }

    fn compute_id(&self) -> String {
        // Match Python SNAP's public candidate-id payload. SHPH-only fields
        // such as relay key references and service contracts stay out of the
        // digest inputs so shared profile fields retain comparable IDs.
        let kind = match self.kind {
            CandidateKind::Direct => "direct",
            CandidateKind::Bridge => "bridge",
        };
        let canonical = serde_json::to_string(&serde_json::json!({
            "kind": kind,
            "adapter": self.adapter,
            "target_ip": self.target_host,
            "target_port": self.target_port,
            "tls_enabled": self.tls_enabled.unwrap_or(false),
            "sni": self.sni,
            "tls_ca_file": self.tls_ca_file,
            "tls_cert_sha256": self.tls_cert_sha256,
            "ws_path": self.ws_path,
            "route_file": self.route_file,
            "source": self.source,
            "priority": self.priority,
            "weight": self.weight,
            "timeout_sec": self.timeout_sec,
            "allowed_fallback": self.allowed_fallback,
            "edge_label": self.edge_label,
            "shroud_profile": self.shroud_profile,
        }))
        .unwrap_or_default();
        let canonical = escape_non_ascii_json(&canonical);
        hex::encode(Sha256::digest(canonical.as_bytes()))[..16].to_owned()
    }

    pub fn id(&self) -> &str {
        &self.candidate_id
    }
}

fn escape_non_ascii_json(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut in_string = false;
    let mut escaped = false;

    for ch in input.chars() {
        if !in_string {
            output.push(ch);
            if ch == '"' {
                in_string = true;
            }
            continue;
        }

        if escaped {
            output.push(ch);
            escaped = false;
            continue;
        }

        match ch {
            '\\' => {
                output.push(ch);
                escaped = true;
            }
            '"' => {
                output.push(ch);
                in_string = false;
            }
            ch if !ch.is_ascii() => {
                let codepoint = ch as u32;
                if codepoint <= 0xffff {
                    output.push_str(&format!("\\u{codepoint:04x}"));
                } else {
                    let adjusted = codepoint - 0x1_0000;
                    let high = 0xd800 + (adjusted >> 10);
                    let low = 0xdc00 + (adjusted & 0x3ff);
                    output.push_str(&format!("\\u{high:04x}\\u{low:04x}"));
                }
            }
            _ => output.push(ch),
        }
    }

    output
}

#[derive(Debug, Clone, Serialize)]
pub struct SnapPlan {
    pub profile_name: String,
    pub profile_hash: String,
    pub peer_alias: String,
    pub connect_timeout_sec: f64,
    pub retry_policy: RetryPolicy,
    pub attempt_limit: usize,
    pub candidates: Vec<SnapCandidate>,
}

impl SnapPlan {
    pub fn effective_candidate_timeout_sec(&self, candidate: &SnapCandidate) -> f64 {
        candidate
            .timeout_sec
            .or_else(|| adapter_default_timeout_sec(&candidate.adapter))
            .unwrap_or(self.connect_timeout_sec)
    }

    pub fn effective_candidate_timeout_source(&self, candidate: &SnapCandidate) -> &'static str {
        if candidate.timeout_sec.is_some() {
            "candidate_timeout"
        } else if adapter_default_timeout_sec(&candidate.adapter).is_some() {
            "adapter_default"
        } else {
            "profile_default"
        }
    }

    pub fn candidate_allows_fallback(&self, from: &SnapCandidate, to: &SnapCandidate) -> bool {
        from.allowed_fallback.is_empty() || from.allowed_fallback.contains(&to.adapter)
    }

    pub fn candidates_for_round(&self, round_index: u32) -> Vec<SnapCandidate> {
        self.retry_policy
            .ordered_round(&self.candidates, round_index)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AttemptOutcome {
    Connected,
    RetryableFailure,
    TerminalFailure,
    FallbackDenied,
    BudgetExceeded,
}

/// Correlation data shared by all sanitized events for one SNAP connection
/// operation. The peer reference is a one-way hash of the locally pinned
/// fingerprint; endpoints and profile file paths are intentionally excluded.
#[derive(Debug, Clone, Serialize)]
pub struct SnapAuditContext {
    pub profile_name: String,
    pub profile_hash: String,
    pub peer_ref: String,
    pub plan_id: String,
    pub correlation_id: String,
}

impl SnapAuditContext {
    pub fn new(plan: &SnapPlan, pinned_peer_fingerprint: &str) -> Self {
        let peer_source = if pinned_peer_fingerprint.trim().is_empty() {
            plan.peer_alias.trim().to_ascii_lowercase()
        } else {
            pinned_peer_fingerprint.trim().to_ascii_lowercase()
        };
        let peer_ref = short_sha256(peer_source.as_bytes());
        let candidate_ids: Vec<&str> = plan.candidates.iter().map(SnapCandidate::id).collect();
        let plan_material = serde_json::json!({
            "profile_hash": plan.profile_hash,
            "peer_ref": peer_ref,
            "candidate_ids": candidate_ids,
        });
        let plan_bytes = serde_json::to_vec(&plan_material)
            .expect("SNAP audit plan material is always JSON-serializable");
        let plan_id = short_sha256(&plan_bytes);
        let mut correlation = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut correlation);

        Self {
            profile_name: plan.profile_name.clone(),
            profile_hash: plan.profile_hash.clone(),
            peer_ref,
            plan_id,
            correlation_id: hex::encode(correlation),
        }
    }
}

fn short_sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))[..16].to_owned()
}

/// Safe path-attempt context. It intentionally excludes endpoints, profile
/// paths, relay keys, and transport error strings.
#[derive(Debug, Clone, Serialize)]
pub struct SnapAuditEvent {
    pub schema_version: u8,
    pub event_name: String,
    pub component: String,
    pub profile_name: String,
    pub profile_hash: String,
    pub peer_ref: String,
    pub plan_id: String,
    pub correlation_id: String,
    pub candidate_id: String,
    pub candidate_source: String,
    pub adapter: String,
    pub edge_label: String,
    pub shroud_profile: Option<String>,
    pub round_index: u32,
    pub attempt_index: u32,
    pub effective_timeout_ms: Option<u64>,
    pub elapsed_ms: u64,
    pub outcome: AttemptOutcome,
    pub result: String,
    pub normalized_failure_reason: String,
    pub detail_code: String,
    pub selected_path_type: CandidateKind,
    pub latency_ms: Option<f64>,
}

impl SnapAuditEvent {
    pub fn new(
        context: &SnapAuditContext,
        candidate: &SnapCandidate,
        round: u32,
        attempt: u32,
        outcome: AttemptOutcome,
        elapsed_ms: u64,
    ) -> Self {
        let (event_name, result, reason, detail_code) = match outcome {
            AttemptOutcome::Connected => (
                "snap_connect_established",
                "success",
                "",
                "session_established",
            ),
            AttemptOutcome::RetryableFailure => (
                "snap_candidate_failed",
                "failure",
                "retryable_failure",
                "adapter_or_connection_failure",
            ),
            AttemptOutcome::TerminalFailure => (
                "snap_candidate_failed",
                "failure",
                "terminal_failure",
                "identity_authentication_or_protocol_failure",
            ),
            AttemptOutcome::FallbackDenied => (
                "snap_fallback_triggered",
                "skipped",
                "fallback_policy_denied",
                "blocked_by_allowed_fallback",
            ),
            AttemptOutcome::BudgetExceeded => (
                "snap_candidate_failed",
                "failure",
                "connect_budget_exceeded",
                "connect_budget_exceeded",
            ),
        };
        Self {
            schema_version: 1,
            event_name: event_name.into(),
            component: "snapv2".into(),
            profile_name: context.profile_name.clone(),
            profile_hash: context.profile_hash.clone(),
            peer_ref: context.peer_ref.clone(),
            plan_id: context.plan_id.clone(),
            correlation_id: context.correlation_id.clone(),
            candidate_id: candidate.id().to_owned(),
            candidate_source: candidate.source.clone(),
            adapter: candidate.adapter.clone(),
            edge_label: candidate.edge_label.clone().unwrap_or_default(),
            shroud_profile: candidate.shroud_profile.clone(),
            round_index: round,
            attempt_index: attempt,
            effective_timeout_ms: None,
            elapsed_ms,
            outcome,
            result: result.into(),
            normalized_failure_reason: reason.into(),
            detail_code: detail_code.into(),
            selected_path_type: candidate.kind,
            latency_ms: None,
        }
    }

    pub fn with_effective_timeout_ms(mut self, timeout_ms: u64) -> Self {
        self.effective_timeout_ms = Some(timeout_ms);
        self
    }

    pub fn with_normalized_failure_reason(mut self, reason: &'static str) -> Self {
        self.normalized_failure_reason = reason.into();
        self
    }
}

fn validate_adapter_order(order: &[String]) -> Result<()> {
    for adapter in order {
        validate_adapter(adapter)?;
    }
    Ok(())
}

fn validate_adapter(adapter: &str) -> Result<()> {
    if !KNOWN_ADAPTERS.contains(&adapter) {
        return Err(SnapError::Invalid(format!(
            "unsupported adapter name: {adapter}"
        )));
    }
    Ok(())
}

fn validate_fallback_names(names: &[String]) -> Result<()> {
    for name in names {
        validate_adapter(name)?;
    }
    Ok(())
}

fn validate_priority_weight(priority: u16, weight: u16) -> Result<()> {
    if priority > 1000 {
        return Err(SnapError::Invalid("priority must not exceed 1000".into()));
    }
    if !(1..=1000).contains(&weight) {
        return Err(SnapError::Invalid(
            "weight must be between 1 and 1000".into(),
        ));
    }
    Ok(())
}

fn validate_optional_timeout(field: &str, value: Option<f64>) -> Result<()> {
    if let Some(value) = value {
        validate_range(field, value, 0.2, 120.0)?;
    }
    Ok(())
}

fn validate_range(field: &str, value: f64, min: f64, max: f64) -> Result<()> {
    if !value.is_finite() || !(min..=max).contains(&value) {
        return Err(SnapError::Invalid(format!(
            "{field} must be between {min} and {max}"
        )));
    }
    Ok(())
}

fn validate_text(field: &str, value: &str, max: usize) -> Result<()> {
    if value.trim().is_empty() || value.len() > max || value.chars().any(char::is_control) {
        return Err(SnapError::Invalid(format!("{field} is invalid")));
    }
    Ok(())
}

fn validate_host(field: &str, value: &str) -> Result<()> {
    validate_text(field, value, 253)?;
    if value.chars().any(char::is_whitespace) || value.contains('/') {
        return Err(SnapError::Invalid(format!("{field} is invalid")));
    }
    Ok(())
}

fn validate_ip(field: &str, value: &str) -> Result<()> {
    value
        .parse::<IpAddr>()
        .map(|_| ())
        .map_err(|_| SnapError::Invalid(format!("{field} must be a literal IP address")))
}

fn validate_port(field: &str, value: u16) -> Result<()> {
    if value == 0 {
        return Err(SnapError::Invalid(format!("{field} must be non-zero")));
    }
    Ok(())
}

fn validate_ws_path(value: &str) -> Result<()> {
    if !value.starts_with('/')
        || value.len() > 1024
        || value
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(SnapError::Invalid(
            "ws_path must be an absolute path without whitespace".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        AttemptOutcome, ProfileFormat, RetryPolicy, RoundOrder, SnapAuditContext, SnapAuditEvent,
        SnapProfile, DEFAULT_ADAPTER_ORDER,
    };

    const JSON_PROFILE: &str = r#"{
        "version": 1,
        "profile_name": "lab",
        "mode": "auto",
        "peer_alias": "peer1",
        "connect_timeout_sec": 8.0,
        "transport_preferences": {"adapter_order": ["direct-tcp", "bridge-tls"]},
        "retry_policy": {"rounds": 2, "backoff_base_sec": 0.6, "backoff_max_sec": 8.0,
            "jitter_ratio": 0.0, "round_order": "rotate", "shuffle_seed": 7,
            "max_total_attempts": 3, "max_elapsed_sec": 10.0},
        "direct_endpoints": [{"ip": "127.0.0.1", "port": 7000}],
        "bridges": [],
        "edge_profiles": {}
    }"#;

    const TOML_PROFILE: &str = r#"
version = 1
profile_name = "lab"
mode = "auto"
peer_alias = "peer1"
connect_timeout_sec = 8.0

[transport_preferences]
adapter_order = ["direct-tcp", "bridge-tls"]

[retry_policy]
rounds = 2
backoff_base_sec = 0.6
backoff_max_sec = 8.0
jitter_ratio = 0.0
round_order = "rotate"
shuffle_seed = 7
max_total_attempts = 3
max_elapsed_sec = 10.0

[[direct_endpoints]]
ip = "127.0.0.1"
port = 7000
"#;

    #[test]
    fn json_and_toml_profiles_produce_equivalent_plans() {
        let json = SnapProfile::parse(JSON_PROFILE.as_bytes(), ProfileFormat::Json).unwrap();
        let toml = SnapProfile::parse(TOML_PROFILE.as_bytes(), ProfileFormat::Toml).unwrap();
        assert_eq!(json.profile_hash(), toml.profile_hash());
        let left = json.plan("127.0.0.1", 7001).unwrap();
        let right = toml.plan("127.0.0.1", 7001).unwrap();
        assert_eq!(left.profile_hash, right.profile_hash);
        assert_eq!(left.candidates[0].id(), right.candidates[0].id());
        assert_eq!(left.candidates[0].target_port, 7000);
        assert_eq!(left.attempt_limit, 2);
    }

    #[test]
    fn strict_profiles_reject_unknown_fields_and_unsupported_versions() {
        let unknown = JSON_PROFILE.replace(
            "\"mode\": \"auto\",",
            "\"mode\": \"auto\", \"surprise\": true,",
        );
        assert!(SnapProfile::parse(unknown.as_bytes(), ProfileFormat::Json).is_err());
        let future = JSON_PROFILE.replace("\"version\": 1", "\"version\": 2");
        assert!(SnapProfile::parse(future.as_bytes(), ProfileFormat::Json).is_err());
    }

    #[test]
    fn json_profiles_reject_duplicate_keys_at_every_depth() {
        let duplicate_root =
            JSON_PROFILE.replace("\"version\": 1,", "\"version\": 1, \"version\": 1,");
        assert!(SnapProfile::parse(duplicate_root.as_bytes(), ProfileFormat::Json).is_err());

        let duplicate_nested = JSON_PROFILE.replace(
            "\"adapter_order\": [",
            "\"adapter_order\": [], \"adapter_order\": [",
        );
        assert!(SnapProfile::parse(duplicate_nested.as_bytes(), ProfileFormat::Json).is_err());

        let duplicate_toml = b"version = 1\nversion = 1\npeer_alias = \"peer1\"\n";
        assert!(SnapProfile::parse(duplicate_toml, ProfileFormat::Toml).is_err());
    }

    #[test]
    fn python_compatible_profile_normalization_is_stable() {
        let raw = r#"{
            "version": 1,
            "profile_name": "  normalized  ",
            "mode": " AUTO ",
            "peer_alias": " peer1 ",
            "transport_preferences": {"adapter_order": [" QUIC ", "quic"]},
            "direct_endpoints": [
                {"ip": "[2001:0db8::1]", "port": 7000},
                {"ip": "2001:db8::1", "port": 7000}
            ],
            "bridges": [
                {"adapter": " QUIC ", "transport": " QUIC ", "ip": "[2001:db8::2]", "port": 7001}
            ]
        }"#;
        let profile = SnapProfile::parse(raw.as_bytes(), ProfileFormat::Json).unwrap();
        assert_eq!(profile.profile_name, "normalized");
        assert_eq!(profile.peer_alias, "peer1");
        assert_eq!(profile.transport_preferences.adapter_order[0], "quic");
        assert_eq!(profile.direct_endpoints.len(), 1);
        assert_eq!(profile.direct_endpoints[0].ip, "2001:db8::1");
        assert_eq!(profile.bridges[0].label, "bridge-1");
        assert_eq!(profile.bridges[0].adapter, "quic");
        assert_eq!(profile.bridges[0].ip, "2001:db8::2");
    }

    #[test]
    fn planner_orders_by_priority_then_adapter_then_weight() {
        let profile = SnapProfile::parse(
            br#"{"version":1,"peer_alias":"peer1","transport_preferences":{"adapter_order":["bridge-tls","direct-tcp"]},"direct_endpoints":[{"ip":"127.0.0.2","port":2,"priority":10,"weight":200},{"ip":"127.0.0.1","port":1,"priority":10,"weight":100}],"bridges":[{"label":"tls","ip":"127.0.0.3","port":3,"key_file":"relay.key","adapter":"bridge-tls","tls_enabled":true,"sni":"localhost","edge_label":"edge","priority":10}],"edge_profiles":{"edge":{"host":"127.0.0.4","port":443}}}"#,
            ProfileFormat::Json,
        )
        .unwrap();
        let plan = profile.plan("127.0.0.1", 7000).unwrap();
        assert_eq!(plan.candidates[0].adapter, "bridge-tls");
        assert_eq!(plan.candidates[1].weight, 200);
        assert_eq!(plan.candidates[2].target_port, 1);
    }

    #[test]
    fn python_default_and_partial_adapter_orders_match_reference() {
        let make_profile = |preferences: &str| {
            format!(
                r#"{{
                    "version":1,
                    "peer_alias":"peer1",
                    "mode":"bridges-only",
                    "transport_preferences":{preferences},
                    "bridges":[
                        {{"label":"shroud","ip":"127.0.0.1","port":9001,"key_file":"relay.key","adapter":"shroud-tcp","tls_enabled":true,"sni":"localhost","edge_label":"edge"}},
                        {{"label":"edge","ip":"127.0.0.1","port":9002,"key_file":"relay.key","adapter":"edge-relay","tls_enabled":true,"sni":"localhost","edge_label":"edge"}}
                    ],
                    "edge_profiles":{{"edge":{{"host":"127.0.0.1","port":8443}}}}
                }}"#
            )
        };

        let default_profile =
            SnapProfile::parse(make_profile("{}").as_bytes(), ProfileFormat::Json).unwrap();
        let default_plan = default_profile.plan("127.0.0.1", 7000).unwrap();
        assert_eq!(default_plan.candidates[0].adapter, "edge-relay");
        assert_eq!(default_plan.candidates[1].adapter, "shroud-tcp");

        let partial_profile = SnapProfile::parse(
            make_profile(r#"{"adapter_order":["SHROUD-TCP","shroud-tcp"]}"#).as_bytes(),
            ProfileFormat::Json,
        )
        .unwrap();
        let partial_plan = partial_profile.plan("127.0.0.1", 7000).unwrap();
        assert_eq!(partial_plan.candidates[0].adapter, "shroud-tcp");
        assert_eq!(partial_plan.candidates[1].adapter, "edge-relay");
        assert_eq!(
            partial_profile.transport_preferences.adapter_order.len(),
            DEFAULT_ADAPTER_ORDER.len()
        );
    }

    #[test]
    fn malformed_adapter_order_types_are_rejected_like_python_snap() {
        let json = br#"{"version":1,"peer_alias":"peer1","transport_preferences":{"adapter_order":"direct-tcp"}}"#;
        assert!(SnapProfile::parse(json, ProfileFormat::Json).is_err());

        let toml = b"version = 1\npeer_alias = \"peer1\"\n\n[transport_preferences]\nadapter_order = \"direct-tcp\"\n";
        assert!(SnapProfile::parse(toml, ProfileFormat::Toml).is_err());
    }

    #[test]
    fn python_adapter_timeout_defaults_and_candidate_overrides_are_preserved() {
        let profile = SnapProfile::parse(
            br#"{
                "version":1,
                "peer_alias":"peer1",
                "mode":"bridges-only",
                "connect_timeout_sec":7.0,
                "bridges":[
                    {"label":"ws","ip":"127.0.0.1","port":9001,"key_file":"ws.key","adapter":"bridge-ws","tls_enabled":true,"sni":"localhost","edge_label":"edge","ws_path":"/snap"},
                    {"label":"shroud","ip":"127.0.0.1","port":9002,"key_file":"shroud.key","adapter":"shroud-tcp","tls_enabled":true,"sni":"localhost","edge_label":"edge","timeout_sec":3.0}
                ],
                "edge_profiles":{"edge":{"host":"127.0.0.1","port":8443}}
            }"#,
            ProfileFormat::Json,
        )
        .unwrap();
        let plan = profile.plan("127.0.0.1", 7000).unwrap();
        let ws = plan
            .candidates
            .iter()
            .find(|candidate| candidate.adapter == "bridge-ws")
            .unwrap();
        let shroud = plan
            .candidates
            .iter()
            .find(|candidate| candidate.adapter == "shroud-tcp")
            .unwrap();

        assert_eq!(plan.effective_candidate_timeout_sec(ws), 12.0);
        assert_eq!(
            plan.effective_candidate_timeout_source(ws),
            "adapter_default"
        );
        assert_eq!(plan.effective_candidate_timeout_sec(shroud), 3.0);
        assert_eq!(
            plan.effective_candidate_timeout_source(shroud),
            "candidate_timeout"
        );
    }

    #[test]
    fn shph_native_extensions_keep_profile_order_after_python_defaults() {
        let profile = SnapProfile::parse(
            br#"{
                "version":1,
                "peer_alias":"peer1",
                "mode":"direct-only",
                "direct_endpoints":[
                    {"ip":"127.0.0.1","port":7001,"adapter":"data-mule","transport":"data-mule"},
                    {"ip":"127.0.0.1","port":7002,"adapter":"offline-mesh","transport":"offline-mesh"},
                    {"ip":"127.0.0.1","port":7003,"adapter":"quic","transport":"quic"},
                    {"ip":"127.0.0.1","port":7004,"adapter":"direct-tcp","transport":"tcp"}
                ]
            }"#,
            ProfileFormat::Json,
        )
        .unwrap();

        let plan = profile.plan("127.0.0.1", 7000).unwrap();
        let adapters: Vec<&str> = plan
            .candidates
            .iter()
            .map(|candidate| candidate.adapter.as_str())
            .collect();
        assert_eq!(
            adapters,
            vec!["direct-tcp", "data-mule", "offline-mesh", "quic"]
        );
    }

    #[test]
    fn native_shph_transport_candidates_are_strictly_typed() {
        for (adapter, transport) in [
            ("quic", "quic"),
            ("quic-standard", "quic-standard"),
            ("offline-mesh", "offline-mesh"),
            ("data-mule", "data-mule"),
        ] {
            let input = format!(
                r#"{{"version":1,"peer_alias":"peer1","mode":"direct-only","direct_endpoints":[{{"ip":"127.0.0.1","port":7443,"adapter":"{adapter}","transport":"{transport}"}}]}}"#
            );
            let profile = SnapProfile::parse(input.as_bytes(), ProfileFormat::Json).unwrap();
            let plan = profile.plan("127.0.0.1", 443).unwrap();
            assert_eq!(plan.candidates[0].adapter, adapter);
            assert_eq!(plan.candidates[0].transport, transport);
        }

        let mismatched = br#"{"version":1,"peer_alias":"peer1","mode":"direct-only","direct_endpoints":[{"ip":"127.0.0.1","port":7443,"adapter":"quic","transport":"tcp"}]}"#;
        assert!(SnapProfile::parse(mismatched, ProfileFormat::Json).is_err());
    }

    #[test]
    fn explicit_fallback_graph_must_resolve_and_be_acyclic() {
        let cycle = br#"{"version":1,"peer_alias":"peer1","direct_endpoints":[{"ip":"127.0.0.1","port":7000,"allowed_fallback":["bridge-onion-tcp"]}],"bridges":[{"label":"bridge","ip":"127.0.0.2","port":7001,"key_file":"relay.key","allowed_fallback":["direct-tcp"]}]}"#;
        assert!(SnapProfile::parse(cycle, ProfileFormat::Json).is_err());
        let missing = br#"{"version":1,"peer_alias":"peer1","direct_endpoints":[{"ip":"127.0.0.1","port":7000,"allowed_fallback":["bridge-tls"]}]}"#;
        assert!(SnapProfile::parse(missing, ProfileFormat::Json).is_err());
    }

    #[test]
    fn explicit_fallback_policy_allows_only_listed_adapter_switches() {
        let profile = SnapProfile::parse(
            br#"{
                "version":1,
                "peer_alias":"peer1",
                "direct_endpoints":[
                    {"ip":"127.0.0.1","port":7000,"priority":1,"allowed_fallback":["direct-tcp"]},
                    {"ip":"127.0.0.1","port":7001,"priority":2},
                    {"ip":"127.0.0.1","port":7002,"priority":3,"adapter":"quic","transport":"quic"}
                ]
            }"#,
            ProfileFormat::Json,
        )
        .unwrap();
        let plan = profile.plan("127.0.0.1", 7003).unwrap();
        assert!(plan.candidate_allows_fallback(&plan.candidates[0], &plan.candidates[1]));
        assert!(!plan.candidate_allows_fallback(&plan.candidates[0], &plan.candidates[2]));
    }

    #[test]
    fn retry_order_rotate_and_budgets_are_bounded() {
        let policy = RetryPolicy {
            rounds: 3,
            round_order: RoundOrder::Rotate,
            max_total_attempts: 4,
            jitter_ratio: 0.0,
            ..RetryPolicy::default()
        };
        assert_eq!(policy.attempt_limit(3), 4);
        assert_eq!(policy.ordered_round(&[1, 2, 3], 2), vec![2, 3, 1]);
        assert_eq!(policy.backoff_after_round(1, 0.5), 0.6);
        assert_eq!(policy.backoff_after_round(3, 0.5), 0.0);
    }

    #[test]
    fn seeded_shuffle_matches_python_random_for_each_round() {
        let policy = RetryPolicy {
            rounds: 2,
            round_order: RoundOrder::Shuffle,
            shuffle_seed: Some(42),
            ..RetryPolicy::default()
        };
        assert_eq!(
            policy.ordered_round(&['a', 'b', 'c', 'd'], 1),
            vec!['c', 'd', 'b', 'a']
        );
        assert_eq!(
            policy.ordered_round(&['a', 'b', 'c', 'd'], 2),
            vec!['b', 'a', 'c', 'd']
        );
    }

    #[test]
    fn absent_direct_endpoint_uses_the_pinned_peer_endpoint() {
        let profile = SnapProfile::parse(
            br#"{"version":1,"peer_alias":"peer1"}"#,
            ProfileFormat::Json,
        )
        .unwrap();
        let plan = profile.plan("127.0.0.1", 443).unwrap();
        assert_eq!(plan.candidates.len(), 1);
        assert_eq!(plan.candidates[0].target_host, "127.0.0.1");
        assert_eq!(plan.candidates[0].target_port, 443);
        assert_eq!(plan.candidates[0].adapter, "direct-tcp");
    }

    #[test]
    fn candidate_id_matches_python_snap_for_shared_profile_fields() {
        let profile = SnapProfile::parse(JSON_PROFILE.as_bytes(), ProfileFormat::Json).unwrap();
        let plan = profile.plan("127.0.0.1", 7001).unwrap();
        assert_eq!(plan.candidates[0].id(), "f77211022051ea33");

        let bridge_profile = SnapProfile::parse(
            br#"{"version":1,"peer_alias":"peer1","mode":"bridges-only","bridges":[{"label":"tls","ip":"127.0.0.3","port":3,"key_file":"relay.key","adapter":"bridge-tls","tls_enabled":true,"sni":"localhost","edge_label":"edge","priority":10}],"edge_profiles":{"edge":{"host":"127.0.0.4","port":443}}}"#,
            ProfileFormat::Json,
        )
        .unwrap();
        let bridge_plan = bridge_profile.plan("127.0.0.1", 7001).unwrap();
        assert_eq!(bridge_plan.candidates[0].id(), "be589d0c92832015");
    }

    #[test]
    fn candidate_id_matches_python_snap_unicode_escaping() {
        let profiles = [
            (
                br#"{"version":1,"peer_alias":"peer1","mode":"bridges-only","bridges":[{"label":"relay-\u2603","ip":"127.0.0.3","port":3,"key_file":"relay.key","adapter":"bridge-tls","tls_enabled":true,"sni":"localhost","edge_label":"edge","priority":10}],"edge_profiles":{"edge":{"host":"127.0.0.4","port":443}}}"#.as_slice(),
                "72c98e26ddd290de",
            ),
            (
                br#"{"version":1,"peer_alias":"peer1","mode":"bridges-only","bridges":[{"label":"relay-\ud83d\ude80","ip":"127.0.0.3","port":3,"key_file":"relay.key","adapter":"bridge-tls","tls_enabled":true,"sni":"localhost","edge_label":"edge","priority":10}],"edge_profiles":{"edge":{"host":"127.0.0.4","port":443}}}"#.as_slice(),
                "1dd307fed62aa983",
            ),
        ];

        for (bytes, expected_id) in profiles {
            let profile = SnapProfile::parse(bytes, ProfileFormat::Json).unwrap();
            let plan = profile.plan("127.0.0.1", 7001).unwrap();
            assert_eq!(plan.candidates[0].id(), expected_id);
        }
    }

    #[test]
    fn audit_event_omits_endpoints_and_private_file_paths() {
        let profile = SnapProfile::parse(JSON_PROFILE.as_bytes(), ProfileFormat::Json).unwrap();
        let plan = profile.plan("127.0.0.1", 7001).unwrap();
        let context = SnapAuditContext::new(&plan, "ABCD1234");
        let second_context = SnapAuditContext::new(&plan, "ABCD1234");
        assert_eq!(context.peer_ref, second_context.peer_ref);
        assert_eq!(context.plan_id, second_context.plan_id);
        assert_ne!(context.correlation_id, second_context.correlation_id);

        let event = SnapAuditEvent::new(
            &context,
            &plan.candidates[0],
            1,
            1,
            AttemptOutcome::RetryableFailure,
            12,
        )
        .with_effective_timeout_ms(800);
        let rendered = serde_json::to_string(&event).unwrap();
        assert!(rendered.contains("retryable_failure"));
        assert!(rendered.contains("\"profile_name\""));
        assert!(rendered.contains("\"peer_ref\""));
        assert!(rendered.contains("\"plan_id\""));
        assert!(rendered.contains("\"correlation_id\""));
        assert!(rendered.contains("\"candidate_source\""));
        assert!(rendered.contains("\"effective_timeout_ms\":800"));
        assert!(!rendered.contains("127.0.0.1"));
        assert!(!rendered.contains("key_file"));
    }
}
