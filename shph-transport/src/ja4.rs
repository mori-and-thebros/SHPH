//! Optional passive JA4-compatible TLS ClientHello observability.
//!
//! This module never changes a ClientHello, certificate choice, or QUIC wire
//! behavior. The exact JA4 algorithm is available for callers that provide
//! complete ClientHello metadata. The live rustls resolver hook exposes only
//! a public subset of that metadata, so live observations are explicitly
//! marked as partial rather than being presented as exact JA4 values.

use std::collections::VecDeque;
use std::fmt;
use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};

use quinn::rustls::{
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use shph_core::{Result, ShphError};

const GREASE_MASK: u16 = 0x0f0f;
const GREASE_VALUE: u16 = 0x0a0a;
const TLS_EXT_SERVER_NAME: u16 = 0x0000;
const TLS_EXT_SUPPORTED_GROUPS: u16 = 0x000a;
const TLS_EXT_ALPN: u16 = 0x0010;
const MAX_OBSERVED_LIST_VALUES: usize = 128;
const MAX_OBSERVED_ALPN_VALUES: usize = 16;
const MAX_OBSERVED_ALPN_BYTES: usize = 256;
const MAX_OBSERVED_SERVER_NAME_BYTES: usize = 255;
const MAX_OBSERVATIONS: usize = 4096;

/// Transport marker used by the JA4 first fingerprint chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ja4Transport {
    /// TLS carried by a stream transport such as TCP.
    Tcp,
    /// TLS carried by QUIC.
    Quic,
    /// Datagram TLS.
    Dtls,
}

impl Ja4Transport {
    fn marker(self) -> char {
        match self {
            Self::Tcp => 't',
            Self::Quic => 'q',
            Self::Dtls => 'd',
        }
    }
}

/// TLS version marker used by the JA4 first fingerprint chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ja4TlsVersion {
    /// SSL 2.0.
    Ssl2,
    /// SSL 3.0.
    Ssl3,
    /// TLS 1.0.
    Tls1_0,
    /// TLS 1.1.
    Tls1_1,
    /// TLS 1.2.
    Tls1_2,
    /// TLS 1.3.
    Tls1_3,
    /// An unrecognized version.
    Unknown,
}

impl Ja4TlsVersion {
    /// Convert a wire version into the JA4 version marker.
    pub fn from_wire(value: u16) -> Self {
        match value {
            0x0002 => Self::Ssl2,
            0x0300 => Self::Ssl3,
            0x0301 => Self::Tls1_0,
            0x0302 => Self::Tls1_1,
            0x0303 => Self::Tls1_2,
            0x0304 => Self::Tls1_3,
            _ => Self::Unknown,
        }
    }
}

impl fmt::Display for Ja4TlsVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let marker = match self {
            Self::Ssl2 => "s2",
            Self::Ssl3 => "s3",
            Self::Tls1_0 => "10",
            Self::Tls1_1 => "11",
            Self::Tls1_2 => "12",
            Self::Tls1_3 => "13",
            Self::Unknown => "00",
        };
        formatter.write_str(marker)
    }
}

/// Complete ClientHello metadata required to compute an exact JA4 value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ja4ClientHello {
    /// The underlying TLS transport.
    pub transport: Ja4Transport,
    /// The highest applicable TLS version from the ClientHello.
    pub tls_version: Ja4TlsVersion,
    /// Whether the SNI extension was present.
    pub server_name_present: bool,
    /// Cipher suites in ClientHello order.
    pub cipher_suites: Vec<u16>,
    /// Extension types in ClientHello order.
    pub extension_types: Vec<u16>,
    /// The first ALPN protocol value, if ALPN was present.
    pub first_alpn: Option<Vec<u8>>,
    /// Signature schemes in ClientHello order.
    pub signature_schemes: Vec<u16>,
}

impl Ja4ClientHello {
    /// Compute the canonical, sorted JA4 fingerprint.
    pub fn fingerprint(&self) -> String {
        self.build_hashed_fingerprint()
    }

    /// Compute the raw-order JA4 representation with un-hashed lists.
    pub fn raw_fingerprint(&self) -> String {
        self.build_raw_fingerprint()
    }

    fn first_chunk(&self, ciphers: &[u16], extensions: &[u16]) -> String {
        let cipher_count = ciphers.len().min(99);
        let extension_count = extensions.len().min(99);
        let (alpn_first, alpn_last) = alpn_marker(self.first_alpn.as_deref());
        format!(
            "{}{}{}{:02}{:02}{}{}",
            self.transport.marker(),
            self.tls_version,
            if self.server_name_present { 'd' } else { 'i' },
            cipher_count,
            extension_count,
            alpn_first,
            alpn_last
        )
    }

    fn signature_text(&self) -> String {
        filtered_values(&self.signature_schemes)
            .iter()
            .map(|value| format!("{value:04x}"))
            .collect::<Vec<_>>()
            .join(",")
    }

    fn build_hashed_fingerprint(&self) -> String {
        let ciphers = filtered_values(&self.cipher_suites);
        let extensions = filtered_values(&self.extension_types);
        let first_chunk = self.first_chunk(&ciphers, &extensions);
        let cipher_text = list_text(&ciphers, false);
        let extension_values = extensions
            .into_iter()
            .filter(|value| *value != TLS_EXT_SERVER_NAME && *value != TLS_EXT_ALPN)
            .collect::<Vec<_>>();
        let extension_text = list_text(&extension_values, false);
        let extension_text_empty = extension_text.is_empty();
        let signature_text = self.signature_text();
        let extension_and_signatures = if extension_text_empty {
            String::new()
        } else if signature_text.is_empty() {
            extension_text
        } else {
            format!("{extension_text}_{signature_text}")
        };

        let cipher_hash = if cipher_text.is_empty() {
            zero_hash().to_owned()
        } else {
            hash12(&cipher_text)
        };
        let extension_hash = if extension_text_empty {
            zero_hash().to_owned()
        } else {
            hash12(&extension_and_signatures)
        };
        format!("{first_chunk}_{cipher_hash}_{extension_hash}")
    }

    fn build_raw_fingerprint(&self) -> String {
        let ciphers = filtered_values(&self.cipher_suites);
        let extensions = filtered_values(&self.extension_types);
        let first_chunk = self.first_chunk(&ciphers, &extensions);
        let cipher_text = list_text(&ciphers, true);
        let extension_text = list_text(&extensions, true);
        let signature_text = self.signature_text();
        let extension_and_signatures = if signature_text.is_empty() {
            extension_text
        } else {
            format!("{extension_text}_{signature_text}")
        };
        format!("{first_chunk}_{cipher_text}_{extension_and_signatures}")
    }
}

/// How much of the standard JA4 input was available to a live observer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ja4ObservationCoverage {
    /// rustls exposed public ClientHello fields, but not the complete ordered
    /// extension list and supported-version extension required for exact JA4.
    PublicRustlsSubset,
}

/// A bounded passive observation emitted by the optional resolver plugin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ja4Observation {
    /// The live observation is intentionally marked partial.
    pub coverage: Ja4ObservationCoverage,
    /// The transport marker for the observed handshake.
    pub transport: Ja4Transport,
    /// QUIC is TLS 1.3-only in this standards path.
    pub tls_version: Ja4TlsVersion,
    /// Whether SNI was present.
    pub sni_present: bool,
    /// SNI value when explicitly enabled by [`Ja4ObserverConfig`].
    pub server_name: Option<String>,
    /// ALPN values exposed by rustls.
    pub alpn: Vec<Vec<u8>>,
    /// Cipher suites exposed by rustls.
    pub cipher_suites: Vec<u16>,
    /// Signature schemes exposed by rustls.
    pub signature_schemes: Vec<u16>,
    /// Named groups exposed by rustls.
    pub named_groups: Vec<u16>,
    /// Extension types whose presence can be established from public fields.
    pub known_extension_types: Vec<u16>,
    /// Stable digest of the captured public metadata.
    pub metadata_sha256: String,
    /// JA4-compatible rendering of the public subset. This is not an exact
    /// wire-level JA4 because rustls does not expose all extension types.
    pub partial_fingerprint: String,
    /// Exact JA4 is unavailable from this public rustls hook.
    pub exact_fingerprint: Option<String>,
    /// Whether the certificate resolver selected a certificate.
    pub certificate_resolved: bool,
    /// Whether one or more public lists were bounded before delivery.
    pub truncated: bool,
}

impl Ja4Observation {
    fn from_client_hello(client_hello: &ClientHello<'_>, config: Ja4ObserverConfig) -> Self {
        let sni = client_hello.server_name();
        let sni_present = sni.is_some();
        let (server_name, server_name_truncated) =
            bounded_server_name(sni, config.include_server_name);

        let cipher_source = client_hello.cipher_suites();
        let (cipher_suites, cipher_truncated) =
            bounded_values(cipher_source.iter().map(|value| u16::from(*value)));
        let signature_source = client_hello.signature_schemes();
        let (signature_schemes, signature_truncated) =
            bounded_values(signature_source.iter().map(|value| u16::from(*value)));
        let (named_groups, groups_truncated) = match client_hello.named_groups() {
            Some(groups) => bounded_values(groups.iter().map(|value| u16::from(*value))),
            None => (Vec::new(), false),
        };

        let (alpn, alpn_truncated) = match client_hello.alpn() {
            Some(protocols) => {
                let mut truncated = false;
                let mut values = Vec::new();
                for (index, protocol) in protocols.enumerate() {
                    if index >= MAX_OBSERVED_ALPN_VALUES {
                        truncated = true;
                        break;
                    }
                    if protocol.len() > MAX_OBSERVED_ALPN_BYTES {
                        truncated = true;
                    }
                    values.push(protocol[..protocol.len().min(MAX_OBSERVED_ALPN_BYTES)].to_vec());
                }
                (values, truncated)
            }
            None => (Vec::new(), false),
        };

        let mut known_extension_types = Vec::with_capacity(3);
        if sni_present {
            known_extension_types.push(TLS_EXT_SERVER_NAME);
        }
        if client_hello.alpn().is_some() {
            known_extension_types.push(TLS_EXT_ALPN);
        }
        if client_hello.named_groups().is_some() {
            known_extension_types.push(TLS_EXT_SUPPORTED_GROUPS);
        }

        let tls_version = Ja4TlsVersion::Tls1_3;
        let partial_fingerprint = Ja4ClientHello {
            transport: Ja4Transport::Quic,
            tls_version,
            server_name_present: sni_present,
            cipher_suites: cipher_suites.clone(),
            extension_types: known_extension_types.clone(),
            first_alpn: alpn.first().cloned(),
            signature_schemes: signature_schemes.clone(),
        }
        .fingerprint();
        let metadata = Ja4ClientHello {
            transport: Ja4Transport::Quic,
            tls_version,
            server_name_present: sni_present,
            cipher_suites: cipher_suites.clone(),
            extension_types: known_extension_types.clone(),
            first_alpn: alpn.first().cloned(),
            signature_schemes: signature_schemes.clone(),
        };
        let metadata_sha256 =
            metadata_digest(&metadata, server_name.as_deref(), &alpn, &named_groups);

        Self {
            coverage: Ja4ObservationCoverage::PublicRustlsSubset,
            transport: Ja4Transport::Quic,
            tls_version,
            sni_present,
            server_name,
            alpn,
            cipher_suites,
            signature_schemes,
            named_groups,
            known_extension_types,
            metadata_sha256,
            partial_fingerprint,
            exact_fingerprint: None,
            certificate_resolved: false,
            truncated: cipher_truncated
                || signature_truncated
                || groups_truncated
                || alpn_truncated
                || server_name_truncated,
        }
    }
}

/// Controls privacy-sensitive behavior of the live observer.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Ja4ObserverConfig {
    /// Include the SNI value in each observation. Defaults to false.
    pub include_server_name: bool,
}

/// Callback invoked synchronously for each incoming ClientHello.
pub trait Ja4Observer: fmt::Debug + Send + Sync + 'static {
    /// Consume one bounded passive observation.
    fn observe(&self, observation: Ja4Observation);
}

/// A bounded in-memory observer suitable for diagnostics and lab tests.
#[derive(Debug)]
pub struct RecordingJa4Observer {
    capacity: usize,
    observations: Mutex<VecDeque<Ja4Observation>>,
}

impl RecordingJa4Observer {
    /// Create a recorder with a bounded ring-buffer capacity.
    pub fn new(capacity: usize) -> Result<Self> {
        if capacity == 0 || capacity > MAX_OBSERVATIONS {
            return Err(ShphError::Config(format!(
                "JA4 observer capacity must be between 1 and {MAX_OBSERVATIONS}"
            )));
        }
        Ok(Self {
            capacity,
            observations: Mutex::new(VecDeque::with_capacity(capacity)),
        })
    }

    /// Return observations in oldest-to-newest order.
    pub fn snapshot(&self) -> Vec<Ja4Observation> {
        let observations = match self.observations.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        observations.iter().cloned().collect()
    }
}

impl Ja4Observer for RecordingJa4Observer {
    fn observe(&self, observation: Ja4Observation) {
        let mut observations = match self.observations.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if observations.len() == self.capacity {
            observations.pop_front();
        }
        observations.push_back(observation);
    }
}

#[derive(Debug)]
struct ObservingServerCertResolver {
    inner: Arc<dyn ResolvesServerCert>,
    observer: Arc<dyn Ja4Observer>,
    config: Ja4ObserverConfig,
}

impl ResolvesServerCert for ObservingServerCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let mut observation = Ja4Observation::from_client_hello(&client_hello, self.config);
        let resolved = self.inner.resolve(client_hello);
        observation.certificate_resolved = resolved.is_some();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.observer.observe(observation);
        }));
        resolved
    }

    fn only_raw_public_keys(&self) -> bool {
        self.inner.only_raw_public_keys()
    }
}

pub(crate) fn wrap_server_cert_resolver(
    resolver: Arc<dyn ResolvesServerCert>,
    observer: Arc<dyn Ja4Observer>,
    config: Ja4ObserverConfig,
) -> Arc<dyn ResolvesServerCert> {
    Arc::new(ObservingServerCertResolver {
        inner: resolver,
        observer,
        config,
    })
}

fn is_grease(value: u16) -> bool {
    value & GREASE_MASK == GREASE_VALUE
}

fn filtered_values(values: &[u16]) -> Vec<u16> {
    values
        .iter()
        .copied()
        .filter(|value| !is_grease(*value))
        .collect()
}

fn list_text(values: &[u16], original_order: bool) -> String {
    let mut values = values.to_vec();
    if !original_order {
        values.sort_unstable();
    }
    values
        .iter()
        .map(|value| format!("{value:04x}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn alpn_marker(first_alpn: Option<&[u8]>) -> (char, char) {
    let Some(value) = first_alpn.filter(|value| !value.is_empty()) else {
        return ('0', '0');
    };
    let first = value[0];
    let last = value[value.len() - 1];
    if first.is_ascii_alphanumeric() && last.is_ascii_alphanumeric() {
        return (first as char, last as char);
    }
    let first_hex = hex_digit(first >> 4);
    let last_hex = hex_digit(last & 0x0f);
    (first_hex, last_hex)
}

fn bounded_values<I>(values: I) -> (Vec<u16>, bool)
where
    I: IntoIterator<Item = u16>,
{
    let mut truncated = false;
    let mut output = Vec::new();
    for (index, value) in values.into_iter().enumerate() {
        if index >= MAX_OBSERVED_LIST_VALUES {
            truncated = true;
            break;
        }
        output.push(value);
    }
    (output, truncated)
}

fn bounded_server_name(value: Option<&str>, include: bool) -> (Option<String>, bool) {
    if !include {
        return (None, false);
    }
    let Some(value) = value else {
        return (None, false);
    };
    if value.len() <= MAX_OBSERVED_SERVER_NAME_BYTES {
        return (Some(value.to_owned()), false);
    }

    let mut end = 0;
    for (index, character) in value.char_indices() {
        let next = index + character.len_utf8();
        if next > MAX_OBSERVED_SERVER_NAME_BYTES {
            break;
        }
        end = next;
    }
    (Some(value[..end].to_owned()), true)
}

fn metadata_digest(
    metadata: &Ja4ClientHello,
    server_name: Option<&str>,
    alpn: &[Vec<u8>],
    named_groups: &[u16],
) -> String {
    let alpn = alpn
        .iter()
        .map(|value| format!("{:x}", value.len()) + &hex_bytes(value))
        .collect::<Vec<_>>()
        .join(",");
    let input = format!(
        "transport={};version={};sni={};name={};alpn={};ciphers={};sigs={};groups={};exts={}",
        metadata.transport.marker(),
        metadata.tls_version,
        if metadata.server_name_present { 1 } else { 0 },
        server_name.unwrap_or(""),
        alpn,
        list_text(&filtered_values(&metadata.cipher_suites), true),
        list_text(&filtered_values(&metadata.signature_schemes), true),
        list_text(&filtered_values(named_groups), true),
        list_text(&filtered_values(&metadata.extension_types), true),
    );
    sha256_hex(input.as_bytes())
}

fn hash12(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    hex_bytes(&digest[..6])
}

fn sha256_hex(value: &[u8]) -> String {
    let digest = Sha256::digest(value);
    hex_bytes(&digest)
}

fn hex_bytes(value: &[u8]) -> String {
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(hex_digit(byte >> 4));
        output.push(hex_digit(byte & 0x0f));
    }
    output
}

fn hex_digit(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        10..=15 => (b'a' + value - 10) as char,
        _ => '0',
    }
}

fn zero_hash() -> &'static str {
    "000000000000"
}

#[cfg(test)]
mod tests {
    use super::{
        Ja4ClientHello, Ja4TlsVersion, Ja4Transport, RecordingJa4Observer, MAX_OBSERVATIONS,
    };

    #[test]
    fn computes_official_ja4_example() {
        let client_hello = Ja4ClientHello {
            transport: Ja4Transport::Tcp,
            tls_version: Ja4TlsVersion::Tls1_3,
            server_name_present: true,
            cipher_suites: vec![
                0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
                0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
            ],
            extension_types: vec![
                0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d, 0x0005, 0x0023,
                0x0012, 0x002b, 0xff01, 0x000b, 0x000a, 0x0015,
            ],
            first_alpn: Some(b"h2".to_vec()),
            signature_schemes: vec![
                0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
            ],
        };
        assert_eq!(
            client_hello.fingerprint(),
            "t13d1516h2_8daaf6152771_e5627efa2ab1"
        );
    }

    #[test]
    fn filters_grease_and_preserves_raw_order() {
        let client_hello = Ja4ClientHello {
            transport: Ja4Transport::Quic,
            tls_version: Ja4TlsVersion::Tls1_3,
            server_name_present: false,
            cipher_suites: vec![0x1a1a, 0x1301, 0x0a0a],
            extension_types: vec![0x2a2a, 0x0010, 0x0000, 0x0033],
            first_alpn: Some(vec![0xab, 0xcd]),
            signature_schemes: vec![0x0804],
        };
        assert!(client_hello.fingerprint().starts_with("q13i0103ad_"));
        assert!(client_hello.raw_fingerprint().starts_with("q13i0103ad_"));
        assert!(!client_hello.raw_fingerprint().contains("1a1a"));
        assert!(!client_hello.raw_fingerprint().contains("2a2a"));
    }

    #[test]
    fn handles_empty_and_non_ascii_alpn() {
        let mut client_hello = Ja4ClientHello {
            transport: Ja4Transport::Quic,
            tls_version: Ja4TlsVersion::Tls1_3,
            server_name_present: true,
            cipher_suites: vec![0x1301],
            extension_types: vec![0x0000, 0x0010],
            first_alpn: None,
            signature_schemes: Vec::new(),
        };
        assert!(client_hello.fingerprint().starts_with("q13d010200_"));
        client_hello.first_alpn = Some(vec![0x20, 0x61]);
        assert!(client_hello.fingerprint().starts_with("q13d010221_"));
    }

    #[test]
    fn recorder_is_bounded() {
        assert!(RecordingJa4Observer::new(0).is_err());
        assert!(RecordingJa4Observer::new(MAX_OBSERVATIONS + 1).is_err());
        let recorder = RecordingJa4Observer::new(1).expect("recorder");
        assert!(recorder.snapshot().is_empty());
    }

    #[test]
    fn included_server_name_is_bounded_without_breaking_utf8() {
        let value = "é".repeat(200);
        let (bounded, truncated) = super::bounded_server_name(Some(&value), true);
        assert!(truncated);
        let bounded = bounded.expect("bounded server name");
        assert!(bounded.len() <= super::MAX_OBSERVED_SERVER_NAME_BYTES);
        assert!(bounded.is_char_boundary(bounded.len()));
        assert_eq!(
            super::bounded_server_name(Some("example.test"), false),
            (None, false)
        );
    }

    #[test]
    fn parses_wire_versions() {
        assert_eq!(Ja4TlsVersion::from_wire(0x0304), Ja4TlsVersion::Tls1_3);
        assert_eq!(Ja4TlsVersion::from_wire(0x1234), Ja4TlsVersion::Unknown);
    }
}
