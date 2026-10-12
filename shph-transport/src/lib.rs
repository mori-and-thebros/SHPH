//! SHPH transport abstractions.
//!
//! Includes stable TCP transport today plus an experimental QUIC-like
//! UDP datagram shim for phased adoption, and an opt-in standards-compliant
//! QUIC transport backed by Quinn.

pub mod cover;
pub mod envelope_policy;
pub mod ja4;
pub mod onion;
pub mod pacing;
pub mod phantom_one;
pub mod shroud2;
pub mod shroud3;
pub mod snap_adapter;
pub mod standards_quic;
#[cfg(target_os = "linux")]
pub mod standards_tun;

use base64::Engine as _;
use phantom_one::{PhantomOneConfig, PhantomOneDecoder, PhantomOneEncoder, PhantomOneFrameType};
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use shph_core::roadmap::{
    data_mule_inbox_path, offline_session_id, safe_path_component, MAX_ADAPTER_POLL_INTERVAL_MS,
    MAX_DATA_MULE_AGE_MS, MAX_DATA_MULE_TOTAL_BYTES,
};
use shph_core::{
    absorb_responder_pq, build_hello_with_profile, finalize_initiator_pq, verify_and_derive,
    DataMuleConfig, DataMuleEnvelope, Endpoint, HandshakeMaterial, HandshakeProfile,
    HandshakeState, Hello, IdentityKeyPair, OfflineMeshConfig, OfflineMeshEnvelope, PeerPolicy,
    ReceiveCipher, Result, SendCipher, ShphError, ShroudProfile, StatelessCookieAuthority,
    ML_KEM_768_CIPHERTEXT_BYTES,
};
use shph_obfuscation::{apply_profile_into, remove_profile_in_place, ProfilePadder, ProfileTier};
use std::collections::{HashSet, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, Zeroizing};

const MAX_HELLO_BYTES: usize = 16 * 1024;
const MAX_FRAME_BYTES: usize = 64 * 1024;
const MAX_QUIC_FRAME_BYTES: usize = 16 * 1024;
const MAX_QUIC_HELLO_BYTES: usize = 12 * 1024;
const SHROUD_AEAD_OVERHEAD: usize = 12 + 16;
const MAX_QUIC_PAYLOAD_BYTES: usize = MAX_QUIC_FRAME_BYTES - 4 - SHROUD_AEAD_OVERHEAD;
/// Maximum plaintext bytes carried by one authenticated TCP frame.
pub const MAX_TCP_PAYLOAD_BYTES: usize = MAX_FRAME_BYTES - SHROUD_AEAD_OVERHEAD;
const PHANTOM_ONE_TCP_PATH_MTU: usize = MAX_TCP_PAYLOAD_BYTES;
const SHROUD_LENGTH_PREFIX: usize = 2;
const QUIC_HANDSHAKE_ATTEMPTS: usize = 3;
const MAX_QUIC_INVALID_DATAGRAMS_PER_RECV: usize = 8;
const MAX_QUIC_TRACKED_PEERS: usize = 1024;
const MAX_QUIC_IDLE_TIMEOUT_SECS: u64 = 300;
const TCP_HANDSHAKE_DEADLINE: Duration = Duration::from_secs(60);
const TCP_PREAUTH_DEADLINE: Duration = Duration::from_secs(5);
const MAX_CONCURRENT_TCP_HANDSHAKES: usize = 16;
const MAX_DNS_RESOLVER_WORKERS: usize = 4;
const MAX_DNS_RESOLVER_QUEUE: usize = 32;
const MAX_RESOLVED_ADDRESSES: usize = 32;
const SOCKS_CANCEL_POLL_INTERVAL: Duration = Duration::from_millis(25);

struct ZeroizeOnDrop<'a> {
    buffer: &'a mut Vec<u8>,
}

impl<'a> ZeroizeOnDrop<'a> {
    fn new(buffer: &'a mut Vec<u8>) -> Self {
        Self { buffer }
    }
}

impl Drop for ZeroizeOnDrop<'_> {
    fn drop(&mut self) {
        self.buffer.zeroize();
        self.buffer.clear();
    }
}

/// Per-source connection-rate limiting for the unauthenticated TCP entry path.
/// A single peer address may open at most `MAX_CONNECTS_PER_PEER_PER_WINDOW`
/// inbound handshakes within `PEER_RATE_WINDOW`. Beyond that, further connects
/// from that source are rejected before any handshake work is done, so one host
/// cannot flood the entry path across sessions (the attempt bound above only
/// covers a single accept loop).
const PEER_RATE_WINDOW: Duration = Duration::from_secs(10);
const MAX_CONNECTS_PER_PEER_PER_WINDOW: usize = 8;
const COOKIE_CHALLENGE_THRESHOLD: usize = MAX_CONNECTS_PER_PEER_PER_WINDOW / 2;
const COOKIE_CHALLENGE_PREFIX: &[u8] = b"SHPH-COOKIE-CHALLENGE ";
const COOKIE_RESPONSE_PREFIX: &[u8] = b"SHPH-COOKIE-RESPONSE ";
const MAX_COOKIE_LINE_BYTES: usize = 128;

/// Derive the authenticated-session Phantom One generation from the transcript hash.
///
/// The transcript hash is already authenticated by the SHPH handshake. Using
/// its first four bytes keeps both directions on the same generation without
/// adding another key-derivation mechanism to the morphology layer.
pub fn phantom_one_generation_from_transcript(transcript_hash_hex: &str) -> Result<u32> {
    let prefix = transcript_hash_hex.get(..8).ok_or_else(|| {
        ShphError::Protocol("transcript hash is too short for Phantom One".into())
    })?;
    u32::from_str_radix(prefix, 16)
        .map_err(|_| ShphError::Protocol("transcript hash is not valid hexadecimal".into()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportMode {
    Tcp,
    Quic,
    QuicStandard,
    OfflineMesh,
    DataMule,
}

/// Network path used to reach a TCP SHPH peer.
///
/// Direct TCP is the default. SOCKS5 is intentionally an underlay adapter:
/// it carries the existing SHPH byte stream through a local proxy such as an
/// explicitly configured Xray instance, without terminating or replacing the
/// SHPH handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpUnderlay {
    Direct,
    Socks5 {
        proxy: String,
    },
    /// Operator-managed Tor SOCKS endpoint. Fresh authentication credentials
    /// request per-connection isolation; only a literal loopback proxy is allowed.
    Tor {
        proxy: String,
    },
}

impl TcpUnderlay {
    pub fn parse(value: Option<&str>) -> Result<Self> {
        let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
            return Ok(Self::Direct);
        };
        if value.eq_ignore_ascii_case("direct") {
            return Ok(Self::Direct);
        }
        let proxy = value
            .strip_prefix("socks5://")
            .or_else(|| value.strip_prefix("socks5h://"))
            .or_else(|| value.strip_prefix("tor://"))
            .ok_or_else(|| {
                ShphError::InvalidArgument(
                    "underlay must be direct, socks5://host:port, socks5h://host:port, or tor://loopback:port".into(),
                )
            })?
            .trim();
        if proxy.is_empty()
            || proxy.contains('@')
            || proxy.contains('/')
            || proxy
                .chars()
                .any(|character| character.is_control() || character.is_whitespace())
        {
            return Err(ShphError::InvalidArgument(
                "SOCKS5 underlay must be a host:port without credentials or path".into(),
            ));
        }
        let endpoint = Endpoint::parse(proxy).map_err(|error| {
            ShphError::InvalidArgument(format!("invalid SOCKS5 proxy: {error}"))
        })?;
        if endpoint.port == 0 {
            return Err(ShphError::InvalidArgument(
                "SOCKS5 proxy port must be non-zero".into(),
            ));
        }
        if value.starts_with("tor://") {
            if !endpoint
                .host
                .parse::<IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
            {
                return Err(ShphError::InvalidArgument(
                    "Tor proxy must be a literal loopback address".into(),
                ));
            }
            return Ok(Self::Tor {
                proxy: format_socket_endpoint(&endpoint.host, endpoint.port),
            });
        }
        Ok(Self::Socks5 {
            proxy: format_socket_endpoint(&endpoint.host, endpoint.port),
        })
    }

    pub fn is_direct(&self) -> bool {
        matches!(self, Self::Direct)
    }

    pub fn label(&self) -> &str {
        match self {
            Self::Direct => "direct",
            Self::Socks5 { .. } => "socks5",
            Self::Tor { .. } => "tor",
        }
    }

    pub fn config_value(&self) -> Option<String> {
        match self {
            Self::Direct => None,
            Self::Socks5 { proxy } => Some(format!("socks5://{proxy}")),
            Self::Tor { proxy } => Some(format!("tor://{proxy}")),
        }
    }
}

fn format_socket_endpoint(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

impl TransportMode {
    pub fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "tcp" => Ok(Self::Tcp),
            "quic" => Ok(Self::Quic),
            "quic-standard" | "quic-std" | "quic-rfc" => Ok(Self::QuicStandard),
            "offline-mesh" | "offlinemesh" => Ok(Self::OfflineMesh),
            "data-mule" | "data_mule" | "datamule" => Ok(Self::DataMule),
            _ => Err(ShphError::InvalidArgument(format!(
                "unsupported transport mode: {value}"
            ))),
        }
    }
}

pub struct SecureSession {
    inner: SecureSessionInner,
    transcript_hash_hex: String,
}

enum SecureSessionInner {
    Tcp(Box<SecureTcpSession>),
    Quic(Box<ExperimentalQuicSession>),
    QuicStandard(Box<standards_quic::BlockingStandardsQuicSession>),
    OfflineMesh(OfflineMeshSession),
    DataMule(DataMuleSession),
}

pub struct SecureSender {
    inner: SecureSenderInner,
}

enum SecureSenderInner {
    Tcp(Box<SecureTcpSender>),
    Quic(Box<ExperimentalQuicSender>),
    QuicStandard(standards_quic::BlockingStandardsQuicSender),
    OfflineMesh(Box<OfflineMeshSender>),
    DataMule(Box<DataMuleSender>),
}

pub struct SecureReceiver {
    inner: SecureReceiverInner,
}

#[derive(Debug, Clone, Default)]
pub struct QuicLabConfig {
    /// Legacy Shroud 2 profile for the experimental datagram transport.
    pub shroud_profile: Option<ShroudProfile>,
    /// Opt-in Phantom One profile for authenticated TCP sessions.
    ///
    /// Phantom One is a separate wire envelope and cannot be stacked with the
    /// legacy Shroud 2 profile.
    pub phantom_one_profile: Option<ProfileTier>,
}

enum SecureReceiverInner {
    Tcp(SecureTcpReceiver),
    Quic(ExperimentalQuicReceiver),
    QuicStandard(standards_quic::BlockingStandardsQuicReceiver),
    OfflineMesh(OfflineMeshReceiver),
    DataMule(DataMuleReceiver),
}

const MAX_FILE_ADAPTER_BYTES: u64 = 256 * 1024;
const MAX_QUEUE_SCAN_ENTRIES: usize = 4096;
const MAX_QUEUE_SCAN_DEPTH: usize = 16;
const MAX_QUEUE_SCAN_BYTES: u64 = 8 * 1024 * 1024;
const MAX_QUEUE_CANDIDATE_MEMORY: usize = 4 * 1024 * 1024;
const MAX_ADAPTER_METADATA_BYTES: usize = 1024;
static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
struct ClaimedFile {
    original: PathBuf,
    path: PathBuf,
}

#[derive(Debug)]
struct OfflineMeshCandidate {
    path: PathBuf,
    created_at_unix_ms: u64,
    sequence: u64,
}

#[derive(Debug)]
struct DataMuleCandidate {
    path: PathBuf,
    created_at_unix_ms: u64,
    envelope_id: String,
    from_node: String,
    to_node: String,
    file_bytes: u64,
}

struct DataMuleScanContext {
    max_file_bytes: u64,
    max_age_ms: u64,
    now_unix_ms: u64,
    scanned: usize,
    scanned_bytes: u64,
    candidate_memory: usize,
}

impl DataMuleScanContext {
    fn new(max_file_bytes: u64, max_age_ms: u64, now_unix_ms: u64) -> Self {
        Self {
            max_file_bytes,
            max_age_ms,
            now_unix_ms,
            scanned: 0,
            scanned_bytes: 0,
            candidate_memory: 0,
        }
    }
}

fn account_scan_entry(scanned: &mut usize) -> Result<()> {
    *scanned = scanned.saturating_add(1);
    if *scanned > MAX_QUEUE_SCAN_ENTRIES {
        return Err(ShphError::ResourceExhausted(
            "file adapter queue contains too many entries to scan safely".into(),
        ));
    }
    Ok(())
}

fn account_scan_bytes(scanned_bytes: &mut u64, bytes: u64) -> Result<()> {
    *scanned_bytes = scanned_bytes.saturating_add(bytes);
    if *scanned_bytes > MAX_QUEUE_SCAN_BYTES {
        return Err(ShphError::ResourceExhausted(
            "file adapter scan byte budget exhausted".into(),
        ));
    }
    Ok(())
}

fn account_candidate_memory(
    candidate_memory: &mut usize,
    path: &Path,
    metadata: &[&str],
) -> Result<()> {
    if metadata
        .iter()
        .any(|value| value.len() > MAX_ADAPTER_METADATA_BYTES)
    {
        return Err(ShphError::Protocol(
            "file adapter envelope metadata exceeds safety bounds".into(),
        ));
    }
    let cost = 128usize.saturating_add(
        path.to_string_lossy()
            .len()
            .saturating_add(metadata.iter().map(|value| value.len()).sum()),
    );
    *candidate_memory = candidate_memory.saturating_add(cost);
    if *candidate_memory > MAX_QUEUE_CANDIDATE_MEMORY {
        return Err(ShphError::ResourceExhausted(
            "file adapter candidate memory budget exhausted".into(),
        ));
    }
    Ok(())
}

fn now_unix_ms() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ShphError::Internal("system clock before unix epoch".into()))?
        .as_millis() as u64)
}

fn data_mule_envelope_expired(created_at_unix_ms: u64, now_unix_ms: u64, max_age_ms: u64) -> bool {
    now_unix_ms.saturating_sub(created_at_unix_ms) > max_age_ms
        || created_at_unix_ms.saturating_sub(now_unix_ms) > max_age_ms
}

fn data_mule_spool_usage(
    root: &Path,
    max_file_bytes: u64,
    max_age_ms: u64,
    now_unix_ms: u64,
) -> Result<u64> {
    let mut candidates = Vec::new();
    let mut scan = DataMuleScanContext::new(max_file_bytes, max_age_ms, now_unix_ms);
    collect_shph_files(root, &mut candidates, 0, &mut scan)?;
    Ok(candidates
        .iter()
        .map(|candidate| candidate.file_bytes)
        .sum())
}

fn sanitize_component(input: &str) -> String {
    safe_path_component(input)
}

fn write_file_atomically(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        ensure_no_reparse_components(parent).map_err(ShphError::Io)?;
        fs::create_dir_all(parent).map_err(ShphError::Io)?;
        ensure_no_reparse_components(parent).map_err(ShphError::Io)?;
    }
    ensure_no_reparse_components(path).map_err(ShphError::Io)?;

    let filename = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("envelope");
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let (mut file, tmp) = create_atomic_temp_file(parent, filename)?;
    if let Err(err) = file.write_all(bytes).map_err(ShphError::Io) {
        drop(file);
        let _ = fs::remove_file(&tmp);
        return Err(err);
    }
    if let Err(err) = file.sync_all().map_err(ShphError::Io) {
        drop(file);
        let _ = fs::remove_file(&tmp);
        return Err(err);
    }
    drop(file);

    ensure_no_reparse_components(path).map_err(ShphError::Io)?;
    if let Err(_err) = fs::rename(&tmp, path) {
        #[cfg(windows)]
        {
            if let Err(replace_err) = persist_file_over_windows(&tmp, path) {
                let _ = fs::remove_file(&tmp);
                return Err(ShphError::Io(replace_err));
            }
        }
        #[cfg(not(windows))]
        {
            let _ = fs::remove_file(&tmp);
            return Err(ShphError::Io(_err));
        }
    }

    Ok(())
}

fn create_atomic_temp_file(parent: &Path, filename: &str) -> Result<(File, PathBuf)> {
    for _ in 0..32 {
        let counter = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp = parent.join(format!(".{filename}.tmp-{}-{counter}", std::process::id()));
        match OpenOptions::new().create_new(true).write(true).open(&tmp) {
            Ok(file) => return Ok((file, tmp)),
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(ShphError::Io(err)),
        }
    }
    Err(ShphError::Io(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "unable to allocate a unique atomic temp file",
    )))
}

fn open_readonly_nofollow(path: &Path) -> io::Result<File> {
    shph_core::open_readonly_no_reparse(path).map_err(|error| match error {
        ShphError::Io(error) => error,
        ShphError::InvalidArgument(message) => io::Error::new(io::ErrorKind::InvalidInput, message),
        error => io::Error::other(error.to_string()),
    })
}

fn quarantine_file(path: &Path) {
    let original = path.to_path_buf();
    move_file_to_rejected(path, &original);
}

fn quarantine_claimed_file(claimed: ClaimedFile) {
    move_file_to_rejected(&claimed.path, &claimed.original);
}

fn move_file_to_rejected(path: &Path, original: &Path) {
    let Some(parent) = path.parent() else {
        return;
    };
    if ensure_no_reparse_components(parent).is_err() {
        return;
    }
    let stem = original
        .file_stem()
        .and_then(|name| name.to_str())
        .unwrap_or("rejected");
    let primary = parent.join(format!("{stem}.rejected"));
    let mut candidates = VecDeque::from([primary]);
    for attempt in 0..32 {
        let counter = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        candidates.push_back(parent.join(format!(
            "{stem}.rejected.{}.{}.{}",
            std::process::id(),
            counter,
            attempt
        )));
    }

    while let Some(rejected) = candidates.pop_front() {
        match rename_without_replace(path, &rejected) {
            Ok(()) => {
                return;
            }
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(_) => return,
        }
    }
}

fn claim_file(path: &Path) -> io::Result<Option<ClaimedFile>> {
    let Some(parent) = path.parent() else {
        return Ok(None);
    };
    ensure_no_reparse_components(path)?;
    ensure_no_reparse_components(parent)?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("envelope");
    for attempt in 0..32 {
        let counter = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let claimed = parent.join(format!(
            ".{name}.processing.{}.{}.{}",
            std::process::id(),
            counter,
            attempt
        ));
        match rename_without_replace(path, &claimed) {
            Ok(()) => {
                return Ok(Some(ClaimedFile {
                    original: path.to_path_buf(),
                    path: claimed,
                }));
            }
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "unable to claim file adapter candidate",
    ))
}

#[cfg(target_os = "linux")]
fn rename_without_replace(from: &Path, to: &Path) -> io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let from = CString::new(from.as_os_str().as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "file adapter path contains an embedded NUL",
        )
    })?;
    let to = CString::new(to.as_os_str().as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "file adapter path contains an embedded NUL",
        )
    })?;
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            from.as_ptr(),
            libc::AT_FDCWD,
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if matches!(error.raw_os_error(), Some(libc::ENOSYS | libc::EINVAL)) {
        return rename_without_replace_by_link(&from, &to);
    }
    Err(error)
}

#[cfg(all(unix, not(target_os = "linux")))]
fn rename_without_replace(from: &Path, to: &Path) -> io::Result<()> {
    rename_without_replace_by_link(from, to)
}

#[cfg(unix)]
fn rename_without_replace_by_link(from: &std::ffi::CStr, to: &std::ffi::CStr) -> io::Result<()> {
    use std::os::unix::ffi::OsStrExt;

    let from_path = Path::new(std::ffi::OsStr::from_bytes(from.to_bytes()));
    let to_path = Path::new(std::ffi::OsStr::from_bytes(to.to_bytes()));
    if to_path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "destination already exists",
        ));
    }
    fs::hard_link(from_path, to_path)?;
    fs::remove_file(from_path)
}

#[cfg(windows)]
fn windows_extended_path(path: &Path) -> io::Result<Vec<u16>> {
    use std::os::windows::ffi::OsStrExt;

    let mut value: Vec<u16> = path.as_os_str().encode_wide().collect();
    if value.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "file adapter path contains an embedded NUL",
        ));
    }
    for unit in &mut value {
        if *unit == b'/' as u16 {
            *unit = b'\\' as u16;
        }
    }

    // Win32 file APIs otherwise apply the legacy MAX_PATH limit. The
    // filesystem adapter deliberately uses bounded but nested paths, so
    // claims/rejections must opt into the extended-length namespace.
    let unc_prefix = "\\\\".encode_utf16().collect::<Vec<_>>();
    let extended_prefix = "\\\\?\\".encode_utf16().collect::<Vec<_>>();
    if path.is_absolute() && !value.starts_with(&extended_prefix) {
        if value.starts_with(&unc_prefix) {
            let mut prefixed = "\\\\?\\UNC\\".encode_utf16().collect::<Vec<_>>();
            prefixed.extend_from_slice(&value[2..]);
            value = prefixed;
        } else {
            let mut prefixed = extended_prefix;
            prefixed.extend_from_slice(&value);
            value = prefixed;
        }
    }

    value.push(0);
    Ok(value)
}

#[cfg(all(test, windows))]
mod windows_extended_path_tests {
    use super::windows_extended_path;
    use std::{ffi::OsString, os::windows::ffi::OsStringExt, path::Path};

    #[test]
    fn drive_paths_normalize_forward_slashes_for_extended_namespace() {
        let encoded = windows_extended_path(Path::new("C:/adapter/spool/file.json"))
            .expect("encode extended path");
        let decoded = OsString::from_wide(&encoded[..encoded.len() - 1]);
        assert_eq!(decoded, r"\\?\C:\adapter\spool\file.json");
    }
}

#[cfg(windows)]
fn rename_without_replace(from: &Path, to: &Path) -> io::Result<()> {
    use windows_sys::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_WRITE_THROUGH};

    let from = windows_extended_path(from)?;
    let to = windows_extended_path(to)?;
    let result = unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), MOVEFILE_WRITE_THROUGH) };
    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(any(unix, windows)))]
fn rename_without_replace(from: &Path, to: &Path) -> io::Result<()> {
    if to.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "destination already exists",
        ));
    }
    fs::rename(from, to)
}

fn ensure_no_reparse_components(path: &Path) -> io::Result<()> {
    let mut current = Some(path);
    while let Some(component) = current {
        if component.as_os_str().is_empty() {
            break;
        }
        match fs::symlink_metadata(component) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "refusing to traverse symlink component '{}'",
                        component.display()
                    ),
                ));
            }
            Ok(_) =>
            {
                #[cfg(windows)]
                match shph_core::ensure_not_reparse_point(component) {
                    Ok(()) => {}
                    Err(ShphError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            error.to_string(),
                        ))
                    }
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        current = component.parent();
    }
    Ok(())
}

#[cfg(windows)]
fn persist_file_over_windows(tmp: &Path, path: &Path) -> io::Result<()> {
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, ReplaceFileW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
        REPLACEFILE_WRITE_THROUGH,
    };

    let tmp_w = windows_extended_path(tmp)?;
    let path_w = windows_extended_path(path)?;
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
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn read_file_bytes(path: &Path, max_bytes: u64) -> Result<Vec<u8>> {
    let file = open_readonly_nofollow(path).map_err(ShphError::Io)?;
    let meta = file.metadata().map_err(ShphError::Io)?;
    if meta.len() > max_bytes {
        return Err(ShphError::Protocol(
            "file envelope exceeds maximum size".into(),
        ));
    }

    let mut bytes = Vec::new();
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(ShphError::Io)?;
    if bytes.len() as u64 > max_bytes {
        return Err(ShphError::Protocol(
            "file envelope exceeds maximum size".into(),
        ));
    }
    Ok(bytes)
}

fn map_io_error(err: io::Error) -> ShphError {
    match err.kind() {
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => ShphError::Timeout,
        io::ErrorKind::UnexpectedEof
        | io::ErrorKind::BrokenPipe
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::NotConnected => ShphError::ConnectionClosed,
        _ => ShphError::Io(err),
    }
}

struct DnsResolveRequest {
    addr: String,
    response: mpsc::SyncSender<Result<Vec<SocketAddr>>>,
}

struct DnsResolverPool {
    senders: Vec<mpsc::SyncSender<DnsResolveRequest>>,
    next: AtomicU64,
}

static DNS_RESOLVER: OnceLock<DnsResolverPool> = OnceLock::new();

fn dns_resolver_pool() -> &'static DnsResolverPool {
    DNS_RESOLVER.get_or_init(|| {
        let mut senders = Vec::with_capacity(MAX_DNS_RESOLVER_WORKERS);
        for worker_id in 0..MAX_DNS_RESOLVER_WORKERS {
            let (sender, receiver) =
                mpsc::sync_channel::<DnsResolveRequest>(MAX_DNS_RESOLVER_QUEUE);
            if thread::Builder::new()
                .name(format!("shph-dns-resolver-{worker_id}"))
                .spawn(move || {
                    while let Ok(request) = receiver.recv() {
                        let result = resolve_socket_addrs_bounded(&request.addr);
                        let _ = request.response.send(result);
                    }
                })
                .is_ok()
            {
                senders.push(sender);
            }
        }

        DnsResolverPool {
            senders,
            next: AtomicU64::new(0),
        }
    })
}

fn resolve_socket_addrs_bounded(addr: &str) -> Result<Vec<SocketAddr>> {
    addr.to_socket_addrs()
        .map(collect_bounded_socket_addrs)
        .map_err(|_| ShphError::Config(format!("invalid peer address: {addr}")))
}

fn collect_bounded_socket_addrs(addrs: impl IntoIterator<Item = SocketAddr>) -> Vec<SocketAddr> {
    let mut seen = HashSet::new();
    addrs
        .into_iter()
        .filter(|address| seen.insert(*address))
        .take(MAX_RESOLVED_ADDRESSES)
        .collect()
}

fn resolve_socket_addrs_with_deadline(addr: &str, deadline: Instant) -> Result<Vec<SocketAddr>> {
    if let Ok(socket_addr) = addr.parse::<SocketAddr>() {
        return Ok(vec![socket_addr]);
    }

    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(ShphError::Timeout);
    }

    let (response_sender, response_receiver) = mpsc::sync_channel(1);
    let pool = dns_resolver_pool();
    if pool.senders.is_empty() {
        return Err(ShphError::Internal(
            "DNS resolver workers are unavailable".into(),
        ));
    }
    let mut request = Some(DnsResolveRequest {
        addr: addr.to_owned(),
        response: response_sender,
    });
    let start = (pool.next.fetch_add(1, Ordering::Relaxed) as usize) % pool.senders.len();
    let mut disconnected = 0;
    for offset in 0..pool.senders.len() {
        let index = (start + offset) % pool.senders.len();
        let Some(pending_request) = request.take() else {
            break;
        };
        match pool.senders[index].try_send(pending_request) {
            Ok(()) => break,
            Err(mpsc::TrySendError::Full(returned)) => request = Some(returned),
            Err(mpsc::TrySendError::Disconnected(returned)) => {
                request = Some(returned);
                disconnected += 1;
            }
        }
    }
    if request.is_some() {
        return if disconnected == pool.senders.len() {
            Err(ShphError::Internal(
                "DNS resolver workers are unavailable".into(),
            ))
        } else {
            Err(ShphError::ResourceExhausted(
                "DNS resolution queues are full".into(),
            ))
        };
    }

    match response_receiver.recv_timeout(remaining) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => Err(ShphError::Timeout),
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            Err(ShphError::Internal("DNS resolver worker exited".into()))
        }
    }
}

fn parse_socket_addr(addr: &str, deadline: Instant) -> Result<SocketAddr> {
    resolve_socket_addrs_with_deadline(addr, deadline)?
        .into_iter()
        .next()
        .ok_or_else(|| ShphError::Config(format!("unable to resolve peer address: {addr}")))
}

fn tcp_handshake_deadline(timeout_secs: u64) -> Instant {
    tcp_handshake_deadline_after(Duration::from_secs(timeout_secs.max(1)))
}

fn tcp_handshake_deadline_after(timeout: Duration) -> Instant {
    Instant::now()
        + timeout
            .max(Duration::from_millis(1))
            .min(TCP_HANDSHAKE_DEADLINE)
}

fn connect_tcp_with_deadline(peer: &str, deadline: Instant) -> Result<TcpStream> {
    let mut last_error = None;
    for addr in resolve_socket_addrs_with_deadline(peer, deadline)? {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match TcpStream::connect_timeout(&addr, remaining) {
            Ok(stream) => {
                if let Err(err) = stream.set_nodelay(true) {
                    tracing::debug!(peer = %addr, error = %err, "failed to enable TCP_NODELAY");
                }
                return Ok(stream);
            }
            Err(err) => last_error = Some(err),
        }
    }
    Err(last_error.map(map_io_error).unwrap_or(ShphError::Timeout))
}

fn connect_tcp_via_underlay(
    peer: &str,
    underlay: &TcpUnderlay,
    deadline: Instant,
) -> Result<TcpStream> {
    connect_tcp_via_underlay_inner(peer, underlay, deadline, None)
}

fn connect_tcp_via_underlay_inner(
    peer: &str,
    underlay: &TcpUnderlay,
    deadline: Instant,
    cancellation: Option<&dyn Fn() -> bool>,
) -> Result<TcpStream> {
    check_setup_cancellation(cancellation)?;
    match underlay {
        TcpUnderlay::Direct => connect_tcp_with_deadline(peer, deadline),
        TcpUnderlay::Socks5 { proxy } => {
            let mut stream = connect_tcp_with_deadline(proxy, deadline)?;
            refresh_deadline_timeout(&stream, deadline)?;
            match cancellation {
                Some(cancelled) => socks5_connect_authenticated_with_cancel(
                    &mut stream,
                    peer,
                    deadline,
                    None,
                    Some(cancelled),
                )?,
                None => socks5_connect(&mut stream, peer, deadline)?,
            }
            refresh_deadline_timeout(&stream, deadline)?;
            Ok(stream)
        }
        TcpUnderlay::Tor { proxy } => {
            // Validate public enum construction too, not just parsed CLI input.
            let address: SocketAddr = proxy.parse().map_err(|_| {
                ShphError::Config("Tor proxy must be a literal loopback socket".into())
            })?;
            if !address.ip().is_loopback() || address.port() == 0 {
                return Err(ShphError::Config(
                    "Tor proxy must be a literal loopback socket".into(),
                ));
            }
            let mut stream = connect_tcp_with_deadline(proxy, deadline)?;
            let username = Zeroizing::new(rand::random::<[u8; 16]>());
            let password = Zeroizing::new(rand::random::<[u8; 16]>());
            match cancellation {
                Some(cancelled) => socks5_connect_authenticated_with_cancel(
                    &mut stream,
                    peer,
                    deadline,
                    Some((&username[..], &password[..])),
                    Some(cancelled),
                )?,
                None => socks5_connect_authenticated(
                    &mut stream,
                    peer,
                    deadline,
                    Some((&username[..], &password[..])),
                )?,
            }
            refresh_deadline_timeout(&stream, deadline)?;
            Ok(stream)
        }
    }
}

fn check_setup_cancellation(cancellation: Option<&dyn Fn() -> bool>) -> Result<()> {
    if cancellation.is_some_and(|cancelled| cancelled()) {
        Err(ShphError::Transport("SOCKS5 setup cancelled".into()))
    } else {
        Ok(())
    }
}

fn socks5_connect(stream: &mut TcpStream, peer: &str, deadline: Instant) -> Result<()> {
    socks5_connect_authenticated(stream, peer, deadline, None)
}

fn socks5_connect_authenticated(
    stream: &mut TcpStream,
    peer: &str,
    deadline: Instant,
    authentication: Option<(&[u8], &[u8])>,
) -> Result<()> {
    socks5_connect_authenticated_with_cancel(stream, peer, deadline, authentication, None)
}

fn socks5_connect_authenticated_with_cancel(
    stream: &mut TcpStream,
    peer: &str,
    deadline: Instant,
    authentication: Option<(&[u8], &[u8])>,
    cancellation: Option<&dyn Fn() -> bool>,
) -> Result<()> {
    const SOCKS5_VERSION: u8 = 5;
    const SOCKS5_NO_AUTH: u8 = 0;
    const SOCKS5_CONNECT: u8 = 1;
    const SOCKS5_RESERVED: u8 = 0;
    const SOCKS5_SUCCESS: u8 = 0;

    let method = if authentication.is_some() {
        2
    } else {
        SOCKS5_NO_AUTH
    };
    if authentication.is_some_and(|(user, password)| {
        user.is_empty() || password.is_empty() || user.len() > 255 || password.len() > 255
    }) {
        return Err(ShphError::Config(
            "SOCKS authentication values must be 1..255 bytes".into(),
        ));
    }
    write_socks5_bytes(stream, &[SOCKS5_VERSION, 1, method], deadline, cancellation)?;
    let mut method_response = [0u8; 2];
    read_socks5_bytes(stream, &mut method_response, deadline, cancellation)?;
    if method_response != [SOCKS5_VERSION, method] {
        return Err(ShphError::Transport(
            "SOCKS5 proxy rejected the required authentication method".into(),
        ));
    }
    if let Some((user, password)) = authentication {
        let mut auth = Zeroizing::new(Vec::with_capacity(user.len() + password.len() + 3));
        auth.extend_from_slice(&[1, user.len() as u8]);
        auth.extend_from_slice(user);
        auth.push(password.len() as u8);
        auth.extend_from_slice(password);
        write_socks5_bytes(stream, &auth, deadline, cancellation)?;
        let mut response = [0; 2];
        read_socks5_bytes(stream, &mut response, deadline, cancellation)?;
        if response != [1, 0] {
            return Err(ShphError::Auth("SOCKS authentication failed".into()));
        }
    }

    let endpoint = Endpoint::parse(peer)
        .map_err(|error| ShphError::InvalidArgument(format!("invalid SHPH peer: {error}")))?;
    if endpoint
        .host
        .chars()
        .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(ShphError::InvalidArgument(
            "SHPH peer host contains whitespace or control characters".into(),
        ));
    }
    let host_bytes = endpoint.host.as_bytes();
    let mut request = Vec::with_capacity(7 + host_bytes.len());
    request.extend_from_slice(&[SOCKS5_VERSION, SOCKS5_CONNECT, SOCKS5_RESERVED]);
    match endpoint.host.parse::<IpAddr>() {
        Ok(IpAddr::V4(address)) => {
            request.push(1);
            request.extend_from_slice(&address.octets());
        }
        Ok(IpAddr::V6(address)) => {
            request.push(4);
            request.extend_from_slice(&address.octets());
        }
        Err(_) => {
            if host_bytes.is_empty() || host_bytes.len() > u8::MAX as usize {
                return Err(ShphError::InvalidArgument(
                    "SOCKS5 destination hostname must be 1-255 bytes".into(),
                ));
            }
            request.push(3);
            request.push(host_bytes.len() as u8);
            request.extend_from_slice(host_bytes);
        }
    }
    request.extend_from_slice(&endpoint.port.to_be_bytes());
    write_socks5_bytes(stream, &request, deadline, cancellation)?;

    let mut response_header = [0u8; 4];
    read_socks5_bytes(stream, &mut response_header, deadline, cancellation)?;
    if response_header[0] != SOCKS5_VERSION {
        return Err(ShphError::Protocol(
            "SOCKS5 proxy returned an invalid version".into(),
        ));
    }
    if response_header[2] != SOCKS5_RESERVED {
        return Err(ShphError::Protocol(
            "SOCKS5 proxy returned an invalid reserved field".into(),
        ));
    }
    if response_header[1] != SOCKS5_SUCCESS {
        return Err(ShphError::Transport(format!(
            "SOCKS5 CONNECT failed with reply code {}",
            response_header[1]
        )));
    }
    match response_header[3] {
        1 => {
            let mut address = [0u8; 4];
            read_socks5_bytes(stream, &mut address, deadline, cancellation)?;
        }
        3 => {
            let mut length = [0u8; 1];
            read_socks5_bytes(stream, &mut length, deadline, cancellation)?;
            let mut address = vec![0u8; length[0] as usize];
            read_socks5_bytes(stream, &mut address, deadline, cancellation)?;
        }
        4 => {
            let mut address = [0u8; 16];
            read_socks5_bytes(stream, &mut address, deadline, cancellation)?;
        }
        value => {
            return Err(ShphError::Protocol(format!(
                "SOCKS5 proxy returned an invalid address type {value}"
            )));
        }
    }
    let mut port = [0u8; 2];
    read_socks5_bytes(stream, &mut port, deadline, cancellation)?;
    check_setup_cancellation(cancellation)
}

fn write_socks5_bytes(
    stream: &mut TcpStream,
    payload: &[u8],
    deadline: Instant,
    cancellation: Option<&dyn Fn() -> bool>,
) -> Result<()> {
    match cancellation {
        Some(cancelled) => {
            write_tcp_all_or_closed_with_deadline_and_cancel(stream, payload, deadline, cancelled)
        }
        None => write_tcp_all_or_closed_with_deadline(stream, payload, deadline),
    }
}

fn read_socks5_bytes(
    stream: &mut TcpStream,
    buffer: &mut [u8],
    deadline: Instant,
    cancellation: Option<&dyn Fn() -> bool>,
) -> Result<()> {
    match cancellation {
        Some(cancelled) => {
            read_exact_or_closed_with_deadline_and_cancel(stream, buffer, deadline, cancelled)
        }
        None => read_exact_or_closed_with_deadline(stream, buffer, deadline),
    }
}

fn bounded_quic_timeout_secs(timeout_secs: u64) -> u64 {
    timeout_secs.clamp(1, MAX_QUIC_IDLE_TIMEOUT_SECS)
}

pub fn connect_and_handshake(
    peer: &str,
    local_identity: &IdentityKeyPair,
    policy: &PeerPolicy,
    timeout_secs: u64,
    mode: TransportMode,
) -> Result<HandshakeState> {
    connect_and_handshake_with_profile(
        peer,
        local_identity,
        policy,
        timeout_secs,
        mode,
        HandshakeProfile::SecureDefault,
    )
}

pub fn connect_and_handshake_with_profile(
    peer: &str,
    local_identity: &IdentityKeyPair,
    policy: &PeerPolicy,
    timeout_secs: u64,
    mode: TransportMode,
    profile: HandshakeProfile,
) -> Result<HandshakeState> {
    match mode {
        TransportMode::Tcp => {
            tcp_handshake_client_with_profile(peer, local_identity, policy, timeout_secs, profile)
        }
        TransportMode::Quic => {
            let (_socket, _peer, state) = quic_handshake_client_with_profile(
                peer,
                local_identity,
                policy,
                timeout_secs,
                profile,
            )?;
            Ok(state)
        }
        TransportMode::QuicStandard => Err(ShphError::Unsupported(
            "quic-standard uses the async standards_quic API".into(),
        )),
        TransportMode::OfflineMesh | TransportMode::DataMule => Err(ShphError::InvalidArgument(
            "offline/data-mule require direct config-based APIs".into(),
        )),
    }
}

pub fn accept_handshake(
    bind_addr: &str,
    local_identity: &IdentityKeyPair,
    policy: &PeerPolicy,
    timeout_secs: u64,
    mode: TransportMode,
) -> Result<HandshakeState> {
    accept_handshake_with_profile(
        bind_addr,
        local_identity,
        policy,
        timeout_secs,
        mode,
        HandshakeProfile::SecureDefault,
    )
}

pub fn accept_handshake_with_profile(
    bind_addr: &str,
    local_identity: &IdentityKeyPair,
    policy: &PeerPolicy,
    timeout_secs: u64,
    mode: TransportMode,
    profile: HandshakeProfile,
) -> Result<HandshakeState> {
    match mode {
        TransportMode::Tcp => tcp_handshake_server_with_profile(
            bind_addr,
            local_identity,
            policy,
            timeout_secs,
            profile,
        ),
        TransportMode::Quic => Ok(quic_handshake_server_with_profile(
            bind_addr,
            local_identity,
            policy,
            timeout_secs,
            profile,
        )?
        .2),
        TransportMode::QuicStandard => Err(ShphError::Unsupported(
            "quic-standard uses the async standards_quic API".into(),
        )),
        TransportMode::OfflineMesh | TransportMode::DataMule => Err(ShphError::InvalidArgument(
            "offline/data-mule require direct config-based APIs".into(),
        )),
    }
}

pub fn offline_mesh_connect_and_handshake(
    cfg: &OfflineMeshConfig,
    local_identity: &IdentityKeyPair,
    policy: &PeerPolicy,
    timeout_secs: u64,
) -> Result<HandshakeState> {
    offline_mesh_connect_and_handshake_with_profile(
        cfg,
        local_identity,
        policy,
        timeout_secs,
        HandshakeProfile::SecureDefault,
    )
}

pub fn offline_mesh_connect_and_handshake_with_profile(
    cfg: &OfflineMeshConfig,
    local_identity: &IdentityKeyPair,
    policy: &PeerPolicy,
    timeout_secs: u64,
    profile: HandshakeProfile,
) -> Result<HandshakeState> {
    let material = build_hello_with_profile(local_identity, profile)?;
    let mut writer = OfflineMeshWriteState::new(cfg, &cfg.node_id, &cfg.peer_id);
    let mut reader = OfflineMeshReadState::new(cfg, &cfg.node_id, &cfg.peer_id);
    let timeout = Duration::from_secs(timeout_secs.max(1));

    let local_hello = serialize_hello_with_padding(&material.local_hello)?;
    writer.send_payload(&local_hello)?;

    let peer_hello = reader.receive_verified_hello(timeout, local_identity, &material, policy)?;

    let mut material = material;
    if profile.uses_pqc() {
        let ct = finalize_initiator_pq(local_identity, &mut material, &peer_hello, policy)?;
        writer.send_payload(&ct)?;
    }
    verify_and_derive(local_identity, &material, &peer_hello, true, policy)
}

pub fn offline_mesh_accept_and_handshake(
    cfg: &OfflineMeshConfig,
    local_identity: &IdentityKeyPair,
    policy: &PeerPolicy,
    timeout_secs: u64,
) -> Result<HandshakeState> {
    offline_mesh_accept_and_handshake_with_profile(
        cfg,
        local_identity,
        policy,
        timeout_secs,
        HandshakeProfile::SecureDefault,
    )
}

pub fn offline_mesh_accept_and_handshake_with_profile(
    cfg: &OfflineMeshConfig,
    local_identity: &IdentityKeyPair,
    policy: &PeerPolicy,
    timeout_secs: u64,
    profile: HandshakeProfile,
) -> Result<HandshakeState> {
    let material = build_hello_with_profile(local_identity, profile)?;
    let mut writer = OfflineMeshWriteState::new(cfg, &cfg.node_id, &cfg.peer_id);
    let mut reader = OfflineMeshReadState::new(cfg, &cfg.node_id, &cfg.peer_id);
    let timeout = Duration::from_secs(timeout_secs.max(1));

    let peer_hello = reader.receive_verified_hello(timeout, local_identity, &material, policy)?;
    let local_hello = serialize_hello_with_padding(&material.local_hello)?;
    writer.send_payload(&local_hello)?;
    let mut material = material;
    if profile.uses_pqc() {
        reader.receive_verified_responder_pq(
            timeout,
            local_identity,
            &mut material,
            &peer_hello,
            policy,
        )?;
    }
    verify_and_derive(local_identity, &material, &peer_hello, false, policy)
}

pub fn offline_mesh_connect_secure_session(
    cfg: &OfflineMeshConfig,
    local_identity: &IdentityKeyPair,
    policy: &PeerPolicy,
    timeout_secs: u64,
) -> Result<(SecureSession, HandshakeState)> {
    offline_mesh_connect_secure_session_with_profile(
        cfg,
        local_identity,
        policy,
        timeout_secs,
        HandshakeProfile::SecureDefault,
    )
}

pub fn offline_mesh_connect_secure_session_with_profile(
    cfg: &OfflineMeshConfig,
    local_identity: &IdentityKeyPair,
    policy: &PeerPolicy,
    timeout_secs: u64,
    profile: HandshakeProfile,
) -> Result<(SecureSession, HandshakeState)> {
    offline_mesh_connect_secure_session_with_profile_timeout(
        cfg,
        local_identity,
        policy,
        Duration::from_secs(timeout_secs.max(1)),
        profile,
    )
}

pub fn offline_mesh_connect_secure_session_with_profile_timeout(
    cfg: &OfflineMeshConfig,
    local_identity: &IdentityKeyPair,
    policy: &PeerPolicy,
    timeout: Duration,
    profile: HandshakeProfile,
) -> Result<(SecureSession, HandshakeState)> {
    let material = build_hello_with_profile(local_identity, profile)?;
    let mut writer = OfflineMeshWriteState::new(cfg, &cfg.node_id, &cfg.peer_id);
    let mut reader = OfflineMeshReadState::new(cfg, &cfg.node_id, &cfg.peer_id);
    let timeout = timeout.max(Duration::from_millis(1));

    writer.send_payload(&serialize_hello_with_padding(&material.local_hello)?)?;
    let peer_hello = reader.receive_verified_hello(timeout, local_identity, &material, policy)?;

    let mut material = material;
    if profile.uses_pqc() {
        let ct = finalize_initiator_pq(local_identity, &mut material, &peer_hello, policy)?;
        writer.send_payload(&ct)?;
    }
    let state = verify_and_derive(local_identity, &material, &peer_hello, true, policy)?;
    let session = SecureSession {
        inner: SecureSessionInner::OfflineMesh(OfflineMeshSession::new(
            OfflineMeshWriteState::new(cfg, &cfg.node_id, &cfg.peer_id),
            OfflineMeshReadState::new(cfg, &cfg.node_id, &cfg.peer_id),
            state.session_keys.send_key,
            state.session_keys.recv_key,
        )),
        transcript_hash_hex: state.transcript_hash_hex.clone(),
    };
    Ok((session, state))
}

pub fn offline_mesh_accept_secure_session(
    cfg: &OfflineMeshConfig,
    local_identity: &IdentityKeyPair,
    policy: &PeerPolicy,
    timeout_secs: u64,
) -> Result<(SecureSession, HandshakeState)> {
    offline_mesh_accept_secure_session_with_profile(
        cfg,
        local_identity,
        policy,
        timeout_secs,
        HandshakeProfile::SecureDefault,
    )
}

pub fn offline_mesh_accept_secure_session_with_profile(
    cfg: &OfflineMeshConfig,
    local_identity: &IdentityKeyPair,
    policy: &PeerPolicy,
    timeout_secs: u64,
    profile: HandshakeProfile,
) -> Result<(SecureSession, HandshakeState)> {
    let material = build_hello_with_profile(local_identity, profile)?;
    let mut writer = OfflineMeshWriteState::new(cfg, &cfg.node_id, &cfg.peer_id);
    let mut reader = OfflineMeshReadState::new(cfg, &cfg.node_id, &cfg.peer_id);
    let timeout = Duration::from_secs(timeout_secs.max(1));

    let peer_hello = reader.receive_verified_hello(timeout, local_identity, &material, policy)?;
    writer.send_payload(&serialize_hello_with_padding(&material.local_hello)?)?;
    let mut material = material;
    if profile.uses_pqc() {
        reader.receive_verified_responder_pq(
            timeout,
            local_identity,
            &mut material,
            &peer_hello,
            policy,
        )?;
    }

    let state = verify_and_derive(local_identity, &material, &peer_hello, false, policy)?;
    let session = SecureSession {
        inner: SecureSessionInner::OfflineMesh(OfflineMeshSession::new(
            OfflineMeshWriteState::new(cfg, &cfg.node_id, &cfg.peer_id),
            OfflineMeshReadState::new(cfg, &cfg.node_id, &cfg.peer_id),
            state.session_keys.send_key,
            state.session_keys.recv_key,
        )),
        transcript_hash_hex: state.transcript_hash_hex.clone(),
    };
    Ok((session, state))
}

pub fn data_mule_connect_and_handshake(
    cfg: &DataMuleConfig,
    local_identity: &IdentityKeyPair,
    peer_node: &str,
    policy: &PeerPolicy,
    timeout_secs: u64,
) -> Result<HandshakeState> {
    data_mule_connect_and_handshake_with_profile(
        cfg,
        local_identity,
        peer_node,
        policy,
        timeout_secs,
        HandshakeProfile::SecureDefault,
    )
}

pub fn data_mule_connect_and_handshake_with_profile(
    cfg: &DataMuleConfig,
    local_identity: &IdentityKeyPair,
    peer_node: &str,
    policy: &PeerPolicy,
    timeout_secs: u64,
    profile: HandshakeProfile,
) -> Result<HandshakeState> {
    let material = build_hello_with_profile(local_identity, profile)?;
    let mut writer = DataMuleWriteState::new(cfg, &local_identity.public_key_b64(), peer_node);
    let mut reader = DataMuleReadState::new(cfg, &local_identity.public_key_b64(), Some(peer_node));
    let timeout = Duration::from_secs(timeout_secs.max(1));

    writer.send_payload(&serialize_hello_with_padding(&material.local_hello)?)?;
    let (peer_hello, _) =
        reader.receive_verified_hello(timeout, local_identity, &material, policy)?;
    let mut material = material;
    if profile.uses_pqc() {
        let ct = finalize_initiator_pq(local_identity, &mut material, &peer_hello, policy)?;
        writer.send_payload(&ct)?;
    }
    verify_and_derive(local_identity, &material, &peer_hello, true, policy)
}

pub fn data_mule_accept_and_handshake(
    cfg: &DataMuleConfig,
    local_identity: &IdentityKeyPair,
    policy: &PeerPolicy,
    timeout_secs: u64,
) -> Result<HandshakeState> {
    data_mule_accept_and_handshake_with_profile(
        cfg,
        local_identity,
        policy,
        timeout_secs,
        HandshakeProfile::SecureDefault,
    )
}

pub fn data_mule_accept_and_handshake_with_profile(
    cfg: &DataMuleConfig,
    local_identity: &IdentityKeyPair,
    policy: &PeerPolicy,
    timeout_secs: u64,
    profile: HandshakeProfile,
) -> Result<HandshakeState> {
    let material = build_hello_with_profile(local_identity, profile)?;
    let local_node = local_identity.public_key_b64();
    let mut reader = DataMuleReadState::new(cfg, &local_identity.public_key_b64(), None);
    let timeout = Duration::from_secs(timeout_secs.max(1));

    let (peer_hello, peer_node) =
        reader.receive_verified_hello(timeout, local_identity, &material, policy)?;
    let mut writer = DataMuleWriteState::new(cfg, &local_node, &peer_node);
    writer.send_payload(&serialize_hello_with_padding(&material.local_hello)?)?;
    let mut material = material;
    if profile.uses_pqc() {
        reader.receive_verified_responder_pq(
            timeout,
            local_identity,
            &mut material,
            &peer_hello,
            policy,
        )?;
    }
    verify_and_derive(local_identity, &material, &peer_hello, false, policy)
}

pub fn data_mule_connect_secure_session(
    cfg: &DataMuleConfig,
    local_identity: &IdentityKeyPair,
    peer_node: &str,
    policy: &PeerPolicy,
    timeout_secs: u64,
) -> Result<(SecureSession, HandshakeState)> {
    data_mule_connect_secure_session_with_profile(
        cfg,
        local_identity,
        peer_node,
        policy,
        timeout_secs,
        HandshakeProfile::SecureDefault,
    )
}

pub fn data_mule_connect_secure_session_with_profile(
    cfg: &DataMuleConfig,
    local_identity: &IdentityKeyPair,
    peer_node: &str,
    policy: &PeerPolicy,
    timeout_secs: u64,
    profile: HandshakeProfile,
) -> Result<(SecureSession, HandshakeState)> {
    data_mule_connect_secure_session_with_profile_timeout(
        cfg,
        local_identity,
        peer_node,
        policy,
        Duration::from_secs(timeout_secs.max(1)),
        profile,
    )
}

pub fn data_mule_connect_secure_session_with_profile_timeout(
    cfg: &DataMuleConfig,
    local_identity: &IdentityKeyPair,
    peer_node: &str,
    policy: &PeerPolicy,
    timeout: Duration,
    profile: HandshakeProfile,
) -> Result<(SecureSession, HandshakeState)> {
    let material = build_hello_with_profile(local_identity, profile)?;
    let local_node = local_identity.public_key_b64();
    let mut writer = DataMuleWriteState::new(cfg, &local_node, peer_node);
    let mut reader = DataMuleReadState::new(cfg, &local_node, Some(peer_node));
    let timeout = timeout.max(Duration::from_millis(1));

    writer.send_payload(&serialize_hello_with_padding(&material.local_hello)?)?;
    let (peer_hello, _) =
        reader.receive_verified_hello(timeout, local_identity, &material, policy)?;
    let mut material = material;
    if profile.uses_pqc() {
        let ct = finalize_initiator_pq(local_identity, &mut material, &peer_hello, policy)?;
        writer.send_payload(&ct)?;
    }
    let state = verify_and_derive(local_identity, &material, &peer_hello, true, policy)?;

    let session = SecureSession {
        inner: SecureSessionInner::DataMule(DataMuleSession::new(
            DataMuleWriteState::new(cfg, &local_node, peer_node),
            DataMuleReadState::new(cfg, &local_node, Some(peer_node)),
            state.session_keys.send_key,
            state.session_keys.recv_key,
        )),
        transcript_hash_hex: state.transcript_hash_hex.clone(),
    };

    Ok((session, state))
}

pub fn data_mule_accept_secure_session(
    cfg: &DataMuleConfig,
    local_identity: &IdentityKeyPair,
    policy: &PeerPolicy,
    timeout_secs: u64,
) -> Result<(SecureSession, HandshakeState)> {
    data_mule_accept_secure_session_with_profile(
        cfg,
        local_identity,
        policy,
        timeout_secs,
        HandshakeProfile::SecureDefault,
    )
}

pub fn data_mule_accept_secure_session_with_profile(
    cfg: &DataMuleConfig,
    local_identity: &IdentityKeyPair,
    policy: &PeerPolicy,
    timeout_secs: u64,
    profile: HandshakeProfile,
) -> Result<(SecureSession, HandshakeState)> {
    let material = build_hello_with_profile(local_identity, profile)?;
    let local_node = local_identity.public_key_b64();
    let mut reader = DataMuleReadState::new(cfg, &local_node, None);
    let timeout = Duration::from_secs(timeout_secs.max(1));

    let (peer_hello, peer_node) =
        reader.receive_verified_hello(timeout, local_identity, &material, policy)?;
    let mut writer = DataMuleWriteState::new(cfg, &local_node, &peer_node);
    writer.send_payload(&serialize_hello_with_padding(&material.local_hello)?)?;
    let mut material = material;
    if profile.uses_pqc() {
        reader.receive_verified_responder_pq(
            timeout,
            local_identity,
            &mut material,
            &peer_hello,
            policy,
        )?;
    }

    let state = verify_and_derive(local_identity, &material, &peer_hello, false, policy)?;

    let session = SecureSession {
        inner: SecureSessionInner::DataMule(DataMuleSession::new(
            DataMuleWriteState::new(cfg, &local_node, &peer_node),
            DataMuleReadState::new(cfg, &local_node, Some(&peer_node)),
            state.session_keys.send_key,
            state.session_keys.recv_key,
        )),
        transcript_hash_hex: state.transcript_hash_hex.clone(),
    };
    Ok((session, state))
}

pub fn connect_secure_session(
    peer: &str,
    local_identity: &IdentityKeyPair,
    policy: &PeerPolicy,
    timeout_secs: u64,
    mode: TransportMode,
) -> Result<(SecureSession, HandshakeState)> {
    connect_secure_session_with_profile(
        peer,
        local_identity,
        policy,
        timeout_secs,
        mode,
        HandshakeProfile::SecureDefault,
    )
}

pub fn connect_secure_session_with_profile(
    peer: &str,
    local_identity: &IdentityKeyPair,
    policy: &PeerPolicy,
    timeout_secs: u64,
    mode: TransportMode,
    profile: HandshakeProfile,
) -> Result<(SecureSession, HandshakeState)> {
    connect_secure_session_with_profile_and_underlay(
        peer,
        local_identity,
        policy,
        timeout_secs,
        mode,
        profile,
        &TcpUnderlay::Direct,
    )
}

pub fn connect_secure_session_with_profile_and_underlay(
    peer: &str,
    local_identity: &IdentityKeyPair,
    policy: &PeerPolicy,
    timeout_secs: u64,
    mode: TransportMode,
    profile: HandshakeProfile,
    underlay: &TcpUnderlay,
) -> Result<(SecureSession, HandshakeState)> {
    connect_secure_session_with_profile_and_underlay_inner(
        peer,
        local_identity,
        policy,
        Duration::from_secs(timeout_secs.max(1)),
        mode,
        profile,
        underlay,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn connect_secure_session_with_profile_and_underlay_inner(
    peer: &str,
    local_identity: &IdentityKeyPair,
    policy: &PeerPolicy,
    timeout: Duration,
    mode: TransportMode,
    profile: HandshakeProfile,
    underlay: &TcpUnderlay,
    cancellation: Option<&dyn Fn() -> bool>,
) -> Result<(SecureSession, HandshakeState)> {
    if !underlay.is_direct() && mode != TransportMode::Tcp {
        return Err(ShphError::InvalidArgument(
            "SOCKS5 underlay currently supports TCP transport only".into(),
        ));
    }
    match mode {
        TransportMode::Tcp => {
            let (stream, state) = tcp_connect_and_handshake_with_profile_and_underlay_inner(
                peer,
                local_identity,
                policy,
                timeout,
                profile,
                underlay,
                cancellation,
            )?;
            Ok((
                SecureSession {
                    inner: SecureSessionInner::Tcp(Box::new(SecureTcpSession::new(
                        stream,
                        state.session_keys.send_key,
                        state.session_keys.recv_key,
                    ))),
                    transcript_hash_hex: state.transcript_hash_hex.clone(),
                },
                state,
            ))
        }
        TransportMode::Quic => {
            let (socket, peer_addr, state) = quic_handshake_client_with_profile_timeout(
                peer,
                local_identity,
                policy,
                timeout,
                profile,
            )?;
            Ok((
                SecureSession {
                    inner: SecureSessionInner::Quic(Box::new(ExperimentalQuicSession::new(
                        socket,
                        peer_addr,
                        state.session_keys.send_key,
                        state.session_keys.recv_key,
                    ))),
                    transcript_hash_hex: state.transcript_hash_hex.clone(),
                },
                state,
            ))
        }
        TransportMode::QuicStandard => Err(ShphError::Unsupported(
            "quic-standard uses the async standards_quic API".into(),
        )),
        TransportMode::OfflineMesh | TransportMode::DataMule => Err(ShphError::InvalidArgument(
            "offline/data-mule require direct config-based APIs".into(),
        )),
    }
}

pub fn connect_secure_session_lab(
    peer: &str,
    local_identity: &IdentityKeyPair,
    policy: &PeerPolicy,
    timeout_secs: u64,
    mode: TransportMode,
    lab: QuicLabConfig,
) -> Result<(SecureSession, HandshakeState)> {
    connect_secure_session_lab_with_profile(
        peer,
        local_identity,
        policy,
        timeout_secs,
        mode,
        lab,
        HandshakeProfile::SecureDefault,
    )
}

pub fn connect_secure_session_lab_with_profile(
    peer: &str,
    local_identity: &IdentityKeyPair,
    policy: &PeerPolicy,
    timeout_secs: u64,
    mode: TransportMode,
    lab: QuicLabConfig,
    profile: HandshakeProfile,
) -> Result<(SecureSession, HandshakeState)> {
    connect_secure_session_lab_with_profile_and_underlay(
        peer,
        local_identity,
        policy,
        timeout_secs,
        mode,
        lab,
        profile,
        &TcpUnderlay::Direct,
    )
}

/// Connect a standards-QUIC data session through the synchronous
/// `SecureSession` interface. The returned session remains gated until the
/// caller completes its local peer-policy checks and calls `activate`.
pub fn connect_standards_quic_session(
    peer_addr: SocketAddr,
    server_name: &str,
    server_certificate_der: &[u8],
    local_identity: &IdentityKeyPair,
    policy: &PeerPolicy,
    profile: HandshakeProfile,
    handshake_timeout: Duration,
) -> Result<(SecureSession, HandshakeState)> {
    let (session, state) = standards_quic::BlockingStandardsQuicSession::connect(
        peer_addr,
        server_name.to_owned(),
        server_certificate_der.to_vec(),
        local_identity.clone(),
        policy.clone(),
        profile,
        handshake_timeout,
    )?;
    Ok((
        SecureSession {
            inner: SecureSessionInner::QuicStandard(Box::new(session)),
            transcript_hash_hex: state.transcript_hash_hex.clone(),
        },
        state,
    ))
}

#[allow(clippy::too_many_arguments)]
pub fn connect_secure_session_lab_with_profile_and_underlay(
    peer: &str,
    local_identity: &IdentityKeyPair,
    policy: &PeerPolicy,
    timeout_secs: u64,
    mode: TransportMode,
    lab: QuicLabConfig,
    profile: HandshakeProfile,
    underlay: &TcpUnderlay,
) -> Result<(SecureSession, HandshakeState)> {
    connect_secure_session_lab_with_profile_and_underlay_timeout(
        peer,
        local_identity,
        policy,
        Duration::from_secs(timeout_secs.max(1)),
        mode,
        lab,
        profile,
        underlay,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn connect_secure_session_lab_with_profile_and_underlay_timeout(
    peer: &str,
    local_identity: &IdentityKeyPair,
    policy: &PeerPolicy,
    timeout: Duration,
    mode: TransportMode,
    lab: QuicLabConfig,
    profile: HandshakeProfile,
    underlay: &TcpUnderlay,
) -> Result<(SecureSession, HandshakeState)> {
    connect_secure_session_lab_with_profile_and_underlay_inner(
        peer,
        local_identity,
        policy,
        timeout,
        mode,
        lab,
        profile,
        underlay,
        None,
    )
}

/// Connect a session while polling `cancelled` during SOCKS5 setup.
///
/// SOCKS exchange I/O checks cancellation at bounded intervals while honoring
/// the existing absolute handshake deadline. Resolving a non-literal SOCKS
/// proxy and connecting its TCP socket remain deadline-bounded blocking calls.
/// Direct TCP connect and the subsequent SHPH handshake are also only
/// deadline-bounded; the CLI uses this variant only for SOCKS underlays.
#[allow(clippy::too_many_arguments)]
pub fn connect_secure_session_lab_with_profile_and_underlay_with_cancel(
    peer: &str,
    local_identity: &IdentityKeyPair,
    policy: &PeerPolicy,
    timeout_secs: u64,
    mode: TransportMode,
    lab: QuicLabConfig,
    profile: HandshakeProfile,
    underlay: &TcpUnderlay,
    cancelled: &dyn Fn() -> bool,
) -> Result<(SecureSession, HandshakeState)> {
    connect_secure_session_lab_with_profile_and_underlay_inner(
        peer,
        local_identity,
        policy,
        Duration::from_secs(timeout_secs.max(1)),
        mode,
        lab,
        profile,
        underlay,
        Some(cancelled),
    )
}

#[allow(clippy::too_many_arguments)]
fn connect_secure_session_lab_with_profile_and_underlay_inner(
    peer: &str,
    local_identity: &IdentityKeyPair,
    policy: &PeerPolicy,
    timeout: Duration,
    mode: TransportMode,
    lab: QuicLabConfig,
    profile: HandshakeProfile,
    underlay: &TcpUnderlay,
    cancellation: Option<&dyn Fn() -> bool>,
) -> Result<(SecureSession, HandshakeState)> {
    validate_lab_profiles(mode, lab.shroud_profile, lab.phantom_one_profile)?;
    let (mut session, state) = connect_secure_session_with_profile_and_underlay_inner(
        peer,
        local_identity,
        policy,
        timeout,
        mode,
        profile,
        underlay,
        cancellation,
    )?;
    if let Some(shroud_profile) = lab.shroud_profile {
        session = match mode {
            TransportMode::Tcp => {
                session.with_tcp_profile(ProfileTier::from_shroud_profile(shroud_profile))?
            }
            TransportMode::Quic => session.with_quic_profile(shroud_profile)?,
            _ => session,
        };
    }
    if let Some(phantom_one_profile) = lab.phantom_one_profile {
        session = session.with_phantom_one_generation_and_profile(
            phantom_one_generation_from_transcript(&state.transcript_hash_hex)?,
            phantom_one_profile,
        )?;
    }
    Ok((session, state))
}

pub fn accept_secure_session(
    bind_addr: &str,
    local_identity: &IdentityKeyPair,
    policy: &PeerPolicy,
    timeout_secs: u64,
    mode: TransportMode,
) -> Result<(SecureSession, HandshakeState)> {
    accept_secure_session_with_profile(
        bind_addr,
        local_identity,
        policy,
        timeout_secs,
        mode,
        HandshakeProfile::SecureDefault,
    )
}

pub fn accept_secure_session_with_profile(
    bind_addr: &str,
    local_identity: &IdentityKeyPair,
    policy: &PeerPolicy,
    timeout_secs: u64,
    mode: TransportMode,
    profile: HandshakeProfile,
) -> Result<(SecureSession, HandshakeState)> {
    match mode {
        TransportMode::Tcp => {
            let (stream, state) = tcp_accept_and_handshake_with_profile(
                bind_addr,
                local_identity,
                policy,
                timeout_secs,
                profile,
            )?;
            Ok((
                SecureSession {
                    inner: SecureSessionInner::Tcp(Box::new(SecureTcpSession::new(
                        stream,
                        state.session_keys.send_key,
                        state.session_keys.recv_key,
                    ))),
                    transcript_hash_hex: state.transcript_hash_hex.clone(),
                },
                state,
            ))
        }
        TransportMode::Quic => {
            let (socket, peer_addr, state) = quic_handshake_server_with_profile(
                bind_addr,
                local_identity,
                policy,
                timeout_secs,
                profile,
            )?;
            Ok((
                SecureSession {
                    inner: SecureSessionInner::Quic(Box::new(ExperimentalQuicSession::new(
                        socket,
                        peer_addr,
                        state.session_keys.send_key,
                        state.session_keys.recv_key,
                    ))),
                    transcript_hash_hex: state.transcript_hash_hex.clone(),
                },
                state,
            ))
        }
        TransportMode::QuicStandard => Err(ShphError::Unsupported(
            "quic-standard uses the async standards_quic API".into(),
        )),
        TransportMode::OfflineMesh | TransportMode::DataMule => Err(ShphError::InvalidArgument(
            "offline/data-mule require direct config-based APIs".into(),
        )),
    }
}

pub fn accept_secure_session_lab(
    bind_addr: &str,
    local_identity: &IdentityKeyPair,
    policy: &PeerPolicy,
    timeout_secs: u64,
    mode: TransportMode,
    lab: QuicLabConfig,
) -> Result<(SecureSession, HandshakeState)> {
    accept_secure_session_lab_with_profile(
        bind_addr,
        local_identity,
        policy,
        timeout_secs,
        mode,
        lab,
        HandshakeProfile::SecureDefault,
    )
}

pub fn accept_secure_session_lab_with_profile(
    bind_addr: &str,
    local_identity: &IdentityKeyPair,
    policy: &PeerPolicy,
    timeout_secs: u64,
    mode: TransportMode,
    lab: QuicLabConfig,
    profile: HandshakeProfile,
) -> Result<(SecureSession, HandshakeState)> {
    validate_lab_profiles(mode, lab.shroud_profile, lab.phantom_one_profile)?;
    let (mut session, state) = accept_secure_session_with_profile(
        bind_addr,
        local_identity,
        policy,
        timeout_secs,
        mode,
        profile,
    )?;
    if let Some(shroud_profile) = lab.shroud_profile {
        session = match mode {
            TransportMode::Tcp => {
                session.with_tcp_profile(ProfileTier::from_shroud_profile(shroud_profile))?
            }
            TransportMode::Quic => session.with_quic_profile(shroud_profile)?,
            _ => session,
        };
    }
    if let Some(phantom_one_profile) = lab.phantom_one_profile {
        session = session.with_phantom_one_generation_and_profile(
            phantom_one_generation_from_transcript(&state.transcript_hash_hex)?,
            phantom_one_profile,
        )?;
    }
    Ok((session, state))
}

fn validate_lab_profiles(
    mode: TransportMode,
    shroud_profile: Option<ShroudProfile>,
    phantom_one_profile: Option<ProfileTier>,
) -> Result<()> {
    if shroud_profile.is_some() && phantom_one_profile.is_some() {
        return Err(ShphError::InvalidArgument(
            "Shroud 2 and Phantom One cannot be enabled together".into(),
        ));
    }
    if phantom_one_profile.is_some() && mode != TransportMode::Tcp {
        return Err(ShphError::Unsupported(
            "Phantom One is currently available on authenticated TCP only".into(),
        ));
    }
    Ok(())
}

impl SecureSession {
    /// Keep a SNAP TLS bridge relay alive for this authenticated TCP session.
    pub fn with_snap_bridge_lifecycle(
        mut self,
        lifecycle: snap_adapter::SnapBridgeLifecycle,
    ) -> Result<Self> {
        match &mut self.inner {
            SecureSessionInner::Tcp(session) => {
                session._snap_bridge_lifecycle = Some(Arc::new(lifecycle));
                Ok(self)
            }
            SecureSessionInner::Quic(_)
            | SecureSessionInner::QuicStandard(_)
            | SecureSessionInner::OfflineMesh(_)
            | SecureSessionInner::DataMule(_) => Err(ShphError::Unsupported(
                "SNAP TLS bridge lifecycle requires an authenticated TCP session".into(),
            )),
        }
    }

    fn with_quic_profile(mut self, profile: ShroudProfile) -> Result<Self> {
        if let SecureSessionInner::Quic(session) = &mut self.inner {
            if profile.is_tuned() {
                // Tuned profiles use the shared discrete envelope directly.
                // This avoids the legacy fixed-cell plus shared-wrapper
                // combination and keeps the full QUIC payload budget usable.
                session.shroud_profile = None;
                session.shroud_rng = None;
                session.padding_profile = Some(ProfileTier::from_shroud_profile(profile));
                session.padding_padder = Some(ProfilePadder::new(
                    ProfileTier::from_shroud_profile(profile),
                ));
                session.padding_buffer.clear();
            } else {
                // Keep the legacy double envelope for compatibility with
                // peers from previous developer releases.
                session.shroud_profile = Some(profile);
                session.shroud_rng = (!profile.deterministic_padding).then(StdRng::from_entropy);
                session.padding_profile = Some(ProfileTier::from_shroud_profile(profile));
                session.padding_padder = Some(ProfilePadder::new(
                    ProfileTier::from_shroud_profile(profile),
                ));
                session.padding_buffer.clear();
            }
        }
        Ok(self)
    }

    fn with_tcp_profile(mut self, profile: ProfileTier) -> Result<Self> {
        if let SecureSessionInner::Tcp(session) = &mut self.inner {
            session.padding_profile = Some(profile);
            session.padding_padder = Some(ProfilePadder::new(profile));
            session.padding_buffer.clear();
        }
        Ok(self)
    }

    /// Enable the opt-in Phantom One inner envelope for authenticated TCP.
    ///
    /// Phantom One is deliberately mutually exclusive with the legacy TCP profile:
    /// stacking two independent padding envelopes makes the wire budget harder
    /// to reason about and can cause avoidable overhead. The authenticated SHPH
    /// AEAD remains the security boundary; Phantom One supplies only bounded framing
    /// and morphology.
    pub fn with_phantom_one_generation(self, generation: u32) -> Result<Self> {
        self.with_phantom_one_generation_and_profile(generation, ProfileTier::Medium)
    }

    /// Enable Phantom One with an explicit profile for authenticated TCP.
    pub fn with_phantom_one_generation_and_profile(
        mut self,
        generation: u32,
        profile: ProfileTier,
    ) -> Result<Self> {
        match &mut self.inner {
            SecureSessionInner::Tcp(session) => {
                session.padding_profile = None;
                session.padding_padder = None;
                session.padding_buffer.clear();
                session.phantom_one_encoder =
                    Some(PhantomOneEncoder::with_profile(generation, profile));
                session.phantom_one_decoder = Some(PhantomOneDecoder::with_config(
                    generation,
                    PhantomOneConfig::for_profile(profile),
                )?);
            }
            SecureSessionInner::Quic(_) | SecureSessionInner::QuicStandard(_) => {
                return Err(ShphError::Unsupported(
                    "Phantom One is currently available on authenticated TCP only".into(),
                ));
            }
            SecureSessionInner::OfflineMesh(_) | SecureSessionInner::DataMule(_) => {
                return Err(ShphError::Unsupported(
                    "Phantom One is not available on offline or data-mule sessions".into(),
                ));
            }
        }
        Ok(self)
    }

    /// Activate a session adapter after local peer-policy checks have passed.
    /// Adapters that do not gate asynchronous setup are already active.
    pub fn activate(&mut self) -> Result<()> {
        match &mut self.inner {
            SecureSessionInner::QuicStandard(session) => session.activate(),
            SecureSessionInner::Tcp(_)
            | SecureSessionInner::Quic(_)
            | SecureSessionInner::OfflineMesh(_)
            | SecureSessionInner::DataMule(_) => Ok(()),
        }
    }

    pub fn send_frame(&mut self, payload: &[u8]) -> Result<()> {
        match &mut self.inner {
            SecureSessionInner::Tcp(session) => session.send_frame(payload),
            SecureSessionInner::Quic(session) => session.send_frame(payload),
            SecureSessionInner::QuicStandard(session) => session.send_frame(payload),
            SecureSessionInner::OfflineMesh(session) => session.send_frame(payload),
            SecureSessionInner::DataMule(session) => session.send_frame(payload),
        }
    }

    pub fn recv_frame(&mut self) -> Result<Vec<u8>> {
        match &mut self.inner {
            SecureSessionInner::Tcp(session) => session.recv_frame(),
            SecureSessionInner::Quic(session) => session.recv_frame(),
            SecureSessionInner::QuicStandard(session) => session.recv_frame(),
            SecureSessionInner::OfflineMesh(session) => session.recv_frame(),
            SecureSessionInner::DataMule(session) => session.recv_frame(),
        }
    }

    pub fn into_split(self) -> Result<(SecureSender, SecureReceiver)> {
        match self.inner {
            SecureSessionInner::Tcp(session) => {
                let (sender, receiver) = (*session).into_split()?;
                Ok((
                    SecureSender {
                        inner: SecureSenderInner::Tcp(Box::new(sender)),
                    },
                    SecureReceiver {
                        inner: SecureReceiverInner::Tcp(receiver),
                    },
                ))
            }
            SecureSessionInner::Quic(session) => {
                let (sender, receiver) = (*session).into_split()?;
                Ok((
                    SecureSender {
                        inner: SecureSenderInner::Quic(Box::new(sender)),
                    },
                    SecureReceiver {
                        inner: SecureReceiverInner::Quic(receiver),
                    },
                ))
            }
            SecureSessionInner::QuicStandard(session) => {
                let (sender, receiver) = (*session).into_split()?;
                Ok((
                    SecureSender {
                        inner: SecureSenderInner::QuicStandard(sender),
                    },
                    SecureReceiver {
                        inner: SecureReceiverInner::QuicStandard(receiver),
                    },
                ))
            }
            SecureSessionInner::OfflineMesh(session) => {
                let (sender, receiver) = session.into_split()?;
                Ok((
                    SecureSender {
                        inner: SecureSenderInner::OfflineMesh(Box::new(sender)),
                    },
                    SecureReceiver {
                        inner: SecureReceiverInner::OfflineMesh(receiver),
                    },
                ))
            }
            SecureSessionInner::DataMule(session) => {
                let (sender, receiver) = session.into_split()?;
                Ok((
                    SecureSender {
                        inner: SecureSenderInner::DataMule(Box::new(sender)),
                    },
                    SecureReceiver {
                        inner: SecureReceiverInner::DataMule(receiver),
                    },
                ))
            }
        }
    }
}

impl SecureSender {
    pub fn send_frame(&mut self, payload: &[u8]) -> Result<()> {
        match &mut self.inner {
            SecureSenderInner::Tcp(sender) => sender.send_frame(payload),
            SecureSenderInner::Quic(sender) => sender.send_frame(payload),
            SecureSenderInner::QuicStandard(sender) => sender.send_frame(payload),
            SecureSenderInner::OfflineMesh(sender) => sender.send_frame(payload),
            SecureSenderInner::DataMule(sender) => sender.send_frame(payload),
        }
    }
}

impl SecureReceiver {
    pub fn set_poll_timeout(&mut self, timeout: Duration) -> Result<()> {
        let timeout = timeout.max(Duration::from_millis(1));
        match &mut self.inner {
            SecureReceiverInner::Tcp(receiver) => receiver
                .stream
                .set_read_timeout(Some(timeout))
                .map_err(map_io_error),
            SecureReceiverInner::Quic(receiver) => receiver
                .socket
                .set_read_timeout(Some(timeout))
                .map_err(map_io_error),
            SecureReceiverInner::QuicStandard(receiver) => receiver.set_poll_timeout(timeout),
            SecureReceiverInner::OfflineMesh(receiver) => {
                receiver.timeout = timeout;
                Ok(())
            }
            SecureReceiverInner::DataMule(receiver) => {
                receiver.timeout = timeout;
                Ok(())
            }
        }
    }

    pub fn recv_frame(&mut self) -> Result<Vec<u8>> {
        match &mut self.inner {
            SecureReceiverInner::Tcp(receiver) => receiver.recv_frame(),
            SecureReceiverInner::Quic(receiver) => receiver.recv_frame(),
            SecureReceiverInner::QuicStandard(receiver) => receiver.recv_frame(),
            SecureReceiverInner::OfflineMesh(receiver) => receiver.recv_frame(),
            SecureReceiverInner::DataMule(receiver) => receiver.recv_frame(),
        }
    }
}

pub fn tcp_handshake_client(
    peer: &str,
    local_identity: &IdentityKeyPair,
    policy: &PeerPolicy,
    timeout_secs: u64,
) -> Result<HandshakeState> {
    tcp_handshake_client_with_profile(
        peer,
        local_identity,
        policy,
        timeout_secs,
        HandshakeProfile::SecureDefault,
    )
}

pub fn tcp_handshake_client_with_profile(
    peer: &str,
    local_identity: &IdentityKeyPair,
    policy: &PeerPolicy,
    timeout_secs: u64,
    profile: HandshakeProfile,
) -> Result<HandshakeState> {
    tcp_handshake_client_with_profile_and_underlay(
        peer,
        local_identity,
        policy,
        timeout_secs,
        profile,
        &TcpUnderlay::Direct,
    )
}

pub fn tcp_handshake_client_with_profile_and_underlay(
    peer: &str,
    local_identity: &IdentityKeyPair,
    policy: &PeerPolicy,
    timeout_secs: u64,
    profile: HandshakeProfile,
    underlay: &TcpUnderlay,
) -> Result<HandshakeState> {
    tcp_handshake_client_with_profile_and_underlay_inner(
        peer,
        local_identity,
        policy,
        timeout_secs,
        profile,
        underlay,
        None,
    )
}

/// Perform a client handshake while polling `cancelled` during SOCKS5 setup.
///
/// The callback is not polled during the subsequent SHPH handshake, DNS
/// resolution, or the initial TCP connect; those operations remain bounded by
/// the aggregate handshake deadline.
pub fn tcp_handshake_client_with_profile_and_underlay_with_cancel(
    peer: &str,
    local_identity: &IdentityKeyPair,
    policy: &PeerPolicy,
    timeout_secs: u64,
    profile: HandshakeProfile,
    underlay: &TcpUnderlay,
    cancelled: &dyn Fn() -> bool,
) -> Result<HandshakeState> {
    tcp_handshake_client_with_profile_and_underlay_inner(
        peer,
        local_identity,
        policy,
        timeout_secs,
        profile,
        underlay,
        Some(cancelled),
    )
}

fn tcp_handshake_client_with_profile_and_underlay_inner(
    peer: &str,
    local_identity: &IdentityKeyPair,
    policy: &PeerPolicy,
    timeout_secs: u64,
    profile: HandshakeProfile,
    underlay: &TcpUnderlay,
    cancellation: Option<&dyn Fn() -> bool>,
) -> Result<HandshakeState> {
    let deadline = tcp_handshake_deadline(timeout_secs);
    let mut stream = match cancellation {
        Some(cancelled) => {
            connect_tcp_via_underlay_inner(peer, underlay, deadline, Some(cancelled))?
        }
        None => connect_tcp_via_underlay(peer, underlay, deadline)?,
    };
    refresh_deadline_timeout(&stream, deadline)?;
    let mut material = build_hello_with_profile(local_identity, profile)?;
    write_tcp_hello_with_deadline(&mut stream, &material.local_hello, deadline)?;
    let peer_hello = read_tcp_server_hello_with_deadline(&mut stream, deadline)?;
    shph_core::verify_hello_signature(local_identity, &material, &peer_hello, policy)?;
    if profile.uses_pqc() {
        let ct = finalize_initiator_pq(local_identity, &mut material, &peer_hello, policy)?;
        write_tcp_pq_ct_with_deadline(&mut stream, &ct, deadline)?;
    }
    verify_and_derive(local_identity, &material, &peer_hello, true, policy)
}

pub fn tcp_handshake_server(
    bind_addr: &str,
    local_identity: &IdentityKeyPair,
    policy: &PeerPolicy,
    timeout_secs: u64,
) -> Result<HandshakeState> {
    tcp_handshake_server_with_profile(
        bind_addr,
        local_identity,
        policy,
        timeout_secs,
        HandshakeProfile::SecureDefault,
    )
}

pub fn tcp_handshake_server_with_profile(
    bind_addr: &str,
    local_identity: &IdentityKeyPair,
    policy: &PeerPolicy,
    timeout_secs: u64,
    profile: HandshakeProfile,
) -> Result<HandshakeState> {
    tcp_accept_and_handshake_with_profile(bind_addr, local_identity, policy, timeout_secs, profile)
        .map(|(_, state)| state)
}

pub fn tcp_connect_and_handshake(
    peer: &str,
    local_identity: &IdentityKeyPair,
    policy: &PeerPolicy,
    timeout_secs: u64,
) -> Result<(TcpStream, HandshakeState)> {
    tcp_connect_and_handshake_with_profile(
        peer,
        local_identity,
        policy,
        timeout_secs,
        HandshakeProfile::SecureDefault,
    )
}

pub fn tcp_connect_and_handshake_with_profile(
    peer: &str,
    local_identity: &IdentityKeyPair,
    policy: &PeerPolicy,
    timeout_secs: u64,
    profile: HandshakeProfile,
) -> Result<(TcpStream, HandshakeState)> {
    tcp_connect_and_handshake_with_profile_and_underlay(
        peer,
        local_identity,
        policy,
        timeout_secs,
        profile,
        &TcpUnderlay::Direct,
    )
}

pub fn tcp_connect_and_handshake_with_profile_and_underlay(
    peer: &str,
    local_identity: &IdentityKeyPair,
    policy: &PeerPolicy,
    timeout_secs: u64,
    profile: HandshakeProfile,
    underlay: &TcpUnderlay,
) -> Result<(TcpStream, HandshakeState)> {
    tcp_connect_and_handshake_with_profile_and_underlay_inner(
        peer,
        local_identity,
        policy,
        Duration::from_secs(timeout_secs.max(1)),
        profile,
        underlay,
        None,
    )
}

fn tcp_connect_and_handshake_with_profile_and_underlay_inner(
    peer: &str,
    local_identity: &IdentityKeyPair,
    policy: &PeerPolicy,
    timeout: Duration,
    profile: HandshakeProfile,
    underlay: &TcpUnderlay,
    cancellation: Option<&dyn Fn() -> bool>,
) -> Result<(TcpStream, HandshakeState)> {
    let deadline = tcp_handshake_deadline_after(timeout);
    let stream = match cancellation {
        Some(cancelled) => {
            connect_tcp_via_underlay_inner(peer, underlay, deadline, Some(cancelled))?
        }
        None => connect_tcp_via_underlay(peer, underlay, deadline)?,
    };
    tcp_handshake_on_connected_stream(stream, local_identity, policy, profile, deadline)
}

fn tcp_handshake_on_connected_stream(
    mut stream: TcpStream,
    local_identity: &IdentityKeyPair,
    policy: &PeerPolicy,
    profile: HandshakeProfile,
    deadline: Instant,
) -> Result<(TcpStream, HandshakeState)> {
    refresh_deadline_timeout(&stream, deadline)?;
    let mut material = build_hello_with_profile(local_identity, profile)?;
    write_tcp_hello_with_deadline(&mut stream, &material.local_hello, deadline)?;
    let peer_hello = read_tcp_server_hello_with_deadline(&mut stream, deadline)?;
    shph_core::verify_hello_signature(local_identity, &material, &peer_hello, policy)?;
    if profile.uses_pqc() {
        let ct = finalize_initiator_pq(local_identity, &mut material, &peer_hello, policy)?;
        write_tcp_pq_ct_with_deadline(&mut stream, &ct, deadline)?;
    }
    let state = verify_and_derive(local_identity, &material, &peer_hello, true, policy)?;
    clear_deadline_timeout(&stream)?;
    Ok((stream, state))
}

/// Authenticate a pre-established TCP stream with the standard SHPH handshake.
///
/// SNAP adapters use this to carry the same pinned-peer session over an
/// operator-configured bridge. The bridge never replaces or terminates the
/// SHPH identity handshake.
pub fn connect_secure_session_on_snap_stream(
    stream: TcpStream,
    local_identity: &IdentityKeyPair,
    policy: &PeerPolicy,
    timeout: Duration,
    lab: QuicLabConfig,
    profile: HandshakeProfile,
) -> Result<(SecureSession, HandshakeState)> {
    validate_lab_profiles(
        TransportMode::Tcp,
        lab.shroud_profile,
        lab.phantom_one_profile,
    )?;
    let deadline = tcp_handshake_deadline_after(timeout);
    let (stream, state) =
        tcp_handshake_on_connected_stream(stream, local_identity, policy, profile, deadline)?;
    let mut session = SecureSession {
        inner: SecureSessionInner::Tcp(Box::new(SecureTcpSession::new(
            stream,
            state.session_keys.send_key,
            state.session_keys.recv_key,
        ))),
        transcript_hash_hex: state.transcript_hash_hex.clone(),
    };
    if let Some(shroud_profile) = lab.shroud_profile {
        session = session.with_tcp_profile(ProfileTier::from_shroud_profile(shroud_profile))?;
    }
    if let Some(phantom_one_profile) = lab.phantom_one_profile {
        session = session.with_phantom_one_generation_and_profile(
            phantom_one_generation_from_transcript(&state.transcript_hash_hex)?,
            phantom_one_profile,
        )?;
    }
    Ok((session, state))
}

/// Connect an authenticated SHPH TCP session through a fixed, pinned onion
/// path. The route remains fail-closed and does not retry the destination
/// directly. This path is experimental and requires operator-managed relays.
pub fn connect_secure_session_onion(
    path: onion::OnionPath,
    local_identity: &IdentityKeyPair,
    policy: &PeerPolicy,
    timeout: Duration,
    lab: QuicLabConfig,
    profile: HandshakeProfile,
) -> Result<(SecureSession, HandshakeState)> {
    validate_lab_profiles(
        TransportMode::Tcp,
        lab.shroud_profile,
        lab.phantom_one_profile,
    )?;
    let stream = onion::connect_onion_bridge(path, timeout)?;
    connect_secure_session_on_snap_stream(stream, local_identity, policy, timeout, lab, profile)
}

/// Per-peer-address connection-rate limiter for the unauthenticated entry path.
///
/// Tracks recent accepted-connect timestamps per peer IP. A peer that has
/// already opened `MAX_CONNECTS_PER_PEER_PER_WINDOW` connections within the
/// rolling `PEER_RATE_WINDOW` is rejected (its stale entries are pruned first)
/// before any handshake work is performed. This complements the per-call
/// deadline, which bounds total unauthenticated work without terminating the
/// listener after a fixed number of malformed peers.
struct PeerRateLimiter {
    window: Duration,
    max: usize,
    // peer IP string -> list of recent connect instants (unsorted append-only;
    // pruned lazily on each check).
    seen: std::collections::HashMap<String, Vec<Instant>>,
}

#[doc(hidden)]
pub struct PeerRateLimiterProbe {
    inner: PeerRateLimiter,
}

#[doc(hidden)]
impl Default for PeerRateLimiterProbe {
    fn default() -> Self {
        Self::new()
    }
}

#[doc(hidden)]
impl PeerRateLimiterProbe {
    pub fn new() -> Self {
        Self {
            inner: PeerRateLimiter::new(),
        }
    }

    pub fn check(&mut self, addr: SocketAddr) -> bool {
        self.inner.check_and_record(addr).is_ok()
    }
}

impl PeerRateLimiter {
    fn new() -> Self {
        Self {
            window: PEER_RATE_WINDOW,
            max: MAX_CONNECTS_PER_PEER_PER_WINDOW,
            seen: std::collections::HashMap::new(),
        }
    }

    /// Record a connect from `addr` and return `Ok(())` if it is within the
    /// rate limit, or `Err` if the peer has exceeded it. The check prunes
    /// entries older than the window before counting.
    fn check_and_record(&mut self, addr: SocketAddr) -> std::result::Result<(), ShphError> {
        let key = addr.ip().to_string();
        let now = Instant::now();
        let cutoff = now - self.window;
        self.seen.retain(|_, entries| {
            entries.retain(|t| *t > cutoff);
            !entries.is_empty()
        });
        if !self.seen.contains_key(&key) && self.seen.len() >= MAX_QUIC_TRACKED_PEERS {
            if let Some(oldest_key) = self
                .seen
                .iter()
                .min_by_key(|(_, entries)| entries.first().copied())
                .map(|(key, _)| key.clone())
            {
                self.seen.remove(&oldest_key);
            }
        }
        let entries = self.seen.entry(key).or_default();
        entries.retain(|t| *t > cutoff);
        if entries.len() >= self.max {
            return Err(ShphError::Transport(format!(
                "peer {} exceeded connection rate limit ({} per {:?})",
                addr.ip(),
                self.max,
                self.window
            )));
        }
        entries.push(now);
        Ok(())
    }

    fn requires_cookie(&self, addr: SocketAddr) -> bool {
        let key = addr.ip().to_string();
        self.seen
            .get(&key)
            .is_some_and(|entries| entries.len() >= COOKIE_CHALLENGE_THRESHOLD)
    }
}

pub fn tcp_accept_and_handshake(
    bind_addr: &str,
    local_identity: &IdentityKeyPair,
    policy: &PeerPolicy,
    timeout_secs: u64,
) -> Result<(TcpStream, HandshakeState)> {
    tcp_accept_and_handshake_with_profile(
        bind_addr,
        local_identity,
        policy,
        timeout_secs,
        HandshakeProfile::SecureDefault,
    )
}

pub fn tcp_accept_and_handshake_with_profile(
    bind_addr: &str,
    local_identity: &IdentityKeyPair,
    policy: &PeerPolicy,
    timeout_secs: u64,
    profile: HandshakeProfile,
) -> Result<(TcpStream, HandshakeState)> {
    let listener = TcpListener::bind(bind_addr).map_err(|e| ShphError::Transport(e.to_string()))?;
    listener.set_nonblocking(true).map_err(ShphError::Io)?;
    let mut last_err: Option<ShphError> = None;
    let mut rate_limiter = PeerRateLimiter::new();
    let cookie_authority = Arc::new(Mutex::new(StatelessCookieAuthority::new()?));
    let cancellation = Arc::new(AtomicBool::new(false));
    let (result_sender, result_receiver) =
        mpsc::sync_channel::<Result<(TcpStream, HandshakeState)>>(MAX_CONCURRENT_TCP_HANDSHAKES);
    let mut active_workers = 0usize;
    let deadline = tcp_handshake_deadline(timeout_secs);

    // Keep accepting while bounded worker threads perform socket reads and
    // pre-authentication. A slow client can consume one short-lived worker
    // instead of blocking the listener from accepting a legitimate peer.
    while Instant::now() < deadline {
        if let Ok(result) = result_receiver.try_recv() {
            if let Some(result) =
                finish_tcp_worker(result, &mut active_workers, &mut last_err, &cancellation)
            {
                return result;
            }
            continue;
        }

        if active_workers >= MAX_CONCURRENT_TCP_HANDSHAKES {
            let wait =
                Duration::from_millis(10).min(deadline.saturating_duration_since(Instant::now()));
            match result_receiver.recv_timeout(wait) {
                Ok(result) => {
                    if let Some(result) =
                        finish_tcp_worker(result, &mut active_workers, &mut last_err, &cancellation)
                    {
                        return result;
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(last_err.unwrap_or_else(|| {
                        ShphError::Internal("TCP handshake workers exited".into())
                    }));
                }
            }
            continue;
        }

        match listener.accept() {
            Ok((stream, peer_addr)) => {
                stream.set_nonblocking(false).map_err(ShphError::Io)?;
                if let Err(error) = stream.set_nodelay(true) {
                    tracing::debug!(peer = %peer_addr, error = %error, "failed to enable TCP_NODELAY");
                }

                // Rate-limit before any handshake work so one source cannot
                // fill the worker budget with repeated malformed sessions.
                if let Err(err) = rate_limiter.check_and_record(peer_addr) {
                    last_err = Some(err);
                    continue;
                }

                let requires_cookie = rate_limiter.requires_cookie(peer_addr);
                let worker_sender = result_sender.clone();
                let worker_cookie_authority = Arc::clone(&cookie_authority);
                let worker_cancellation = Arc::clone(&cancellation);
                let worker_identity = local_identity.clone();
                let worker_policy = policy.clone();
                active_workers += 1;
                thread::spawn(move || {
                    let result = TcpHandshakeWorker {
                        stream,
                        peer_addr,
                        local_identity: worker_identity,
                        policy: worker_policy,
                        profile,
                        aggregate_deadline: deadline,
                        requires_cookie,
                        cookie_authority: worker_cookie_authority,
                        cancellation: Arc::clone(&worker_cancellation),
                    }
                    .run();
                    if result.is_ok() {
                        worker_cancellation.store(true, Ordering::Release);
                    }
                    let _ = worker_sender.send(result);
                });
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                let wait = Duration::from_millis(10)
                    .min(deadline.saturating_duration_since(Instant::now()));
                match result_receiver.recv_timeout(wait) {
                    Ok(result) => {
                        if let Some(result) = finish_tcp_worker(
                            result,
                            &mut active_workers,
                            &mut last_err,
                            &cancellation,
                        ) {
                            return result;
                        }
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        return Err(last_err.unwrap_or_else(|| {
                            ShphError::Internal("TCP handshake workers exited".into())
                        }));
                    }
                }
            }
            Err(err) => return Err(ShphError::Transport(err.to_string())),
        }
    }
    cancellation.store(true, Ordering::Release);
    Err(last_err.unwrap_or(ShphError::Timeout))
}

fn finish_tcp_worker(
    result: Result<(TcpStream, HandshakeState)>,
    active_workers: &mut usize,
    last_err: &mut Option<ShphError>,
    cancellation: &AtomicBool,
) -> Option<Result<(TcpStream, HandshakeState)>> {
    *active_workers = active_workers.saturating_sub(1);
    match result {
        Ok(session) => {
            cancellation.store(true, Ordering::Release);
            Some(Ok(session))
        }
        Err(error) => {
            *last_err = Some(error);
            None
        }
    }
}

struct TcpHandshakeWorker {
    stream: TcpStream,
    peer_addr: SocketAddr,
    local_identity: IdentityKeyPair,
    policy: PeerPolicy,
    profile: HandshakeProfile,
    aggregate_deadline: Instant,
    requires_cookie: bool,
    cookie_authority: Arc<Mutex<StatelessCookieAuthority>>,
    cancellation: Arc<AtomicBool>,
}

impl TcpHandshakeWorker {
    fn run(mut self) -> Result<(TcpStream, HandshakeState)> {
        if self.cancellation.load(Ordering::Acquire) {
            return Err(ShphError::Timeout);
        }
        let preauth_deadline = std::cmp::min(
            self.aggregate_deadline,
            Instant::now() + TCP_PREAUTH_DEADLINE,
        );
        refresh_deadline_timeout(&self.stream, preauth_deadline)?;
        let peer_hello = read_tcp_hello_with_deadline(&mut self.stream, preauth_deadline)?;
        if self.cancellation.load(Ordering::Acquire) {
            return Err(ShphError::Timeout);
        }

        if self.requires_cookie {
            let cookie = {
                let mut authority = self.cookie_authority.lock().map_err(|_| {
                    ShphError::Internal("TCP cookie authority lock poisoned".into())
                })?;
                authority.issue(self.peer_addr)?
            };
            write_tcp_cookie_challenge_with_deadline(&mut self.stream, &cookie, preauth_deadline)?;
            let response =
                read_tcp_cookie_response_with_deadline(&mut self.stream, preauth_deadline)?;
            let valid = {
                let mut authority = self.cookie_authority.lock().map_err(|_| {
                    ShphError::Internal("TCP cookie authority lock poisoned".into())
                })?;
                authority.verify(self.peer_addr, &response)?
            };
            if !valid {
                return Err(ShphError::Auth(
                    "invalid or expired pre-authentication cookie".into(),
                ));
            }
        }

        if self.cancellation.load(Ordering::Acquire) {
            return Err(ShphError::Timeout);
        }
        let mut material = build_hello_with_profile(&self.local_identity, self.profile)?;
        shph_core::verify_hello_signature(
            &self.local_identity,
            &material,
            &peer_hello,
            &self.policy,
        )?;
        write_tcp_hello_with_deadline(&mut self.stream, &material.local_hello, preauth_deadline)?;
        if self.profile.uses_pqc() {
            let ct = read_tcp_pq_ct_with_deadline(&mut self.stream, preauth_deadline)?;
            absorb_responder_pq(
                &self.local_identity,
                &mut material,
                &peer_hello,
                &ct,
                &self.policy,
            )?;
        }
        let state = verify_and_derive(
            &self.local_identity,
            &material,
            &peer_hello,
            false,
            &self.policy,
        )?;
        clear_deadline_timeout(&self.stream)?;
        Ok((self.stream, state))
    }
}

fn write_tcp_hello_with_deadline(
    stream: &mut TcpStream,
    hello: &Hello,
    deadline: Instant,
) -> Result<()> {
    let payload = serialize_hello_with_padding(hello)?;
    if payload.len() > MAX_HELLO_BYTES {
        return Err(ShphError::Protocol("hello exceeds size limit".into()));
    }
    write_tcp_all_or_closed_with_deadline(stream, &payload, deadline)?;
    write_tcp_all_or_closed_with_deadline(stream, b"\n", deadline)?;
    refresh_deadline_timeout(stream, deadline)?;
    stream.flush().map_err(map_io_error)?;
    Ok(())
}

fn serialize_hello_with_padding(hello: &Hello) -> Result<Vec<u8>> {
    shph_core::serialize_hello_frame(hello)
}

#[cfg(test)]
fn serialize_hello_with_padding_len(hello: &Hello, padding_len: usize) -> Result<Vec<u8>> {
    shph_core::serialize_hello_frame_with_padding_len(hello, padding_len)
}

fn read_tcp_hello_with_deadline(stream: &mut TcpStream, deadline: Instant) -> Result<Hello> {
    let buf = read_tcp_line_with_deadline(stream, MAX_HELLO_BYTES, deadline)?;
    let hello_line =
        std::str::from_utf8(&buf).map_err(|_| ShphError::Protocol("hello not utf8".into()))?;
    serde_json::from_str::<Hello>(hello_line).map_err(|e| ShphError::Protocol(e.to_string()))
}

fn read_tcp_server_hello_with_deadline(stream: &mut TcpStream, deadline: Instant) -> Result<Hello> {
    let line = read_tcp_line_with_deadline(stream, MAX_HELLO_BYTES, deadline)?;
    if line.starts_with(COOKIE_CHALLENGE_PREFIX) {
        let encoded = &line[COOKIE_CHALLENGE_PREFIX.len()..];
        let cookie = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| ShphError::Protocol("invalid cookie challenge encoding".into()))?;
        if cookie.len() != 32 {
            return Err(ShphError::Protocol(
                "cookie challenge has invalid length".into(),
            ));
        }
        write_tcp_cookie_response_with_deadline(stream, &cookie, deadline)?;
        return read_tcp_hello_with_deadline(stream, deadline);
    }
    let hello_line =
        std::str::from_utf8(&line).map_err(|_| ShphError::Protocol("hello not utf8".into()))?;
    serde_json::from_str::<Hello>(hello_line).map_err(|e| ShphError::Protocol(e.to_string()))
}

#[cfg(test)]
fn write_tcp_cookie_challenge(stream: &mut TcpStream, cookie: &[u8; 32]) -> Result<()> {
    let encoded = base64::engine::general_purpose::STANDARD.encode(cookie);
    write_tcp_all_or_closed(stream, COOKIE_CHALLENGE_PREFIX)?;
    write_tcp_all_or_closed(stream, encoded.as_bytes())?;
    write_tcp_all_or_closed(stream, b"\n")?;
    stream.flush().map_err(map_io_error)?;
    Ok(())
}

fn write_tcp_cookie_challenge_with_deadline(
    stream: &mut TcpStream,
    cookie: &[u8; 32],
    deadline: Instant,
) -> Result<()> {
    let encoded = base64::engine::general_purpose::STANDARD.encode(cookie);
    write_tcp_all_or_closed_with_deadline(stream, COOKIE_CHALLENGE_PREFIX, deadline)?;
    write_tcp_all_or_closed_with_deadline(stream, encoded.as_bytes(), deadline)?;
    write_tcp_all_or_closed_with_deadline(stream, b"\n", deadline)?;
    refresh_deadline_timeout(stream, deadline)?;
    stream.flush().map_err(map_io_error)?;
    Ok(())
}

#[cfg(test)]
fn write_tcp_cookie_response(stream: &mut TcpStream, cookie: &[u8]) -> Result<()> {
    if cookie.len() != 32 {
        return Err(ShphError::Protocol(
            "cookie response has invalid length".into(),
        ));
    }
    let encoded = base64::engine::general_purpose::STANDARD.encode(cookie);
    write_tcp_all_or_closed(stream, COOKIE_RESPONSE_PREFIX)?;
    write_tcp_all_or_closed(stream, encoded.as_bytes())?;
    write_tcp_all_or_closed(stream, b"\n")?;
    stream.flush().map_err(map_io_error)?;
    Ok(())
}

fn write_tcp_cookie_response_with_deadline(
    stream: &mut TcpStream,
    cookie: &[u8],
    deadline: Instant,
) -> Result<()> {
    if cookie.len() != 32 {
        return Err(ShphError::Protocol(
            "cookie response has invalid length".into(),
        ));
    }
    let encoded = base64::engine::general_purpose::STANDARD.encode(cookie);
    write_tcp_all_or_closed_with_deadline(stream, COOKIE_RESPONSE_PREFIX, deadline)?;
    write_tcp_all_or_closed_with_deadline(stream, encoded.as_bytes(), deadline)?;
    write_tcp_all_or_closed_with_deadline(stream, b"\n", deadline)?;
    refresh_deadline_timeout(stream, deadline)?;
    stream.flush().map_err(map_io_error)?;
    Ok(())
}

#[cfg(test)]
fn read_tcp_cookie_response(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let line = read_tcp_line(stream, MAX_COOKIE_LINE_BYTES)?;
    if !line.starts_with(COOKIE_RESPONSE_PREFIX) {
        return Err(ShphError::Protocol(
            "expected pre-authentication cookie response".into(),
        ));
    }
    let cookie = base64::engine::general_purpose::STANDARD
        .decode(&line[COOKIE_RESPONSE_PREFIX.len()..])
        .map_err(|_| ShphError::Protocol("invalid cookie response encoding".into()))?;
    if cookie.len() != 32 {
        return Err(ShphError::Protocol(
            "cookie response has invalid length".into(),
        ));
    }
    Ok(cookie)
}

fn read_tcp_cookie_response_with_deadline(
    stream: &mut TcpStream,
    deadline: Instant,
) -> Result<Vec<u8>> {
    let line = read_tcp_line_with_deadline(stream, MAX_COOKIE_LINE_BYTES, deadline)?;
    if !line.starts_with(COOKIE_RESPONSE_PREFIX) {
        return Err(ShphError::Protocol(
            "expected pre-authentication cookie response".into(),
        ));
    }
    let cookie = base64::engine::general_purpose::STANDARD
        .decode(&line[COOKIE_RESPONSE_PREFIX.len()..])
        .map_err(|_| ShphError::Protocol("invalid cookie response encoding".into()))?;
    if cookie.len() != 32 {
        return Err(ShphError::Protocol(
            "cookie response has invalid length".into(),
        ));
    }
    Ok(cookie)
}

#[cfg(test)]
fn read_tcp_line(stream: &mut TcpStream, max_bytes: usize) -> Result<Vec<u8>> {
    read_tcp_line_until(stream, max_bytes, None)
}

fn read_tcp_line_with_deadline(
    stream: &mut TcpStream,
    max_bytes: usize,
    deadline: Instant,
) -> Result<Vec<u8>> {
    read_tcp_line_until(stream, max_bytes, Some(deadline))
}

fn read_tcp_line_until(
    stream: &mut TcpStream,
    max_bytes: usize,
    deadline: Option<Instant>,
) -> Result<Vec<u8>> {
    // Read exactly one byte at a time so bytes belonging to the next
    // length-prefixed handshake message cannot be consumed and discarded when
    // a peer pipelines its hello and PQ ciphertext. The aggregate deadline
    // below bounds the deliberately small amount of extra syscall overhead.
    let mut buf = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    let max_with_newline = max_bytes.saturating_add(1);
    loop {
        if let Some(deadline) = deadline {
            refresh_deadline_timeout(stream, deadline)?;
        }
        let read = stream.read(&mut byte).map_err(map_io_error)?;
        if read == 0 {
            return if buf.is_empty() {
                Err(ShphError::ConnectionClosed)
            } else {
                Err(ShphError::Protocol("truncated hello".into()))
            };
        }
        // Enforce the cap including any data already buffered.
        if buf.len() >= max_with_newline {
            return Err(ShphError::Protocol("hello exceeds size limit".into()));
        }
        buf.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
    }
    // Strip the trailing newline (and a CR if present).
    while buf
        .last()
        .map(|&b| b == b'\n' || b == b'\r')
        .unwrap_or(false)
    {
        buf.pop();
    }
    if buf.len() > max_bytes {
        return Err(ShphError::Protocol("hello exceeds size limit".into()));
    }
    Ok(buf)
}

fn write_tcp_pq_ct_with_deadline(
    stream: &mut TcpStream,
    ct: &[u8],
    deadline: Instant,
) -> Result<()> {
    if ct.len() != ML_KEM_768_CIPHERTEXT_BYTES {
        return Err(ShphError::Protocol(format!(
            "pq ciphertext size mismatch: expected {}, got {}",
            ML_KEM_768_CIPHERTEXT_BYTES,
            ct.len()
        )));
    }
    write_tcp_all_or_closed_with_deadline(stream, &(ct.len() as u32).to_be_bytes(), deadline)?;
    write_tcp_all_or_closed_with_deadline(stream, ct, deadline)?;
    refresh_deadline_timeout(stream, deadline)?;
    stream.flush().map_err(map_io_error)?;
    Ok(())
}

fn read_tcp_pq_ct_with_deadline(stream: &mut TcpStream, deadline: Instant) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    read_exact_or_closed_with_deadline(stream, &mut len_buf, deadline)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len != ML_KEM_768_CIPHERTEXT_BYTES {
        return Err(ShphError::Protocol(format!(
            "pq ciphertext length mismatch: expected {}, got {}",
            ML_KEM_768_CIPHERTEXT_BYTES, len
        )));
    }
    let mut ct = vec![0u8; len];
    read_exact_or_closed_with_deadline(stream, &mut ct, deadline)?;
    Ok(ct)
}

fn read_exact_or_closed_with_deadline(
    stream: &mut TcpStream,
    buf: &mut [u8],
    deadline: Instant,
) -> Result<()> {
    let mut filled = 0;
    while filled < buf.len() {
        refresh_deadline_timeout(stream, deadline)?;
        let n = stream.read(&mut buf[filled..]).map_err(map_io_error)?;
        if n == 0 {
            return Err(ShphError::ConnectionClosed);
        }
        filled += n;
    }
    Ok(())
}

fn read_exact_or_closed_with_deadline_and_cancel(
    stream: &mut TcpStream,
    buffer: &mut [u8],
    deadline: Instant,
    cancelled: &dyn Fn() -> bool,
) -> Result<()> {
    let mut filled = 0;
    while filled < buffer.len() {
        check_setup_cancellation(Some(cancelled))?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(ShphError::Timeout);
        }
        stream.set_read_timeout(Some(remaining.min(SOCKS_CANCEL_POLL_INTERVAL)))?;
        match stream.read(&mut buffer[filled..]) {
            Ok(0) => return Err(ShphError::ConnectionClosed),
            Ok(read) => filled += read,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                check_setup_cancellation(Some(cancelled))?;
                if Instant::now() >= deadline {
                    return Err(ShphError::Timeout);
                }
            }
            Err(error) => return Err(map_io_error(error)),
        }
    }
    check_setup_cancellation(Some(cancelled))
}

fn refresh_deadline_timeout(stream: &TcpStream, deadline: Instant) -> Result<()> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(ShphError::Timeout);
    }
    stream.set_read_timeout(Some(remaining))?;
    stream.set_write_timeout(Some(remaining))?;
    Ok(())
}

fn clear_deadline_timeout(stream: &TcpStream) -> Result<()> {
    stream.set_read_timeout(None).map_err(ShphError::Io)?;
    stream.set_write_timeout(None).map_err(ShphError::Io)?;
    Ok(())
}

pub fn tcp_connect_secure_session(
    peer: &str,
    local_identity: &IdentityKeyPair,
    policy: &PeerPolicy,
    timeout_secs: u64,
) -> Result<(SecureTcpSession, HandshakeState)> {
    let (stream, state) = tcp_connect_and_handshake(peer, local_identity, policy, timeout_secs)?;
    let session = SecureTcpSession::new(
        stream,
        state.session_keys.send_key,
        state.session_keys.recv_key,
    );
    Ok((session, state))
}

pub fn tcp_accept_secure_session(
    bind_addr: &str,
    local_identity: &IdentityKeyPair,
    policy: &PeerPolicy,
    timeout_secs: u64,
) -> Result<(SecureTcpSession, HandshakeState)> {
    let (stream, state) =
        tcp_accept_and_handshake(bind_addr, local_identity, policy, timeout_secs)?;
    let session = SecureTcpSession::new(
        stream,
        state.session_keys.send_key,
        state.session_keys.recv_key,
    );
    Ok((session, state))
}

pub struct SecureTcpSession {
    stream: TcpStream,
    send_cipher: SendCipher,
    recv_cipher: ReceiveCipher,
    padding_profile: Option<ProfileTier>,
    padding_padder: Option<ProfilePadder>,
    padding_buffer: Vec<u8>,
    phantom_one_encoder: Option<PhantomOneEncoder>,
    phantom_one_decoder: Option<PhantomOneDecoder>,
    frame_reader: TcpFrameReader,
    _snap_bridge_lifecycle: Option<Arc<snap_adapter::SnapBridgeLifecycle>>,
}

impl SecureTcpSession {
    pub fn new(stream: TcpStream, send_key: [u8; 32], recv_key: [u8; 32]) -> Self {
        Self {
            stream,
            send_cipher: SendCipher::new(send_key),
            recv_cipher: ReceiveCipher::new(recv_key),
            padding_profile: None,
            padding_padder: None,
            padding_buffer: Vec::new(),
            phantom_one_encoder: None,
            phantom_one_decoder: None,
            frame_reader: TcpFrameReader::default(),
            _snap_bridge_lifecycle: None,
        }
    }

    pub fn send_frame(&mut self, payload: &[u8]) -> Result<()> {
        write_encrypted_tcp_frame(
            &mut self.stream,
            &mut self.send_cipher,
            payload,
            self.padding_profile,
            self.padding_padder.as_mut(),
            &mut self.padding_buffer,
            self.phantom_one_encoder.as_mut(),
        )
    }

    pub fn recv_frame(&mut self) -> Result<Vec<u8>> {
        read_encrypted_tcp_frame(
            &mut self.stream,
            &mut self.recv_cipher,
            &mut self.frame_reader,
            self.padding_profile,
            self.phantom_one_decoder.as_mut(),
        )
    }

    pub fn with_padding_profile(mut self, profile: ProfileTier) -> Self {
        self.padding_profile = Some(profile);
        self.padding_padder = Some(ProfilePadder::new(profile));
        self.padding_buffer.clear();
        self
    }

    pub fn stream_mut(&mut self) -> &mut TcpStream {
        &mut self.stream
    }

    pub fn into_split(self) -> Result<(SecureTcpSender, SecureTcpReceiver)> {
        let recv_stream = self.stream.try_clone().map_err(map_io_error)?;
        let snap_bridge_lifecycle = self._snap_bridge_lifecycle;
        let sender = SecureTcpSender {
            stream: self.stream,
            send_cipher: self.send_cipher,
            padding_profile: self.padding_profile,
            padding_padder: self.padding_padder,
            padding_buffer: self.padding_buffer,
            phantom_one_encoder: self.phantom_one_encoder,
            _snap_bridge_lifecycle: snap_bridge_lifecycle.clone(),
        };
        let receiver = SecureTcpReceiver {
            stream: recv_stream,
            recv_cipher: self.recv_cipher,
            padding_profile: self.padding_profile,
            phantom_one_decoder: self.phantom_one_decoder,
            frame_reader: self.frame_reader,
            _snap_bridge_lifecycle: snap_bridge_lifecycle,
        };
        Ok((sender, receiver))
    }
}

pub struct SecureTcpSender {
    stream: TcpStream,
    send_cipher: SendCipher,
    padding_profile: Option<ProfileTier>,
    padding_padder: Option<ProfilePadder>,
    padding_buffer: Vec<u8>,
    phantom_one_encoder: Option<PhantomOneEncoder>,
    _snap_bridge_lifecycle: Option<Arc<snap_adapter::SnapBridgeLifecycle>>,
}

impl SecureTcpSender {
    pub fn send_frame(&mut self, payload: &[u8]) -> Result<()> {
        write_encrypted_tcp_frame(
            &mut self.stream,
            &mut self.send_cipher,
            payload,
            self.padding_profile,
            self.padding_padder.as_mut(),
            &mut self.padding_buffer,
            self.phantom_one_encoder.as_mut(),
        )
    }
}

pub struct SecureTcpReceiver {
    stream: TcpStream,
    recv_cipher: ReceiveCipher,
    padding_profile: Option<ProfileTier>,
    phantom_one_decoder: Option<PhantomOneDecoder>,
    frame_reader: TcpFrameReader,
    _snap_bridge_lifecycle: Option<Arc<snap_adapter::SnapBridgeLifecycle>>,
}

impl SecureTcpReceiver {
    pub fn recv_frame(&mut self) -> Result<Vec<u8>> {
        read_encrypted_tcp_frame(
            &mut self.stream,
            &mut self.recv_cipher,
            &mut self.frame_reader,
            self.padding_profile,
            self.phantom_one_decoder.as_mut(),
        )
    }
}

/// Send one encrypted TCP frame using the caller-owned, stateful AEAD cipher.
///
/// The cipher must be retained for the lifetime of the session so its nonce
/// counter advances for every frame. Constructing a new cipher per send would
/// restart the counter and risk nonce reuse under the same key.
pub fn tcp_secure_send(
    stream: &mut TcpStream,
    send_cipher: &mut SendCipher,
    payload: &[u8],
) -> Result<()> {
    let mut padding_buffer = Vec::new();
    write_encrypted_tcp_frame(
        stream,
        send_cipher,
        payload,
        None,
        None,
        &mut padding_buffer,
        None,
    )
}

/// Send one encrypted TCP frame with a shared discrete padding profile.
pub fn tcp_secure_send_with_profile(
    stream: &mut TcpStream,
    send_cipher: &mut SendCipher,
    payload: &[u8],
    profile: ProfileTier,
) -> Result<()> {
    let mut padder = ProfilePadder::new(profile);
    let mut padding_buffer = Vec::new();
    tcp_secure_send_with_profile_stateful(
        stream,
        send_cipher,
        payload,
        &mut padder,
        &mut padding_buffer,
    )
}

/// Send one encrypted TCP frame using caller-owned session padding state.
///
/// Reuse `padder` and `padding_buffer` for every frame in a session. This
/// keeps profile randomness session-stable and avoids recreating the padding
/// generator or its working buffer for each call.
pub fn tcp_secure_send_with_profile_stateful(
    stream: &mut TcpStream,
    send_cipher: &mut SendCipher,
    payload: &[u8],
    padder: &mut ProfilePadder,
    padding_buffer: &mut Vec<u8>,
) -> Result<()> {
    write_encrypted_tcp_frame(
        stream,
        send_cipher,
        payload,
        Some(padder.profile()),
        Some(padder),
        padding_buffer,
        None,
    )
}

/// Receive one encrypted TCP frame using the caller-owned, stateful AEAD cipher.
///
/// The cipher must be retained for the lifetime of the session so replay
/// protection remembers every authenticated frame received on the connection.
pub fn tcp_secure_receive(
    stream: &mut TcpStream,
    recv_cipher: &mut ReceiveCipher,
) -> Result<Vec<u8>> {
    let mut frame_reader = TcpFrameReader::default();
    read_encrypted_tcp_frame(stream, recv_cipher, &mut frame_reader, None, None)
}

/// Receive one encrypted TCP frame and remove its shared discrete padding
/// profile after authenticated decryption.
pub fn tcp_secure_receive_with_profile(
    stream: &mut TcpStream,
    recv_cipher: &mut ReceiveCipher,
    profile: ProfileTier,
) -> Result<Vec<u8>> {
    let mut frame_reader = TcpFrameReader::default();
    read_encrypted_tcp_frame(stream, recv_cipher, &mut frame_reader, Some(profile), None)
}

// Experimental QUIC-like shim.
pub fn quic_handshake_client(
    peer: &str,
    local_identity: &IdentityKeyPair,
    policy: &PeerPolicy,
    timeout_secs: u64,
) -> Result<(UdpSocket, SocketAddr, HandshakeState)> {
    quic_handshake_client_with_profile(
        peer,
        local_identity,
        policy,
        timeout_secs,
        HandshakeProfile::SecureDefault,
    )
}

pub fn quic_handshake_client_with_profile(
    peer: &str,
    local_identity: &IdentityKeyPair,
    policy: &PeerPolicy,
    timeout_secs: u64,
    profile: HandshakeProfile,
) -> Result<(UdpSocket, SocketAddr, HandshakeState)> {
    quic_handshake_client_with_profile_timeout(
        peer,
        local_identity,
        policy,
        Duration::from_secs(bounded_quic_timeout_secs(timeout_secs)),
        profile,
    )
}

pub fn quic_handshake_client_with_profile_timeout(
    peer: &str,
    local_identity: &IdentityKeyPair,
    policy: &PeerPolicy,
    timeout: Duration,
    profile: HandshakeProfile,
) -> Result<(UdpSocket, SocketAddr, HandshakeState)> {
    let timeout = timeout
        .max(Duration::from_millis(1))
        .min(Duration::from_secs(MAX_QUIC_IDLE_TIMEOUT_SECS));
    let deadline = Instant::now() + timeout;
    let peer_addr = parse_socket_addr(peer, deadline)?;
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| ShphError::Transport(e.to_string()))?;
    socket
        .set_read_timeout(Some(timeout))
        .map_err(ShphError::Io)?;
    socket
        .set_write_timeout(Some(timeout))
        .map_err(ShphError::Io)?;

    let material = build_hello_with_profile(local_identity, profile)?;
    let mut buf = vec![0u8; MAX_QUIC_HELLO_BYTES];
    let mut last_err: Option<ShphError> = None;

    for _ in 0..QUIC_HANDSHAKE_ATTEMPTS {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        socket
            .set_read_timeout(Some(remaining))
            .map_err(ShphError::Io)?;
        socket
            .set_write_timeout(Some(remaining))
            .map_err(ShphError::Io)?;
        let peer_hello = write_and_wait_quic_hello(
            &socket,
            peer_addr,
            &material.local_hello,
            &mut buf,
            deadline,
        );
        match peer_hello {
            Ok((peer_hello, addr)) if addr == peer_addr => {
                let mut material = material;
                shph_core::verify_hello_signature(local_identity, &material, &peer_hello, policy)?;
                if profile.uses_pqc() {
                    let ct =
                        finalize_initiator_pq(local_identity, &mut material, &peer_hello, policy)?;
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        return Err(ShphError::Timeout);
                    }
                    socket
                        .set_write_timeout(Some(remaining))
                        .map_err(ShphError::Io)?;
                    write_quic_pq_ct(&socket, peer_addr, &ct)?;
                }
                let state =
                    verify_and_derive(local_identity, &material, &peer_hello, true, policy)?;
                return Ok((socket, peer_addr, state));
            }
            Ok((_, _)) => {
                last_err = Some(ShphError::Protocol(
                    "peer address mismatch during handshake".into(),
                ));
            }
            Err(err) => last_err = Some(err),
        }
    }

    Err(last_err.unwrap_or(ShphError::Timeout))
}

pub fn quic_handshake_server(
    bind_addr: &str,
    local_identity: &IdentityKeyPair,
    policy: &PeerPolicy,
    timeout_secs: u64,
) -> Result<(UdpSocket, SocketAddr, HandshakeState)> {
    quic_handshake_server_with_profile(
        bind_addr,
        local_identity,
        policy,
        timeout_secs,
        HandshakeProfile::SecureDefault,
    )
}

pub fn quic_handshake_server_with_profile(
    bind_addr: &str,
    local_identity: &IdentityKeyPair,
    policy: &PeerPolicy,
    timeout_secs: u64,
    profile: HandshakeProfile,
) -> Result<(UdpSocket, SocketAddr, HandshakeState)> {
    let socket = UdpSocket::bind(bind_addr).map_err(|e| ShphError::Transport(e.to_string()))?;
    quic_handshake_server_on_socket_with_profile(
        socket,
        local_identity,
        policy,
        timeout_secs,
        profile,
    )
}

/// Complete the experimental QUIC-like UDP handshake on an already-bound
/// socket.
///
/// Keeping socket creation separate lets callers reserve a port before
/// starting a server thread, avoiding a bind/send startup race in local
/// integration and benchmark harnesses.
pub fn quic_handshake_server_on_socket_with_profile(
    socket: UdpSocket,
    local_identity: &IdentityKeyPair,
    policy: &PeerPolicy,
    timeout_secs: u64,
    profile: HandshakeProfile,
) -> Result<(UdpSocket, SocketAddr, HandshakeState)> {
    let timeout_secs = bounded_quic_timeout_secs(timeout_secs);
    socket
        .set_read_timeout(Some(Duration::from_secs(timeout_secs)))
        .map_err(ShphError::Io)?;
    socket
        .set_write_timeout(Some(Duration::from_secs(timeout_secs)))
        .map_err(ShphError::Io)?;

    let material = build_hello_with_profile(local_identity, profile)?;
    let mut line = vec![0u8; MAX_QUIC_HELLO_BYTES];
    let mut peer_hello = None;
    // Per-source rate limit, mirroring the TCP accept path: a single host that
    // floods the UDP entry path is dropped before its hello is parsed, so it
    // cannot exhaust the handshake loop budget or burn CPU on deserialization.
    let mut rate_limiter = PeerRateLimiter::new();

    let start = Instant::now();
    let deadline = Duration::from_secs(timeout_secs.max(1));

    while start.elapsed() < deadline {
        match read_quic_datagram(&socket, &mut line) {
            Ok((len, peer_addr)) => {
                if rate_limiter.check_and_record(peer_addr).is_err() {
                    continue;
                }
                match decode_quic_hello(len, &line[..len], peer_addr) {
                    Ok(hello) => {
                        if shph_core::verify_hello_signature(
                            local_identity,
                            &material,
                            &hello.0,
                            policy,
                        )
                        .is_err()
                        {
                            continue;
                        }
                        peer_hello = Some(hello);
                        break;
                    }
                    Err(_) => continue,
                }
            }
            Err(ShphError::Timeout) => continue,
            Err(ShphError::Protocol(_)) => continue,
            Err(err) => return Err(err),
        }
    }

    let (peer_hello, peer_addr) = peer_hello.ok_or(ShphError::Timeout)?;

    let remaining = Duration::from_secs(timeout_secs).saturating_sub(start.elapsed());
    if remaining.is_zero() {
        return Err(ShphError::Timeout);
    }
    socket
        .set_read_timeout(Some(remaining))
        .map_err(ShphError::Io)?;
    write_tcp_hello_to_peer(&socket, peer_addr, &material.local_hello)?;
    let mut material = material;
    shph_core::verify_hello_signature(local_identity, &material, &peer_hello, policy)?;
    if profile.uses_pqc() {
        let ct = read_quic_pq_ct(&socket, peer_addr)?;
        absorb_responder_pq(local_identity, &mut material, &peer_hello, &ct, policy)?;
    }
    let state = verify_and_derive(local_identity, &material, &peer_hello, false, policy)?;
    Ok((socket, peer_addr, state))
}

pub fn quic_connect_and_handshake(
    peer: &str,
    local_identity: &IdentityKeyPair,
    policy: &PeerPolicy,
    timeout_secs: u64,
) -> Result<(UdpSocket, SocketAddr, HandshakeState)> {
    quic_handshake_client(peer, local_identity, policy, timeout_secs)
}

pub fn quic_accept_and_handshake(
    bind_addr: &str,
    local_identity: &IdentityKeyPair,
    policy: &PeerPolicy,
    timeout_secs: u64,
) -> Result<(UdpSocket, SocketAddr, HandshakeState)> {
    quic_handshake_server(bind_addr, local_identity, policy, timeout_secs)
}

fn write_and_wait_quic_hello(
    socket: &UdpSocket,
    peer_addr: SocketAddr,
    hello: &Hello,
    buf: &mut [u8],
    deadline: Instant,
) -> Result<(Hello, SocketAddr)> {
    let payload = serialize_hello_with_padding(hello)?;
    if payload.len() > MAX_QUIC_HELLO_BYTES {
        return Err(ShphError::Protocol(
            "quic hello payload exceeds size limit".into(),
        ));
    }

    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(ShphError::Timeout);
    }
    socket
        .set_write_timeout(Some(remaining))
        .map_err(ShphError::Io)?;
    socket.send_to(&payload, peer_addr).map_err(map_io_error)?;

    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(ShphError::Timeout);
    }
    socket
        .set_read_timeout(Some(remaining))
        .map_err(ShphError::Io)?;
    let read = socket.recv_from(buf).map_err(map_io_error)?;
    if read.0 == buf.len() {
        return Err(ShphError::Protocol(
            "quic hello may be truncated (fills receive buffer)".into(),
        ));
    }
    decode_quic_hello(read.0, &buf[0..read.0], read.1)
}

fn read_quic_datagram(socket: &UdpSocket, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
    let (len, peer_addr) = socket.recv_from(buf).map_err(map_io_error)?;
    // If the datagram exactly filled the buffer it may have been truncated by
    // the kernel (recv_from never reports the true on-wire size). A legitimate
    // hello is strictly smaller than the cap, so a full buffer is treated as an
    // oversized/rejected hello to prevent parsing a truncated message.
    if len == buf.len() {
        return Err(ShphError::Protocol(
            "quic hello may be truncated (fills receive buffer)".into(),
        ));
    }
    Ok((len, peer_addr))
}

fn decode_quic_hello(
    len: usize,
    payload: &[u8],
    peer_addr: SocketAddr,
) -> Result<(Hello, SocketAddr)> {
    if len == 0 || len > MAX_QUIC_HELLO_BYTES {
        return Err(ShphError::Protocol("invalid quic hello length".into()));
    }

    let hello_line =
        std::str::from_utf8(payload).map_err(|_| ShphError::Protocol("hello not utf8".into()))?;
    let hello = serde_json::from_str::<Hello>(hello_line)
        .map_err(|e| ShphError::Protocol(e.to_string()))?;
    Ok((hello, peer_addr))
}

fn write_tcp_hello_to_peer(socket: &UdpSocket, peer_addr: SocketAddr, hello: &Hello) -> Result<()> {
    let payload = serialize_hello_with_padding(hello)?;
    if payload.len() > MAX_QUIC_HELLO_BYTES {
        return Err(ShphError::Protocol(
            "quic hello payload exceeds size limit".into(),
        ));
    }
    socket
        .send_to(&payload, peer_addr)
        .map_err(map_io_error)
        .map(|_| ())
}

/// Send the initiator's PQ ciphertext as a single bounded UDP datagram.
fn write_quic_pq_ct(socket: &UdpSocket, peer_addr: SocketAddr, ct: &[u8]) -> Result<()> {
    if ct.len() != ML_KEM_768_CIPHERTEXT_BYTES {
        return Err(ShphError::Protocol(format!(
            "pq ciphertext size mismatch: expected {}, got {}",
            ML_KEM_768_CIPHERTEXT_BYTES,
            ct.len()
        )));
    }
    socket.send_to(ct, peer_addr).map_err(map_io_error)?;
    Ok(())
}

/// Receive the initiator's PQ ciphertext datagram from the expected peer.
fn read_quic_pq_ct(socket: &UdpSocket, expected_peer: SocketAddr) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; ML_KEM_768_CIPHERTEXT_BYTES + 1];
    let mut invalid = 0;
    loop {
        let (len, addr) = socket.recv_from(&mut buf).map_err(map_io_error)?;
        if addr != expected_peer || len != ML_KEM_768_CIPHERTEXT_BYTES {
            invalid += 1;
            if invalid >= MAX_QUIC_INVALID_DATAGRAMS_PER_RECV {
                return Err(ShphError::Protocol(
                    "too many invalid QUIC handshake datagrams".into(),
                ));
            }
            continue;
        }
        return Ok(buf[..len].to_vec());
    }
}

pub struct ExperimentalQuicSession {
    socket: UdpSocket,
    peer: SocketAddr,
    send_cipher: SendCipher,
    recv_cipher: ReceiveCipher,
    shroud_profile: Option<ShroudProfile>,
    shroud_rng: Option<StdRng>,
    padding_profile: Option<ProfileTier>,
    padding_padder: Option<ProfilePadder>,
    padding_buffer: Vec<u8>,
}

pub struct ExperimentalQuicSender {
    socket: UdpSocket,
    peer: SocketAddr,
    send_cipher: SendCipher,
    shroud_profile: Option<ShroudProfile>,
    shroud_rng: Option<StdRng>,
    padding_profile: Option<ProfileTier>,
    padding_padder: Option<ProfilePadder>,
    padding_buffer: Vec<u8>,
}

pub struct ExperimentalQuicReceiver {
    socket: UdpSocket,
    peer: SocketAddr,
    recv_cipher: ReceiveCipher,
    shroud_profile: Option<ShroudProfile>,
    padding_profile: Option<ProfileTier>,
}

impl ExperimentalQuicSession {
    fn new(socket: UdpSocket, peer: SocketAddr, send_key: [u8; 32], recv_key: [u8; 32]) -> Self {
        Self {
            socket,
            peer,
            send_cipher: SendCipher::new(send_key),
            recv_cipher: ReceiveCipher::new_with_replay_window(recv_key, 128),
            shroud_profile: None,
            shroud_rng: None,
            padding_profile: None,
            padding_padder: None,
            padding_buffer: Vec::new(),
        }
    }

    pub fn send_frame(&mut self, payload: &[u8]) -> Result<()> {
        write_encrypted_quic_frame_with_profile(
            &self.socket,
            self.peer,
            &mut self.send_cipher,
            payload,
            self.shroud_profile,
            self.padding_profile,
            self.padding_padder.as_mut(),
            &mut self.padding_buffer,
            self.shroud_rng.as_mut(),
        )
    }

    pub fn recv_frame(&mut self) -> Result<Vec<u8>> {
        read_encrypted_quic_frame(
            &self.socket,
            &mut self.recv_cipher,
            self.peer,
            self.shroud_profile,
            self.padding_profile,
        )
    }

    pub fn into_split(self) -> Result<(ExperimentalQuicSender, ExperimentalQuicReceiver)> {
        let recv_socket = self.socket.try_clone().map_err(map_io_error)?;
        let send_socket = self.socket;
        let peer = self.peer;
        Ok((
            ExperimentalQuicSender {
                socket: send_socket,
                peer,
                send_cipher: self.send_cipher,
                shroud_profile: self.shroud_profile,
                shroud_rng: self.shroud_rng,
                padding_profile: self.padding_profile,
                padding_padder: self.padding_padder,
                padding_buffer: self.padding_buffer,
            },
            ExperimentalQuicReceiver {
                socket: recv_socket,
                peer,
                recv_cipher: self.recv_cipher,
                shroud_profile: self.shroud_profile,
                padding_profile: self.padding_profile,
            },
        ))
    }
}

impl ExperimentalQuicSender {
    pub fn send_frame(&mut self, payload: &[u8]) -> Result<()> {
        write_encrypted_quic_frame_with_profile(
            &self.socket,
            self.peer,
            &mut self.send_cipher,
            payload,
            self.shroud_profile,
            self.padding_profile,
            self.padding_padder.as_mut(),
            &mut self.padding_buffer,
            self.shroud_rng.as_mut(),
        )
    }
}

impl ExperimentalQuicReceiver {
    pub fn recv_frame(&mut self) -> Result<Vec<u8>> {
        read_encrypted_quic_frame(
            &self.socket,
            &mut self.recv_cipher,
            self.peer,
            self.shroud_profile,
            self.padding_profile,
        )
    }
}

fn write_encrypted_tcp_frame(
    stream: &mut TcpStream,
    cipher: &mut SendCipher,
    payload: &[u8],
    padding_profile: Option<ProfileTier>,
    padding_padder: Option<&mut ProfilePadder>,
    padding_buffer: &mut Vec<u8>,
    phantom_one_encoder: Option<&mut PhantomOneEncoder>,
) -> Result<()> {
    let padding_cleanup = ZeroizeOnDrop::new(padding_buffer);
    validate_tcp_payload(payload)?;
    if phantom_one_encoder.is_some() && (padding_profile.is_some() || padding_padder.is_some()) {
        return Err(ShphError::Protocol(
            "Phantom One cannot be combined with the legacy TCP padding profile".into(),
        ));
    }
    let framed = match (padding_profile, padding_padder) {
        (Some(_), Some(padder)) => {
            padder.apply_into(payload, padding_cleanup.buffer)?;
            padding_cleanup.buffer.as_slice()
        }
        (Some(profile), None) => {
            apply_profile_into(profile, payload, padding_cleanup.buffer)?;
            padding_cleanup.buffer.as_slice()
        }
        (None, _) => match phantom_one_encoder {
            Some(encoder) => {
                encoder.encode_into(
                    PhantomOneFrameType::Data,
                    payload,
                    PHANTOM_ONE_TCP_PATH_MTU,
                    padding_cleanup.buffer,
                )?;
                padding_cleanup.buffer.as_slice()
            }
            None => payload,
        },
    };
    let encrypted = cipher.encrypt(framed)?;
    let len = u32::try_from(encrypted.len())
        .map_err(|_| ShphError::Protocol("encrypted frame length overflows u32".into()))?;
    write_tcp_all_or_closed(stream, &len.to_be_bytes())?;
    write_tcp_all_or_closed(stream, &encrypted)?;
    stream.flush().map_err(map_io_error)?;
    Ok(())
}

fn validate_tcp_payload(payload: &[u8]) -> Result<()> {
    if payload.len() > MAX_TCP_PAYLOAD_BYTES {
        return Err(ShphError::Protocol(format!(
            "TCP payload exceeds the {MAX_TCP_PAYLOAD_BYTES}-byte frame capacity"
        )));
    }
    Ok(())
}

/// Incrementally collects length-prefixed TCP frames without losing bytes
/// when a polling read times out between segments.
///
/// Native TUN loops intentionally use a short read timeout so shutdown can be
/// observed promptly. `std::io::Read::read_exact` is unsafe for that pattern:
/// it may consume a partial prefix or ciphertext and then return `TimedOut`,
/// leaving the next call misaligned. This reader retains all bytes and the
/// current frame boundary across calls.
#[derive(Debug, Default)]
struct TcpFrameReader {
    wire: Vec<u8>,
    expected_wire_len: Option<usize>,
}

impl TcpFrameReader {
    fn recv_frame(
        &mut self,
        stream: &mut TcpStream,
        cipher: &mut ReceiveCipher,
        padding_profile: Option<ProfileTier>,
    ) -> Result<Vec<u8>> {
        loop {
            if self.expected_wire_len.is_none() && self.wire.len() >= 4 {
                let len =
                    u32::from_be_bytes([self.wire[0], self.wire[1], self.wire[2], self.wire[3]])
                        as usize;
                if len == 0 || len > MAX_FRAME_BYTES {
                    self.wire.zeroize();
                    self.wire.clear();
                    self.expected_wire_len = None;
                    return Err(ShphError::Protocol("encrypted frame length invalid".into()));
                }
                self.expected_wire_len = Some(4 + len);
            }

            if let Some(expected_wire_len) = self.expected_wire_len {
                if self.wire.len() >= expected_wire_len {
                    let decrypted = cipher.decrypt(&self.wire[4..expected_wire_len]);
                    self.wire.zeroize();
                    self.wire.clear();
                    self.expected_wire_len = None;
                    let mut framed = decrypted?;
                    if let Some(profile) = padding_profile {
                        if let Err(error) = remove_profile_in_place(profile, &mut framed) {
                            framed.zeroize();
                            return Err(error);
                        }
                    }
                    return Ok(framed);
                }
            }

            let needed = match self.expected_wire_len {
                Some(expected_wire_len) => expected_wire_len.saturating_sub(self.wire.len()),
                None => 4usize.saturating_sub(self.wire.len()),
            };
            let mut chunk = [0u8; 8192];
            let read_len = needed.min(chunk.len());
            let read = match stream.read(&mut chunk[..read_len]) {
                Ok(read) => read,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(map_io_error(error)),
            };
            if read == 0 {
                return Err(ShphError::ConnectionClosed);
            }
            self.wire.extend_from_slice(&chunk[..read]);
        }
    }
}

fn read_encrypted_tcp_frame(
    stream: &mut TcpStream,
    cipher: &mut ReceiveCipher,
    frame_reader: &mut TcpFrameReader,
    padding_profile: Option<ProfileTier>,
    phantom_one_decoder: Option<&mut PhantomOneDecoder>,
) -> Result<Vec<u8>> {
    if phantom_one_decoder.is_some() && padding_profile.is_some() {
        return Err(ShphError::Protocol(
            "Phantom One cannot be combined with the legacy TCP padding profile".into(),
        ));
    }
    let mut framed = frame_reader.recv_frame(stream, cipher, padding_profile)?;
    match phantom_one_decoder {
        Some(decoder) => {
            if let Err(error) = decoder.decode_in_place(&mut framed, PHANTOM_ONE_TCP_PATH_MTU) {
                framed.zeroize();
                return Err(error);
            }
            Ok(framed)
        }
        None => Ok(framed),
    }
}

#[cfg(test)]
fn write_encrypted_quic_frame(
    socket: &UdpSocket,
    peer: SocketAddr,
    cipher: &mut SendCipher,
    payload: &[u8],
    shroud_profile: Option<ShroudProfile>,
) -> Result<()> {
    let mut padding_buffer = Vec::new();
    write_encrypted_quic_frame_with_profile(
        socket,
        peer,
        cipher,
        payload,
        shroud_profile,
        None,
        None,
        &mut padding_buffer,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn write_encrypted_quic_frame_with_profile(
    socket: &UdpSocket,
    peer: SocketAddr,
    cipher: &mut SendCipher,
    payload: &[u8],
    shroud_profile: Option<ShroudProfile>,
    padding_profile: Option<ProfileTier>,
    padding_padder: Option<&mut ProfilePadder>,
    padding_buffer: &mut Vec<u8>,
    shroud_rng: Option<&mut StdRng>,
) -> Result<()> {
    let padding_cleanup = ZeroizeOnDrop::new(padding_buffer);
    let framed_payload = match (padding_profile, padding_padder) {
        (Some(_), Some(padder)) => {
            padder.apply_into(payload, padding_cleanup.buffer)?;
            padding_cleanup.buffer.as_slice()
        }
        (Some(profile), None) => {
            apply_profile_into(profile, payload, padding_cleanup.buffer)?;
            padding_cleanup.buffer.as_slice()
        }
        (None, _) => payload,
    };
    let encrypted = if let Some(profile) = shroud_profile {
        if !profile.is_valid() {
            return Err(ShphError::Protocol("invalid Shroud profile".into()));
        }
        let plaintext_capacity = profile
            .payload_capacity()
            .checked_sub(SHROUD_AEAD_OVERHEAD)
            .ok_or_else(|| ShphError::Protocol("Shroud cell too small for AEAD".into()))?;
        let max_payload = plaintext_capacity
            .checked_sub(SHROUD_LENGTH_PREFIX)
            .ok_or_else(|| ShphError::Protocol("Shroud cell too small for length prefix".into()))?
            .min(profile.max_payload_chunk);
        if framed_payload.len() > max_payload || framed_payload.len() > u16::MAX as usize {
            return Err(ShphError::Protocol(
                "payload exceeds Shroud profile capacity".into(),
            ));
        }
        let mut padded = Zeroizing::new(vec![0u8; plaintext_capacity]);
        padded[..SHROUD_LENGTH_PREFIX]
            .copy_from_slice(&(framed_payload.len() as u16).to_be_bytes());
        padded[SHROUD_LENGTH_PREFIX..SHROUD_LENGTH_PREFIX + framed_payload.len()]
            .copy_from_slice(framed_payload);
        if !profile.deterministic_padding {
            if let Some(rng) = shroud_rng {
                rng.try_fill_bytes(&mut padded[SHROUD_LENGTH_PREFIX + framed_payload.len()..])
                    .map_err(|_| ShphError::Crypto("Shroud padding randomness failed".into()))?;
            } else {
                rand::rngs::OsRng
                    .try_fill_bytes(&mut padded[SHROUD_LENGTH_PREFIX + framed_payload.len()..])
                    .map_err(|_| ShphError::Crypto("Shroud padding randomness failed".into()))?;
            }
        }
        cipher.encrypt(padded.as_slice())?
    } else {
        if framed_payload.len() > MAX_QUIC_PAYLOAD_BYTES {
            return Err(ShphError::Protocol(format!(
                "QUIC payload exceeds the {MAX_QUIC_PAYLOAD_BYTES}-byte frame capacity"
            )));
        }
        cipher.encrypt(framed_payload)?
    };
    let encrypted = if let Some(profile) = shroud_profile {
        shph_core::encode_cell(profile, shph_core::SHROUD_FRAME_DATA, &encrypted)?
    } else {
        encrypted
    };
    if encrypted.is_empty() {
        return Err(ShphError::Protocol("empty QUIC payload".into()));
    }
    if encrypted.len() > MAX_QUIC_FRAME_BYTES {
        return Err(ShphError::Protocol(
            "QUIC frame exceeds configured size".into(),
        ));
    }

    let mut packet = Zeroizing::new(Vec::with_capacity(4 + encrypted.len()));
    packet.extend_from_slice(&(encrypted.len() as u32).to_be_bytes());
    packet.extend_from_slice(&encrypted);
    if packet.len() > MAX_QUIC_FRAME_BYTES {
        return Err(ShphError::Protocol(
            "QUIC frame exceeds transport datagram budget".into(),
        ));
    }
    socket
        .send_to(packet.as_slice(), peer)
        .map_err(map_io_error)
        .map(|_| ())
}

fn read_encrypted_quic_frame(
    socket: &UdpSocket,
    cipher: &mut ReceiveCipher,
    expected_peer: SocketAddr,
    shroud_profile: Option<ShroudProfile>,
    padding_profile: Option<ProfileTier>,
) -> Result<Vec<u8>> {
    // Source-address binding: after the handshake authenticates a peer address,
    // every data-frame datagram must arrive from that same address. Without this
    // check an off-path attacker could inject forged ciphertext datagrams,
    // forcing expensive AEAD-decrypt work and disrupting the authenticated
    // stream. Rejecting foreign sources closes the injection/amplification path.
    let mut packet = Zeroizing::new(vec![0u8; MAX_QUIC_FRAME_BYTES + 1]);
    let mut invalid = 0;
    loop {
        let (len, addr) = match socket.recv_from(packet.as_mut_slice()) {
            Ok(packet) => packet,
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                if invalid > 0 {
                    return Err(ShphError::Protocol(
                        "invalid QUIC data datagrams received before timeout".into(),
                    ));
                }
                return Err(ShphError::Timeout);
            }
            Err(err) => return Err(map_io_error(err)),
        };
        if addr != expected_peer {
            invalid += 1;
        } else {
            match decode_encrypted_quic_frame_with_profile(
                &packet[..len.min(packet.len())],
                len,
                cipher,
                shroud_profile,
                padding_profile,
            ) {
                Ok(payload) => return Ok(payload),
                Err(_) => invalid += 1,
            }
        }
        if invalid >= MAX_QUIC_INVALID_DATAGRAMS_PER_RECV {
            return Err(ShphError::Protocol(
                "too many invalid QUIC data datagrams".into(),
            ));
        }
    }
}

#[cfg(test)]
fn decode_encrypted_quic_frame(
    packet: &[u8],
    len: usize,
    cipher: &mut ReceiveCipher,
    shroud_profile: Option<ShroudProfile>,
) -> Result<Vec<u8>> {
    decode_encrypted_quic_frame_with_profile(packet, len, cipher, shroud_profile, None)
}

fn decode_encrypted_quic_frame_with_profile(
    packet: &[u8],
    len: usize,
    cipher: &mut ReceiveCipher,
    shroud_profile: Option<ShroudProfile>,
    padding_profile: Option<ProfileTier>,
) -> Result<Vec<u8>> {
    if !(4..=MAX_QUIC_FRAME_BYTES).contains(&len) || packet.len() != len {
        return Err(ShphError::Protocol("invalid QUIC frame length".into()));
    }

    let payload_len = u32::from_be_bytes([packet[0], packet[1], packet[2], packet[3]]) as usize;
    if payload_len == 0 || payload_len > MAX_QUIC_FRAME_BYTES || 4 + payload_len != len {
        return Err(ShphError::Protocol("invalid QUIC payload length".into()));
    }

    let payload = &packet[4..];
    if let Some(profile) = shroud_profile {
        if !profile.is_valid() {
            return Err(ShphError::Protocol("invalid Shroud profile".into()));
        }
        let encrypted = shph_core::decode_cell_payload(profile, payload)?
            .ok_or_else(|| ShphError::Protocol("unexpected shroud chaff frame".into()))?;
        let mut padded = cipher.decrypt(encrypted)?;
        if padded.len() < SHROUD_LENGTH_PREFIX {
            padded.zeroize();
            return Err(ShphError::Protocol(
                "Shroud payload missing length prefix".into(),
            ));
        }
        let payload_len = u16::from_be_bytes([padded[0], padded[1]]) as usize;
        if payload_len > padded.len() - SHROUD_LENGTH_PREFIX
            || payload_len > profile.max_payload_chunk
        {
            padded.zeroize();
            return Err(ShphError::Protocol(
                "Shroud payload length exceeds profile capacity".into(),
            ));
        }
        let payload_end = SHROUD_LENGTH_PREFIX + payload_len;
        padded.copy_within(SHROUD_LENGTH_PREFIX..payload_end, 0);
        padded[payload_len..].zeroize();
        padded.truncate(payload_len);
        if let Some(profile) = padding_profile {
            if let Err(error) = remove_profile_in_place(profile, &mut padded) {
                padded.zeroize();
                return Err(error);
            }
        }
        Ok(padded)
    } else {
        let mut framed = cipher.decrypt(payload)?;
        if let Some(profile) = padding_profile {
            if let Err(error) = remove_profile_in_place(profile, &mut framed) {
                framed.zeroize();
                return Err(error);
            }
        }
        Ok(framed)
    }
}
fn write_tcp_all_or_closed(stream: &mut TcpStream, payload: &[u8]) -> Result<()> {
    stream.write_all(payload).map_err(map_io_error)
}

fn write_tcp_all_or_closed_with_deadline(
    stream: &mut TcpStream,
    payload: &[u8],
    deadline: Instant,
) -> Result<()> {
    let mut written = 0;
    while written < payload.len() {
        refresh_deadline_timeout(stream, deadline)?;
        let n = stream.write(&payload[written..]).map_err(map_io_error)?;
        if n == 0 {
            return Err(ShphError::ConnectionClosed);
        }
        written += n;
    }
    Ok(())
}

fn write_tcp_all_or_closed_with_deadline_and_cancel(
    stream: &mut TcpStream,
    payload: &[u8],
    deadline: Instant,
    cancelled: &dyn Fn() -> bool,
) -> Result<()> {
    let mut written = 0;
    while written < payload.len() {
        check_setup_cancellation(Some(cancelled))?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(ShphError::Timeout);
        }
        stream.set_write_timeout(Some(remaining.min(SOCKS_CANCEL_POLL_INTERVAL)))?;
        match stream.write(&payload[written..]) {
            Ok(0) => return Err(ShphError::ConnectionClosed),
            Ok(count) => written += count,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                check_setup_cancellation(Some(cancelled))?;
                if Instant::now() >= deadline {
                    return Err(ShphError::Timeout);
                }
            }
            Err(error) => return Err(map_io_error(error)),
        }
    }
    check_setup_cancellation(Some(cancelled))
}

struct OfflineMeshSession {
    send_state: OfflineMeshWriteState,
    recv_state: OfflineMeshReadState,
    send_cipher: SendCipher,
    recv_cipher: ReceiveCipher,
}

impl OfflineMeshSession {
    fn new(
        send_state: OfflineMeshWriteState,
        recv_state: OfflineMeshReadState,
        send_key: [u8; 32],
        recv_key: [u8; 32],
    ) -> Self {
        Self {
            send_state,
            recv_state,
            send_cipher: SendCipher::new(send_key),
            recv_cipher: ReceiveCipher::new(recv_key),
        }
    }

    fn send_frame(&mut self, payload: &[u8]) -> Result<()> {
        validate_file_adapter_payload(
            payload,
            self.send_state.max_payload_bytes,
            self.send_state.max_file_bytes,
        )?;
        let ciphertext = self.send_cipher.encrypt(payload)?;
        self.send_state.send_payload(&ciphertext)
    }

    fn recv_frame(&mut self) -> Result<Vec<u8>> {
        let timeout = self.recv_state.poll_interval;
        self.recv_state
            .receive_decrypted_frame(&mut self.recv_cipher, timeout)
    }

    fn into_split(self) -> Result<(OfflineMeshSender, OfflineMeshReceiver)> {
        let timeout = self.recv_state.poll_interval;
        Ok((
            OfflineMeshSender {
                state: self.send_state,
                cipher: self.send_cipher,
            },
            OfflineMeshReceiver {
                state: self.recv_state,
                cipher: self.recv_cipher,
                timeout,
            },
        ))
    }
}

struct OfflineMeshSender {
    state: OfflineMeshWriteState,
    cipher: SendCipher,
}

impl OfflineMeshSender {
    fn send_frame(&mut self, payload: &[u8]) -> Result<()> {
        validate_file_adapter_payload(
            payload,
            self.state.max_payload_bytes,
            self.state.max_file_bytes,
        )?;
        let ciphertext = self.cipher.encrypt(payload)?;
        self.state.send_payload(&ciphertext)
    }
}

struct OfflineMeshReceiver {
    state: OfflineMeshReadState,
    cipher: ReceiveCipher,
    timeout: Duration,
}

impl OfflineMeshReceiver {
    fn recv_frame(&mut self) -> Result<Vec<u8>> {
        self.state
            .receive_decrypted_frame(&mut self.cipher, self.timeout)
    }
}

struct OfflineMeshWriteState {
    spool_dir: String,
    local_node: String,
    peer_node: String,
    next_sequence: u64,
    max_file_bytes: u64,
    max_payload_bytes: usize,
}

impl OfflineMeshWriteState {
    fn new(cfg: &OfflineMeshConfig, local_node: &str, peer_node: &str) -> Self {
        let max_file_bytes = MAX_FILE_ADAPTER_BYTES;
        Self {
            spool_dir: cfg.spool_dir.clone(),
            local_node: local_node.to_string(),
            peer_node: peer_node.to_string(),
            next_sequence: 0,
            max_file_bytes,
            max_payload_bytes: offline_mesh_payload_capacity(max_file_bytes, local_node, peer_node),
        }
    }

    fn send_payload(&mut self, payload: &[u8]) -> Result<()> {
        let session_id = offline_session_id(&self.local_node, &self.peer_node);
        let envelope = OfflineMeshEnvelope {
            session_id: session_id.clone(),
            from: self.local_node.clone(),
            to: self.peer_node.clone(),
            created_at_unix_ms: now_unix_ms()?,
            sequence: self.next_sequence,
            ciphertext_b64: base64::engine::general_purpose::STANDARD.encode(payload),
        };
        self.next_sequence = self.next_sequence.saturating_add(1);

        let out_dir = Path::new(&self.spool_dir)
            .join(session_id)
            .join("out")
            .join(sanitize_component(&self.local_node))
            .join(sanitize_component(&self.peer_node));

        ensure_no_reparse_components(&out_dir).map_err(ShphError::Io)?;
        fs::create_dir_all(&out_dir).map_err(ShphError::Io)?;
        ensure_no_reparse_components(&out_dir).map_err(ShphError::Io)?;

        let filename = format!("{}-{}.json", envelope.created_at_unix_ms, envelope.sequence);
        let path = out_dir.join(filename);
        let bytes = serde_json::to_vec(&envelope).map_err(ShphError::Serialization)?;
        if bytes.len() as u64 > self.max_file_bytes {
            return Err(ShphError::Protocol(
                "offline mesh envelope too large".into(),
            ));
        }

        write_file_atomically(&path, &bytes)
    }
}

struct OfflineMeshReadState {
    spool_dir: String,
    local_node: String,
    peer_node: String,
    poll_interval: Duration,
    seen_frames: HashSet<(u64, u64)>,
    seen_order: VecDeque<(u64, u64)>,
    max_seen: usize,
    max_file_bytes: u64,
}

impl OfflineMeshReadState {
    fn new(cfg: &OfflineMeshConfig, local_node: &str, peer_node: &str) -> Self {
        Self {
            spool_dir: cfg.spool_dir.clone(),
            local_node: local_node.to_string(),
            peer_node: peer_node.to_string(),
            poll_interval: Duration::from_millis(
                cfg.poll_interval_ms.clamp(1, MAX_ADAPTER_POLL_INTERVAL_MS),
            ),
            seen_frames: HashSet::new(),
            seen_order: VecDeque::new(),
            max_seen: cfg.max_idle_entries.clamp(1, 65_536) as usize,
            max_file_bytes: MAX_FILE_ADAPTER_BYTES,
        }
    }

    fn inbound_queue_dir(&self) -> PathBuf {
        let session_id = offline_session_id(&self.local_node, &self.peer_node);
        Path::new(&self.spool_dir)
            .join(session_id)
            .join("out")
            .join(sanitize_component(&self.peer_node))
            .join(sanitize_component(&self.local_node))
    }

    fn receive_verified_hello(
        &mut self,
        timeout: Duration,
        local_identity: &IdentityKeyPair,
        material: &HandshakeMaterial,
        policy: &PeerPolicy,
    ) -> Result<Hello> {
        let frame = self.receive_raw_payload(timeout)?;
        let peer_hello = match serde_json::from_slice::<Hello>(&frame.payload) {
            Ok(hello) => hello,
            Err(error) => {
                quarantine_claimed_file(frame.claimed);
                return Err(ShphError::Protocol(format!("invalid peer hello: {error}")));
            }
        };
        if let Err(error) =
            shph_core::verify_hello_signature(local_identity, material, &peer_hello, policy)
        {
            quarantine_claimed_file(frame.claimed);
            return Err(error);
        }
        self.commit_frame(&frame);
        Ok(peer_hello)
    }

    fn receive_verified_responder_pq(
        &mut self,
        timeout: Duration,
        local_identity: &IdentityKeyPair,
        material: &mut HandshakeMaterial,
        peer_hello: &Hello,
        policy: &PeerPolicy,
    ) -> Result<()> {
        let frame = self.receive_raw_payload(timeout)?;
        match shph_core::absorb_responder_pq(
            local_identity,
            material,
            peer_hello,
            &frame.payload,
            policy,
        ) {
            Ok(()) => {
                self.commit_frame(&frame);
                Ok(())
            }
            Err(error) => {
                quarantine_claimed_file(frame.claimed);
                Err(error)
            }
        }
    }

    fn receive_raw_payload(&mut self, timeout: Duration) -> Result<OfflineMeshFrame> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(frame) = self.poll_inbound()? {
                return Ok(frame);
            }

            if Instant::now() >= deadline {
                return Err(ShphError::Timeout);
            }

            thread::sleep(self.poll_interval);
        }
    }

    fn receive_decrypted_frame(
        &mut self,
        cipher: &mut ReceiveCipher,
        timeout: Duration,
    ) -> Result<Vec<u8>> {
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let frame = self.receive_raw_payload(remaining)?;
            match cipher.decrypt(&frame.payload) {
                Ok(plaintext) => {
                    self.commit_frame(&frame);
                    return Ok(plaintext);
                }
                Err(error) => {
                    quarantine_claimed_file(frame.claimed);
                    if Instant::now() >= deadline {
                        return Err(error);
                    }
                }
            }
        }
    }

    fn poll_inbound(&mut self) -> Result<Option<OfflineMeshFrame>> {
        let queue_dir = self.inbound_queue_dir();
        ensure_no_reparse_components(&queue_dir).map_err(ShphError::Io)?;
        let queue_metadata = match fs::symlink_metadata(&queue_dir) {
            Ok(metadata) if metadata.is_dir() => Some(metadata),
            Ok(_) => {
                return Err(ShphError::Protocol(
                    "offline-mesh queue path is not a directory".into(),
                ))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(ShphError::Io(error)),
        };
        if queue_metadata.is_none() {
            return Ok(None);
        }

        let expected_session = offline_session_id(&self.local_node, &self.peer_node);
        let mut candidates = Vec::new();
        let mut scanned = 0usize;
        let mut scanned_bytes = 0u64;
        let mut candidate_memory = 0usize;
        for entry in fs::read_dir(&queue_dir).map_err(ShphError::Io)? {
            account_scan_entry(&mut scanned)?;
            let entry = entry.map_err(ShphError::Io)?;
            let path = entry.path();
            ensure_no_reparse_components(&path).map_err(ShphError::Io)?;
            let metadata = match fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(ShphError::Io(error)),
            };
            if !metadata.file_type().is_file() {
                continue;
            }

            let ext = path.extension().and_then(|ext| ext.to_str()).unwrap_or("");
            if ext != "json" {
                continue;
            }
            if metadata.len() > self.max_file_bytes {
                quarantine_file(&path);
                continue;
            }
            account_scan_bytes(&mut scanned_bytes, metadata.len())?;

            let bytes = match read_file_bytes(&path, self.max_file_bytes) {
                Ok(bytes) => bytes,
                Err(ShphError::Protocol(_)) => {
                    quarantine_file(&path);
                    continue;
                }
                Err(err) => return Err(err),
            };
            let envelope: OfflineMeshEnvelope = match serde_json::from_slice(&bytes) {
                Ok(e) => e,
                Err(_) => {
                    quarantine_file(&path);
                    continue;
                }
            };
            if envelope.session_id != expected_session
                || envelope.from != self.peer_node
                || envelope.to != self.local_node
                || self
                    .seen_frames
                    .contains(&(envelope.created_at_unix_ms, envelope.sequence))
            {
                continue;
            }
            match account_candidate_memory(
                &mut candidate_memory,
                &path,
                &[&envelope.session_id, &envelope.from, &envelope.to],
            ) {
                Ok(()) => {}
                Err(ShphError::Protocol(_)) => {
                    quarantine_file(&path);
                    continue;
                }
                Err(error) => return Err(error),
            }
            candidates.push(OfflineMeshCandidate {
                path,
                created_at_unix_ms: envelope.created_at_unix_ms,
                sequence: envelope.sequence,
            });
        }
        if candidates.is_empty() {
            return Ok(None);
        }

        candidates.sort_by_key(|candidate| (candidate.created_at_unix_ms, candidate.sequence));
        for candidate in candidates {
            let Some(claimed) = claim_file(&candidate.path).map_err(ShphError::Io)? else {
                continue;
            };
            let bytes = match read_file_bytes(&claimed.path, self.max_file_bytes) {
                Ok(bytes) => bytes,
                Err(ShphError::Protocol(_)) => {
                    quarantine_claimed_file(claimed);
                    continue;
                }
                Err(ShphError::Io(error)) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(err) => return Err(err),
            };
            let envelope: OfflineMeshEnvelope = match serde_json::from_slice(&bytes) {
                Ok(envelope) => envelope,
                Err(_) => {
                    quarantine_claimed_file(claimed);
                    continue;
                }
            };
            if envelope.session_id != expected_session
                || envelope.from != self.peer_node
                || envelope.to != self.local_node
                || envelope.created_at_unix_ms != candidate.created_at_unix_ms
                || envelope.sequence != candidate.sequence
                || self
                    .seen_frames
                    .contains(&(envelope.created_at_unix_ms, envelope.sequence))
            {
                quarantine_claimed_file(claimed);
                continue;
            }
            match base64::engine::general_purpose::STANDARD
                .decode(envelope.ciphertext_b64.as_bytes())
            {
                Ok(payload) => {
                    return Ok(Some(OfflineMeshFrame {
                        payload,
                        claimed,
                        created_at_unix_ms: envelope.created_at_unix_ms,
                        sequence: envelope.sequence,
                    }))
                }
                Err(_) => quarantine_claimed_file(claimed),
            }
        }
        Ok(None)
    }

    fn commit_payload(&mut self, created_at_unix_ms: u64, sequence: u64) {
        self.mark_seen(created_at_unix_ms, sequence);
    }

    fn commit_frame(&mut self, frame: &OfflineMeshFrame) {
        self.commit_payload(frame.created_at_unix_ms, frame.sequence);
        let _ = fs::remove_file(&frame.claimed.path);
    }

    fn mark_seen(&mut self, created_at_unix_ms: u64, sequence: u64) {
        let key = (created_at_unix_ms, sequence);
        if self.seen_frames.insert(key) {
            self.seen_order.push_back(key);
        }
        while self.seen_order.len() > self.max_seen.max(1) {
            if let Some(oldest) = self.seen_order.pop_front() {
                self.seen_frames.remove(&oldest);
            }
        }
    }
}

struct OfflineMeshFrame {
    payload: Vec<u8>,
    claimed: ClaimedFile,
    created_at_unix_ms: u64,
    sequence: u64,
}

struct DataMuleSession {
    send_state: DataMuleWriteState,
    recv_state: DataMuleReadState,
    send_cipher: SendCipher,
    recv_cipher: ReceiveCipher,
}

impl DataMuleSession {
    fn new(
        send_state: DataMuleWriteState,
        recv_state: DataMuleReadState,
        send_key: [u8; 32],
        recv_key: [u8; 32],
    ) -> Self {
        Self {
            send_state,
            recv_state,
            send_cipher: SendCipher::new(send_key),
            recv_cipher: ReceiveCipher::new(recv_key),
        }
    }

    fn send_frame(&mut self, payload: &[u8]) -> Result<()> {
        validate_file_adapter_payload(
            payload,
            self.send_state.max_payload_bytes,
            self.send_state.max_file_bytes,
        )?;
        let encrypted = self.send_cipher.encrypt(payload)?;
        self.send_state.send_payload(&encrypted)
    }

    fn recv_frame(&mut self) -> Result<Vec<u8>> {
        let timeout = self.recv_state.poll_interval;
        self.recv_state
            .receive_decrypted_frame(&mut self.recv_cipher, timeout)
    }

    fn into_split(self) -> Result<(DataMuleSender, DataMuleReceiver)> {
        let timeout = self.recv_state.poll_interval;
        Ok((
            DataMuleSender {
                state: self.send_state,
                cipher: self.send_cipher,
            },
            DataMuleReceiver {
                state: self.recv_state,
                cipher: self.recv_cipher,
                timeout,
            },
        ))
    }
}

struct DataMuleSender {
    state: DataMuleWriteState,
    cipher: SendCipher,
}

impl DataMuleSender {
    fn send_frame(&mut self, payload: &[u8]) -> Result<()> {
        validate_file_adapter_payload(
            payload,
            self.state.max_payload_bytes,
            self.state.max_file_bytes,
        )?;
        let encrypted = self.cipher.encrypt(payload)?;
        self.state.send_payload(&encrypted)
    }
}

struct DataMuleReceiver {
    state: DataMuleReadState,
    cipher: ReceiveCipher,
    timeout: Duration,
}

impl DataMuleReceiver {
    fn recv_frame(&mut self) -> Result<Vec<u8>> {
        self.state
            .receive_decrypted_frame(&mut self.cipher, self.timeout)
    }
}

struct DataMuleEnvelopeFrame {
    payload: Vec<u8>,
    envelope: DataMuleEnvelope,
    claimed: ClaimedFile,
}

fn base64_encoded_len(bytes: usize) -> usize {
    bytes
        .checked_add(2)
        .and_then(|rounded| rounded.checked_div(3))
        .and_then(|groups| groups.checked_mul(4))
        .unwrap_or(usize::MAX)
}

fn max_plaintext_for_file_adapter(max_file_bytes: u64, fixed_envelope_bytes: usize) -> usize {
    let max_file_bytes = usize::try_from(max_file_bytes).unwrap_or(usize::MAX);
    if fixed_envelope_bytes > max_file_bytes {
        return 0;
    }

    let mut low = 0usize;
    let mut high = max_file_bytes;
    while low < high {
        let candidate = low + (high - low).div_ceil(2);
        let encrypted_bytes = candidate.saturating_add(SHROUD_AEAD_OVERHEAD);
        let total_bytes = fixed_envelope_bytes.saturating_add(base64_encoded_len(encrypted_bytes));
        if total_bytes <= max_file_bytes {
            low = candidate;
        } else {
            high = candidate - 1;
        }
    }
    low
}

fn offline_mesh_payload_capacity(max_file_bytes: u64, local_node: &str, peer_node: &str) -> usize {
    let envelope = OfflineMeshEnvelope {
        session_id: offline_session_id(local_node, peer_node),
        from: local_node.to_owned(),
        to: peer_node.to_owned(),
        created_at_unix_ms: u64::MAX,
        sequence: u64::MAX,
        ciphertext_b64: String::new(),
    };
    let fixed_bytes = match serde_json::to_vec(&envelope) {
        Ok(bytes) => bytes.len(),
        Err(_) => return 0,
    };
    max_plaintext_for_file_adapter(max_file_bytes, fixed_bytes)
}

fn data_mule_payload_capacity(max_file_bytes: u64, local_node: &str, peer_node: &str) -> usize {
    let envelope = DataMuleEnvelope {
        envelope_id: format!("{}-{}", u64::MAX, u64::MAX),
        created_at_unix_ms: u64::MAX,
        from_node: local_node.to_owned(),
        to_node: peer_node.to_owned(),
        ciphertext_b64: String::new(),
        nonce_b64: base64::engine::general_purpose::STANDARD.encode(u64::MAX.to_le_bytes()),
    };
    let fixed_bytes = match serde_json::to_vec(&envelope) {
        Ok(bytes) => bytes.len(),
        Err(_) => return 0,
    };
    max_plaintext_for_file_adapter(max_file_bytes, fixed_bytes)
}

fn validate_file_adapter_payload(
    payload: &[u8],
    max_payload_bytes: usize,
    max_file_bytes: u64,
) -> Result<()> {
    if payload.len() > max_payload_bytes {
        return Err(ShphError::Protocol(format!(
            "file-adapter plaintext payload exceeds the {max_payload_bytes}-byte capacity of the configured {max_file_bytes}-byte envelope bound"
        )));
    }
    Ok(())
}

struct DataMuleWriteState {
    outbox_dir: String,
    local_node: String,
    peer_node: String,
    next_sequence: u64,
    max_file_bytes: u64,
    max_total_bytes: u64,
    max_age_ms: u64,
    max_payload_bytes: usize,
}

impl DataMuleWriteState {
    fn new(cfg: &DataMuleConfig, local_node: &str, peer_node: &str) -> Self {
        let max_file_bytes = cfg.max_file_bytes.clamp(1, MAX_FILE_ADAPTER_BYTES);
        let max_total_bytes = cfg
            .max_total_bytes
            .clamp(max_file_bytes, MAX_DATA_MULE_TOTAL_BYTES);
        let max_age_ms = cfg.max_age_ms.clamp(1, MAX_DATA_MULE_AGE_MS);
        Self {
            outbox_dir: cfg.outbox_dir.clone(),
            local_node: local_node.to_string(),
            peer_node: peer_node.to_string(),
            next_sequence: 0,
            max_file_bytes,
            max_total_bytes,
            max_age_ms,
            max_payload_bytes: data_mule_payload_capacity(max_file_bytes, local_node, peer_node),
        }
    }

    fn send_payload(&mut self, payload: &[u8]) -> Result<()> {
        let created_at = now_unix_ms()?;
        let envelope = DataMuleEnvelope {
            envelope_id: format!("{}-{}", created_at, self.next_sequence),
            created_at_unix_ms: created_at,
            from_node: self.local_node.clone(),
            to_node: self.peer_node.clone(),
            ciphertext_b64: base64::engine::general_purpose::STANDARD.encode(payload),
            nonce_b64: base64::engine::general_purpose::STANDARD
                .encode(self.next_sequence.to_le_bytes()),
        };
        self.next_sequence = self.next_sequence.saturating_add(1);

        let path = data_mule_inbox_path(&self.outbox_dir, &self.peer_node, &envelope.envelope_id);
        let bytes = serde_json::to_vec(&envelope).map_err(ShphError::Serialization)?;
        if bytes.len() as u64 > self.max_file_bytes {
            return Err(ShphError::Protocol("data-mule envelope too large".into()));
        }
        let queued_bytes = data_mule_spool_usage(
            Path::new(&self.outbox_dir),
            self.max_file_bytes,
            self.max_age_ms,
            created_at,
        )?;
        if queued_bytes.saturating_add(bytes.len() as u64) > self.max_total_bytes {
            return Err(ShphError::ResourceExhausted(format!(
                "data-mule outbox quota exhausted ({} bytes of {} configured)",
                queued_bytes, self.max_total_bytes
            )));
        }
        write_file_atomically(&path, &bytes)
    }
}

struct DataMuleReadState {
    inbox_dir: String,
    local_node: String,
    peer_filter: Option<String>,
    pending_candidates: VecDeque<DataMuleCandidate>,
    poll_interval: Duration,
    seen_envelopes: HashSet<String>,
    seen_order: VecDeque<String>,
    max_seen: usize,
    max_file_bytes: u64,
    max_age_ms: u64,
}

impl DataMuleReadState {
    fn new(cfg: &DataMuleConfig, local_node: &str, peer_filter: Option<&str>) -> Self {
        let max_file_bytes = cfg.max_file_bytes.clamp(1, MAX_FILE_ADAPTER_BYTES);
        Self {
            inbox_dir: cfg.inbox_dir.clone(),
            local_node: local_node.to_string(),
            peer_filter: peer_filter.map(std::string::ToString::to_string),
            pending_candidates: VecDeque::new(),
            poll_interval: Duration::from_millis(
                cfg.poll_interval_ms.clamp(1, MAX_ADAPTER_POLL_INTERVAL_MS),
            ),
            seen_envelopes: HashSet::new(),
            seen_order: VecDeque::new(),
            max_seen: 1024,
            max_file_bytes,
            max_age_ms: cfg.max_age_ms.clamp(1, MAX_DATA_MULE_AGE_MS),
        }
    }

    fn receive_envelope(&mut self, timeout: Duration) -> Result<DataMuleEnvelopeFrame> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(frame) = self.poll_envelope()? {
                if frame.envelope.to_node != self.local_node {
                    quarantine_claimed_file(frame.claimed);
                    continue;
                }
                if let Some(peer) = self.peer_filter.as_ref() {
                    if peer != &frame.envelope.from_node {
                        quarantine_claimed_file(frame.claimed);
                        continue;
                    }
                }

                return Ok(frame);
            }

            if Instant::now() >= deadline {
                return Err(ShphError::Timeout);
            }

            thread::sleep(self.poll_interval);
        }
    }

    fn receive_verified_hello(
        &mut self,
        timeout: Duration,
        local_identity: &IdentityKeyPair,
        material: &HandshakeMaterial,
        policy: &PeerPolicy,
    ) -> Result<(Hello, String)> {
        let frame = self.receive_envelope(timeout)?;
        let peer_node = frame.envelope.from_node.clone();
        let peer_hello = match serde_json::from_slice::<Hello>(&frame.payload) {
            Ok(hello) => hello,
            Err(error) => {
                quarantine_claimed_file(frame.claimed);
                return Err(ShphError::Protocol(format!("invalid peer hello: {error}")));
            }
        };
        if peer_node != peer_hello.identity_pub_b64 {
            quarantine_claimed_file(frame.claimed);
            return Err(ShphError::Auth(
                "data-mule envelope sender does not match the signed hello identity".into(),
            ));
        }
        if let Err(error) =
            shph_core::verify_hello_signature(local_identity, material, &peer_hello, policy)
        {
            quarantine_claimed_file(frame.claimed);
            return Err(error);
        }
        self.commit_envelope(&frame)?;
        if self.peer_filter.is_none() {
            self.peer_filter = Some(peer_node.clone());
            self.pending_candidates
                .retain(|candidate| candidate.from_node == peer_node);
        }
        Ok((peer_hello, peer_node))
    }

    fn receive_verified_responder_pq(
        &mut self,
        timeout: Duration,
        local_identity: &IdentityKeyPair,
        material: &mut HandshakeMaterial,
        peer_hello: &Hello,
        policy: &PeerPolicy,
    ) -> Result<()> {
        let frame = self.receive_envelope(timeout)?;
        match shph_core::absorb_responder_pq(
            local_identity,
            material,
            peer_hello,
            &frame.payload,
            policy,
        ) {
            Ok(()) => self.commit_envelope(&frame),
            Err(error) => {
                quarantine_claimed_file(frame.claimed);
                Err(error)
            }
        }
    }

    fn receive_decrypted_frame(
        &mut self,
        cipher: &mut ReceiveCipher,
        timeout: Duration,
    ) -> Result<Vec<u8>> {
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let frame = self.receive_envelope(remaining)?;
            match cipher.decrypt(&frame.payload) {
                Ok(plaintext) => {
                    self.commit_envelope(&frame)?;
                    return Ok(plaintext);
                }
                Err(error) => {
                    quarantine_claimed_file(frame.claimed);
                    if Instant::now() >= deadline {
                        return Err(error);
                    }
                }
            }
        }
    }

    fn commit_envelope(&mut self, frame: &DataMuleEnvelopeFrame) -> Result<()> {
        self.mark_seen(&frame.envelope)?;
        let _ = fs::remove_file(&frame.claimed.path);
        Ok(())
    }

    fn poll_envelope(&mut self) -> Result<Option<DataMuleEnvelopeFrame>> {
        if self.pending_candidates.is_empty() {
            let inbox_root = Path::new(&self.inbox_dir);
            ensure_no_reparse_components(inbox_root).map_err(ShphError::Io)?;
            let inbox_metadata = match fs::symlink_metadata(inbox_root) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(ShphError::Io(error)),
            };
            if !inbox_metadata.is_dir() {
                return Err(ShphError::Protocol(
                    "data-mule inbox root is not a directory".into(),
                ));
            }
            let recipient_inbox = inbox_root.join(safe_path_component(&self.local_node));
            let mut candidates = Vec::new();
            let now = now_unix_ms()?;
            let mut scan = DataMuleScanContext::new(self.max_file_bytes, self.max_age_ms, now);
            collect_shph_files(&recipient_inbox, &mut candidates, 0, &mut scan)?;
            candidates.retain(|candidate: &DataMuleCandidate| {
                candidate.to_node == self.local_node
                    && self
                        .peer_filter
                        .as_ref()
                        .is_none_or(|peer| peer == &candidate.from_node)
                    && !self.seen_envelopes.contains(&format!(
                        "{}\0{}",
                        candidate.from_node, candidate.envelope_id
                    ))
            });
            candidates.sort_by_key(|candidate| {
                (candidate.created_at_unix_ms, candidate.envelope_id.clone())
            });
            self.pending_candidates = candidates.into();
        }

        while let Some(candidate) = self.pending_candidates.pop_front() {
            let Some(claimed) = claim_file(&candidate.path).map_err(ShphError::Io)? else {
                continue;
            };
            let bytes = match read_file_bytes(&claimed.path, self.max_file_bytes) {
                Ok(bytes) => bytes,
                Err(ShphError::Protocol(_)) => {
                    quarantine_claimed_file(claimed);
                    continue;
                }
                Err(ShphError::Io(err)) if err.kind() == io::ErrorKind::NotFound => continue,
                Err(err) => return Err(err),
            };
            let envelope: DataMuleEnvelope = match serde_json::from_slice(&bytes) {
                Ok(envelope) => envelope,
                Err(_) => {
                    quarantine_claimed_file(claimed);
                    continue;
                }
            };
            if envelope.to_node != self.local_node
                || self
                    .peer_filter
                    .as_ref()
                    .is_some_and(|peer| peer != &envelope.from_node)
                || self.seen_envelopes.contains(&Self::replay_key(&envelope))
                || envelope.created_at_unix_ms != candidate.created_at_unix_ms
                || envelope.envelope_id != candidate.envelope_id
                || envelope.from_node != candidate.from_node
                || envelope.to_node != candidate.to_node
            {
                quarantine_claimed_file(claimed);
                continue;
            }
            let payload = match base64::engine::general_purpose::STANDARD
                .decode(envelope.ciphertext_b64.as_bytes())
            {
                Ok(payload) => payload,
                Err(_) => {
                    quarantine_claimed_file(claimed);
                    continue;
                }
            };

            return Ok(Some(DataMuleEnvelopeFrame {
                payload,
                envelope,
                claimed,
            }));
        }
        Ok(None)
    }

    fn replay_key(envelope: &DataMuleEnvelope) -> String {
        format!("{}\0{}", envelope.from_node, envelope.envelope_id)
    }

    fn mark_seen(&mut self, envelope: &DataMuleEnvelope) -> Result<()> {
        let key = Self::replay_key(envelope);
        if self.seen_envelopes.insert(key.clone()) {
            self.seen_order.push_back(key);
        }
        while self.seen_order.len() > self.max_seen {
            if let Some(oldest) = self.seen_order.pop_front() {
                self.seen_envelopes.remove(&oldest);
            }
        }
        Ok(())
    }
}

fn collect_shph_files(
    root: &Path,
    out: &mut Vec<DataMuleCandidate>,
    depth: usize,
    scan: &mut DataMuleScanContext,
) -> Result<()> {
    ensure_no_reparse_components(root).map_err(ShphError::Io)?;
    let root_metadata = match fs::symlink_metadata(root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(ShphError::Io(error)),
    };
    if !root_metadata.is_dir() {
        return Err(ShphError::Protocol(
            "data-mule inbox root is not a directory".into(),
        ));
    }
    if depth > MAX_QUEUE_SCAN_DEPTH {
        return Err(ShphError::ResourceExhausted(
            "data-mule inbox nesting exceeds scan depth".into(),
        ));
    }

    for entry in fs::read_dir(root).map_err(ShphError::Io)? {
        account_scan_entry(&mut scan.scanned)?;
        let entry = entry.map_err(ShphError::Io)?;
        let path = entry.path();
        ensure_no_reparse_components(&path).map_err(ShphError::Io)?;
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(ShphError::Io(error)),
        };
        if metadata.file_type().is_symlink() {
            continue;
        }
        if metadata.is_dir() {
            collect_shph_files(&path, out, depth + 1, scan)?;
            continue;
        }

        let ext = path.extension().and_then(|ext| ext.to_str()).unwrap_or("");
        if ext != "shph" {
            continue;
        }
        if metadata.len() > scan.max_file_bytes {
            quarantine_file(&path);
            continue;
        }
        account_scan_bytes(&mut scan.scanned_bytes, metadata.len())?;

        let bytes = match read_file_bytes(&path, scan.max_file_bytes) {
            Ok(bytes) => bytes,
            Err(ShphError::Protocol(_)) => {
                quarantine_file(&path);
                continue;
            }
            Err(ShphError::Io(error)) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(err) => return Err(err),
        };
        match serde_json::from_slice::<DataMuleEnvelope>(&bytes) {
            Ok(envelope) => {
                if data_mule_envelope_expired(
                    envelope.created_at_unix_ms,
                    scan.now_unix_ms,
                    scan.max_age_ms,
                ) {
                    quarantine_file(&path);
                    continue;
                }
                match account_candidate_memory(
                    &mut scan.candidate_memory,
                    &path,
                    &[
                        &envelope.envelope_id,
                        &envelope.from_node,
                        &envelope.to_node,
                    ],
                ) {
                    Ok(()) => {}
                    Err(ShphError::Protocol(_)) => {
                        quarantine_file(&path);
                        continue;
                    }
                    Err(error) => return Err(error),
                }
                out.push(DataMuleCandidate {
                    path,
                    created_at_unix_ms: envelope.created_at_unix_ms,
                    envelope_id: envelope.envelope_id,
                    from_node: envelope.from_node,
                    to_node: envelope.to_node,
                    file_bytes: metadata.len(),
                });
            }
            Err(_) => {
                quarantine_file(&path);
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        accept_secure_session_lab, connect_secure_session_lab,
        data_mule_accept_secure_session_with_profile,
        data_mule_connect_secure_session_with_profile,
        offline_mesh_accept_secure_session_with_profile,
        offline_mesh_connect_secure_session_with_profile, tcp_secure_receive, tcp_secure_send,
        DataMuleConfig, DataMuleReadState, DataMuleSession, DataMuleWriteState, OfflineMeshConfig,
        OfflineMeshReadState, OfflineMeshWriteState, QuicLabConfig,
    };
    use super::{
        collect_shph_files, offline_session_id, DataMuleScanContext, MAX_DATA_MULE_AGE_MS,
        MAX_RESOLVED_ADDRESSES, TEMP_FILE_COUNTER,
    };
    use super::{
        decode_encrypted_quic_frame, PeerRateLimiter, TcpUnderlay, TransportMode,
        COOKIE_CHALLENGE_THRESHOLD, MAX_CONNECTS_PER_PEER_PER_WINDOW, MAX_QUIC_TRACKED_PEERS,
    };
    use base64::Engine as _;
    use shph_core::{
        HandshakeProfile, IdentityKeyPair, OfflineMeshEnvelope, PeerPin, PeerPolicy, ReceiveCipher,
        SendCipher, ShphError,
    };
    use shph_obfuscation::ProfileTier;
    use std::collections::HashSet;
    use std::fs;
    use std::io::{Read, Write};
    use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{mpsc, Arc};
    use std::thread;
    use std::time::{Duration, Instant};

    fn test_root(prefix: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "{prefix}-{}-{}",
            std::process::id(),
            TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn copy_tree(source: &Path, destination: &Path) {
        fs::create_dir_all(destination).expect("create replication destination");
        for entry in fs::read_dir(source).expect("read replication source") {
            let entry = entry.expect("read replication entry");
            let source_path = entry.path();
            let destination_path = destination.join(entry.file_name());
            let metadata = fs::symlink_metadata(&source_path).expect("replication metadata");
            if metadata.is_dir() {
                copy_tree(&source_path, &destination_path);
            } else {
                fs::create_dir_all(destination_path.parent().expect("replication parent"))
                    .expect("create replication parent");
                fs::copy(&source_path, &destination_path).expect("copy replicated envelope");
            }
        }
    }

    #[test]
    fn tcp_secure_helpers_preserve_aead_nonce_state_between_frames() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind TCP listener");
        let address = listener.local_addr().expect("listener address");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept client");
            let mut receiver = ReceiveCipher::new([0x41; 32]);
            assert_eq!(
                tcp_secure_receive(&mut stream, &mut receiver).expect("receive first frame"),
                b"first"
            );
            assert_eq!(
                tcp_secure_receive(&mut stream, &mut receiver).expect("receive second frame"),
                b"second"
            );
        });

        let mut stream = TcpStream::connect(address).expect("connect TCP listener");
        let mut sender = SendCipher::new([0x41; 32]);
        tcp_secure_send(&mut stream, &mut sender, b"first").expect("send first frame");
        tcp_secure_send(&mut stream, &mut sender, b"second").expect("send second frame");
        server.join().expect("server thread");
    }

    #[test]
    fn tcp_profile_helpers_round_trip_the_original_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind TCP listener");
        let address = listener.local_addr().expect("listener address");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept client");
            let mut receiver = ReceiveCipher::new([0x42; 32]);
            assert_eq!(
                super::tcp_secure_receive_with_profile(
                    &mut stream,
                    &mut receiver,
                    ProfileTier::Medium
                )
                .expect("receive profiled frame"),
                b"profiled"
            );
        });

        let mut stream = TcpStream::connect(address).expect("connect TCP listener");
        let mut sender = SendCipher::new([0x42; 32]);
        super::tcp_secure_send_with_profile(
            &mut stream,
            &mut sender,
            b"profiled",
            ProfileTier::Medium,
        )
        .expect("send profiled frame");
        server.join().expect("server thread");
    }

    #[test]
    fn tcp_reusable_padding_buffer_is_wiped_on_preflight_rejection() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind TCP listener");
        let address = listener.local_addr().expect("listener address");
        let mut stream = TcpStream::connect(address).expect("connect TCP listener");
        let mut cipher = SendCipher::new([0x44; 32]);
        let mut padding_buffer = vec![0xa5; 256];
        let payload = vec![0x5a; super::MAX_TCP_PAYLOAD_BYTES + 1];

        let result = super::write_encrypted_tcp_frame(
            &mut stream,
            &mut cipher,
            &payload,
            None,
            None,
            &mut padding_buffer,
            None,
        );

        assert!(matches!(result, Err(ShphError::Protocol(_))));
        assert!(padding_buffer.is_empty());
    }

    #[test]
    fn tcp_frame_reader_preserves_partial_frames_across_poll_timeouts() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind TCP listener");
        let address = listener.local_addr().expect("listener address");
        let mut sender = SendCipher::new([0x43; 32]);
        let encrypted = sender.encrypt(b"partial-frame").expect("encrypt frame");
        let mut wire = Vec::with_capacity(4 + encrypted.len());
        wire.extend_from_slice(&(encrypted.len() as u32).to_be_bytes());
        wire.extend_from_slice(&encrypted);

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept client");
            stream.write_all(&wire[..2]).expect("write partial prefix");
            thread::sleep(Duration::from_millis(100));
            stream.write_all(&wire[2..]).expect("write remaining frame");
        });

        let mut stream = TcpStream::connect(address).expect("connect TCP listener");
        stream
            .set_read_timeout(Some(Duration::from_millis(25)))
            .expect("set polling timeout");
        let mut reader = super::TcpFrameReader::default();
        let mut receiver = ReceiveCipher::new([0x43; 32]);
        assert!(matches!(
            super::read_encrypted_tcp_frame(&mut stream, &mut receiver, &mut reader, None, None,),
            Err(ShphError::Timeout)
        ));

        thread::sleep(Duration::from_millis(125));
        assert_eq!(
            super::read_encrypted_tcp_frame(&mut stream, &mut receiver, &mut reader, None, None,)
                .expect("receive frame after timeout"),
            b"partial-frame"
        );
        server.join().expect("server");
    }

    #[test]
    fn tcp_sender_rejects_payload_that_would_exceed_frame_limit() {
        let payload = vec![0u8; super::MAX_TCP_PAYLOAD_BYTES + 1];
        assert!(super::validate_tcp_payload(&payload).is_err());
        assert!(super::validate_tcp_payload(&payload[..super::MAX_TCP_PAYLOAD_BYTES]).is_ok());
    }

    #[test]
    fn handshake_padding_preserves_json_and_bounds_size() {
        let identity = IdentityKeyPair::generate().expect("identity");
        let material = super::build_hello_with_profile(&identity, HandshakeProfile::ClassicalLab)
            .expect("hello");
        let canonical = serde_json::to_vec(&material.local_hello).expect("canonical hello");
        let padded =
            super::serialize_hello_with_padding_len(&material.local_hello, 64).expect("padding");

        assert_eq!(&padded[..canonical.len()], canonical.as_slice());
        assert!(padded[canonical.len()..]
            .iter()
            .all(u8::is_ascii_whitespace));
        assert_eq!(
            serde_json::from_slice::<shph_core::Hello>(&padded)
                .expect("padded hello")
                .proto,
            material.local_hello.proto
        );
        assert!(super::serialize_hello_with_padding_len(&material.local_hello, 65).is_err());
    }

    #[test]
    fn randomized_handshake_padding_stays_within_bound() {
        let identity = IdentityKeyPair::generate().expect("identity");
        let material = super::build_hello_with_profile(&identity, HandshakeProfile::ClassicalLab)
            .expect("hello");
        let canonical_len = serde_json::to_vec(&material.local_hello)
            .expect("canonical hello")
            .len();

        for _ in 0..128 {
            let padded =
                super::serialize_hello_with_padding(&material.local_hello).expect("padding");
            assert!((canonical_len..=canonical_len + 64).contains(&padded.len()));
            serde_json::from_slice::<shph_core::Hello>(&padded).expect("padded hello");
        }
    }

    #[test]
    fn tcp_underlay_parses_direct_and_socks5_endpoints() {
        assert_eq!(
            TcpUnderlay::parse(None).expect("default underlay"),
            TcpUnderlay::Direct
        );
        assert_eq!(
            TcpUnderlay::parse(Some("direct")).expect("direct underlay"),
            TcpUnderlay::Direct
        );
        assert_eq!(
            TcpUnderlay::parse(Some("socks5://127.0.0.1:10808")).expect("SOCKS5 underlay"),
            TcpUnderlay::Socks5 {
                proxy: "127.0.0.1:10808".into()
            }
        );
        assert_eq!(
            TcpUnderlay::parse(Some("socks5h://[::1]:10808")).expect("SOCKS5h underlay"),
            TcpUnderlay::Socks5 {
                proxy: "[::1]:10808".into()
            }
        );
        assert!(TcpUnderlay::parse(Some("socks5://user:pass@127.0.0.1:10808")).is_err());
        assert!(TcpUnderlay::parse(Some("socks5://127.0.0.1:0")).is_err());
        assert!(TcpUnderlay::parse(Some("http://127.0.0.1:8080")).is_err());
    }

    #[test]
    fn socks5_connect_uses_domain_target_and_consumes_success_response() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind SOCKS5 listener");
        let proxy_address = listener.local_addr().expect("proxy address");
        let proxy = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept SOCKS5 client");
            let mut greeting = [0u8; 3];
            stream.read_exact(&mut greeting).expect("read greeting");
            assert_eq!(greeting, [5, 1, 0]);
            stream.write_all(&[5, 0]).expect("write no-auth method");

            let mut request_header = [0u8; 4];
            stream
                .read_exact(&mut request_header)
                .expect("read CONNECT header");
            assert_eq!(request_header, [5, 1, 0, 3]);
            let mut hostname_len = [0u8; 1];
            stream
                .read_exact(&mut hostname_len)
                .expect("read hostname length");
            let mut hostname = vec![0u8; hostname_len[0] as usize];
            stream.read_exact(&mut hostname).expect("read hostname");
            assert_eq!(hostname, b"example.test");
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).expect("read destination port");
            assert_eq!(u16::from_be_bytes(port), 443);

            stream
                .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0x12, 0x34])
                .expect("write success response");
        });

        let mut stream = TcpStream::connect(proxy_address).expect("connect SOCKS5 listener");
        let deadline = Instant::now() + Duration::from_secs(5);
        super::socks5_connect(&mut stream, "example.test:443", deadline).expect("SOCKS5 CONNECT");
        proxy.join().expect("proxy thread");
    }

    #[test]
    fn tor_underlay_uses_fresh_auth_and_forwards_onion_name() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind Tor SOCKS listener");
        let proxy_address = listener.local_addr().expect("Tor SOCKS address");
        let proxy = thread::spawn(move || {
            let mut credentials = Vec::new();
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().expect("accept Tor SOCKS client");
                let mut greeting = [0u8; 3];
                stream.read_exact(&mut greeting).expect("read Tor greeting");
                assert_eq!(greeting, [5, 1, 2]);
                stream
                    .write_all(&[5, 2])
                    .expect("select username/password auth");

                let mut auth_header = [0u8; 2];
                stream
                    .read_exact(&mut auth_header)
                    .expect("read SOCKS auth header");
                assert_eq!(auth_header, [1, 16]);
                let mut username = vec![0u8; auth_header[1] as usize];
                stream
                    .read_exact(&mut username)
                    .expect("read SOCKS username");
                let mut password_len = [0u8; 1];
                stream
                    .read_exact(&mut password_len)
                    .expect("read SOCKS password length");
                assert_eq!(password_len[0], 16);
                let mut password = vec![0u8; password_len[0] as usize];
                stream
                    .read_exact(&mut password)
                    .expect("read SOCKS password");
                stream.write_all(&[1, 0]).expect("accept SOCKS auth");
                credentials.push((username, password));

                let mut request_header = [0u8; 4];
                stream
                    .read_exact(&mut request_header)
                    .expect("read onion CONNECT header");
                assert_eq!(request_header, [5, 1, 0, 3]);
                let mut hostname_len = [0u8; 1];
                stream
                    .read_exact(&mut hostname_len)
                    .expect("read onion hostname length");
                let mut hostname = vec![0u8; hostname_len[0] as usize];
                stream
                    .read_exact(&mut hostname)
                    .expect("read onion hostname");
                assert_eq!(hostname, b"service-test.onion");
                let mut port = [0u8; 2];
                stream
                    .read_exact(&mut port)
                    .expect("read onion destination port");
                assert_eq!(u16::from_be_bytes(port), 443);
                stream
                    .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
                    .expect("write SOCKS success response");
            }
            credentials
        });

        let underlay = TcpUnderlay::Tor {
            proxy: proxy_address.to_string(),
        };
        for _ in 0..2 {
            let stream = super::connect_tcp_via_underlay(
                "service-test.onion:443",
                &underlay,
                Instant::now() + Duration::from_secs(2),
            )
            .expect("connect through Tor SOCKS");
            drop(stream);
        }
        let credentials = proxy.join().expect("Tor SOCKS thread");
        assert_eq!(credentials.len(), 2);
        assert_ne!(credentials[0], credentials[1]);
    }

    #[test]
    fn tor_underlay_failure_closes_and_never_connects_directly() {
        let proxy_listener = TcpListener::bind("127.0.0.1:0").expect("bind Tor SOCKS listener");
        let proxy_address = proxy_listener.local_addr().expect("Tor SOCKS address");
        let peer_listener = TcpListener::bind("127.0.0.1:0").expect("bind peer sentinel");
        peer_listener
            .set_nonblocking(true)
            .expect("set peer sentinel nonblocking");
        let proxy = thread::spawn(move || {
            let (mut stream, _) = proxy_listener.accept().expect("accept Tor SOCKS client");
            let mut greeting = [0u8; 3];
            stream.read_exact(&mut greeting).expect("read Tor greeting");
            assert_eq!(greeting, [5, 1, 2]);
            stream
                .write_all(&[5, 0])
                .expect("reject required username/password auth");
            let mut byte = [0u8; 1];
            match stream.read(&mut byte) {
                Ok(0) => {}
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
                result => panic!("expected client close, got {result:?}"),
            }
        });

        let underlay = TcpUnderlay::Tor {
            proxy: proxy_address.to_string(),
        };
        let result = super::connect_tcp_via_underlay(
            &peer_listener
                .local_addr()
                .expect("peer sentinel address")
                .to_string(),
            &underlay,
            Instant::now() + Duration::from_secs(2),
        );
        assert!(matches!(result, Err(ShphError::Transport(_))));
        proxy.join().expect("Tor SOCKS thread");
        assert!(matches!(
            peer_listener.accept(),
            Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock
        ));
    }

    #[test]
    fn tor_underlay_proxy_setup_obeys_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind stalled Tor SOCKS listener");
        let proxy_address = listener.local_addr().expect("Tor SOCKS address");
        let proxy = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept Tor SOCKS client");
            let mut greeting = [0u8; 3];
            stream.read_exact(&mut greeting).expect("read Tor greeting");
            assert_eq!(greeting, [5, 1, 2]);
            let mut byte = [0u8; 1];
            match stream.read(&mut byte) {
                Ok(0) => {}
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
                result => panic!("expected client close, got {result:?}"),
            }
        });

        let underlay = TcpUnderlay::Tor {
            proxy: proxy_address.to_string(),
        };
        let started = Instant::now();
        let result = super::connect_tcp_via_underlay(
            "service-test.onion:443",
            &underlay,
            started + Duration::from_millis(250),
        );
        assert!(matches!(result, Err(ShphError::Timeout)));
        assert!(started.elapsed() < Duration::from_secs(2));
        proxy.join().expect("stalled Tor SOCKS thread");
    }

    #[test]
    fn tor_underlay_setup_honors_preexisting_cancellation() {
        let proxy_listener = TcpListener::bind("127.0.0.1:0").expect("bind Tor SOCKS listener");
        proxy_listener
            .set_nonblocking(true)
            .expect("set Tor listener nonblocking");
        let proxy_address = proxy_listener.local_addr().expect("Tor SOCKS address");
        let underlay = TcpUnderlay::Tor {
            proxy: proxy_address.to_string(),
        };
        let cancellation = AtomicBool::new(true);
        let cancelled = || cancellation.load(Ordering::Acquire);

        let result = super::connect_tcp_via_underlay_inner(
            "service-test.onion:443",
            &underlay,
            Instant::now() + Duration::from_secs(2),
            Some(&cancelled),
        );

        assert!(matches!(
            result,
            Err(ShphError::Transport(message)) if message == "SOCKS5 setup cancelled"
        ));
        assert!(matches!(
            proxy_listener.accept(),
            Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock
        ));
    }

    #[test]
    fn tor_underlay_setup_cancellation_closes_proxy_without_direct_fallback() {
        let proxy_listener = TcpListener::bind("127.0.0.1:0").expect("bind Tor SOCKS listener");
        let proxy_address = proxy_listener.local_addr().expect("Tor SOCKS address");
        let peer_listener = TcpListener::bind("127.0.0.1:0").expect("bind peer sentinel");
        peer_listener
            .set_nonblocking(true)
            .expect("set peer sentinel nonblocking");
        let (stalled_sender, stalled_receiver) = mpsc::channel();
        let proxy = thread::spawn(move || {
            let (mut stream, _) = proxy_listener.accept().expect("accept Tor SOCKS client");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set mock read timeout");
            let mut greeting = [0u8; 3];
            stream.read_exact(&mut greeting).expect("read Tor greeting");
            assert_eq!(greeting, [5, 1, 2]);
            stream
                .write_all(&[5, 2])
                .expect("select username/password auth");
            let mut authentication = [0u8; 35];
            stream
                .read_exact(&mut authentication)
                .expect("read SOCKS auth");
            assert_eq!(&authentication[..2], &[1, 16]);
            assert_eq!(authentication[18], 16);
            stalled_sender.send(()).expect("notify stalled setup");

            let mut byte = [0u8; 1];
            match stream.read(&mut byte) {
                Ok(0) => {}
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
                result => panic!("expected client close after cancellation, got {result:?}"),
            }
        });

        let underlay = TcpUnderlay::Tor {
            proxy: proxy_address.to_string(),
        };
        let cancellation = Arc::new(AtomicBool::new(false));
        let connector_cancellation = Arc::clone(&cancellation);
        let peer = peer_listener
            .local_addr()
            .expect("peer sentinel address")
            .to_string();
        let connector = thread::spawn(move || {
            let cancelled = || connector_cancellation.load(Ordering::Acquire);
            super::connect_tcp_via_underlay_inner(
                &peer,
                &underlay,
                Instant::now() + Duration::from_secs(5),
                Some(&cancelled),
            )
        });

        stalled_receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("proxy reached stalled authentication response");
        let cancellation_started = Instant::now();
        cancellation.store(true, Ordering::Release);
        let result = connector.join().expect("connector thread");
        assert!(matches!(
            result,
            Err(ShphError::Transport(message)) if message == "SOCKS5 setup cancelled"
        ));
        assert!(cancellation_started.elapsed() < Duration::from_secs(1));
        proxy.join().expect("Tor SOCKS mock thread");
        assert!(matches!(
            peer_listener.accept(),
            Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock
        ));
    }

    #[test]
    fn unshrouded_quic_sender_rejects_payload_that_would_exceed_datagram_limit() {
        use std::net::UdpSocket;

        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind UDP socket");
        let peer = socket.local_addr().expect("UDP address");
        let mut cipher = SendCipher::new([0x52; 32]);
        let payload = vec![0u8; super::MAX_QUIC_PAYLOAD_BYTES + 1];
        assert!(
            super::write_encrypted_quic_frame(&socket, peer, &mut cipher, &payload, None).is_err()
        );
    }

    #[test]
    fn file_adapter_sender_rejects_payload_before_encryption_bound() {
        let payload = vec![0u8; 4097];
        assert!(super::validate_file_adapter_payload(&payload, 4096, 4096).is_err());
        assert!(super::validate_file_adapter_payload(&payload[..4096], 4096, 4096).is_ok());
    }

    #[test]
    fn file_adapter_capacity_accounts_for_encryption_and_envelope_overhead() {
        let data_mule = super::data_mule_payload_capacity(4096, "local", "peer");
        let offline_mesh = super::offline_mesh_payload_capacity(4096, "local", "peer");
        assert!(data_mule < 4096);
        assert!(offline_mesh < 4096);
        assert!(
            super::validate_file_adapter_payload(&vec![0u8; data_mule], data_mule, 4096).is_ok()
        );
        assert!(super::validate_file_adapter_payload(
            &vec![0u8; data_mule.saturating_add(1)],
            data_mule,
            4096
        )
        .is_err());
    }

    #[test]
    fn offline_mesh_secure_session_roundtrips_on_a_shared_spool() {
        let root = test_root("shph-offline-session");
        fs::create_dir_all(&root).expect("create offline spool");
        let client = IdentityKeyPair::generate().expect("client identity");
        let server = IdentityKeyPair::generate().expect("server identity");
        let client_cfg = OfflineMeshConfig {
            node_id: "client".into(),
            peer_id: "server".into(),
            spool_dir: root.to_string_lossy().into_owned(),
            poll_interval_ms: 1,
            max_idle_entries: 64,
        };
        let server_cfg = OfflineMeshConfig {
            node_id: "server".into(),
            peer_id: "client".into(),
            spool_dir: root.to_string_lossy().into_owned(),
            poll_interval_ms: 1,
            max_idle_entries: 64,
        };
        let server_policy = PeerPolicy::single(PeerPin::for_identity(&client));
        let client_policy = PeerPolicy::single(PeerPin::for_identity(&server));
        let server_thread = thread::spawn(move || {
            let result = offline_mesh_accept_secure_session_with_profile(
                &server_cfg,
                &server,
                &server_policy,
                10,
                HandshakeProfile::SecureDefault,
            );
            if let Err(error) = &result {
                eprintln!("offline-mesh server fixture failed: {error:?}");
            }
            result
        });

        let (mut client_session, client_state) = offline_mesh_connect_secure_session_with_profile(
            &client_cfg,
            &client,
            &client_policy,
            10,
            HandshakeProfile::SecureDefault,
        )
        .expect("offline-mesh client handshake");
        let (mut server_session, server_state) = server_thread
            .join()
            .expect("offline-mesh server thread")
            .expect("offline-mesh server handshake");

        assert_eq!(
            client_state.transcript_hash_hex,
            server_state.transcript_hash_hex
        );
        client_session
            .send_frame(b"offline-mesh-client-to-server")
            .expect("send client frame");
        assert_eq!(
            server_session.recv_frame().expect("receive client frame"),
            b"offline-mesh-client-to-server"
        );
        server_session
            .send_frame(b"offline-mesh-server-to-client")
            .expect("send server frame");
        assert_eq!(
            client_session.recv_frame().expect("receive server frame"),
            b"offline-mesh-server-to-client"
        );
        fs::remove_dir_all(root).expect("remove offline spool");
    }

    #[test]
    fn data_mule_secure_session_roundtrips_between_paired_spools() {
        let root = test_root("shph-data-mule-session");
        let client_outbox = root.join("client-outbox");
        let server_outbox = root.join("server-outbox");
        fs::create_dir_all(&client_outbox).expect("create client outbox");
        fs::create_dir_all(&server_outbox).expect("create server outbox");
        let client = IdentityKeyPair::generate().expect("client identity");
        let server = IdentityKeyPair::generate().expect("server identity");
        let client_cfg = DataMuleConfig {
            inbox_dir: server_outbox.to_string_lossy().into_owned(),
            outbox_dir: client_outbox.to_string_lossy().into_owned(),
            poll_interval_ms: 1,
            max_file_bytes: 256 * 1024,
            max_total_bytes: 8 * 1024 * 1024,
            max_age_ms: MAX_DATA_MULE_AGE_MS,
        };
        let server_cfg = DataMuleConfig {
            inbox_dir: client_outbox.to_string_lossy().into_owned(),
            outbox_dir: server_outbox.to_string_lossy().into_owned(),
            poll_interval_ms: 1,
            max_file_bytes: 256 * 1024,
            max_total_bytes: 8 * 1024 * 1024,
            max_age_ms: MAX_DATA_MULE_AGE_MS,
        };
        let server_policy = PeerPolicy::single(PeerPin::for_identity(&client));
        let client_policy = PeerPolicy::single(PeerPin::for_identity(&server));
        let server_node = server.public_key_b64();
        let server_thread = thread::spawn(move || {
            let result = data_mule_accept_secure_session_with_profile(
                &server_cfg,
                &server,
                &server_policy,
                10,
                HandshakeProfile::SecureDefault,
            );
            if let Err(error) = &result {
                eprintln!("data-mule server fixture failed: {error:?}");
            }
            result
        });

        let (mut client_session, client_state) = data_mule_connect_secure_session_with_profile(
            &client_cfg,
            &client,
            &server_node,
            &client_policy,
            10,
            HandshakeProfile::SecureDefault,
        )
        .expect("data-mule client handshake");
        let (mut server_session, server_state) = server_thread
            .join()
            .expect("data-mule server thread")
            .expect("data-mule server handshake");

        assert_eq!(
            client_state.transcript_hash_hex,
            server_state.transcript_hash_hex
        );
        client_session
            .send_frame(b"data-mule-client-to-server")
            .expect("send client frame");
        assert_eq!(
            server_session.recv_frame().expect("receive client frame"),
            b"data-mule-client-to-server"
        );
        server_session
            .send_frame(b"data-mule-server-to-client")
            .expect("send server frame");
        assert_eq!(
            client_session.recv_frame().expect("receive server frame"),
            b"data-mule-server-to-client"
        );
        fs::remove_dir_all(root).expect("remove data-mule spool");
    }

    #[test]
    fn offline_mesh_replication_between_distinct_spools_preserves_aead_data() {
        let source_root = test_root("shph-offline-source");
        let destination_root = test_root("shph-offline-destination");
        fs::create_dir_all(&source_root).expect("create source spool");
        fs::create_dir_all(&destination_root).expect("create destination spool");
        let writer_cfg = OfflineMeshConfig {
            node_id: "courier".into(),
            peer_id: "receiver".into(),
            spool_dir: source_root.to_string_lossy().into_owned(),
            poll_interval_ms: 1,
            max_idle_entries: 64,
        };
        let reader_cfg = OfflineMeshConfig {
            node_id: "receiver".into(),
            peer_id: "courier".into(),
            spool_dir: destination_root.to_string_lossy().into_owned(),
            poll_interval_ms: 1,
            max_idle_entries: 64,
        };
        let mut writer = OfflineMeshWriteState::new(&writer_cfg, "courier", "receiver");
        let mut sender = SendCipher::new([0x71; 32]);
        writer
            .send_payload(
                &sender
                    .encrypt(b"replicated-offline-frame")
                    .expect("encrypt"),
            )
            .expect("write source envelope");

        copy_tree(&source_root, &destination_root);

        let mut reader = OfflineMeshReadState::new(&reader_cfg, "receiver", "courier");
        let mut receiver = ReceiveCipher::new([0x71; 32]);
        assert_eq!(
            reader
                .receive_decrypted_frame(&mut receiver, Duration::from_secs(2))
                .expect("receive replicated envelope"),
            b"replicated-offline-frame"
        );
        let session_id = offline_session_id("courier", "receiver");
        assert!(
            source_root
                .join(session_id)
                .join("out")
                .join(super::sanitize_component("courier"))
                .join(super::sanitize_component("receiver"))
                .read_dir()
                .expect("read source queue")
                .any(|entry| entry.is_ok()),
            "replication source remains available after destination consumption"
        );
        fs::remove_dir_all(source_root).expect("remove source spool");
        fs::remove_dir_all(destination_root).expect("remove destination spool");
    }

    #[test]
    fn offline_mesh_replay_key_allows_new_timestamp_after_sequence_restart() {
        let root = test_root("shph-offline-restart");
        fs::create_dir_all(&root).expect("create restart spool");
        let writer_cfg = OfflineMeshConfig {
            node_id: "peer".into(),
            peer_id: "local".into(),
            spool_dir: root.to_string_lossy().into_owned(),
            poll_interval_ms: 1,
            max_idle_entries: 64,
        };
        let reader_cfg = OfflineMeshConfig {
            node_id: "local".into(),
            peer_id: "peer".into(),
            spool_dir: root.to_string_lossy().into_owned(),
            poll_interval_ms: 1,
            max_idle_entries: 64,
        };
        let mut writer = OfflineMeshWriteState::new(&writer_cfg, "peer", "local");
        let mut sender = SendCipher::new([0x72; 32]);
        writer
            .send_payload(&sender.encrypt(b"before-restart").expect("encrypt first"))
            .expect("write first envelope");
        let queue = root
            .join(offline_session_id("peer", "local"))
            .join("out")
            .join(super::sanitize_component("peer"))
            .join(super::sanitize_component("local"));
        let first_path = fs::read_dir(&queue)
            .expect("read first queue")
            .next()
            .expect("first envelope")
            .expect("first envelope entry")
            .path();
        let first: OfflineMeshEnvelope =
            serde_json::from_slice(&fs::read(&first_path).expect("read first envelope"))
                .expect("decode first envelope");
        let mut reader = OfflineMeshReadState::new(&reader_cfg, "local", "peer");
        let mut receiver = ReceiveCipher::new([0x72; 32]);
        assert_eq!(
            reader
                .receive_decrypted_frame(&mut receiver, Duration::from_secs(2))
                .expect("receive first envelope"),
            b"before-restart"
        );

        let second = OfflineMeshEnvelope {
            session_id: first.session_id,
            from: "peer".into(),
            to: "local".into(),
            created_at_unix_ms: first.created_at_unix_ms.saturating_add(1),
            sequence: 0,
            ciphertext_b64: base64::engine::general_purpose::STANDARD
                .encode(sender.encrypt(b"after-restart").expect("encrypt second")),
        };
        let second_path = queue.join(format!(
            "{}-{}.json",
            second.created_at_unix_ms, second.sequence
        ));
        fs::write(
            second_path,
            serde_json::to_vec(&second).expect("serialize second envelope"),
        )
        .expect("write second envelope");
        assert_eq!(
            reader
                .receive_decrypted_frame(&mut receiver, Duration::from_secs(2))
                .expect("receive post-restart sequence"),
            b"after-restart"
        );
        fs::remove_dir_all(root).expect("remove restart spool");
    }

    #[test]
    fn file_adapter_session_rejects_before_creating_an_envelope() {
        let root = std::env::temp_dir().join(format!(
            "shph-mule-capacity-{}-{}",
            std::process::id(),
            TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let cfg = DataMuleConfig {
            inbox_dir: root.to_string_lossy().into_owned(),
            outbox_dir: root.to_string_lossy().into_owned(),
            poll_interval_ms: 1,
            max_file_bytes: 4096,
            max_total_bytes: 8 * 1024 * 1024,
            max_age_ms: MAX_DATA_MULE_AGE_MS,
        };
        let writer = DataMuleWriteState::new(&cfg, "local", "peer");
        let oversized = vec![0u8; writer.max_payload_bytes.saturating_add(1)];
        let mut session = DataMuleSession::new(
            writer,
            DataMuleReadState::new(&cfg, "local", Some("peer")),
            [0x11; 32],
            [0x22; 32],
        );
        assert!(session.send_frame(&oversized).is_err());
        assert!(
            !root.exists(),
            "pre-encryption rejection must not create an envelope directory"
        );
    }

    #[test]
    fn hostname_resolution_honors_an_expired_aggregate_deadline() {
        assert!(matches!(
            super::resolve_socket_addrs_with_deadline("localhost:1", Instant::now()),
            Err(shph_core::ShphError::Timeout)
        ));
    }

    #[test]
    fn hostname_resolution_deduplicates_and_bounds_addresses() {
        let addresses = (1..=MAX_RESOLVED_ADDRESSES + 8)
            .map(|offset| SocketAddr::from(([192, 0, 2, (offset % 254) as u8], 443)))
            .collect::<Vec<_>>();
        let bounded = super::collect_bounded_socket_addrs(
            addresses
                .iter()
                .copied()
                .chain(addresses.iter().copied().take(4)),
        );
        assert_eq!(bounded.len(), MAX_RESOLVED_ADDRESSES);
        assert_eq!(bounded.iter().collect::<HashSet<_>>().len(), bounded.len());
    }

    #[test]
    fn transport_mode_parses_supported_values() {
        assert!(TransportMode::parse("tcp").is_ok());
        assert!(TransportMode::parse("quic").is_ok());
        assert!(TransportMode::parse("offline-mesh").is_ok());
        assert!(TransportMode::parse("data_mule").is_ok());
        assert!(TransportMode::parse("bad").is_err());
    }

    #[test]
    fn peer_rate_limiter_allows_under_cap() {
        let mut rl = PeerRateLimiter::new();
        let addr: SocketAddr = "127.0.0.1:7000".parse().unwrap();
        for _ in 0..MAX_CONNECTS_PER_PEER_PER_WINDOW {
            assert!(
                rl.check_and_record(addr).is_ok(),
                "under-cap connects allowed"
            );
        }
        // One over the cap is rejected.
        assert!(
            rl.check_and_record(addr).is_err(),
            "over-cap connect from same peer must be rejected"
        );
    }

    #[test]
    fn peer_rate_limiter_keys_by_ip_not_port() {
        let mut rl = PeerRateLimiter::new();
        // Same IP, different ports: share the budget.
        for port in 0..MAX_CONNECTS_PER_PEER_PER_WINDOW {
            let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
            assert!(rl.check_and_record(addr).is_ok());
        }
        let over: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        assert!(
            rl.check_and_record(over).is_err(),
            "rate limit is per-IP, so a new port on a capped IP is still rejected"
        );
    }

    #[test]
    fn peer_rate_limiter_isolates_distinct_ips() {
        let mut rl = PeerRateLimiter::new();
        // Exhausting one IP must not affect a different IP.
        let a: SocketAddr = "10.0.0.1:1".parse().unwrap();
        for _ in 0..MAX_CONNECTS_PER_PEER_PER_WINDOW {
            rl.check_and_record(a).unwrap();
        }
        assert!(rl.check_and_record(a).is_err());
        let b: SocketAddr = "10.0.0.2:1".parse().unwrap();
        assert!(
            rl.check_and_record(b).is_ok(),
            "a distinct IP has its own budget"
        );
    }

    #[test]
    fn peer_rate_limiter_requires_cookie_only_after_threshold() {
        let mut rl = PeerRateLimiter::new();
        let addr: SocketAddr = "192.0.2.10:1".parse().unwrap();
        for _ in 0..COOKIE_CHALLENGE_THRESHOLD.saturating_sub(1) {
            rl.check_and_record(addr).unwrap();
        }
        assert!(!rl.requires_cookie(addr));
        rl.check_and_record(addr).unwrap();
        assert!(rl.requires_cookie(addr));
    }

    #[test]
    fn cookie_wire_challenge_and_response_are_bounded() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let cookie = [0x5au8; 32];
            super::write_tcp_cookie_challenge(&mut stream, &cookie).expect("challenge");
            assert_eq!(
                super::read_tcp_cookie_response(&mut stream).expect("response"),
                cookie
            );
        });

        let mut client = TcpStream::connect(address).expect("connect");
        let cookie = [0x5au8; 32];
        let line = super::read_tcp_line(&mut client, super::MAX_COOKIE_LINE_BYTES)
            .expect("challenge line");
        assert!(line.starts_with(super::COOKIE_CHALLENGE_PREFIX));
        let encoded = &line[super::COOKIE_CHALLENGE_PREFIX.len()..];
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .expect("challenge encoding");
        assert_eq!(decoded, cookie);
        super::write_tcp_cookie_response(&mut client, &decoded).expect("response");
        server.join().expect("server");
    }

    #[test]
    fn tcp_line_reader_preserves_pipelined_followup_bytes() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            stream.write_all(b"hello\nnext").expect("pipelined write");
        });

        let mut client = TcpStream::connect(address).expect("connect");
        assert_eq!(
            super::read_tcp_line(&mut client, 64).expect("line"),
            b"hello"
        );
        let mut followup = [0u8; 4];
        client.read_exact(&mut followup).expect("follow-up bytes");
        assert_eq!(&followup, b"next");
        server.join().expect("server");
    }

    #[test]
    fn tcp_listener_survives_malformed_peer_flood() {
        let probe = TcpListener::bind("127.0.0.1:0").expect("reserve TCP port");
        let address = probe.local_addr().expect("probe address");
        drop(probe);

        let server_identity = IdentityKeyPair::generate().expect("server identity");
        let client_identity = IdentityKeyPair::generate().expect("client identity");
        let server_policy = PeerPolicy::single(PeerPin::for_identity(&client_identity));
        let client_policy = PeerPolicy::single(PeerPin::for_identity(&server_identity));
        let server_identity_for_thread = server_identity.clone();
        let server_policy_for_thread = server_policy.clone();
        let server_address = address.to_string();
        let server = thread::spawn(move || {
            super::tcp_accept_and_handshake_with_profile(
                &server_address,
                &server_identity_for_thread,
                &server_policy_for_thread,
                5,
                HandshakeProfile::ClassicalLab,
            )
        });

        thread::sleep(Duration::from_millis(50));
        for _ in 0..6 {
            let mut stream = TcpStream::connect(address).expect("malformed peer connection");
            stream
                .set_read_timeout(Some(Duration::from_millis(100)))
                .expect("malformed peer read timeout");
            stream
                .write_all(b"not-a-valid-hello\n")
                .expect("malformed hello");
            stream
                .shutdown(Shutdown::Write)
                .expect("malformed peer shutdown");
            let mut response = [0u8; 1];
            let received = match stream.read(&mut response) {
                Ok(bytes) => bytes,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                    ) =>
                {
                    0
                }
                Err(error) => panic!("malformed peer received unexpected I/O error: {error}"),
            };
            assert_eq!(received, 0, "malformed peer received a response byte");
        }

        let client_address = address.to_string();
        let valid = thread::spawn(move || {
            super::tcp_handshake_client_with_profile(
                &client_address,
                &client_identity,
                &client_policy,
                5,
                HandshakeProfile::ClassicalLab,
            )
        })
        .join()
        .expect("valid client thread");
        assert!(
            valid.is_ok(),
            "valid peer should connect after malformed peers"
        );

        let accepted = server.join().expect("server thread");
        assert!(
            accepted.is_ok(),
            "listener should remain alive after malformed peers"
        );
    }

    #[test]
    fn tcp_listener_accepts_legitimate_peer_while_slow_preauth_client_is_connected() {
        let probe = TcpListener::bind("127.0.0.1:0").expect("reserve TCP port");
        let address = probe.local_addr().expect("probe address");
        drop(probe);

        let server_identity = IdentityKeyPair::generate().expect("server identity");
        let client_identity = IdentityKeyPair::generate().expect("client identity");
        let server_policy = PeerPolicy::single(PeerPin::for_identity(&client_identity));
        let client_policy = PeerPolicy::single(PeerPin::for_identity(&server_identity));
        let server_identity_for_thread = server_identity.clone();
        let server_policy_for_thread = server_policy.clone();
        let server_address = address.to_string();
        let server = thread::spawn(move || {
            super::tcp_accept_and_handshake_with_profile(
                &server_address,
                &server_identity_for_thread,
                &server_policy_for_thread,
                5,
                HandshakeProfile::ClassicalLab,
            )
        });

        thread::sleep(Duration::from_millis(50));
        let mut slow_client = TcpStream::connect(address).expect("slow client connection");
        slow_client
            .write_all(b"{")
            .expect("slow client partial hello");
        thread::sleep(Duration::from_millis(100));

        let client_address = address.to_string();
        let started = Instant::now();
        let valid = thread::spawn(move || {
            super::tcp_handshake_client_with_profile(
                &client_address,
                &client_identity,
                &client_policy,
                5,
                HandshakeProfile::ClassicalLab,
            )
        })
        .join()
        .expect("valid client thread");
        assert!(
            valid.is_ok(),
            "valid peer should not wait behind a slow pre-auth client: {valid:?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "legitimate handshake was delayed by a slow pre-auth client"
        );

        slow_client
            .shutdown(Shutdown::Both)
            .expect("close slow client");
        assert!(
            server.join().expect("server thread").is_ok(),
            "listener should return the legitimate session"
        );
    }

    #[test]
    fn tcp_established_session_outlives_handshake_deadline() {
        let probe = TcpListener::bind("127.0.0.1:0").expect("reserve TCP port");
        let address = probe.local_addr().expect("probe address");
        drop(probe);

        let server_identity = IdentityKeyPair::generate().expect("server identity");
        let client_identity = IdentityKeyPair::generate().expect("client identity");
        let server_policy = PeerPolicy::single(PeerPin::for_identity(&client_identity));
        let client_policy = PeerPolicy::single(PeerPin::for_identity(&server_identity));
        let server_address = address.to_string();
        let server_identity_for_thread = server_identity.clone();
        let server_policy_for_thread = server_policy.clone();
        let client_handle = thread::spawn(move || {
            super::connect_secure_session_with_profile(
                &server_address,
                &client_identity,
                &client_policy,
                1,
                TransportMode::Tcp,
                HandshakeProfile::ClassicalLab,
            )
        });

        let (mut server_session, _) = super::accept_secure_session_with_profile(
            &address.to_string(),
            &server_identity_for_thread,
            &server_policy_for_thread,
            1,
            TransportMode::Tcp,
            HandshakeProfile::ClassicalLab,
        )
        .expect("server handshake");
        let (mut client_session, _) = client_handle
            .join()
            .expect("client thread")
            .expect("client handshake");

        thread::sleep(Duration::from_millis(1_200));
        client_session
            .send_frame(b"post-handshake-client-frame")
            .expect("send client frame after handshake deadline");
        assert_eq!(
            server_session.recv_frame().expect("receive client frame"),
            b"post-handshake-client-frame"
        );
        server_session
            .send_frame(b"post-handshake-server-frame")
            .expect("send server frame after handshake deadline");
        assert_eq!(
            client_session.recv_frame().expect("receive server frame"),
            b"post-handshake-server-frame"
        );
    }

    #[test]
    fn tcp_phantom_one_session_round_trips_inside_authenticated_aead() {
        let probe = TcpListener::bind("127.0.0.1:0").expect("reserve TCP port");
        let address = probe.local_addr().expect("probe address");
        drop(probe);

        let server_identity = IdentityKeyPair::generate().expect("server identity");
        let client_identity = IdentityKeyPair::generate().expect("client identity");
        let server_policy = PeerPolicy::single(PeerPin::for_identity(&client_identity));
        let client_policy = PeerPolicy::single(PeerPin::for_identity(&server_identity));
        let client_address = address.to_string();
        let client_policy_for_thread = client_policy.clone();
        let client_handle = thread::spawn(move || {
            connect_secure_session_lab(
                &client_address,
                &client_identity,
                &client_policy_for_thread,
                5,
                TransportMode::Tcp,
                QuicLabConfig {
                    shroud_profile: None,
                    phantom_one_profile: Some(ProfileTier::Medium),
                },
            )
        });

        let (mut server_session, server_state) = accept_secure_session_lab(
            &address.to_string(),
            &server_identity,
            &server_policy,
            5,
            TransportMode::Tcp,
            QuicLabConfig {
                shroud_profile: None,
                phantom_one_profile: Some(ProfileTier::Medium),
            },
        )
        .expect("server handshake");
        let (mut client_session, client_state) = client_handle
            .join()
            .expect("client thread")
            .expect("client handshake");
        assert_eq!(
            server_state.transcript_hash_hex,
            client_state.transcript_hash_hex
        );

        client_session
            .send_frame(b"phantom_one-client-frame")
            .expect("send Phantom One client frame");
        assert_eq!(
            server_session
                .recv_frame()
                .expect("receive Phantom One client frame"),
            b"phantom_one-client-frame"
        );
        server_session
            .send_frame(b"phantom_one-server-frame")
            .expect("send Phantom One server frame");
        assert_eq!(
            client_session
                .recv_frame()
                .expect("receive Phantom One server frame"),
            b"phantom_one-server-frame"
        );
    }

    #[test]
    fn peer_rate_limiter_evicts_oldest_source() {
        let mut rl = PeerRateLimiter::new();
        for octet in 0..MAX_QUIC_TRACKED_PEERS {
            let addr: SocketAddr = format!("10.{}.{}.1:1", octet / 256, octet % 256)
                .parse()
                .unwrap();
            assert!(rl.check_and_record(addr).is_ok());
        }
        let admitted: SocketAddr = "11.0.0.1:1".parse().unwrap();
        assert!(rl.check_and_record(admitted).is_ok());
        assert!(rl.seen.len() <= MAX_QUIC_TRACKED_PEERS);
        assert!(!rl.seen.contains_key("10.0.0.1"));
        assert!(rl.seen.contains_key("11.0.0.1"));
    }

    #[test]
    fn quic_frame_decoder_rejects_trailing_and_empty_payloads() {
        use shph_core::ReceiveCipher;

        let mut cipher = ReceiveCipher::new([7u8; 32]);
        assert!(decode_encrypted_quic_frame(&[0, 0, 0, 0], 4, &mut cipher, None).is_err());
        assert!(decode_encrypted_quic_frame(&[0, 0, 0, 1, 9, 9], 6, &mut cipher, None).is_err());
    }

    fn shroud_packet(
        profile: shph_core::ShroudProfile,
        cipher: &mut shph_core::SendCipher,
        payload_len: usize,
    ) -> Vec<u8> {
        let plaintext_capacity = profile.payload_capacity() - (12 + 16);
        let mut padded = vec![0u8; plaintext_capacity];
        padded[..2].copy_from_slice(&(payload_len as u16).to_be_bytes());
        for byte in &mut padded[2..2 + payload_len] {
            *byte = 0x5a;
        }
        let encrypted = cipher.encrypt(&padded).unwrap();
        let cell =
            shph_core::encode_cell(profile, shph_core::SHROUD_FRAME_DATA, &encrypted).unwrap();
        let mut packet = Vec::with_capacity(4 + cell.len());
        packet.extend_from_slice(&(cell.len() as u32).to_be_bytes());
        packet.extend_from_slice(&cell);
        packet
    }

    #[test]
    fn quic_shroud_decoder_accepts_each_profile() {
        use shph_core::{profiles, ReceiveCipher, SendCipher};

        for profile in profiles() {
            let key = [0x31u8; 32];
            let mut sender = SendCipher::new(key);
            let packet = shroud_packet(*profile, &mut sender, 1);
            let mut receiver = ReceiveCipher::new_with_replay_window(key, 128);
            assert_eq!(
                decode_encrypted_quic_frame(&packet, packet.len(), &mut receiver, Some(*profile))
                    .unwrap(),
                vec![0x5a]
            );
        }
    }

    #[test]
    fn quic_shroud_decoder_rejects_profile_size_mismatch() {
        use shph_core::{ReceiveCipher, SendCipher, BALANCED, LOW_LATENCY};

        let key = [0x32u8; 32];
        let mut sender = SendCipher::new(key);
        let packet = shroud_packet(BALANCED, &mut sender, 1);
        let mut receiver = ReceiveCipher::new_with_replay_window(key, 128);
        assert!(decode_encrypted_quic_frame(
            &packet,
            packet.len(),
            &mut receiver,
            Some(LOW_LATENCY)
        )
        .is_err());
    }

    #[test]
    fn quic_shroud_decoder_rejects_non_canonical_outer_padding() {
        use shph_core::{ReceiveCipher, SendCipher, BALANCED};

        let key = [0x33u8; 32];
        let mut sender = SendCipher::new(key);
        let mut packet = shroud_packet(BALANCED, &mut sender, 1);
        let last = packet.len() - 1;
        packet[last] = 1;
        let mut receiver = ReceiveCipher::new_with_replay_window(key, 128);
        assert!(
            decode_encrypted_quic_frame(&packet, packet.len(), &mut receiver, Some(BALANCED))
                .is_err()
        );
    }

    #[test]
    fn quic_shroud_decoder_rejects_inner_payload_length_over_profile_limit() {
        use shph_core::{ReceiveCipher, SendCipher, BALANCED};

        let key = [0x34u8; 32];
        let plaintext_capacity = BALANCED.payload_capacity() - (12 + 16);
        let mut padded = vec![0u8; plaintext_capacity];
        let declared = BALANCED.max_payload_chunk + 1;
        padded[..2].copy_from_slice(&(declared as u16).to_be_bytes());
        let mut sender = SendCipher::new(key);
        let encrypted = sender.encrypt(&padded).unwrap();
        let cell =
            shph_core::encode_cell(BALANCED, shph_core::SHROUD_FRAME_DATA, &encrypted).unwrap();
        let mut packet = Vec::with_capacity(4 + cell.len());
        packet.extend_from_slice(&(cell.len() as u32).to_be_bytes());
        packet.extend_from_slice(&cell);
        let mut receiver = ReceiveCipher::new_with_replay_window(key, 128);
        assert!(
            decode_encrypted_quic_frame(&packet, packet.len(), &mut receiver, Some(BALANCED))
                .is_err()
        );
    }

    #[test]
    fn quic_shroud_decoder_rejects_replayed_cell() {
        use shph_core::{ReceiveCipher, SendCipher, BALANCED};

        let key = [0x35u8; 32];
        let mut sender = SendCipher::new(key);
        let packet = shroud_packet(BALANCED, &mut sender, 1);
        let mut receiver = ReceiveCipher::new_with_replay_window(key, 128);
        assert_eq!(
            decode_encrypted_quic_frame(&packet, packet.len(), &mut receiver, Some(BALANCED))
                .unwrap(),
            vec![0x5a]
        );
        assert!(
            decode_encrypted_quic_frame(&packet, packet.len(), &mut receiver, Some(BALANCED))
                .is_err()
        );
    }

    #[test]
    fn quic_receiver_accepts_authenticated_reordering_once() {
        use shph_core::{ReceiveCipher, SendCipher};

        let key = [8u8; 32];
        let mut sender = SendCipher::new(key);
        let first = sender.encrypt(b"first").unwrap();
        let second = sender.encrypt(b"second").unwrap();
        let frame = |payload: Vec<u8>| {
            let mut packet = Vec::with_capacity(4 + payload.len());
            packet.extend_from_slice(&(payload.len() as u32).to_be_bytes());
            packet.extend_from_slice(&payload);
            packet
        };
        let second = frame(second);
        let first = frame(first);
        let mut receiver = ReceiveCipher::new_with_replay_window(key, 128);
        assert_eq!(
            decode_encrypted_quic_frame(&second, second.len(), &mut receiver, None).unwrap(),
            b"second"
        );
        assert_eq!(
            decode_encrypted_quic_frame(&first, first.len(), &mut receiver, None).unwrap(),
            b"first"
        );
        assert!(
            decode_encrypted_quic_frame(&first, first.len(), &mut receiver, None).is_err(),
            "a reordered frame remains rejected when replayed"
        );
    }

    #[test]
    fn quic_frame_rejects_foreign_source() {
        // Post-handshake source binding: after a QUIC handshake authenticates a
        // peer address, a data-frame datagram arriving from any other address
        // must be rejected before AEAD decryption. This closes an off-path
        // injection/amplification surface where an attacker could force
        // expensive decrypt work or disrupt the authenticated stream.
        use shph_core::IdentityKeyPair;
        use std::io::ErrorKind;
        use std::net::UdpSocket;
        use std::thread;

        let server_id = IdentityKeyPair::generate().unwrap();
        let client_id = IdentityKeyPair::generate().unwrap();
        let server_policy = PeerPolicy::single(PeerPin::for_identity(&client_id));
        let client_policy = PeerPolicy::single(PeerPin::for_identity(&server_id));
        // Reserve a real loopback port, then release it so the server can bind.
        let probe = match UdpSocket::bind("127.0.0.1:0") {
            Ok(socket) => socket,
            Err(err) if err.kind() == ErrorKind::PermissionDenied => {
                eprintln!("skipping quic source-binding test: UDP bind denied ({err})");
                return;
            }
            Err(err) => panic!("quic source-binding test requires UDP bind: {err}"),
        };
        let server_addr = probe.local_addr().unwrap();
        drop(probe);

        // Run the server (accept) on the main thread so its bound socket is the
        // injection target; the client connects from a background thread.
        let client_id2 = client_id.clone();
        let client_policy2 = client_policy.clone();
        let peer = server_addr.to_string();
        let client_handle = thread::spawn(move || {
            super::connect_secure_session(
                &peer,
                &client_id2,
                &client_policy2,
                5,
                super::TransportMode::Quic,
            )
        });
        let (mut server_sess, _state) = super::accept_secure_session(
            &server_addr.to_string(),
            &server_id,
            &server_policy,
            5,
            super::TransportMode::Quic,
        )
        .expect("server handshake");
        client_handle.join().unwrap().expect("client handshake");

        // An unauthenticated second socket injects a well-formed-looking frame
        // datagram from a foreign port into the server's bound socket. The
        // server session is bound to the authenticated client peer; the
        // injection arrives from a different source address.
        let injector = match UdpSocket::bind("127.0.0.1:0") {
            Ok(socket) => socket,
            Err(err) if err.kind() == ErrorKind::PermissionDenied => {
                eprintln!("skipping quic source-binding test: injector bind denied ({err})");
                return;
            }
            Err(err) => panic!("quic source-binding test requires injector bind: {err}"),
        };
        let mut forged = Vec::new();
        forged.extend_from_slice(&4u32.to_be_bytes());
        forged.extend_from_slice(&[0u8; 4]); // bogus ciphertext body
        injector.send_to(&forged, server_addr).unwrap();

        let res = server_sess.recv_frame();
        assert!(
            matches!(res, Err(shph_core::ShphError::Protocol(_))),
            "foreign-source QUIC frame must be rejected, got {res:?}"
        );
    }

    #[test]
    fn quic_shroud_profile_roundtrip() {
        use shph_core::IdentityKeyPair;
        use std::io::ErrorKind;
        use std::net::UdpSocket;
        use std::thread;

        match UdpSocket::bind("0.0.0.0:0") {
            Ok(socket) => drop(socket),
            Err(err) if err.kind() == ErrorKind::PermissionDenied => {
                eprintln!("skipping quic shroud test: UDP bind denied ({err})");
                return;
            }
            Err(err) => panic!("quic shroud test requires UDP bind: {err}"),
        }
        let server_id = IdentityKeyPair::generate().unwrap();
        let client_id = IdentityKeyPair::generate().unwrap();
        let server_policy = PeerPolicy::single(PeerPin::for_identity(&client_id));
        let client_policy = PeerPolicy::single(PeerPin::for_identity(&server_id));
        let probe = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = probe.local_addr().unwrap();
        drop(probe);
        let peer = server_addr.to_string();
        let client_policy2 = client_policy.clone();
        let client_handle = thread::spawn(move || {
            let (mut session, _) = connect_secure_session_lab(
                &peer,
                &client_id,
                &client_policy2,
                5,
                TransportMode::Quic,
                QuicLabConfig {
                    shroud_profile: Some(shph_core::BALANCED),
                    phantom_one_profile: None,
                },
            )
            .unwrap();
            session.send_frame(b"shroud-lab").unwrap();
        });
        let (mut session, _) = accept_secure_session_lab(
            &server_addr.to_string(),
            &server_id,
            &server_policy,
            5,
            TransportMode::Quic,
            QuicLabConfig {
                shroud_profile: Some(shph_core::BALANCED),
                phantom_one_profile: None,
            },
        )
        .unwrap();
        assert_eq!(session.recv_frame().unwrap(), b"shroud-lab");
        client_handle.join().unwrap();
    }

    #[test]
    fn quic_tuned_profile_roundtrip_uses_shared_envelope_capacity() {
        use shph_core::IdentityKeyPair;
        use std::io::ErrorKind;
        use std::net::UdpSocket;
        use std::thread;

        match UdpSocket::bind("0.0.0.0:0") {
            Ok(socket) => drop(socket),
            Err(err) if err.kind() == ErrorKind::PermissionDenied => {
                eprintln!("skipping tuned quic test: UDP bind denied ({err})");
                return;
            }
            Err(err) => panic!("tuned quic test requires UDP bind: {err}"),
        }
        let server_id = IdentityKeyPair::generate().unwrap();
        let client_id = IdentityKeyPair::generate().unwrap();
        let server_policy = PeerPolicy::single(PeerPin::for_identity(&client_id));
        let client_policy = PeerPolicy::single(PeerPin::for_identity(&server_id));
        let probe = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = probe.local_addr().unwrap();
        drop(probe);
        let peer = server_addr.to_string();
        let client_policy2 = client_policy.clone();
        let client_handle = thread::spawn(move || {
            let (mut session, _) = connect_secure_session_lab(
                &peer,
                &client_id,
                &client_policy2,
                5,
                TransportMode::Quic,
                QuicLabConfig {
                    shroud_profile: Some(shph_core::TUNED_MEDIUM),
                    phantom_one_profile: None,
                },
            )
            .unwrap();
            session.send_frame(&[0x4d; 1_000]).unwrap();
        });
        let (mut session, _) = accept_secure_session_lab(
            &server_addr.to_string(),
            &server_id,
            &server_policy,
            5,
            TransportMode::Quic,
            QuicLabConfig {
                shroud_profile: Some(shph_core::TUNED_MEDIUM),
                phantom_one_profile: None,
            },
        )
        .unwrap();
        assert_eq!(session.recv_frame().unwrap(), vec![0x4d; 1_000]);
        client_handle.join().unwrap();
    }

    #[test]
    fn quic_randomized_shroud_profile_roundtrip() {
        use shph_core::IdentityKeyPair;
        use std::io::ErrorKind;
        use std::net::UdpSocket;
        use std::thread;

        match UdpSocket::bind("0.0.0.0:0") {
            Ok(socket) => drop(socket),
            Err(err) if err.kind() == ErrorKind::PermissionDenied => {
                eprintln!("skipping randomized quic shroud test: UDP bind denied ({err})");
                return;
            }
            Err(err) => panic!("randomized quic shroud test requires UDP bind: {err}"),
        }
        let server_id = IdentityKeyPair::generate().unwrap();
        let client_id = IdentityKeyPair::generate().unwrap();
        let server_policy = PeerPolicy::single(PeerPin::for_identity(&client_id));
        let client_policy = PeerPolicy::single(PeerPin::for_identity(&server_id));
        let probe = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = probe.local_addr().unwrap();
        drop(probe);
        let peer = server_addr.to_string();
        let client_policy2 = client_policy.clone();
        let client_handle = thread::spawn(move || {
            let (mut session, _) = connect_secure_session_lab(
                &peer,
                &client_id,
                &client_policy2,
                5,
                TransportMode::Quic,
                QuicLabConfig {
                    shroud_profile: shph_core::shroud_profile_by_name("randomized-lab"),
                    phantom_one_profile: None,
                },
            )
            .unwrap();
            session.send_frame(b"randomized-shroud-lab").unwrap();
        });
        let (mut session, _) = accept_secure_session_lab(
            &server_addr.to_string(),
            &server_id,
            &server_policy,
            5,
            TransportMode::Quic,
            QuicLabConfig {
                shroud_profile: shph_core::shroud_profile_by_name("randomized-lab"),
                phantom_one_profile: None,
            },
        )
        .unwrap();
        assert_eq!(session.recv_frame().unwrap(), b"randomized-shroud-lab");
        client_handle.join().unwrap();
    }

    #[test]
    fn data_mule_scan_quarantines_malformed_files() {
        let root = std::env::temp_dir().join(format!(
            "shph-mule-scan-{}-{}",
            std::process::id(),
            TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let bad = root.join("bad.shph");
        fs::write(&bad, b"not-json").unwrap();

        let mut out = Vec::new();
        let mut scan =
            DataMuleScanContext::new(4096, MAX_DATA_MULE_AGE_MS, super::now_unix_ms().unwrap());
        collect_shph_files(&root, &mut out, 0, &mut scan).unwrap();

        assert!(out.is_empty());
        assert!(!bad.exists());
        assert!(root.join("bad.rejected").exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn data_mule_quarantine_preserves_existing_rejection() {
        let root = std::env::temp_dir().join(format!(
            "shph-mule-quarantine-{}-{}",
            std::process::id(),
            TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let bad = root.join("bad.shph");
        let existing = root.join("bad.rejected");
        fs::write(&bad, b"not-json").unwrap();
        fs::write(&existing, b"previous evidence").unwrap();

        let mut out = Vec::new();
        let mut scan =
            DataMuleScanContext::new(4096, MAX_DATA_MULE_AGE_MS, super::now_unix_ms().unwrap());
        collect_shph_files(&root, &mut out, 0, &mut scan).unwrap();

        assert_eq!(fs::read_to_string(existing).unwrap(), "previous evidence");
        assert!(root
            .read_dir()
            .unwrap()
            .filter_map(std::result::Result::ok)
            .any(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("bad.rejected.")
            }));
        assert!(!bad.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn data_mule_scan_skips_bad_candidate_and_returns_next_valid_file() {
        let root = std::env::temp_dir().join(format!(
            "shph-mule-scan-order-{}-{}",
            std::process::id(),
            TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let recipient_inbox = root.join(super::safe_path_component("local"));
        fs::create_dir_all(&recipient_inbox).unwrap();
        let bad = recipient_inbox.join("a.shph");
        let good = recipient_inbox.join("b.shph");
        let now = super::now_unix_ms().unwrap();
        let bad_envelope = serde_json::json!({
            "envelope_id": "a",
            "created_at_unix_ms": now,
            "from_node": "peer",
            "to_node": "local",
            "ciphertext_b64": "%%%",
            "nonce_b64": "AA=="
        });
        let good_envelope = serde_json::json!({
            "envelope_id": "b",
            "created_at_unix_ms": now,
            "from_node": "peer",
            "to_node": "local",
            "ciphertext_b64": "AQ==",
            "nonce_b64": "AQ=="
        });
        fs::write(&bad, serde_json::to_vec(&bad_envelope).unwrap()).unwrap();
        fs::write(&good, serde_json::to_vec(&good_envelope).unwrap()).unwrap();

        let cfg = DataMuleConfig {
            inbox_dir: root.to_string_lossy().into_owned(),
            outbox_dir: root.join("out").to_string_lossy().into_owned(),
            poll_interval_ms: 1,
            max_file_bytes: 4096,
            max_total_bytes: 8 * 1024 * 1024,
            max_age_ms: MAX_DATA_MULE_AGE_MS,
        };
        let mut state = super::DataMuleReadState::new(&cfg, "local", Some("peer"));
        let frame = state
            .poll_envelope()
            .expect("scan")
            .expect("valid candidate");
        assert_eq!(frame.envelope.envelope_id, "b");
        assert!(bad.with_extension("rejected").exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn data_mule_quota_ignores_other_peers_without_quarantining_them() {
        let root = std::env::temp_dir().join(format!(
            "shph-mule-peer-quota-{}-{}",
            std::process::id(),
            TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let recipient_inbox = root.join(super::safe_path_component("local"));
        fs::create_dir_all(&recipient_inbox).unwrap();
        let now = super::now_unix_ms().unwrap();
        let legitimate = recipient_inbox.join("legitimate.shph");
        let unrelated = recipient_inbox.join("unrelated.shph");
        let legitimate_bytes = serde_json::to_vec(&serde_json::json!({
            "envelope_id": "legitimate",
            "created_at_unix_ms": now.saturating_sub(1_000),
            "from_node": "peer",
            "to_node": "local",
            "ciphertext_b64": "AQ==",
            "nonce_b64": "AQ=="
        }))
        .unwrap();
        let unrelated_bytes = serde_json::to_vec(&serde_json::json!({
            "envelope_id": "unrelated",
            "created_at_unix_ms": now.saturating_sub(500),
            "from_node": "other-peer",
            "to_node": "local",
            "ciphertext_b64": "AQ==",
            "nonce_b64": "AQ=="
        }))
        .unwrap();
        let quota = legitimate_bytes.len() as u64;
        fs::write(&legitimate, legitimate_bytes).unwrap();
        fs::write(&unrelated, unrelated_bytes).unwrap();

        let cfg = DataMuleConfig {
            inbox_dir: root.to_string_lossy().into_owned(),
            outbox_dir: root.join("out").to_string_lossy().into_owned(),
            poll_interval_ms: 1,
            max_file_bytes: 256,
            max_total_bytes: quota,
            max_age_ms: MAX_DATA_MULE_AGE_MS,
        };
        let mut state = super::DataMuleReadState::new(&cfg, "local", Some("peer"));
        let frame = state
            .poll_envelope()
            .expect("scan")
            .expect("eligible message remains deliverable");

        assert_eq!(frame.envelope.envelope_id, "legitimate");
        assert!(unrelated.exists());
        assert!(!unrelated.with_extension("rejected").exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn data_mule_ignores_unrelated_recipient_spool_above_scan_budget() {
        let root = test_root("shph-mule-recipient-scan-budget");
        let unrelated_inbox = root.join(super::safe_path_component("unrelated-recipient"));
        let recipient_inbox = root.join(super::safe_path_component("local"));
        fs::create_dir_all(&unrelated_inbox).unwrap();
        fs::create_dir_all(&recipient_inbox).unwrap();

        let now = super::now_unix_ms().unwrap();
        let large_bytes = serde_json::to_vec(&serde_json::json!({
            "envelope_id": "unrelated-entry",
            "created_at_unix_ms": now,
            "from_node": "peer",
            "to_node": "unrelated-recipient",
            "ciphertext_b64": "A".repeat(250_000),
            "nonce_b64": "AA=="
        }))
        .unwrap();
        let max_file_bytes = 256 * 1024;
        assert!(large_bytes.len() <= max_file_bytes);
        let unrelated_count = super::MAX_QUEUE_SCAN_BYTES / large_bytes.len() as u64 + 1;
        assert!(unrelated_count * large_bytes.len() as u64 > super::MAX_QUEUE_SCAN_BYTES);
        for index in 0..unrelated_count {
            fs::write(
                unrelated_inbox.join(format!("unrelated-{index}.shph")),
                &large_bytes,
            )
            .unwrap();
        }

        let local_bytes = serde_json::to_vec(&serde_json::json!({
            "envelope_id": "local-delivery",
            "created_at_unix_ms": now,
            "from_node": "peer",
            "to_node": "local",
            "ciphertext_b64": "AQ==",
            "nonce_b64": "AQ=="
        }))
        .unwrap();
        fs::write(recipient_inbox.join("local-delivery.shph"), local_bytes).unwrap();

        let cfg = DataMuleConfig {
            inbox_dir: root.to_string_lossy().into_owned(),
            outbox_dir: root.join("out").to_string_lossy().into_owned(),
            poll_interval_ms: 1,
            max_file_bytes: max_file_bytes as u64,
            max_total_bytes: 8 * 1024 * 1024,
            max_age_ms: MAX_DATA_MULE_AGE_MS,
        };
        let mut state = super::DataMuleReadState::new(&cfg, "local", Some("peer"));
        let frame = state
            .poll_envelope()
            .expect("scan local recipient inbox")
            .expect("local delivery remains available");

        assert_eq!(frame.envelope.envelope_id, "local-delivery");
        assert_eq!(
            fs::read_dir(&unrelated_inbox).unwrap().count() as u64,
            unrelated_count
        );
        assert!(unrelated_inbox.read_dir().unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains("rejected")));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn data_mule_spoofed_over_quota_entry_does_not_block_authenticated_delivery() {
        let root = std::env::temp_dir().join(format!(
            "shph-mule-over-quota-{}-{}",
            std::process::id(),
            TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let recipient_inbox = root.join(super::safe_path_component("local"));
        fs::create_dir_all(&recipient_inbox).unwrap();
        let now = super::now_unix_ms().unwrap();
        let spoofed = recipient_inbox.join("spoofed.shph");
        let authenticated = recipient_inbox.join("authenticated.shph");
        let spoofed_bytes = serde_json::to_vec(&serde_json::json!({
            "envelope_id": "a-spoofed",
            "created_at_unix_ms": now.saturating_sub(1),
            "from_node": "peer",
            "to_node": "local",
            "ciphertext_b64": base64::engine::general_purpose::STANDARD.encode(b"forged"),
            "nonce_b64": "AAAAAAAAAAA="
        }))
        .unwrap();
        let mut sender = SendCipher::new([0x74; 32]);
        let ciphertext = sender.encrypt(b"authenticated delivery").unwrap();
        let authenticated_bytes = serde_json::to_vec(&serde_json::json!({
            "envelope_id": "b-authenticated",
            "created_at_unix_ms": now,
            "from_node": "peer",
            "to_node": "local",
            "ciphertext_b64": base64::engine::general_purpose::STANDARD.encode(ciphertext),
            "nonce_b64": "AAAAAAAAAAA="
        }))
        .unwrap();
        assert!(spoofed_bytes.len() <= 256);
        assert!(authenticated_bytes.len() <= 256);
        assert!(spoofed_bytes.len() + authenticated_bytes.len() > 256);
        fs::write(&spoofed, spoofed_bytes).unwrap();
        fs::write(&authenticated, authenticated_bytes).unwrap();

        let cfg = DataMuleConfig {
            inbox_dir: root.to_string_lossy().into_owned(),
            outbox_dir: root.join("out").to_string_lossy().into_owned(),
            poll_interval_ms: 1,
            max_file_bytes: 256,
            max_total_bytes: 256,
            max_age_ms: MAX_DATA_MULE_AGE_MS,
        };
        let mut state = super::DataMuleReadState::new(&cfg, "local", Some("peer"));
        let mut receiver = ReceiveCipher::new([0x74; 32]);

        assert_eq!(
            state
                .receive_decrypted_frame(&mut receiver, Duration::from_secs(1))
                .unwrap(),
            b"authenticated delivery"
        );
        assert!(spoofed.with_extension("rejected").exists());
        assert!(!authenticated.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn data_mule_scan_quarantines_expired_files() {
        let root = std::env::temp_dir().join(format!(
            "shph-mule-expiry-{}-{}",
            std::process::id(),
            TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let recipient_inbox = root.join(super::safe_path_component("local"));
        fs::create_dir_all(&recipient_inbox).unwrap();
        let stale = recipient_inbox.join("stale.shph");
        let now = super::now_unix_ms().unwrap();
        let envelope = serde_json::json!({
            "envelope_id": "stale",
            "created_at_unix_ms": now.saturating_sub(10_000),
            "from_node": "peer",
            "to_node": "local",
            "ciphertext_b64": "AQ==",
            "nonce_b64": "AQ=="
        });
        fs::write(&stale, serde_json::to_vec(&envelope).unwrap()).unwrap();

        let cfg = DataMuleConfig {
            inbox_dir: root.to_string_lossy().into_owned(),
            outbox_dir: root.join("out").to_string_lossy().into_owned(),
            poll_interval_ms: 1,
            max_file_bytes: 4096,
            max_total_bytes: 8 * 1024 * 1024,
            max_age_ms: 1_000,
        };
        let mut state = DataMuleReadState::new(&cfg, "local", Some("peer"));
        assert!(state.poll_envelope().expect("scan").is_none());
        assert!(!stale.exists());
        assert!(recipient_inbox.join("stale.rejected").exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn data_mule_scan_quarantines_far_future_files() {
        let root = std::env::temp_dir().join(format!(
            "shph-mule-future-{}-{}",
            std::process::id(),
            TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let recipient_inbox = root.join(super::safe_path_component("local"));
        fs::create_dir_all(&recipient_inbox).unwrap();
        let future = recipient_inbox.join("future.shph");
        let now = super::now_unix_ms().unwrap();
        let envelope = serde_json::json!({
            "envelope_id": "future",
            "created_at_unix_ms": now.saturating_add(10_000),
            "from_node": "peer",
            "to_node": "local",
            "ciphertext_b64": "AQ==",
            "nonce_b64": "AQ=="
        });
        fs::write(&future, serde_json::to_vec(&envelope).unwrap()).unwrap();

        let cfg = DataMuleConfig {
            inbox_dir: root.to_string_lossy().into_owned(),
            outbox_dir: root.join("out").to_string_lossy().into_owned(),
            poll_interval_ms: 1,
            max_file_bytes: 4096,
            max_total_bytes: 8 * 1024 * 1024,
            max_age_ms: 1_000,
        };
        let mut state = DataMuleReadState::new(&cfg, "local", Some("peer"));
        assert!(state.poll_envelope().expect("scan").is_none());
        assert!(!future.exists());
        assert!(recipient_inbox.join("future.rejected").exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn data_mule_outbox_enforces_aggregate_quota() {
        let root = std::env::temp_dir().join(format!(
            "shph-mule-quota-{}-{}",
            std::process::id(),
            TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let cfg = DataMuleConfig {
            inbox_dir: root.join("in").to_string_lossy().into_owned(),
            outbox_dir: root.join("out").to_string_lossy().into_owned(),
            poll_interval_ms: 1,
            max_file_bytes: 4096,
            max_total_bytes: 4096,
            max_age_ms: MAX_DATA_MULE_AGE_MS,
        };
        let mut writer = DataMuleWriteState::new(&cfg, "local", "peer");
        let mut exhausted = false;
        for _ in 0..64 {
            match writer.send_payload(&[0x41; 100]) {
                Ok(()) => {}
                Err(ShphError::ResourceExhausted(_)) => {
                    exhausted = true;
                    break;
                }
                Err(error) => panic!("unexpected data-mule write error: {error}"),
            }
        }
        assert!(
            exhausted,
            "aggregate quota must stop unbounded outbox growth"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn data_mule_session_quarantines_aead_failures() {
        let root = std::env::temp_dir().join(format!(
            "shph-mule-aead-{}-{}",
            std::process::id(),
            TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let cfg = DataMuleConfig {
            inbox_dir: root.to_string_lossy().into_owned(),
            outbox_dir: root.to_string_lossy().into_owned(),
            poll_interval_ms: 1,
            max_file_bytes: 4096,
            max_total_bytes: 8 * 1024 * 1024,
            max_age_ms: MAX_DATA_MULE_AGE_MS,
        };

        let mut writer = DataMuleWriteState::new(&cfg, "peer", "local");
        writer
            .send_payload(b"not-a-valid-ciphertext")
            .expect("write malformed encrypted frame");

        let mut session = DataMuleSession::new(
            DataMuleWriteState::new(&cfg, "local", "peer"),
            DataMuleReadState::new(&cfg, "local", Some("peer")),
            [0x11; 32],
            [0x22; 32],
        );
        assert!(session.recv_frame().is_err());

        let local_dir = root.join(super::safe_path_component("local"));
        let names: Vec<String> = fs::read_dir(local_dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            names.iter().any(|name| name.contains(".rejected")),
            "failed ciphertext must be quarantined"
        );
        assert!(
            names.iter().all(|name| !name.contains(".processing")),
            "failed ciphertext must not remain in processing state"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn data_mule_verified_hello_quarantines_unauthorized_sender() {
        let root = std::env::temp_dir().join(format!(
            "shph-mule-auth-{}-{}",
            std::process::id(),
            TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let cfg = DataMuleConfig {
            inbox_dir: root.to_string_lossy().into_owned(),
            outbox_dir: root.to_string_lossy().into_owned(),
            poll_interval_ms: 1,
            max_file_bytes: 64 * 1024,
            max_total_bytes: 8 * 1024 * 1024,
            max_age_ms: MAX_DATA_MULE_AGE_MS,
        };
        let local = IdentityKeyPair::generate().unwrap();
        let attacker = IdentityKeyPair::generate().unwrap();
        let expected = IdentityKeyPair::generate().unwrap();
        let material =
            super::build_hello_with_profile(&local, HandshakeProfile::SecureDefault).unwrap();
        let attacker_material =
            super::build_hello_with_profile(&attacker, HandshakeProfile::SecureDefault).unwrap();
        let mut writer =
            DataMuleWriteState::new(&cfg, &attacker.public_key_b64(), &local.public_key_b64());
        writer
            .send_payload(&serde_json::to_vec(&attacker_material.local_hello).unwrap())
            .unwrap();

        let mut reader = DataMuleReadState::new(&cfg, &local.public_key_b64(), None);
        let result = reader.receive_verified_hello(
            Duration::from_millis(100),
            &local,
            &material,
            &PeerPolicy::single(PeerPin::for_identity(&expected)),
        );
        assert!(matches!(result, Err(shph_core::ShphError::Auth(_))));

        let local_dir = root.join(super::safe_path_component(&local.public_key_b64()));
        let names: Vec<String> = fs::read_dir(local_dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(names.iter().any(|name| name.contains(".rejected")));
        assert!(names.iter().all(|name| !name.contains(".processing")));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn data_mule_verified_hello_binds_envelope_sender_to_identity() {
        let root = std::env::temp_dir().join(format!(
            "shph-mule-binding-{}-{}",
            std::process::id(),
            TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let cfg = DataMuleConfig {
            inbox_dir: root.to_string_lossy().into_owned(),
            outbox_dir: root.to_string_lossy().into_owned(),
            poll_interval_ms: 1,
            max_file_bytes: 64 * 1024,
            max_total_bytes: 8 * 1024 * 1024,
            max_age_ms: MAX_DATA_MULE_AGE_MS,
        };
        let local = IdentityKeyPair::generate().unwrap();
        let peer = IdentityKeyPair::generate().unwrap();
        let local_material =
            super::build_hello_with_profile(&local, HandshakeProfile::SecureDefault).unwrap();
        let peer_material =
            super::build_hello_with_profile(&peer, HandshakeProfile::SecureDefault).unwrap();
        let mut writer =
            DataMuleWriteState::new(&cfg, "not-the-peer-identity", &local.public_key_b64());
        writer
            .send_payload(&serde_json::to_vec(&peer_material.local_hello).unwrap())
            .unwrap();

        let mut reader = DataMuleReadState::new(&cfg, &local.public_key_b64(), None);
        let result = reader.receive_verified_hello(
            Duration::from_millis(100),
            &local,
            &local_material,
            &PeerPolicy::single(PeerPin::for_identity(&peer)),
        );
        assert!(matches!(result, Err(shph_core::ShphError::Auth(_))));

        let local_dir = root.join(super::safe_path_component(&local.public_key_b64()));
        let names: Vec<String> = fs::read_dir(local_dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(names.iter().any(|name| name.contains(".rejected")));
        assert!(names.iter().all(|name| !name.contains(".processing")));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn data_mule_pinned_sender_with_wrong_signed_hello_is_terminal() {
        let root = std::env::temp_dir().join(format!(
            "shph-mule-pinned-identity-{}-{}",
            std::process::id(),
            TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let cfg = DataMuleConfig {
            inbox_dir: root.to_string_lossy().into_owned(),
            outbox_dir: root.to_string_lossy().into_owned(),
            poll_interval_ms: 1,
            max_file_bytes: 64 * 1024,
            max_total_bytes: 8 * 1024 * 1024,
            max_age_ms: MAX_DATA_MULE_AGE_MS,
        };
        let local = IdentityKeyPair::generate().unwrap();
        let pinned = IdentityKeyPair::generate().unwrap();
        let wrong = IdentityKeyPair::generate().unwrap();
        let local_material =
            super::build_hello_with_profile(&local, HandshakeProfile::SecureDefault).unwrap();
        let wrong_material =
            super::build_hello_with_profile(&wrong, HandshakeProfile::SecureDefault).unwrap();
        let pinned_node = pinned.public_key_b64();
        let mut writer = DataMuleWriteState::new(&cfg, &pinned_node, &local.public_key_b64());
        writer
            .send_payload(&serde_json::to_vec(&wrong_material.local_hello).unwrap())
            .unwrap();

        let mut reader = DataMuleReadState::new(&cfg, &local.public_key_b64(), Some(&pinned_node));
        let result = reader.receive_verified_hello(
            Duration::from_millis(100),
            &local,
            &local_material,
            &PeerPolicy::single(PeerPin::for_identity(&pinned)),
        );
        assert!(matches!(result, Err(ShphError::Auth(_))));

        let local_dir = root.join(super::safe_path_component(&local.public_key_b64()));
        let names: Vec<String> = fs::read_dir(local_dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(names.iter().any(|name| name.contains(".rejected")));
        assert!(names.iter().all(|name| !name.contains(".processing")));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn data_mule_responder_pq_quarantines_invalid_ciphertext() {
        let root = std::env::temp_dir().join(format!(
            "shph-mule-pq-{}-{}",
            std::process::id(),
            TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let cfg = DataMuleConfig {
            inbox_dir: root.to_string_lossy().into_owned(),
            outbox_dir: root.to_string_lossy().into_owned(),
            poll_interval_ms: 1,
            max_file_bytes: 64 * 1024,
            max_total_bytes: 8 * 1024 * 1024,
            max_age_ms: MAX_DATA_MULE_AGE_MS,
        };
        let local = IdentityKeyPair::generate().unwrap();
        let peer = IdentityKeyPair::generate().unwrap();
        let mut local_material =
            super::build_hello_with_profile(&local, HandshakeProfile::SecureDefault).unwrap();
        let peer_material =
            super::build_hello_with_profile(&peer, HandshakeProfile::SecureDefault).unwrap();
        let mut writer =
            DataMuleWriteState::new(&cfg, &peer.public_key_b64(), &local.public_key_b64());
        writer.send_payload(b"invalid-pq-ciphertext").unwrap();

        let mut reader =
            DataMuleReadState::new(&cfg, &local.public_key_b64(), Some(&peer.public_key_b64()));
        let result = reader.receive_verified_responder_pq(
            Duration::from_millis(100),
            &local,
            &mut local_material,
            &peer_material.local_hello,
            &PeerPolicy::single(PeerPin::for_identity(&peer)),
        );
        assert!(result.is_err());

        let local_dir = root.join(super::safe_path_component(&local.public_key_b64()));
        let names: Vec<String> = fs::read_dir(local_dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(names.iter().any(|name| name.contains(".rejected")));
        assert!(names.iter().all(|name| !name.contains(".processing")));
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn read_file_bytes_rejects_symlink_without_following_it() {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join(format!(
            "shph-mule-symlink-{}-{}",
            std::process::id(),
            TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let target = root.join("target");
        let link = root.join("link");
        fs::write(&target, b"secret").unwrap();
        symlink(&target, &link).unwrap();
        assert!(super::read_file_bytes(&link, 4096).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
