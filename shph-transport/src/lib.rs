//! SHPH transport abstractions.
//!
//! Includes stable TCP transport today plus an experimental QUIC-like
//! UDP datagram shim for phased adoption.

use base64::Engine as _;
use rand::RngCore;
use shph_core::roadmap::{data_mule_inbox_path, offline_session_id};
use shph_core::{
    absorb_responder_pq, build_hello_with_profile, finalize_initiator_pq, verify_and_derive,
    DataMuleConfig, DataMuleEnvelope, HandshakeProfile, HandshakeState, Hello, IdentityKeyPair,
    OfflineMeshConfig, OfflineMeshEnvelope, ReceiveCipher, Result, SendCipher, ShphError,
    ShroudProfile, ML_KEM_768_CIPHERTEXT_BYTES,
};
use std::collections::{HashSet, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MAX_HELLO_BYTES: usize = 16 * 1024;
const MAX_FRAME_BYTES: usize = 64 * 1024;
const MAX_QUIC_FRAME_BYTES: usize = 16 * 1024;
const MAX_QUIC_HELLO_BYTES: usize = 12 * 1024;
const SHROUD_AEAD_OVERHEAD: usize = 12 + 16;
const SHROUD_LENGTH_PREFIX: usize = 2;
const QUIC_HANDSHAKE_ATTEMPTS: usize = 3;
const MAX_QUIC_HANDSHAKE_DATAGRAMS: usize = 64;
const MAX_QUIC_INVALID_DATAGRAMS_PER_RECV: usize = 8;
const MAX_QUIC_TRACKED_PEERS: usize = 1024;
const MAX_QUIC_IDLE_TIMEOUT_SECS: u64 = 300;
/// Maximum number of inbound TCP handshake attempts the accept path will
/// tolerate from malformed/early-closing peers before giving up. This bounds
/// the effort an unauthenticated attacker can force on the entry path.
const TCP_HANDSHAKE_ATTEMPTS: usize = 5;
const TCP_HANDSHAKE_DEADLINE: Duration = Duration::from_secs(60);

/// Per-source connection-rate limiting for the unauthenticated TCP entry path.
/// A single peer address may open at most `MAX_CONNECTS_PER_PEER_PER_WINDOW`
/// inbound handshakes within `PEER_RATE_WINDOW`. Beyond that, further connects
/// from that source are rejected before any handshake work is done, so one host
/// cannot flood the entry path across sessions (the attempt bound above only
/// covers a single accept loop).
const PEER_RATE_WINDOW: Duration = Duration::from_secs(10);
const MAX_CONNECTS_PER_PEER_PER_WINDOW: usize = 8;

#[derive(Debug, Clone, Copy)]
pub enum TransportMode {
    Tcp,
    Quic,
    OfflineMesh,
    DataMule,
}

impl TransportMode {
    pub fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "tcp" => Ok(Self::Tcp),
            "quic" => Ok(Self::Quic),
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
}

enum SecureSessionInner {
    Tcp(SecureTcpSession),
    Quic(ExperimentalQuicSession),
    OfflineMesh(OfflineMeshSession),
    DataMule(DataMuleSession),
}

pub struct SecureSender {
    inner: SecureSenderInner,
}

enum SecureSenderInner {
    Tcp(SecureTcpSender),
    Quic(ExperimentalQuicSender),
    OfflineMesh(OfflineMeshSender),
    DataMule(DataMuleSender),
}

pub struct SecureReceiver {
    inner: SecureReceiverInner,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct QuicLabConfig {
    pub shroud_profile: Option<ShroudProfile>,
}

enum SecureReceiverInner {
    Tcp(SecureTcpReceiver),
    Quic(ExperimentalQuicReceiver),
    OfflineMesh(OfflineMeshReceiver),
    DataMule(DataMuleReceiver),
}

const MAX_FILE_ADAPTER_BYTES: u64 = 256 * 1024;
const MAX_QUEUE_SCAN_ENTRIES: usize = 4096;
const MAX_QUEUE_SCAN_DEPTH: usize = 16;
static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

fn now_unix_ms() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ShphError::Internal("system clock before unix epoch".into()))?
        .as_millis() as u64)
}

fn sanitize_component(input: &str) -> String {
    input
        .chars()
        .map(|ch| match ch {
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            _ => ch,
        })
        .collect()
}

fn write_file_atomically(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(ShphError::Io)?;
    }

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

    if let Err(err) = fs::rename(&tmp, path) {
        #[cfg(windows)]
        {
            if path.exists() {
                if let Err(remove_err) = fs::remove_file(path).map_err(ShphError::Io) {
                    let _ = fs::remove_file(&tmp);
                    return Err(remove_err);
                }
                if let Err(rename_err) = fs::rename(&tmp, path).map_err(ShphError::Io) {
                    let _ = fs::remove_file(&tmp);
                    return Err(rename_err);
                }
            } else {
                let _ = fs::remove_file(&tmp);
                return Err(ShphError::Io(err));
            }
        }
        #[cfg(not(windows))]
        {
            let _ = fs::remove_file(&tmp);
            return Err(ShphError::Io(err));
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
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
    }
    #[cfg(not(unix))]
    {
        File::open(path)
    }
}

fn quarantine_file(path: &Path) {
    let Some(parent) = path.parent() else {
        return;
    };
    let stem = path
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
        match fs::hard_link(path, &rejected) {
            Ok(()) => {
                if fs::remove_file(path).is_err() {
                    let _ = fs::remove_file(&rejected);
                }
                return;
            }
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(_) => return,
        }
    }
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

fn parse_socket_addr(addr: &str) -> Result<SocketAddr> {
    resolve_socket_addrs(addr)?
        .next()
        .ok_or_else(|| ShphError::Config(format!("unable to resolve peer address: {addr}")))
}

fn resolve_socket_addrs(addr: &str) -> Result<std::vec::IntoIter<SocketAddr>> {
    let addrs: Vec<_> = addr
        .to_socket_addrs()
        .map_err(|_| ShphError::Config(format!("invalid peer address: {addr}")))?
        .collect();
    Ok(addrs.into_iter())
}

fn connect_tcp_with_timeout(peer: &str, timeout_secs: u64) -> Result<TcpStream> {
    let deadline = Instant::now() + Duration::from_secs(timeout_secs.max(1));
    let mut last_error = None;
    for addr in resolve_socket_addrs(peer)? {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match TcpStream::connect_timeout(&addr, remaining) {
            Ok(stream) => return Ok(stream),
            Err(err) => last_error = Some(err),
        }
    }
    Err(last_error.map(map_io_error).unwrap_or(ShphError::Timeout))
}

fn bounded_quic_timeout_secs(timeout_secs: u64) -> u64 {
    timeout_secs.clamp(1, MAX_QUIC_IDLE_TIMEOUT_SECS)
}

pub fn connect_and_handshake(
    peer: &str,
    local_identity: &IdentityKeyPair,
    timeout_secs: u64,
    mode: TransportMode,
) -> Result<HandshakeState> {
    connect_and_handshake_with_profile(
        peer,
        local_identity,
        timeout_secs,
        mode,
        HandshakeProfile::SecureDefault,
    )
}

pub fn connect_and_handshake_with_profile(
    peer: &str,
    local_identity: &IdentityKeyPair,
    timeout_secs: u64,
    mode: TransportMode,
    profile: HandshakeProfile,
) -> Result<HandshakeState> {
    match mode {
        TransportMode::Tcp => {
            tcp_handshake_client_with_profile(peer, local_identity, timeout_secs, profile)
        }
        TransportMode::Quic => {
            let (_socket, _peer, state) =
                quic_handshake_client_with_profile(peer, local_identity, timeout_secs, profile)?;
            Ok(state)
        }
        TransportMode::OfflineMesh | TransportMode::DataMule => Err(ShphError::InvalidArgument(
            "offline/data-mule require direct config-based APIs".into(),
        )),
    }
}

pub fn accept_handshake(
    bind_addr: &str,
    local_identity: &IdentityKeyPair,
    timeout_secs: u64,
    mode: TransportMode,
) -> Result<HandshakeState> {
    accept_handshake_with_profile(
        bind_addr,
        local_identity,
        timeout_secs,
        mode,
        HandshakeProfile::SecureDefault,
    )
}

pub fn accept_handshake_with_profile(
    bind_addr: &str,
    local_identity: &IdentityKeyPair,
    timeout_secs: u64,
    mode: TransportMode,
    profile: HandshakeProfile,
) -> Result<HandshakeState> {
    match mode {
        TransportMode::Tcp => {
            tcp_handshake_server_with_profile(bind_addr, local_identity, timeout_secs, profile)
        }
        TransportMode::Quic => Ok(quic_handshake_server_with_profile(
            bind_addr,
            local_identity,
            timeout_secs,
            profile,
        )?
        .2),
        TransportMode::OfflineMesh | TransportMode::DataMule => Err(ShphError::InvalidArgument(
            "offline/data-mule require direct config-based APIs".into(),
        )),
    }
}

pub fn offline_mesh_connect_and_handshake(
    cfg: &OfflineMeshConfig,
    local_identity: &IdentityKeyPair,
    timeout_secs: u64,
) -> Result<HandshakeState> {
    offline_mesh_connect_and_handshake_with_profile(
        cfg,
        local_identity,
        timeout_secs,
        HandshakeProfile::SecureDefault,
    )
}

pub fn offline_mesh_connect_and_handshake_with_profile(
    cfg: &OfflineMeshConfig,
    local_identity: &IdentityKeyPair,
    timeout_secs: u64,
    profile: HandshakeProfile,
) -> Result<HandshakeState> {
    let material = build_hello_with_profile(local_identity, profile)?;
    let mut writer = OfflineMeshWriteState::new(cfg, &cfg.node_id, &cfg.peer_id);
    let mut reader = OfflineMeshReadState::new(cfg, &cfg.node_id, &cfg.peer_id);
    let timeout = Duration::from_secs(timeout_secs.max(1));

    let local_hello =
        serde_json::to_vec(&material.local_hello).map_err(ShphError::Serialization)?;
    writer.send_payload(&local_hello)?;

    let peer_payload = reader.receive_payload(timeout)?;
    let peer_hello = serde_json::from_slice::<Hello>(&peer_payload)
        .map_err(|e| ShphError::Protocol(format!("invalid peer hello: {e}")))?;

    let mut material = material;
    if profile.uses_pqc() {
        let ct = finalize_initiator_pq(&mut material, &peer_hello)?;
        writer.send_payload(&ct)?;
    }
    verify_and_derive(local_identity, &material, &peer_hello, true)
}

pub fn offline_mesh_accept_and_handshake(
    cfg: &OfflineMeshConfig,
    local_identity: &IdentityKeyPair,
    timeout_secs: u64,
) -> Result<HandshakeState> {
    offline_mesh_accept_and_handshake_with_profile(
        cfg,
        local_identity,
        timeout_secs,
        HandshakeProfile::SecureDefault,
    )
}

pub fn offline_mesh_accept_and_handshake_with_profile(
    cfg: &OfflineMeshConfig,
    local_identity: &IdentityKeyPair,
    timeout_secs: u64,
    profile: HandshakeProfile,
) -> Result<HandshakeState> {
    let material = build_hello_with_profile(local_identity, profile)?;
    let mut writer = OfflineMeshWriteState::new(cfg, &cfg.node_id, &cfg.peer_id);
    let mut reader = OfflineMeshReadState::new(cfg, &cfg.node_id, &cfg.peer_id);
    let timeout = Duration::from_secs(timeout_secs.max(1));

    let peer_payload = reader.receive_payload(timeout)?;
    let peer_hello = serde_json::from_slice::<Hello>(&peer_payload)
        .map_err(|e| ShphError::Protocol(format!("invalid peer hello: {e}")))?;
    let local_hello =
        serde_json::to_vec(&material.local_hello).map_err(ShphError::Serialization)?;
    writer.send_payload(&local_hello)?;
    let mut material = material;
    if profile.uses_pqc() {
        let ct_payload = reader.receive_payload(timeout)?;
        absorb_responder_pq(&mut material, &ct_payload)?;
    }
    verify_and_derive(local_identity, &material, &peer_hello, false)
}

pub fn offline_mesh_connect_secure_session(
    cfg: &OfflineMeshConfig,
    local_identity: &IdentityKeyPair,
    timeout_secs: u64,
) -> Result<(SecureSession, HandshakeState)> {
    offline_mesh_connect_secure_session_with_profile(
        cfg,
        local_identity,
        timeout_secs,
        HandshakeProfile::SecureDefault,
    )
}

pub fn offline_mesh_connect_secure_session_with_profile(
    cfg: &OfflineMeshConfig,
    local_identity: &IdentityKeyPair,
    timeout_secs: u64,
    profile: HandshakeProfile,
) -> Result<(SecureSession, HandshakeState)> {
    let material = build_hello_with_profile(local_identity, profile)?;
    let mut writer = OfflineMeshWriteState::new(cfg, &cfg.node_id, &cfg.peer_id);
    let mut reader = OfflineMeshReadState::new(cfg, &cfg.node_id, &cfg.peer_id);
    let timeout = Duration::from_secs(timeout_secs.max(1));

    writer.send_payload(
        &serde_json::to_vec(&material.local_hello).map_err(ShphError::Serialization)?,
    )?;
    let peer_payload = reader.receive_payload(timeout)?;
    let peer_hello = serde_json::from_slice::<Hello>(&peer_payload)
        .map_err(|e| ShphError::Protocol(format!("invalid peer hello: {e}")))?;

    let mut material = material;
    if profile.uses_pqc() {
        let ct = finalize_initiator_pq(&mut material, &peer_hello)?;
        writer.send_payload(&ct)?;
    }
    let state = verify_and_derive(local_identity, &material, &peer_hello, true)?;
    let session = SecureSession {
        inner: SecureSessionInner::OfflineMesh(OfflineMeshSession::new(
            OfflineMeshWriteState::new(cfg, &cfg.node_id, &cfg.peer_id),
            OfflineMeshReadState::new(cfg, &cfg.node_id, &cfg.peer_id),
            state.session_keys.send_key,
            state.session_keys.recv_key,
        )),
    };
    Ok((session, state))
}

pub fn offline_mesh_accept_secure_session(
    cfg: &OfflineMeshConfig,
    local_identity: &IdentityKeyPair,
    timeout_secs: u64,
) -> Result<(SecureSession, HandshakeState)> {
    offline_mesh_accept_secure_session_with_profile(
        cfg,
        local_identity,
        timeout_secs,
        HandshakeProfile::SecureDefault,
    )
}

pub fn offline_mesh_accept_secure_session_with_profile(
    cfg: &OfflineMeshConfig,
    local_identity: &IdentityKeyPair,
    timeout_secs: u64,
    profile: HandshakeProfile,
) -> Result<(SecureSession, HandshakeState)> {
    let material = build_hello_with_profile(local_identity, profile)?;
    let mut writer = OfflineMeshWriteState::new(cfg, &cfg.node_id, &cfg.peer_id);
    let mut reader = OfflineMeshReadState::new(cfg, &cfg.node_id, &cfg.peer_id);
    let timeout = Duration::from_secs(timeout_secs.max(1));

    let peer_payload = reader.receive_payload(timeout)?;
    let peer_hello = serde_json::from_slice::<Hello>(&peer_payload)
        .map_err(|e| ShphError::Protocol(format!("invalid peer hello: {e}")))?;
    writer.send_payload(
        &serde_json::to_vec(&material.local_hello).map_err(ShphError::Serialization)?,
    )?;
    let mut material = material;
    if profile.uses_pqc() {
        let ct_payload = reader.receive_payload(timeout)?;
        absorb_responder_pq(&mut material, &ct_payload)?;
    }

    let state = verify_and_derive(local_identity, &material, &peer_hello, false)?;
    let session = SecureSession {
        inner: SecureSessionInner::OfflineMesh(OfflineMeshSession::new(
            OfflineMeshWriteState::new(cfg, &cfg.node_id, &cfg.peer_id),
            OfflineMeshReadState::new(cfg, &cfg.node_id, &cfg.peer_id),
            state.session_keys.send_key,
            state.session_keys.recv_key,
        )),
    };
    Ok((session, state))
}

pub fn data_mule_connect_and_handshake(
    cfg: &DataMuleConfig,
    local_identity: &IdentityKeyPair,
    peer_node: &str,
    timeout_secs: u64,
) -> Result<HandshakeState> {
    data_mule_connect_and_handshake_with_profile(
        cfg,
        local_identity,
        peer_node,
        timeout_secs,
        HandshakeProfile::SecureDefault,
    )
}

pub fn data_mule_connect_and_handshake_with_profile(
    cfg: &DataMuleConfig,
    local_identity: &IdentityKeyPair,
    peer_node: &str,
    timeout_secs: u64,
    profile: HandshakeProfile,
) -> Result<HandshakeState> {
    let material = build_hello_with_profile(local_identity, profile)?;
    let mut writer = DataMuleWriteState::new(cfg, &local_identity.public_key_b64(), peer_node);
    let mut reader = DataMuleReadState::new(cfg, &local_identity.public_key_b64(), Some(peer_node));
    let timeout = Duration::from_secs(timeout_secs.max(1));

    writer.send_payload(
        &serde_json::to_vec(&material.local_hello).map_err(ShphError::Serialization)?,
    )?;
    let peer_payload = reader.receive_payload(timeout)?;
    let peer_hello = serde_json::from_slice::<Hello>(&peer_payload)
        .map_err(|e| ShphError::Protocol(format!("invalid peer hello: {e}")))?;
    let mut material = material;
    if profile.uses_pqc() {
        let ct = finalize_initiator_pq(&mut material, &peer_hello)?;
        writer.send_payload(&ct)?;
    }
    verify_and_derive(local_identity, &material, &peer_hello, true)
}

pub fn data_mule_accept_and_handshake(
    cfg: &DataMuleConfig,
    local_identity: &IdentityKeyPair,
    timeout_secs: u64,
) -> Result<HandshakeState> {
    data_mule_accept_and_handshake_with_profile(
        cfg,
        local_identity,
        timeout_secs,
        HandshakeProfile::SecureDefault,
    )
}

pub fn data_mule_accept_and_handshake_with_profile(
    cfg: &DataMuleConfig,
    local_identity: &IdentityKeyPair,
    timeout_secs: u64,
    profile: HandshakeProfile,
) -> Result<HandshakeState> {
    let material = build_hello_with_profile(local_identity, profile)?;
    let local_node = local_identity.public_key_b64();
    let mut reader = DataMuleReadState::new(cfg, &local_identity.public_key_b64(), None);
    let timeout = Duration::from_secs(timeout_secs.max(1));

    let peer_envelope = reader.receive_envelope(timeout)?;
    let peer_hello = match serde_json::from_slice::<Hello>(&peer_envelope.payload) {
        Ok(hello) => hello,
        Err(err) => {
            reader.commit_envelope(&peer_envelope)?;
            return Err(ShphError::Protocol(format!("invalid peer hello: {err}")));
        }
    };
    reader.commit_envelope(&peer_envelope)?;
    let peer_node = peer_envelope.envelope.from_node;
    let mut writer = DataMuleWriteState::new(cfg, &local_node, &peer_node);
    writer.send_payload(
        &serde_json::to_vec(&material.local_hello).map_err(ShphError::Serialization)?,
    )?;
    let mut material = material;
    if profile.uses_pqc() {
        let ct_payload = reader.receive_payload(timeout)?;
        absorb_responder_pq(&mut material, &ct_payload)?;
    }
    verify_and_derive(local_identity, &material, &peer_hello, false)
}

pub fn data_mule_connect_secure_session(
    cfg: &DataMuleConfig,
    local_identity: &IdentityKeyPair,
    peer_node: &str,
    timeout_secs: u64,
) -> Result<(SecureSession, HandshakeState)> {
    data_mule_connect_secure_session_with_profile(
        cfg,
        local_identity,
        peer_node,
        timeout_secs,
        HandshakeProfile::SecureDefault,
    )
}

pub fn data_mule_connect_secure_session_with_profile(
    cfg: &DataMuleConfig,
    local_identity: &IdentityKeyPair,
    peer_node: &str,
    timeout_secs: u64,
    profile: HandshakeProfile,
) -> Result<(SecureSession, HandshakeState)> {
    let material = build_hello_with_profile(local_identity, profile)?;
    let local_node = local_identity.public_key_b64();
    let mut writer = DataMuleWriteState::new(cfg, &local_node, peer_node);
    let mut reader = DataMuleReadState::new(cfg, &local_node, Some(peer_node));
    let timeout = Duration::from_secs(timeout_secs.max(1));

    writer.send_payload(
        &serde_json::to_vec(&material.local_hello).map_err(ShphError::Serialization)?,
    )?;
    let peer_payload = reader.receive_payload(timeout)?;
    let peer_hello = serde_json::from_slice::<Hello>(&peer_payload)
        .map_err(|e| ShphError::Protocol(format!("invalid peer hello: {e}")))?;
    let mut material = material;
    if profile.uses_pqc() {
        let ct = finalize_initiator_pq(&mut material, &peer_hello)?;
        writer.send_payload(&ct)?;
    }
    let state = verify_and_derive(local_identity, &material, &peer_hello, true)?;

    let session = SecureSession {
        inner: SecureSessionInner::DataMule(DataMuleSession::new(
            DataMuleWriteState::new(cfg, &local_node, peer_node),
            DataMuleReadState::new(cfg, &local_node, Some(peer_node)),
            state.session_keys.send_key,
            state.session_keys.recv_key,
        )),
    };

    Ok((session, state))
}

pub fn data_mule_accept_secure_session(
    cfg: &DataMuleConfig,
    local_identity: &IdentityKeyPair,
    timeout_secs: u64,
) -> Result<(SecureSession, HandshakeState)> {
    data_mule_accept_secure_session_with_profile(
        cfg,
        local_identity,
        timeout_secs,
        HandshakeProfile::SecureDefault,
    )
}

pub fn data_mule_accept_secure_session_with_profile(
    cfg: &DataMuleConfig,
    local_identity: &IdentityKeyPair,
    timeout_secs: u64,
    profile: HandshakeProfile,
) -> Result<(SecureSession, HandshakeState)> {
    let material = build_hello_with_profile(local_identity, profile)?;
    let local_node = local_identity.public_key_b64();
    let mut reader = DataMuleReadState::new(cfg, &local_node, None);
    let timeout = Duration::from_secs(timeout_secs.max(1));

    let envelope = reader.receive_envelope(timeout)?;
    let peer_hello = match serde_json::from_slice::<Hello>(&envelope.payload) {
        Ok(hello) => hello,
        Err(err) => {
            reader.commit_envelope(&envelope)?;
            return Err(ShphError::Protocol(format!("invalid peer hello: {err}")));
        }
    };
    reader.commit_envelope(&envelope)?;
    let peer_node = envelope.envelope.from_node;
    let mut writer = DataMuleWriteState::new(cfg, &local_node, &peer_node);
    writer.send_payload(
        &serde_json::to_vec(&material.local_hello).map_err(ShphError::Serialization)?,
    )?;
    let mut material = material;
    if profile.uses_pqc() {
        let ct_payload = reader.receive_payload(timeout)?;
        absorb_responder_pq(&mut material, &ct_payload)?;
    }

    let state = verify_and_derive(local_identity, &material, &peer_hello, false)?;

    let session = SecureSession {
        inner: SecureSessionInner::DataMule(DataMuleSession::new(
            DataMuleWriteState::new(cfg, &local_node, &peer_node),
            DataMuleReadState::new(cfg, &local_node, Some(&peer_node)),
            state.session_keys.send_key,
            state.session_keys.recv_key,
        )),
    };
    Ok((session, state))
}

pub fn connect_secure_session(
    peer: &str,
    local_identity: &IdentityKeyPair,
    timeout_secs: u64,
    mode: TransportMode,
) -> Result<(SecureSession, HandshakeState)> {
    connect_secure_session_with_profile(
        peer,
        local_identity,
        timeout_secs,
        mode,
        HandshakeProfile::SecureDefault,
    )
}

pub fn connect_secure_session_with_profile(
    peer: &str,
    local_identity: &IdentityKeyPair,
    timeout_secs: u64,
    mode: TransportMode,
    profile: HandshakeProfile,
) -> Result<(SecureSession, HandshakeState)> {
    match mode {
        TransportMode::Tcp => {
            let (stream, state) = tcp_connect_and_handshake_with_profile(
                peer,
                local_identity,
                timeout_secs,
                profile,
            )?;
            Ok((
                SecureSession {
                    inner: SecureSessionInner::Tcp(SecureTcpSession::new(
                        stream,
                        state.session_keys.send_key,
                        state.session_keys.recv_key,
                    )),
                },
                state,
            ))
        }
        TransportMode::Quic => {
            let (socket, peer_addr, state) =
                quic_handshake_client_with_profile(peer, local_identity, timeout_secs, profile)?;
            Ok((
                SecureSession {
                    inner: SecureSessionInner::Quic(ExperimentalQuicSession::new(
                        socket,
                        peer_addr,
                        state.session_keys.send_key,
                        state.session_keys.recv_key,
                    )),
                },
                state,
            ))
        }
        TransportMode::OfflineMesh | TransportMode::DataMule => Err(ShphError::InvalidArgument(
            "offline/data-mule require direct config-based APIs".into(),
        )),
    }
}

pub fn connect_secure_session_lab(
    peer: &str,
    local_identity: &IdentityKeyPair,
    timeout_secs: u64,
    mode: TransportMode,
    lab: QuicLabConfig,
) -> Result<(SecureSession, HandshakeState)> {
    connect_secure_session_lab_with_profile(
        peer,
        local_identity,
        timeout_secs,
        mode,
        lab,
        HandshakeProfile::SecureDefault,
    )
}

pub fn connect_secure_session_lab_with_profile(
    peer: &str,
    local_identity: &IdentityKeyPair,
    timeout_secs: u64,
    mode: TransportMode,
    lab: QuicLabConfig,
    profile: HandshakeProfile,
) -> Result<(SecureSession, HandshakeState)> {
    let (session, state) =
        connect_secure_session_with_profile(peer, local_identity, timeout_secs, mode, profile)?;
    if let (TransportMode::Quic, Some(profile)) = (mode, lab.shroud_profile) {
        return Ok((session.with_quic_profile(profile)?, state));
    }
    Ok((session, state))
}

pub fn accept_secure_session(
    bind_addr: &str,
    local_identity: &IdentityKeyPair,
    timeout_secs: u64,
    mode: TransportMode,
) -> Result<(SecureSession, HandshakeState)> {
    accept_secure_session_with_profile(
        bind_addr,
        local_identity,
        timeout_secs,
        mode,
        HandshakeProfile::SecureDefault,
    )
}

pub fn accept_secure_session_with_profile(
    bind_addr: &str,
    local_identity: &IdentityKeyPair,
    timeout_secs: u64,
    mode: TransportMode,
    profile: HandshakeProfile,
) -> Result<(SecureSession, HandshakeState)> {
    match mode {
        TransportMode::Tcp => {
            let (stream, state) = tcp_accept_and_handshake_with_profile(
                bind_addr,
                local_identity,
                timeout_secs,
                profile,
            )?;
            Ok((
                SecureSession {
                    inner: SecureSessionInner::Tcp(SecureTcpSession::new(
                        stream,
                        state.session_keys.send_key,
                        state.session_keys.recv_key,
                    )),
                },
                state,
            ))
        }
        TransportMode::Quic => {
            let (socket, peer_addr, state) = quic_handshake_server_with_profile(
                bind_addr,
                local_identity,
                timeout_secs,
                profile,
            )?;
            Ok((
                SecureSession {
                    inner: SecureSessionInner::Quic(ExperimentalQuicSession::new(
                        socket,
                        peer_addr,
                        state.session_keys.send_key,
                        state.session_keys.recv_key,
                    )),
                },
                state,
            ))
        }
        TransportMode::OfflineMesh | TransportMode::DataMule => Err(ShphError::InvalidArgument(
            "offline/data-mule require direct config-based APIs".into(),
        )),
    }
}

pub fn accept_secure_session_lab(
    bind_addr: &str,
    local_identity: &IdentityKeyPair,
    timeout_secs: u64,
    mode: TransportMode,
    lab: QuicLabConfig,
) -> Result<(SecureSession, HandshakeState)> {
    accept_secure_session_lab_with_profile(
        bind_addr,
        local_identity,
        timeout_secs,
        mode,
        lab,
        HandshakeProfile::SecureDefault,
    )
}

pub fn accept_secure_session_lab_with_profile(
    bind_addr: &str,
    local_identity: &IdentityKeyPair,
    timeout_secs: u64,
    mode: TransportMode,
    lab: QuicLabConfig,
    profile: HandshakeProfile,
) -> Result<(SecureSession, HandshakeState)> {
    let (session, state) =
        accept_secure_session_with_profile(bind_addr, local_identity, timeout_secs, mode, profile)?;
    if let (TransportMode::Quic, Some(profile)) = (mode, lab.shroud_profile) {
        return Ok((session.with_quic_profile(profile)?, state));
    }
    Ok((session, state))
}

impl SecureSession {
    fn with_quic_profile(mut self, profile: ShroudProfile) -> Result<Self> {
        if let SecureSessionInner::Quic(session) = &mut self.inner {
            session.shroud_profile = Some(profile);
        }
        Ok(self)
    }
    pub fn send_frame(&mut self, payload: &[u8]) -> Result<()> {
        match &mut self.inner {
            SecureSessionInner::Tcp(session) => session.send_frame(payload),
            SecureSessionInner::Quic(session) => session.send_frame(payload),
            SecureSessionInner::OfflineMesh(session) => session.send_frame(payload),
            SecureSessionInner::DataMule(session) => session.send_frame(payload),
        }
    }

    pub fn recv_frame(&mut self) -> Result<Vec<u8>> {
        match &mut self.inner {
            SecureSessionInner::Tcp(session) => session.recv_frame(),
            SecureSessionInner::Quic(session) => session.recv_frame(),
            SecureSessionInner::OfflineMesh(session) => session.recv_frame(),
            SecureSessionInner::DataMule(session) => session.recv_frame(),
        }
    }

    pub fn into_split(self) -> Result<(SecureSender, SecureReceiver)> {
        match self.inner {
            SecureSessionInner::Tcp(session) => {
                let (sender, receiver) = session.into_split()?;
                Ok((
                    SecureSender {
                        inner: SecureSenderInner::Tcp(sender),
                    },
                    SecureReceiver {
                        inner: SecureReceiverInner::Tcp(receiver),
                    },
                ))
            }
            SecureSessionInner::Quic(session) => {
                let (sender, receiver) = session.into_split()?;
                Ok((
                    SecureSender {
                        inner: SecureSenderInner::Quic(sender),
                    },
                    SecureReceiver {
                        inner: SecureReceiverInner::Quic(receiver),
                    },
                ))
            }
            SecureSessionInner::OfflineMesh(session) => {
                let (sender, receiver) = session.into_split()?;
                Ok((
                    SecureSender {
                        inner: SecureSenderInner::OfflineMesh(sender),
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
                        inner: SecureSenderInner::DataMule(sender),
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
            SecureSenderInner::OfflineMesh(sender) => sender.send_frame(payload),
            SecureSenderInner::DataMule(sender) => sender.send_frame(payload),
        }
    }
}

impl SecureReceiver {
    pub fn recv_frame(&mut self) -> Result<Vec<u8>> {
        match &mut self.inner {
            SecureReceiverInner::Tcp(receiver) => receiver.recv_frame(),
            SecureReceiverInner::Quic(receiver) => receiver.recv_frame(),
            SecureReceiverInner::OfflineMesh(receiver) => receiver.recv_frame(),
            SecureReceiverInner::DataMule(receiver) => receiver.recv_frame(),
        }
    }
}

// Backward-compatible TCP API
pub fn tcp_handshake_client(
    peer: &str,
    local_identity: &IdentityKeyPair,
    timeout_secs: u64,
) -> Result<HandshakeState> {
    tcp_handshake_client_with_profile(
        peer,
        local_identity,
        timeout_secs,
        HandshakeProfile::SecureDefault,
    )
}

pub fn tcp_handshake_client_with_profile(
    peer: &str,
    local_identity: &IdentityKeyPair,
    timeout_secs: u64,
    profile: HandshakeProfile,
) -> Result<HandshakeState> {
    let mut stream = connect_tcp_with_timeout(peer, timeout_secs)?;
    apply_timeout(&stream, timeout_secs)?;
    let mut material = build_hello_with_profile(local_identity, profile)?;
    write_tcp_hello(&mut stream, &material.local_hello)?;
    let peer_hello = read_tcp_hello(&mut stream)?;
    if profile.uses_pqc() {
        let ct = finalize_initiator_pq(&mut material, &peer_hello)?;
        write_tcp_pq_ct(&mut stream, &ct)?;
    }
    verify_and_derive(local_identity, &material, &peer_hello, true)
}

pub fn tcp_handshake_server(
    bind_addr: &str,
    local_identity: &IdentityKeyPair,
    timeout_secs: u64,
) -> Result<HandshakeState> {
    tcp_handshake_server_with_profile(
        bind_addr,
        local_identity,
        timeout_secs,
        HandshakeProfile::SecureDefault,
    )
}

pub fn tcp_handshake_server_with_profile(
    bind_addr: &str,
    local_identity: &IdentityKeyPair,
    timeout_secs: u64,
    profile: HandshakeProfile,
) -> Result<HandshakeState> {
    tcp_accept_and_handshake_with_profile(bind_addr, local_identity, timeout_secs, profile)
        .map(|(_, state)| state)
}

pub fn tcp_connect_and_handshake(
    peer: &str,
    local_identity: &IdentityKeyPair,
    timeout_secs: u64,
) -> Result<(TcpStream, HandshakeState)> {
    tcp_connect_and_handshake_with_profile(
        peer,
        local_identity,
        timeout_secs,
        HandshakeProfile::SecureDefault,
    )
}

pub fn tcp_connect_and_handshake_with_profile(
    peer: &str,
    local_identity: &IdentityKeyPair,
    timeout_secs: u64,
    profile: HandshakeProfile,
) -> Result<(TcpStream, HandshakeState)> {
    let mut stream = connect_tcp_with_timeout(peer, timeout_secs)?;
    apply_timeout(&stream, timeout_secs)?;
    let mut material = build_hello_with_profile(local_identity, profile)?;
    write_tcp_hello(&mut stream, &material.local_hello)?;
    let peer_hello = read_tcp_hello(&mut stream)?;
    if profile.uses_pqc() {
        let ct = finalize_initiator_pq(&mut material, &peer_hello)?;
        write_tcp_pq_ct(&mut stream, &ct)?;
    }
    let state = verify_and_derive(local_identity, &material, &peer_hello, true)?;
    Ok((stream, state))
}

/// Per-peer-address connection-rate limiter for the unauthenticated entry path.
///
/// Tracks recent accepted-connect timestamps per peer IP. A peer that has
/// already opened `MAX_CONNECTS_PER_PEER_PER_WINDOW` connections within the
/// rolling `PEER_RATE_WINDOW` is rejected (its stale entries are pruned first)
/// before any handshake work is performed. This complements the per-loop
/// `TCP_HANDSHAKE_ATTEMPTS` bound, which only governs a single accept loop.
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
            return Err(ShphError::ResourceExhausted(
                "peer rate-limit table is full".into(),
            ));
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
}

pub fn tcp_accept_and_handshake(
    bind_addr: &str,
    local_identity: &IdentityKeyPair,
    timeout_secs: u64,
) -> Result<(TcpStream, HandshakeState)> {
    tcp_accept_and_handshake_with_profile(
        bind_addr,
        local_identity,
        timeout_secs,
        HandshakeProfile::SecureDefault,
    )
}

pub fn tcp_accept_and_handshake_with_profile(
    bind_addr: &str,
    local_identity: &IdentityKeyPair,
    timeout_secs: u64,
    profile: HandshakeProfile,
) -> Result<(TcpStream, HandshakeState)> {
    let listener = TcpListener::bind(bind_addr).map_err(|e| ShphError::Transport(e.to_string()))?;
    listener.set_nonblocking(true).map_err(ShphError::Io)?;
    // Bounded handshake loop on the unauthenticated entry path: tolerate
    // malformed/early-closing peers up to TCP_HANDSHAKE_ATTEMPTS, then fail
    // closed. Genuine listener failures and timeouts propagate immediately so
    // an attacker cannot exhaust the attempt budget with a slow/blocked socket.
    let mut last_err: Option<ShphError> = None;
    let mut rate_limiter = PeerRateLimiter::new();
    let deadline = Instant::now()
        + Duration::from_secs(timeout_secs.max(1).min(TCP_HANDSHAKE_DEADLINE.as_secs()));
    for _ in 0..TCP_HANDSHAKE_ATTEMPTS {
        if Instant::now() >= deadline {
            break;
        }
        let (mut stream, peer_addr) = loop {
            match listener.accept() {
                Ok(accepted) => break accepted,
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        break Err(ShphError::Timeout)?;
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                Err(err) => return Err(ShphError::Transport(err.to_string())),
            }
        };
        stream.set_nonblocking(false).map_err(ShphError::Io)?;

        // Per-source rate limit BEFORE any handshake work: a single host that
        // is hammering the entry path is dropped immediately, so it cannot
        // exhaust the attempt budget or burn CPU on hello parsing across
        // repeated sessions.
        if let Err(err) = rate_limiter.check_and_record(peer_addr) {
            last_err = Some(err);
            drop(stream);
            continue;
        }

        let remaining = deadline.saturating_duration_since(Instant::now());
        apply_timeout_duration(
            &stream,
            remaining.min(Duration::from_secs(timeout_secs.max(1))),
        )?;

        match read_tcp_hello(&mut stream) {
            Ok(peer_hello) => {
                let mut material = build_hello_with_profile(local_identity, profile)?;
                write_tcp_hello(&mut stream, &material.local_hello)?;
                if profile.uses_pqc() {
                    let ct = match read_tcp_pq_ct(&mut stream) {
                        Ok(ct) => ct,
                        Err(ShphError::ConnectionClosed) | Err(ShphError::Protocol(_)) => {
                            last_err = Some(ShphError::ConnectionClosed);
                            continue;
                        }
                        Err(err) => return Err(err),
                    };
                    if absorb_responder_pq(&mut material, &ct).is_err() {
                        last_err = Some(ShphError::Handshake("pq decapsulation failed".into()));
                        continue;
                    }
                }
                match verify_and_derive(local_identity, &material, &peer_hello, false) {
                    Ok(state) => return Ok((stream, state)),
                    Err(err) => {
                        // Signature/protocol failure: hostile or wrong-key peer.
                        // Drop and keep listening for a legitimate one.
                        last_err = Some(err);
                        let _ = peer_addr;
                        continue;
                    }
                }
            }
            Err(ShphError::ConnectionClosed) | Err(ShphError::Protocol(_)) => {
                // Unauthenticated peer sent a malformed/truncated hello or
                // closed early; drop and retry without consuming the budget on
                // a single bad actor beyond the loop bound.
                last_err = Some(ShphError::ConnectionClosed);
                continue;
            }
            Err(err) => return Err(err),
        }
    }
    Err(last_err.unwrap_or(ShphError::Transport(
        "handshake attempt budget exhausted".into(),
    )))
}

fn write_tcp_hello(stream: &mut TcpStream, hello: &Hello) -> Result<()> {
    let payload = serde_json::to_string(hello).map_err(|e| ShphError::Protocol(e.to_string()))?;
    write_tcp_all_or_closed(stream, payload.as_bytes())?;
    write_tcp_all_or_closed(stream, b"\n")?;
    stream.flush().map_err(map_io_error)?;
    Ok(())
}

fn read_tcp_hello(stream: &mut TcpStream) -> Result<Hello> {
    // Read the newline-terminated hello in chunks into a single bounded buffer
    // rather than one syscall per byte. The buffer is capped at
    // `MAX_HELLO_BYTES` (+1 to detect overshoot), so a slowloris-style peer
    // cannot hold the connection open with dribbled single bytes beyond the
    // cap, and the cost per peer is O(1) reads instead of O(len) reads.
    let mut buf = Vec::with_capacity(512);
    let mut chunk = [0u8; 1024];
    loop {
        let read = stream.read(&mut chunk).map_err(map_io_error)?;
        if read == 0 {
            return if buf.is_empty() {
                Err(ShphError::ConnectionClosed)
            } else {
                Err(ShphError::Protocol("truncated hello".into()))
            };
        }
        // Look for the newline within this chunk and append up to (and
        // including) it; anything after the newline is ignored (the hello is a
        // single line).
        let nl = chunk[..read].iter().position(|&b| b == b'\n');
        let take = match nl {
            Some(i) => &chunk[..=i],
            None => &chunk[..read],
        };
        // Enforce the cap including any data already buffered.
        if buf.len() + take.len() > MAX_HELLO_BYTES + 1 {
            return Err(ShphError::Protocol("hello exceeds size limit".into()));
        }
        buf.extend_from_slice(take);
        if nl.is_some() {
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
    if buf.len() > MAX_HELLO_BYTES {
        return Err(ShphError::Protocol("hello exceeds size limit".into()));
    }

    let hello_line =
        std::str::from_utf8(&buf).map_err(|_| ShphError::Protocol("hello not utf8".into()))?;
    let hello = serde_json::from_str::<Hello>(hello_line)
        .map_err(|e| ShphError::Protocol(e.to_string()))?;
    Ok(hello)
}

/// Write the initiator's ML-KEM ciphertext to the stream as a length-prefixed,
/// size-bounded frame so the responder can read exactly the expected bytes.
fn write_tcp_pq_ct(stream: &mut TcpStream, ct: &[u8]) -> Result<()> {
    if ct.len() != ML_KEM_768_CIPHERTEXT_BYTES {
        return Err(ShphError::Protocol(format!(
            "pq ciphertext size mismatch: expected {}, got {}",
            ML_KEM_768_CIPHERTEXT_BYTES,
            ct.len()
        )));
    }
    write_tcp_all_or_closed(stream, &(ct.len() as u32).to_be_bytes())?;
    write_tcp_all_or_closed(stream, ct)?;
    stream.flush().map_err(map_io_error)?;
    Ok(())
}

/// Read the initiator's ML-KEM ciphertext frame. The 4-byte length prefix must
/// announce exactly `ML_KEM_768_CIPHERTEXT_BYTES`; anything else is rejected
/// before any allocation, and the read is capped so a malicious peer cannot
/// stream an unbounded payload into the handshake.
fn read_tcp_pq_ct(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    read_exact_or_closed(stream, &mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len != ML_KEM_768_CIPHERTEXT_BYTES {
        return Err(ShphError::Protocol(format!(
            "pq ciphertext length mismatch: expected {}, got {}",
            ML_KEM_768_CIPHERTEXT_BYTES, len
        )));
    }
    let mut ct = vec![0u8; len];
    read_exact_or_closed(stream, &mut ct)?;
    Ok(ct)
}

/// Read exactly `buf.len()` bytes or fail closed on early EOF. Used for the
/// fixed-size PQ ciphertext frame where a short read means a truncated/attacking
/// peer.
fn read_exact_or_closed(stream: &mut TcpStream, buf: &mut [u8]) -> Result<()> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = stream.read(&mut buf[filled..]).map_err(map_io_error)?;
        if n == 0 {
            return Err(ShphError::ConnectionClosed);
        }
        filled += n;
    }
    Ok(())
}

fn apply_timeout(stream: &TcpStream, timeout_secs: u64) -> Result<()> {
    apply_timeout_duration(stream, Duration::from_secs(timeout_secs.max(1)))
}

fn apply_timeout_duration(stream: &TcpStream, timeout: Duration) -> Result<()> {
    let timeout = timeout.max(Duration::from_millis(1));
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    Ok(())
}

pub fn tcp_connect_secure_session(
    peer: &str,
    local_identity: &IdentityKeyPair,
    timeout_secs: u64,
) -> Result<(SecureTcpSession, HandshakeState)> {
    let (stream, state) = tcp_connect_and_handshake(peer, local_identity, timeout_secs)?;
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
    timeout_secs: u64,
) -> Result<(SecureTcpSession, HandshakeState)> {
    let (stream, state) = tcp_accept_and_handshake(bind_addr, local_identity, timeout_secs)?;
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
}

impl SecureTcpSession {
    pub fn new(stream: TcpStream, send_key: [u8; 32], recv_key: [u8; 32]) -> Self {
        Self {
            stream,
            send_cipher: SendCipher::new(send_key),
            recv_cipher: ReceiveCipher::new(recv_key),
        }
    }

    pub fn send_frame(&mut self, payload: &[u8]) -> Result<()> {
        write_encrypted_tcp_frame(&mut self.stream, &mut self.send_cipher, payload)
    }

    pub fn recv_frame(&mut self) -> Result<Vec<u8>> {
        read_encrypted_tcp_frame(&mut self.stream, &mut self.recv_cipher)
    }

    pub fn stream_mut(&mut self) -> &mut TcpStream {
        &mut self.stream
    }

    pub fn into_split(self) -> Result<(SecureTcpSender, SecureTcpReceiver)> {
        let recv_stream = self.stream.try_clone().map_err(map_io_error)?;
        let sender = SecureTcpSender {
            stream: self.stream,
            send_cipher: self.send_cipher,
        };
        let receiver = SecureTcpReceiver {
            stream: recv_stream,
            recv_cipher: self.recv_cipher,
        };
        Ok((sender, receiver))
    }
}

pub struct SecureTcpSender {
    stream: TcpStream,
    send_cipher: SendCipher,
}

impl SecureTcpSender {
    pub fn send_frame(&mut self, payload: &[u8]) -> Result<()> {
        write_encrypted_tcp_frame(&mut self.stream, &mut self.send_cipher, payload)
    }
}

pub struct SecureTcpReceiver {
    stream: TcpStream,
    recv_cipher: ReceiveCipher,
}

impl SecureTcpReceiver {
    pub fn recv_frame(&mut self) -> Result<Vec<u8>> {
        read_encrypted_tcp_frame(&mut self.stream, &mut self.recv_cipher)
    }
}

pub fn tcp_secure_send(stream: &mut TcpStream, send_key: [u8; 32], payload: &[u8]) -> Result<()> {
    let mut cipher = SendCipher::new(send_key);
    write_encrypted_tcp_frame(stream, &mut cipher, payload)
}

pub fn tcp_secure_receive(stream: &mut TcpStream, recv_key: [u8; 32]) -> Result<Vec<u8>> {
    let mut cipher = ReceiveCipher::new(recv_key);
    read_encrypted_tcp_frame(stream, &mut cipher)
}

// Experimental QUIC-like shim.
pub fn quic_handshake_client(
    peer: &str,
    local_identity: &IdentityKeyPair,
    timeout_secs: u64,
) -> Result<(UdpSocket, SocketAddr, HandshakeState)> {
    quic_handshake_client_with_profile(
        peer,
        local_identity,
        timeout_secs,
        HandshakeProfile::SecureDefault,
    )
}

pub fn quic_handshake_client_with_profile(
    peer: &str,
    local_identity: &IdentityKeyPair,
    timeout_secs: u64,
    profile: HandshakeProfile,
) -> Result<(UdpSocket, SocketAddr, HandshakeState)> {
    let peer_addr = parse_socket_addr(peer)?;
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| ShphError::Transport(e.to_string()))?;
    let timeout_secs = bounded_quic_timeout_secs(timeout_secs);
    socket
        .set_read_timeout(Some(Duration::from_secs(timeout_secs)))
        .map_err(ShphError::Io)?;
    socket
        .set_write_timeout(Some(Duration::from_secs(timeout_secs)))
        .map_err(ShphError::Io)?;

    let material = build_hello_with_profile(local_identity, profile)?;
    let mut buf = vec![0u8; MAX_QUIC_HELLO_BYTES];
    let mut last_err: Option<ShphError> = None;
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);

    for _ in 0..QUIC_HANDSHAKE_ATTEMPTS {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        socket
            .set_read_timeout(Some(remaining))
            .map_err(ShphError::Io)?;
        let peer_hello =
            write_and_wait_quic_hello(&socket, peer_addr, &material.local_hello, &mut buf);
        match peer_hello {
            Ok((peer_hello, addr)) if addr == peer_addr => {
                let mut material = material;
                if profile.uses_pqc() {
                    let ct = finalize_initiator_pq(&mut material, &peer_hello)?;
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        return Err(ShphError::Timeout);
                    }
                    socket
                        .set_write_timeout(Some(remaining))
                        .map_err(ShphError::Io)?;
                    write_quic_pq_ct(&socket, peer_addr, &ct)?;
                }
                let state = verify_and_derive(local_identity, &material, &peer_hello, true)?;
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
    timeout_secs: u64,
) -> Result<(UdpSocket, SocketAddr, HandshakeState)> {
    quic_handshake_server_with_profile(
        bind_addr,
        local_identity,
        timeout_secs,
        HandshakeProfile::SecureDefault,
    )
}

pub fn quic_handshake_server_with_profile(
    bind_addr: &str,
    local_identity: &IdentityKeyPair,
    timeout_secs: u64,
    profile: HandshakeProfile,
) -> Result<(UdpSocket, SocketAddr, HandshakeState)> {
    let socket = UdpSocket::bind(bind_addr).map_err(|e| ShphError::Transport(e.to_string()))?;
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
    let mut invalid_handshake_datagrams = 0usize;
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
                        peer_hello = Some(hello);
                        break;
                    }
                    Err(_) => {
                        invalid_handshake_datagrams += 1;
                        if invalid_handshake_datagrams >= MAX_QUIC_HANDSHAKE_DATAGRAMS {
                            return Err(ShphError::Protocol(
                                "too many invalid QUIC handshake datagrams".into(),
                            ));
                        }
                    }
                }
            }
            Err(ShphError::Timeout) => continue,
            Err(ShphError::Protocol(_)) => {
                invalid_handshake_datagrams += 1;
                if invalid_handshake_datagrams >= MAX_QUIC_HANDSHAKE_DATAGRAMS {
                    return Err(ShphError::Protocol(
                        "too many invalid QUIC handshake datagrams".into(),
                    ));
                }
            }
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
    if profile.uses_pqc() {
        let ct = read_quic_pq_ct(&socket, peer_addr)?;
        absorb_responder_pq(&mut material, &ct)?;
    }
    let state = verify_and_derive(local_identity, &material, &peer_hello, false)?;
    Ok((socket, peer_addr, state))
}

pub fn quic_connect_and_handshake(
    peer: &str,
    local_identity: &IdentityKeyPair,
    timeout_secs: u64,
) -> Result<(UdpSocket, SocketAddr, HandshakeState)> {
    quic_handshake_client(peer, local_identity, timeout_secs)
}

pub fn quic_accept_and_handshake(
    bind_addr: &str,
    local_identity: &IdentityKeyPair,
    timeout_secs: u64,
) -> Result<(UdpSocket, SocketAddr, HandshakeState)> {
    quic_handshake_server(bind_addr, local_identity, timeout_secs)
}

fn write_and_wait_quic_hello(
    socket: &UdpSocket,
    peer_addr: SocketAddr,
    hello: &Hello,
    buf: &mut [u8],
) -> Result<(Hello, SocketAddr)> {
    let payload = serde_json::to_string(hello).map_err(|e| ShphError::Protocol(e.to_string()))?;
    if payload.len() + 1 > MAX_QUIC_HELLO_BYTES {
        return Err(ShphError::Protocol(
            "quic hello payload exceeds size limit".into(),
        ));
    }

    socket
        .send_to(payload.as_bytes(), peer_addr)
        .map_err(map_io_error)?;

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
    let payload = serde_json::to_string(hello).map_err(|e| ShphError::Protocol(e.to_string()))?;
    socket
        .send_to(payload.as_bytes(), peer_addr)
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
}

pub struct ExperimentalQuicSender {
    socket: UdpSocket,
    peer: SocketAddr,
    send_cipher: SendCipher,
    shroud_profile: Option<ShroudProfile>,
}

pub struct ExperimentalQuicReceiver {
    socket: UdpSocket,
    peer: SocketAddr,
    recv_cipher: ReceiveCipher,
    shroud_profile: Option<ShroudProfile>,
}

impl ExperimentalQuicSession {
    fn new(socket: UdpSocket, peer: SocketAddr, send_key: [u8; 32], recv_key: [u8; 32]) -> Self {
        Self {
            socket,
            peer,
            send_cipher: SendCipher::new(send_key),
            recv_cipher: ReceiveCipher::new_with_replay_window(recv_key, 128),
            shroud_profile: None,
        }
    }

    pub fn send_frame(&mut self, payload: &[u8]) -> Result<()> {
        write_encrypted_quic_frame(
            &self.socket,
            self.peer,
            &mut self.send_cipher,
            payload,
            self.shroud_profile,
        )
    }

    pub fn recv_frame(&mut self) -> Result<Vec<u8>> {
        read_encrypted_quic_frame(
            &self.socket,
            &mut self.recv_cipher,
            self.peer,
            self.shroud_profile,
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
            },
            ExperimentalQuicReceiver {
                socket: recv_socket,
                peer,
                recv_cipher: self.recv_cipher,
                shroud_profile: self.shroud_profile,
            },
        ))
    }
}

impl ExperimentalQuicSender {
    pub fn send_frame(&mut self, payload: &[u8]) -> Result<()> {
        write_encrypted_quic_frame(
            &self.socket,
            self.peer,
            &mut self.send_cipher,
            payload,
            self.shroud_profile,
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
        )
    }
}

fn write_encrypted_tcp_frame(
    stream: &mut TcpStream,
    cipher: &mut SendCipher,
    payload: &[u8],
) -> Result<()> {
    let encrypted = cipher.encrypt(payload)?;
    let len = encrypted.len() as u32;
    write_tcp_all_or_closed(stream, &len.to_be_bytes())?;
    write_tcp_all_or_closed(stream, &encrypted)?;
    stream.flush().map_err(map_io_error)?;
    Ok(())
}

fn read_encrypted_tcp_frame(stream: &mut TcpStream, cipher: &mut ReceiveCipher) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    read_tcp_exact_or_closed(stream, &mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > MAX_FRAME_BYTES {
        return Err(ShphError::Protocol("encrypted frame length invalid".into()));
    }
    let mut ciphertext = vec![0u8; len];
    read_tcp_exact_or_closed(stream, &mut ciphertext)?;
    cipher.decrypt(&ciphertext)
}

fn write_encrypted_quic_frame(
    socket: &UdpSocket,
    peer: SocketAddr,
    cipher: &mut SendCipher,
    payload: &[u8],
    shroud_profile: Option<ShroudProfile>,
) -> Result<()> {
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
        if payload.len() > max_payload || payload.len() > u16::MAX as usize {
            return Err(ShphError::Protocol(
                "payload exceeds Shroud profile capacity".into(),
            ));
        }
        let mut padded = vec![0u8; plaintext_capacity];
        padded[..SHROUD_LENGTH_PREFIX].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        padded[SHROUD_LENGTH_PREFIX..SHROUD_LENGTH_PREFIX + payload.len()].copy_from_slice(payload);
        if !profile.deterministic_padding {
            rand::rngs::OsRng.fill_bytes(&mut padded[SHROUD_LENGTH_PREFIX + payload.len()..]);
        }
        cipher.encrypt(&padded)?
    } else {
        cipher.encrypt(payload)?
    };
    let encrypted = if let Some(profile) = shroud_profile {
        shph_core::encode_cell(profile, 0x01, &encrypted)?
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

    let mut packet = Vec::with_capacity(4 + encrypted.len());
    packet.extend_from_slice(&(encrypted.len() as u32).to_be_bytes());
    packet.extend_from_slice(&encrypted);
    if packet.len() > MAX_QUIC_FRAME_BYTES {
        return Err(ShphError::Protocol(
            "QUIC frame exceeds transport datagram budget".into(),
        ));
    }
    socket
        .send_to(&packet, peer)
        .map_err(map_io_error)
        .map(|_| ())
}

fn read_encrypted_quic_frame(
    socket: &UdpSocket,
    cipher: &mut ReceiveCipher,
    expected_peer: SocketAddr,
    shroud_profile: Option<ShroudProfile>,
) -> Result<Vec<u8>> {
    // Source-address binding: after the handshake authenticates a peer address,
    // every data-frame datagram must arrive from that same address. Without this
    // check an off-path attacker could inject forged ciphertext datagrams,
    // forcing expensive AEAD-decrypt work and disrupting the authenticated
    // stream. Rejecting foreign sources closes the injection/amplification path.
    let mut packet = vec![0u8; MAX_QUIC_FRAME_BYTES + 1];
    let mut invalid = 0;
    loop {
        let (len, addr) = match socket.recv_from(&mut packet) {
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
            match decode_encrypted_quic_frame(
                &packet[..len.min(packet.len())],
                len,
                cipher,
                shroud_profile,
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

fn decode_encrypted_quic_frame(
    packet: &[u8],
    len: usize,
    cipher: &mut ReceiveCipher,
    shroud_profile: Option<ShroudProfile>,
) -> Result<Vec<u8>> {
    if !(4..=MAX_QUIC_FRAME_BYTES).contains(&len) || packet.len() != len {
        return Err(ShphError::Protocol("invalid QUIC frame length".into()));
    }

    let payload_len = u32::from_be_bytes([packet[0], packet[1], packet[2], packet[3]]) as usize;
    if payload_len == 0 || payload_len > MAX_QUIC_FRAME_BYTES || 4 + payload_len != len {
        return Err(ShphError::Protocol("invalid QUIC payload length".into()));
    }

    let payload = &packet[4..];
    let payload = if let Some(profile) = shroud_profile {
        if !profile.is_valid() {
            return Err(ShphError::Protocol("invalid Shroud profile".into()));
        }
        let encrypted = shph_core::decode_cell(profile, payload)?
            .ok_or_else(|| ShphError::Protocol("unexpected shroud chaff frame".into()))?;
        let padded = cipher.decrypt(&encrypted)?;
        if padded.len() < SHROUD_LENGTH_PREFIX {
            return Err(ShphError::Protocol(
                "Shroud payload missing length prefix".into(),
            ));
        }
        let payload_len = u16::from_be_bytes([padded[0], padded[1]]) as usize;
        if payload_len > padded.len() - SHROUD_LENGTH_PREFIX
            || payload_len > profile.max_payload_chunk
        {
            return Err(ShphError::Protocol(
                "Shroud payload length exceeds profile capacity".into(),
            ));
        }
        padded[SHROUD_LENGTH_PREFIX..SHROUD_LENGTH_PREFIX + payload_len].to_vec()
    } else {
        payload.to_vec()
    };
    if shroud_profile.is_some() {
        Ok(payload)
    } else {
        cipher.decrypt(&payload)
    }
}
fn write_tcp_all_or_closed(stream: &mut TcpStream, payload: &[u8]) -> Result<()> {
    stream.write_all(payload).map_err(map_io_error)
}

fn read_tcp_exact_or_closed(stream: &mut TcpStream, payload: &mut [u8]) -> Result<()> {
    stream.read_exact(payload).map_err(map_io_error)
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
        let ciphertext = self.send_cipher.encrypt(payload)?;
        self.send_state.send_payload(&ciphertext)
    }

    fn recv_frame(&mut self) -> Result<Vec<u8>> {
        let (ciphertext, path, sequence) = self
            .recv_state
            .receive_raw_payload(self.recv_state.poll_interval)?;
        let plaintext = self.recv_cipher.decrypt(&ciphertext)?;
        self.recv_state.commit_payload(sequence);
        let _ = fs::remove_file(path);
        Ok(plaintext)
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
        let (ciphertext, path, sequence) = self.state.receive_raw_payload(self.timeout)?;
        let plaintext = self.cipher.decrypt(&ciphertext)?;
        self.state.commit_payload(sequence);
        let _ = fs::remove_file(path);
        Ok(plaintext)
    }
}

struct OfflineMeshWriteState {
    spool_dir: String,
    local_node: String,
    peer_node: String,
    next_sequence: u64,
    max_file_bytes: u64,
}

impl OfflineMeshWriteState {
    fn new(cfg: &OfflineMeshConfig, local_node: &str, peer_node: &str) -> Self {
        Self {
            spool_dir: cfg.spool_dir.clone(),
            local_node: local_node.to_string(),
            peer_node: peer_node.to_string(),
            next_sequence: 0,
            max_file_bytes: MAX_FILE_ADAPTER_BYTES,
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

        fs::create_dir_all(&out_dir).map_err(ShphError::Io)?;

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
    seen_sequences: HashSet<u64>,
    seen_order: VecDeque<u64>,
    max_seen: usize,
    max_file_bytes: u64,
}

impl OfflineMeshReadState {
    fn new(cfg: &OfflineMeshConfig, local_node: &str, peer_node: &str) -> Self {
        Self {
            spool_dir: cfg.spool_dir.clone(),
            local_node: local_node.to_string(),
            peer_node: peer_node.to_string(),
            poll_interval: Duration::from_millis(cfg.poll_interval_ms.max(1)),
            seen_sequences: HashSet::new(),
            seen_order: VecDeque::new(),
            max_seen: cfg.max_idle_entries as usize,
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

    fn receive_payload(&mut self, timeout: Duration) -> Result<Vec<u8>> {
        let (payload, path, sequence) = self.receive_raw_payload(timeout)?;
        self.commit_payload(sequence);
        let _ = fs::remove_file(path);
        Ok(payload)
    }

    fn receive_raw_payload(&mut self, timeout: Duration) -> Result<(Vec<u8>, PathBuf, u64)> {
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

    fn poll_inbound(&mut self) -> Result<Option<(Vec<u8>, PathBuf, u64)>> {
        let queue_dir = self.inbound_queue_dir();
        let mut candidates: Vec<(PathBuf, OfflineMeshEnvelope)> = Vec::new();

        if queue_dir.exists() {
            for entry in fs::read_dir(&queue_dir).map_err(ShphError::Io)? {
                if candidates.len() >= MAX_QUEUE_SCAN_ENTRIES {
                    return Err(ShphError::ResourceExhausted(
                        "offline-mesh queue contains too many envelopes to scan safely".into(),
                    ));
                }
                let entry = entry.map_err(ShphError::Io)?;
                let path = entry.path();
                let metadata = fs::symlink_metadata(&path).map_err(ShphError::Io)?;
                if !metadata.file_type().is_file() {
                    continue;
                }

                let ext = path.extension().and_then(|ext| ext.to_str()).unwrap_or("");
                if ext != "json" {
                    continue;
                }

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

                if envelope.session_id != offline_session_id(&self.local_node, &self.peer_node)
                    || envelope.from != self.peer_node
                    || envelope.to != self.local_node
                    || self.seen_sequences.contains(&envelope.sequence)
                {
                    continue;
                }

                candidates.push((path, envelope));
            }
        }

        if candidates.is_empty() {
            return Ok(None);
        }

        candidates.sort_by_key(|a| a.1.sequence);
        for (path, envelope) in candidates {
            match base64::engine::general_purpose::STANDARD
                .decode(envelope.ciphertext_b64.as_bytes())
            {
                Ok(payload) => return Ok(Some((payload, path, envelope.sequence))),
                Err(_) => quarantine_file(&path),
            }
        }
        Ok(None)
    }

    fn commit_payload(&mut self, sequence: u64) {
        self.mark_seen(sequence);
    }

    fn mark_seen(&mut self, sequence: u64) {
        if self.seen_sequences.insert(sequence) {
            self.seen_order.push_back(sequence);
        }
        while self.seen_order.len() > self.max_seen.max(1) {
            if let Some(oldest) = self.seen_order.pop_front() {
                self.seen_sequences.remove(&oldest);
            }
        }
    }
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
        let encrypted = self.send_cipher.encrypt(payload)?;
        self.send_state.send_payload(&encrypted)
    }

    fn recv_frame(&mut self) -> Result<Vec<u8>> {
        let frame = self
            .recv_state
            .receive_envelope(self.recv_state.poll_interval)?;
        let plaintext = self.recv_cipher.decrypt(&frame.payload)?;
        self.recv_state.commit_envelope(&frame)?;
        Ok(plaintext)
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
        let frame = self.state.receive_envelope(self.timeout)?;
        let plaintext = self.cipher.decrypt(&frame.payload)?;
        self.state.commit_envelope(&frame)?;
        Ok(plaintext)
    }
}

struct DataMuleEnvelopeFrame {
    payload: Vec<u8>,
    envelope: DataMuleEnvelope,
    path: PathBuf,
}

struct DataMuleWriteState {
    outbox_dir: String,
    local_node: String,
    peer_node: String,
    next_sequence: u64,
    max_file_bytes: u64,
}

impl DataMuleWriteState {
    fn new(cfg: &DataMuleConfig, local_node: &str, peer_node: &str) -> Self {
        Self {
            outbox_dir: cfg.outbox_dir.clone(),
            local_node: local_node.to_string(),
            peer_node: peer_node.to_string(),
            next_sequence: 0,
            max_file_bytes: cfg.max_file_bytes,
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
        write_file_atomically(&path, &bytes)
    }
}

struct DataMuleReadState {
    inbox_dir: String,
    local_node: String,
    peer_filter: Option<String>,
    poll_interval: Duration,
    seen_envelopes: HashSet<String>,
    seen_order: VecDeque<String>,
    max_seen: usize,
    max_file_bytes: u64,
}

impl DataMuleReadState {
    fn new(cfg: &DataMuleConfig, local_node: &str, peer_filter: Option<&str>) -> Self {
        Self {
            inbox_dir: cfg.inbox_dir.clone(),
            local_node: local_node.to_string(),
            peer_filter: peer_filter.map(std::string::ToString::to_string),
            poll_interval: Duration::from_millis(cfg.poll_interval_ms.max(1)),
            seen_envelopes: HashSet::new(),
            seen_order: VecDeque::new(),
            max_seen: 1024,
            max_file_bytes: cfg.max_file_bytes,
        }
    }

    fn receive_envelope(&mut self, timeout: Duration) -> Result<DataMuleEnvelopeFrame> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(frame) = self.poll_envelope()? {
                if frame.envelope.to_node != self.local_node {
                    continue;
                }
                if let Some(peer) = self.peer_filter.as_ref() {
                    if peer != &frame.envelope.from_node {
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

    fn receive_payload(&mut self, timeout: Duration) -> Result<Vec<u8>> {
        let frame = self.receive_envelope(timeout)?;
        let payload = frame.payload.clone();
        self.commit_envelope(&frame)?;
        Ok(payload)
    }

    fn commit_envelope(&mut self, frame: &DataMuleEnvelopeFrame) -> Result<()> {
        self.mark_seen(&frame.envelope)?;
        let _ = fs::remove_file(&frame.path);
        Ok(())
    }

    fn poll_envelope(&mut self) -> Result<Option<DataMuleEnvelopeFrame>> {
        let root = Path::new(&self.inbox_dir);
        let mut candidates: Vec<(PathBuf, DataMuleEnvelope)> = Vec::new();
        let mut scanned = 0;
        collect_shph_files(root, &mut candidates, self.max_file_bytes, 0, &mut scanned)?;

        candidates.retain(|(_, envelope)| {
            envelope.to_node == self.local_node
                && self
                    .peer_filter
                    .as_ref()
                    .is_none_or(|peer| peer == &envelope.from_node)
                && !self.seen_envelopes.contains(&Self::replay_key(envelope))
        });

        if candidates.is_empty() {
            return Ok(None);
        }

        candidates.sort_by_key(|a| (a.1.created_at_unix_ms, a.1.envelope_id.clone()));
        for (path, _) in candidates {
            let bytes = match read_file_bytes(&path, self.max_file_bytes) {
                Ok(bytes) => bytes,
                Err(ShphError::Protocol(_)) => {
                    quarantine_file(&path);
                    continue;
                }
                Err(ShphError::Io(err)) if err.kind() == io::ErrorKind::NotFound => continue,
                Err(err) => return Err(err),
            };
            let envelope: DataMuleEnvelope = match serde_json::from_slice(&bytes) {
                Ok(envelope) => envelope,
                Err(_) => {
                    quarantine_file(&path);
                    continue;
                }
            };
            if envelope.to_node != self.local_node
                || self
                    .peer_filter
                    .as_ref()
                    .is_some_and(|peer| peer != &envelope.from_node)
                || self.seen_envelopes.contains(&Self::replay_key(&envelope))
            {
                continue;
            }
            let payload = match base64::engine::general_purpose::STANDARD
                .decode(envelope.ciphertext_b64.as_bytes())
            {
                Ok(payload) => payload,
                Err(_) => {
                    quarantine_file(&path);
                    continue;
                }
            };

            return Ok(Some(DataMuleEnvelopeFrame {
                payload,
                envelope,
                path,
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
    out: &mut Vec<(PathBuf, DataMuleEnvelope)>,
    max_file_bytes: u64,
    depth: usize,
    scanned: &mut usize,
) -> Result<()> {
    if !root.exists() {
        return Ok(());
    }
    if depth > MAX_QUEUE_SCAN_DEPTH {
        return Err(ShphError::ResourceExhausted(
            "data-mule inbox nesting exceeds scan depth".into(),
        ));
    }

    for entry in fs::read_dir(root).map_err(ShphError::Io)? {
        *scanned = scanned.saturating_add(1);
        if *scanned > MAX_QUEUE_SCAN_ENTRIES {
            return Err(ShphError::ResourceExhausted(
                "data-mule inbox contains too many entries to scan safely".into(),
            ));
        }
        let entry = entry.map_err(ShphError::Io)?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(ShphError::Io)?;
        if metadata.file_type().is_symlink() {
            continue;
        }
        if metadata.is_dir() {
            collect_shph_files(&path, out, max_file_bytes, depth + 1, scanned)?;
            continue;
        }

        let ext = path.extension().and_then(|ext| ext.to_str()).unwrap_or("");
        if ext != "shph" {
            continue;
        }

        let bytes = match read_file_bytes(&path, max_file_bytes) {
            Ok(bytes) => bytes,
            Err(ShphError::Protocol(_)) => {
                quarantine_file(&path);
                continue;
            }
            Err(err) => return Err(err),
        };
        match serde_json::from_slice::<DataMuleEnvelope>(&bytes) {
            Ok(envelope) => out.push((path, envelope)),
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
        accept_secure_session_lab, connect_secure_session_lab, DataMuleConfig, QuicLabConfig,
    };
    use super::{collect_shph_files, TEMP_FILE_COUNTER};
    use super::{
        decode_encrypted_quic_frame, PeerRateLimiter, TransportMode,
        MAX_CONNECTS_PER_PEER_PER_WINDOW, MAX_QUIC_TRACKED_PEERS,
    };
    use std::fs;
    use std::net::SocketAddr;
    use std::sync::atomic::Ordering;

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
    fn peer_rate_limiter_bounds_source_table() {
        let mut rl = PeerRateLimiter::new();
        for octet in 0..MAX_QUIC_TRACKED_PEERS {
            let addr: SocketAddr = format!("10.{}.{}.1:1", octet / 256, octet % 256)
                .parse()
                .unwrap();
            assert!(rl.check_and_record(addr).is_ok());
        }
        let rejected: SocketAddr = "11.0.0.1:1".parse().unwrap();
        assert!(rl.check_and_record(rejected).is_err());
        assert!(rl.seen.len() <= MAX_QUIC_TRACKED_PEERS);
    }

    #[test]
    fn quic_frame_decoder_rejects_trailing_and_empty_payloads() {
        use shph_core::ReceiveCipher;

        let mut cipher = ReceiveCipher::new([7u8; 32]);
        assert!(decode_encrypted_quic_frame(&[0, 0, 0, 0], 4, &mut cipher, None).is_err());
        assert!(decode_encrypted_quic_frame(&[0, 0, 0, 1, 9, 9], 6, &mut cipher, None).is_err());
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
        let peer = server_addr.to_string();
        let client_handle = thread::spawn(move || {
            super::connect_secure_session(&peer, &client_id2, 5, super::TransportMode::Quic)
        });
        let (mut server_sess, _state) = super::accept_secure_session(
            &server_addr.to_string(),
            &server_id,
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
        let probe = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = probe.local_addr().unwrap();
        drop(probe);
        let peer = server_addr.to_string();
        let client_handle = thread::spawn(move || {
            let (mut session, _) = connect_secure_session_lab(
                &peer,
                &client_id,
                5,
                TransportMode::Quic,
                QuicLabConfig {
                    shroud_profile: Some(shph_core::BALANCED),
                },
            )
            .unwrap();
            session.send_frame(b"shroud-lab").unwrap();
        });
        let (mut session, _) = accept_secure_session_lab(
            &server_addr.to_string(),
            &server_id,
            5,
            TransportMode::Quic,
            QuicLabConfig {
                shroud_profile: Some(shph_core::BALANCED),
            },
        )
        .unwrap();
        assert_eq!(session.recv_frame().unwrap(), b"shroud-lab");
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
        let probe = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = probe.local_addr().unwrap();
        drop(probe);
        let peer = server_addr.to_string();
        let client_handle = thread::spawn(move || {
            let (mut session, _) = connect_secure_session_lab(
                &peer,
                &client_id,
                5,
                TransportMode::Quic,
                QuicLabConfig {
                    shroud_profile: shph_core::shroud_profile_by_name("randomized-lab"),
                },
            )
            .unwrap();
            session.send_frame(b"randomized-shroud-lab").unwrap();
        });
        let (mut session, _) = accept_secure_session_lab(
            &server_addr.to_string(),
            &server_id,
            5,
            TransportMode::Quic,
            QuicLabConfig {
                shroud_profile: shph_core::shroud_profile_by_name("randomized-lab"),
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
        let mut scanned = 0;
        collect_shph_files(&root, &mut out, 4096, 0, &mut scanned).unwrap();

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
        let mut scanned = 0;
        collect_shph_files(&root, &mut out, 4096, 0, &mut scanned).unwrap();

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
        let bad = root.join("a.shph");
        let good = root.join("b.shph");
        fs::write(&bad, br#"{"envelope_id":"a","created_at_unix_ms":1,"from_node":"peer","to_node":"local","ciphertext_b64":"%%%","nonce_b64":"AA=="}"#).unwrap();
        fs::write(&good, br#"{"envelope_id":"b","created_at_unix_ms":2,"from_node":"peer","to_node":"local","ciphertext_b64":"AQ==","nonce_b64":"AQ=="}"#).unwrap();

        let cfg = DataMuleConfig {
            inbox_dir: root.to_string_lossy().into_owned(),
            outbox_dir: root.join("out").to_string_lossy().into_owned(),
            poll_interval_ms: 1,
            max_file_bytes: 4096,
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
