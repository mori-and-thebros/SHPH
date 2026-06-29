//! SHPH transport abstractions.
//!
//! Includes stable TCP transport today plus an experimental QUIC-like
//! UDP datagram shim for phased adoption.

use base64::Engine as _;
use shph_core::roadmap::{data_mule_inbox_path, offline_session_id};
use shph_core::{
    build_hello, verify_and_derive, DataMuleConfig, DataMuleEnvelope, HandshakeState, Hello,
    IdentityKeyPair, OfflineMeshConfig, OfflineMeshEnvelope, ReceiveCipher, Result, SendCipher,
    ShphError,
};
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MAX_HELLO_BYTES: usize = 16 * 1024;
const MAX_FRAME_BYTES: usize = 64 * 1024;
const MAX_QUIC_FRAME_BYTES: usize = 1024;
const MAX_QUIC_HELLO_BYTES: usize = 12 * 1024;
const QUIC_HANDSHAKE_ATTEMPTS: usize = 3;
/// Maximum number of inbound TCP handshake attempts the accept path will
/// tolerate from malformed/early-closing peers before giving up. This bounds
/// the effort an unauthenticated attacker can force on the entry path.
const TCP_HANDSHAKE_ATTEMPTS: usize = 5;

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

enum SecureReceiverInner {
    Tcp(SecureTcpReceiver),
    Quic(ExperimentalQuicReceiver),
    OfflineMesh(OfflineMeshReceiver),
    DataMule(DataMuleReceiver),
}

const MAX_FILE_ADAPTER_BYTES: u64 = 256 * 1024;

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

    let mut tmp = path.to_path_buf();
    tmp.set_extension("tmp");
    let mut file = File::create(&tmp).map_err(ShphError::Io)?;
    file.write_all(bytes).map_err(ShphError::Io)?;
    file.sync_all().map_err(ShphError::Io)?;

    if path.exists() {
        fs::remove_file(path).map_err(ShphError::Io)?;
    }

    fs::rename(&tmp, path).map_err(ShphError::Io)
}

fn read_file_bytes(path: &Path, max_bytes: u64) -> Result<Vec<u8>> {
    let meta = fs::metadata(path).map_err(ShphError::Io)?;
    if meta.len() > max_bytes {
        return Err(ShphError::Protocol(
            "file envelope exceeds maximum size".into(),
        ));
    }

    let mut file = File::open(path).map_err(ShphError::Io)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(ShphError::Io)?;
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
    addr.to_socket_addrs()
        .map_err(|_| ShphError::Config(format!("invalid peer address: {addr}")))?
        .next()
        .ok_or_else(|| ShphError::Config(format!("unable to resolve peer address: {addr}")))
}

pub fn connect_and_handshake(
    peer: &str,
    local_identity: &IdentityKeyPair,
    timeout_secs: u64,
    mode: TransportMode,
) -> Result<HandshakeState> {
    match mode {
        TransportMode::Tcp => tcp_handshake_client(peer, local_identity, timeout_secs),
        TransportMode::Quic => {
            let (_socket, _peer, state) =
                quic_handshake_client(peer, local_identity, timeout_secs)?;
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
    match mode {
        TransportMode::Tcp => tcp_handshake_server(bind_addr, local_identity, timeout_secs),
        TransportMode::Quic => {
            Ok(quic_handshake_server(bind_addr, local_identity, timeout_secs)?.2)
        }
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
    let material = build_hello(local_identity)?;
    let mut writer = OfflineMeshWriteState::new(cfg, &cfg.node_id, &cfg.peer_id);
    let mut reader = OfflineMeshReadState::new(cfg, &cfg.node_id, &cfg.peer_id);
    let timeout = Duration::from_secs(timeout_secs.max(1));

    let local_hello =
        serde_json::to_vec(&material.local_hello).map_err(ShphError::Serialization)?;
    writer.send_payload(&local_hello)?;

    let peer_payload = reader.receive_payload(timeout)?;
    let peer_hello = serde_json::from_slice::<Hello>(&peer_payload)
        .map_err(|e| ShphError::Protocol(format!("invalid peer hello: {e}")))?;

    verify_and_derive(local_identity, &material, &peer_hello, true)
}

pub fn offline_mesh_accept_and_handshake(
    cfg: &OfflineMeshConfig,
    local_identity: &IdentityKeyPair,
    timeout_secs: u64,
) -> Result<HandshakeState> {
    let material = build_hello(local_identity)?;
    let mut writer = OfflineMeshWriteState::new(cfg, &cfg.node_id, &cfg.peer_id);
    let mut reader = OfflineMeshReadState::new(cfg, &cfg.node_id, &cfg.peer_id);
    let timeout = Duration::from_secs(timeout_secs.max(1));

    let peer_payload = reader.receive_payload(timeout)?;
    let peer_hello = serde_json::from_slice::<Hello>(&peer_payload)
        .map_err(|e| ShphError::Protocol(format!("invalid peer hello: {e}")))?;
    let local_hello =
        serde_json::to_vec(&material.local_hello).map_err(ShphError::Serialization)?;
    writer.send_payload(&local_hello)?;
    verify_and_derive(local_identity, &material, &peer_hello, false)
}

pub fn offline_mesh_connect_secure_session(
    cfg: &OfflineMeshConfig,
    local_identity: &IdentityKeyPair,
    timeout_secs: u64,
) -> Result<(SecureSession, HandshakeState)> {
    let material = build_hello(local_identity)?;
    let mut writer = OfflineMeshWriteState::new(cfg, &cfg.node_id, &cfg.peer_id);
    let mut reader = OfflineMeshReadState::new(cfg, &cfg.node_id, &cfg.peer_id);
    let timeout = Duration::from_secs(timeout_secs.max(1));

    writer.send_payload(
        &serde_json::to_vec(&material.local_hello).map_err(ShphError::Serialization)?,
    )?;
    let peer_payload = reader.receive_payload(timeout)?;
    let peer_hello = serde_json::from_slice::<Hello>(&peer_payload)
        .map_err(|e| ShphError::Protocol(format!("invalid peer hello: {e}")))?;

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
    let material = build_hello(local_identity)?;
    let mut writer = OfflineMeshWriteState::new(cfg, &cfg.node_id, &cfg.peer_id);
    let mut reader = OfflineMeshReadState::new(cfg, &cfg.node_id, &cfg.peer_id);
    let timeout = Duration::from_secs(timeout_secs.max(1));

    let peer_payload = reader.receive_payload(timeout)?;
    let peer_hello = serde_json::from_slice::<Hello>(&peer_payload)
        .map_err(|e| ShphError::Protocol(format!("invalid peer hello: {e}")))?;
    writer.send_payload(
        &serde_json::to_vec(&material.local_hello).map_err(ShphError::Serialization)?,
    )?;

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
    let material = build_hello(local_identity)?;
    let mut writer = DataMuleWriteState::new(cfg, &local_identity.public_key_b64(), peer_node);
    let mut reader = DataMuleReadState::new(cfg, &local_identity.public_key_b64(), Some(peer_node));
    let timeout = Duration::from_secs(timeout_secs.max(1));

    writer.send_payload(
        &serde_json::to_vec(&material.local_hello).map_err(ShphError::Serialization)?,
    )?;
    let peer_payload = reader.receive_payload(timeout)?;
    let peer_hello = serde_json::from_slice::<Hello>(&peer_payload)
        .map_err(|e| ShphError::Protocol(format!("invalid peer hello: {e}")))?;
    verify_and_derive(local_identity, &material, &peer_hello, true)
}

pub fn data_mule_accept_and_handshake(
    cfg: &DataMuleConfig,
    local_identity: &IdentityKeyPair,
    timeout_secs: u64,
) -> Result<HandshakeState> {
    let material = build_hello(local_identity)?;
    let local_node = local_identity.public_key_b64();
    let mut reader = DataMuleReadState::new(cfg, &local_identity.public_key_b64(), None);
    let timeout = Duration::from_secs(timeout_secs.max(1));

    let peer_envelope = reader.receive_envelope(timeout)?;
    let peer_hello = serde_json::from_slice::<Hello>(&peer_envelope.payload)
        .map_err(|e| ShphError::Protocol(format!("invalid peer hello: {e}")))?;
    let peer_node = peer_envelope.envelope.from_node;
    let mut writer = DataMuleWriteState::new(cfg, &local_node, &peer_node);
    writer.send_payload(
        &serde_json::to_vec(&material.local_hello).map_err(ShphError::Serialization)?,
    )?;
    verify_and_derive(local_identity, &material, &peer_hello, false)
}

pub fn data_mule_connect_secure_session(
    cfg: &DataMuleConfig,
    local_identity: &IdentityKeyPair,
    peer_node: &str,
    timeout_secs: u64,
) -> Result<(SecureSession, HandshakeState)> {
    let material = build_hello(local_identity)?;
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
    let material = build_hello(local_identity)?;
    let local_node = local_identity.public_key_b64();
    let mut reader = DataMuleReadState::new(cfg, &local_node, None);
    let timeout = Duration::from_secs(timeout_secs.max(1));

    let envelope = reader.receive_envelope(timeout)?;
    let peer_hello = serde_json::from_slice::<Hello>(&envelope.payload)
        .map_err(|e| ShphError::Protocol(format!("invalid peer hello: {e}")))?;
    let peer_node = envelope.envelope.from_node;
    let mut writer = DataMuleWriteState::new(cfg, &local_node, &peer_node);
    writer.send_payload(
        &serde_json::to_vec(&material.local_hello).map_err(ShphError::Serialization)?,
    )?;

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
    match mode {
        TransportMode::Tcp => {
            let (stream, state) = tcp_connect_and_handshake(peer, local_identity, timeout_secs)?;
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
                quic_connect_and_handshake(peer, local_identity, timeout_secs)?;
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

pub fn accept_secure_session(
    bind_addr: &str,
    local_identity: &IdentityKeyPair,
    timeout_secs: u64,
    mode: TransportMode,
) -> Result<(SecureSession, HandshakeState)> {
    match mode {
        TransportMode::Tcp => {
            let (stream, state) =
                tcp_accept_and_handshake(bind_addr, local_identity, timeout_secs)?;
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
                quic_accept_and_handshake(bind_addr, local_identity, timeout_secs)?;
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

impl SecureSession {
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
    let mut stream = TcpStream::connect(peer).map_err(|e| ShphError::Transport(e.to_string()))?;
    apply_timeout(&stream, timeout_secs)?;
    let material = build_hello(local_identity)?;
    write_tcp_hello(&mut stream, &material.local_hello)?;
    let peer_hello = read_tcp_hello(&mut stream)?;
    verify_and_derive(local_identity, &material, &peer_hello, true)
}

pub fn tcp_handshake_server(
    bind_addr: &str,
    local_identity: &IdentityKeyPair,
    timeout_secs: u64,
) -> Result<HandshakeState> {
    let listener = TcpListener::bind(bind_addr).map_err(|e| ShphError::Transport(e.to_string()))?;
    let (mut stream, _) = listener
        .accept()
        .map_err(|e| ShphError::Transport(e.to_string()))?;
    apply_timeout(&stream, timeout_secs)?;
    let peer_hello = read_tcp_hello(&mut stream)?;
    let material = build_hello(local_identity)?;
    write_tcp_hello(&mut stream, &material.local_hello)?;
    verify_and_derive(local_identity, &material, &peer_hello, false)
}

pub fn tcp_connect_and_handshake(
    peer: &str,
    local_identity: &IdentityKeyPair,
    timeout_secs: u64,
) -> Result<(TcpStream, HandshakeState)> {
    let mut stream = TcpStream::connect(peer).map_err(|e| ShphError::Transport(e.to_string()))?;
    apply_timeout(&stream, timeout_secs)?;
    let material = build_hello(local_identity)?;
    write_tcp_hello(&mut stream, &material.local_hello)?;
    let peer_hello = read_tcp_hello(&mut stream)?;
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
    let listener = TcpListener::bind(bind_addr).map_err(|e| ShphError::Transport(e.to_string()))?;
    // Bounded handshake loop on the unauthenticated entry path: tolerate
    // malformed/early-closing peers up to TCP_HANDSHAKE_ATTEMPTS, then fail
    // closed. Genuine listener failures and timeouts propagate immediately so
    // an attacker cannot exhaust the attempt budget with a slow/blocked socket.
    let mut last_err: Option<ShphError> = None;
    let mut rate_limiter = PeerRateLimiter::new();
    for _ in 0..TCP_HANDSHAKE_ATTEMPTS {
        let (mut stream, peer_addr) = listener
            .accept()
            .map_err(|e| ShphError::Transport(e.to_string()))?;

        // Per-source rate limit BEFORE any handshake work: a single host that
        // is hammering the entry path is dropped immediately, so it cannot
        // exhaust the attempt budget or burn CPU on hello parsing across
        // repeated sessions.
        if let Err(err) = rate_limiter.check_and_record(peer_addr) {
            last_err = Some(err);
            drop(stream);
            continue;
        }

        apply_timeout(&stream, timeout_secs)?;

        match read_tcp_hello(&mut stream) {
            Ok(peer_hello) => {
                let material = build_hello(local_identity)?;
                write_tcp_hello(&mut stream, &material.local_hello)?;
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

fn apply_timeout(stream: &TcpStream, timeout_secs: u64) -> Result<()> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
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
    let peer_addr = parse_socket_addr(peer)?;
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| ShphError::Transport(e.to_string()))?;
    socket
        .set_read_timeout(Some(Duration::from_secs(timeout_secs.max(1))))
        .map_err(ShphError::Io)?;
    socket
        .set_write_timeout(Some(Duration::from_secs(timeout_secs.max(1))))
        .map_err(ShphError::Io)?;

    let material = build_hello(local_identity)?;
    let mut buf = vec![0u8; MAX_QUIC_HELLO_BYTES];
    let mut last_err: Option<ShphError> = None;

    for _ in 0..QUIC_HANDSHAKE_ATTEMPTS {
        let peer_hello =
            write_and_wait_quic_hello(&socket, peer_addr, &material.local_hello, &mut buf);
        match peer_hello {
            Ok((peer_hello, addr)) if addr == peer_addr => {
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
    let socket = UdpSocket::bind(bind_addr).map_err(|e| ShphError::Transport(e.to_string()))?;
    socket
        .set_read_timeout(Some(Duration::from_secs(timeout_secs.max(1))))
        .map_err(ShphError::Io)?;
    socket
        .set_write_timeout(Some(Duration::from_secs(timeout_secs.max(1))))
        .map_err(ShphError::Io)?;

    let material = build_hello(local_identity)?;
    let mut line = vec![0u8; MAX_QUIC_HELLO_BYTES];
    let mut peer_hello = None;

    let start = Instant::now();
    let deadline = Duration::from_secs(timeout_secs.max(1));

    while start.elapsed() < deadline {
        match read_quic_hello(&socket, &mut line) {
            Ok((hello, peer_addr)) => {
                peer_hello = Some((hello, peer_addr));
                break;
            }
            Err(ShphError::Timeout) => continue,
            Err(err) => return Err(err),
        }
    }

    let (peer_hello, peer_addr) = peer_hello.ok_or(ShphError::Timeout)?;

    write_tcp_hello_to_peer(&socket, peer_addr, &material.local_hello)?;
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
    decode_quic_hello(read.0, &buf[0..read.0], read.1)
}

fn read_quic_hello(socket: &UdpSocket, buf: &mut [u8]) -> Result<(Hello, SocketAddr)> {
    let (len, peer_addr) = socket.recv_from(buf).map_err(map_io_error)?;
    decode_quic_hello(len, &buf[..len], peer_addr)
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

pub struct ExperimentalQuicSession {
    socket: UdpSocket,
    peer: SocketAddr,
    send_cipher: SendCipher,
    recv_cipher: ReceiveCipher,
}

pub struct ExperimentalQuicSender {
    socket: UdpSocket,
    peer: SocketAddr,
    send_cipher: SendCipher,
}

pub struct ExperimentalQuicReceiver {
    socket: UdpSocket,
    recv_cipher: ReceiveCipher,
}

impl ExperimentalQuicSession {
    fn new(socket: UdpSocket, peer: SocketAddr, send_key: [u8; 32], recv_key: [u8; 32]) -> Self {
        Self {
            socket,
            peer,
            send_cipher: SendCipher::new(send_key),
            recv_cipher: ReceiveCipher::new(recv_key),
        }
    }

    pub fn send_frame(&mut self, payload: &[u8]) -> Result<()> {
        write_encrypted_quic_frame(&self.socket, self.peer, &mut self.send_cipher, payload)
    }

    pub fn recv_frame(&mut self) -> Result<Vec<u8>> {
        read_encrypted_quic_frame(&self.socket, &mut self.recv_cipher)
    }

    pub fn into_split(self) -> Result<(ExperimentalQuicSender, ExperimentalQuicReceiver)> {
        let recv_socket = self.socket.try_clone().map_err(map_io_error)?;
        let send_socket = self.socket;
        Ok((
            ExperimentalQuicSender {
                socket: send_socket,
                peer: self.peer,
                send_cipher: self.send_cipher,
            },
            ExperimentalQuicReceiver {
                socket: recv_socket,
                recv_cipher: self.recv_cipher,
            },
        ))
    }
}

impl ExperimentalQuicSender {
    pub fn send_frame(&mut self, payload: &[u8]) -> Result<()> {
        write_encrypted_quic_frame(&self.socket, self.peer, &mut self.send_cipher, payload)
    }
}

impl ExperimentalQuicReceiver {
    pub fn recv_frame(&mut self) -> Result<Vec<u8>> {
        read_encrypted_quic_frame(&self.socket, &mut self.recv_cipher)
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
) -> Result<()> {
    let encrypted = cipher.encrypt(payload)?;
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

fn read_encrypted_quic_frame(socket: &UdpSocket, cipher: &mut ReceiveCipher) -> Result<Vec<u8>> {
    let mut packet = vec![0u8; MAX_QUIC_HELLO_BYTES];
    let (len, _) = socket.recv_from(&mut packet).map_err(map_io_error)?;
    if len < 4 {
        return Err(ShphError::Protocol("invalid QUIC frame length".into()));
    }
    if len > MAX_QUIC_HELLO_BYTES {
        return Err(ShphError::Protocol("invalid QUIC frame length".into()));
    }

    let payload_len = u32::from_be_bytes([packet[0], packet[1], packet[2], packet[3]]) as usize;
    if payload_len == 0 || payload_len > MAX_QUIC_FRAME_BYTES {
        return Err(ShphError::Protocol("invalid QUIC payload length".into()));
    }
    if 4 + payload_len > len {
        return Err(ShphError::Protocol("truncated QUIC frame".into()));
    }

    cipher.decrypt(&packet[4..4 + payload_len])
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
        let ciphertext = self
            .recv_state
            .receive_payload(self.recv_state.poll_interval)?;
        self.recv_cipher.decrypt(&ciphertext)
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
        let ciphertext = self.state.receive_payload(self.timeout)?;
        self.cipher.decrypt(&ciphertext)
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
    max_idle_entries: usize,
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
            max_idle_entries: cfg.max_idle_entries as usize,
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
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(payload) = self.poll_inbound()? {
                return Ok(payload);
            }

            if Instant::now() >= deadline {
                return Err(ShphError::Timeout);
            }

            thread::sleep(self.poll_interval);
        }
    }

    fn poll_inbound(&mut self) -> Result<Option<Vec<u8>>> {
        let queue_dir = self.inbound_queue_dir();
        let mut candidates: Vec<(PathBuf, OfflineMeshEnvelope)> = Vec::new();

        if queue_dir.exists() {
            for entry in fs::read_dir(&queue_dir).map_err(ShphError::Io)? {
                let entry = entry.map_err(ShphError::Io)?;
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }

                let ext = path.extension().and_then(|ext| ext.to_str()).unwrap_or("");
                if ext != "json" {
                    continue;
                }

                let bytes = read_file_bytes(&path, self.max_file_bytes)?;
                let envelope: OfflineMeshEnvelope = match serde_json::from_slice(&bytes) {
                    Ok(e) => e,
                    Err(_) => {
                        let _ = fs::remove_file(&path);
                        continue;
                    }
                };

                if envelope.from != self.peer_node
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
        let (path, envelope) = candidates.remove(0);
        let payload = base64::engine::general_purpose::STANDARD
            .decode(envelope.ciphertext_b64.as_bytes())
            .map_err(|_| ShphError::Protocol("invalid offline mesh payload".into()))?;
        self.mark_seen(envelope.sequence);
        if fs::remove_file(path).is_err() {
            // best effort cleanup for best-effort transports
        }

        Ok(Some(payload))
    }

    fn mark_seen(&mut self, sequence: u64) {
        self.seen_sequences.insert(sequence);
        if self.seen_sequences.len() > self.max_idle_entries.max(1) {
            self.seen_sequences.clear();
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
        let payload = self
            .recv_state
            .receive_payload(self.recv_state.poll_interval)?;
        self.recv_cipher.decrypt(&payload)
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
        let payload = self.state.receive_payload(self.timeout)?;
        self.cipher.decrypt(&payload)
    }
}

struct DataMuleEnvelopeFrame {
    payload: Vec<u8>,
    envelope: DataMuleEnvelope,
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
    seen_sequences: HashSet<u64>,
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
            seen_sequences: HashSet::new(),
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

                self.mark_seen(frame.envelope.created_at_unix_ms);
                return Ok(frame);
            }

            if Instant::now() >= deadline {
                return Err(ShphError::Timeout);
            }

            thread::sleep(self.poll_interval);
        }
    }

    fn receive_payload(&mut self, timeout: Duration) -> Result<Vec<u8>> {
        Ok(self.receive_envelope(timeout)?.payload)
    }

    fn poll_envelope(&mut self) -> Result<Option<DataMuleEnvelopeFrame>> {
        let root = Path::new(&self.inbox_dir);
        let mut candidates: Vec<(PathBuf, DataMuleEnvelope)> = Vec::new();
        collect_shph_files(root, &mut candidates)?;

        candidates
            .retain(|(_, envelope)| !self.seen_sequences.contains(&envelope.created_at_unix_ms));

        if candidates.is_empty() {
            return Ok(None);
        }

        candidates.sort_by_key(|a| a.1.created_at_unix_ms);
        let (path, _envelope) = candidates.remove(0);

        let bytes = read_file_bytes(&path, self.max_file_bytes)?;
        let _ = fs::remove_file(&path);
        let envelope: DataMuleEnvelope = match serde_json::from_slice(&bytes) {
            Ok(e) => e,
            Err(_) => return Ok(None),
        };
        let payload = base64::engine::general_purpose::STANDARD
            .decode(envelope.ciphertext_b64.as_bytes())
            .map_err(|_| ShphError::Protocol("invalid data-mule payload".into()))?;

        Ok(Some(DataMuleEnvelopeFrame { payload, envelope }))
    }

    fn mark_seen(&mut self, sequence: u64) {
        self.seen_sequences.insert(sequence);
        if self.seen_sequences.len() > self.max_seen {
            self.seen_sequences.clear();
        }
    }
}

fn collect_shph_files(root: &Path, out: &mut Vec<(PathBuf, DataMuleEnvelope)>) -> Result<()> {
    if !root.exists() {
        return Ok(());
    }

    for entry in fs::read_dir(root).map_err(ShphError::Io)? {
        let entry = entry.map_err(ShphError::Io)?;
        let path = entry.path();
        if path.is_dir() {
            collect_shph_files(&path, out)?;
            continue;
        }

        let ext = path.extension().and_then(|ext| ext.to_str()).unwrap_or("");
        if ext != "shph" {
            continue;
        }

        let bytes = fs::read(&path).map_err(ShphError::Io)?;
        match serde_json::from_slice::<DataMuleEnvelope>(&bytes) {
            Ok(envelope) => out.push((path, envelope)),
            Err(_) => {
                let _ = fs::remove_file(&path);
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{PeerRateLimiter, TransportMode, MAX_CONNECTS_PER_PEER_PER_WINDOW};
    use std::net::SocketAddr;

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
}
