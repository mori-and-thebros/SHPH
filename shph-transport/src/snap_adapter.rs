//! SNAP TCP adapter setup that preserves the ordinary SHPH session handshake.
//!
//! Adapters in this module only establish a byte stream to the selected SHPH
//! peer. Peer identity, authentication, and application encryption remain in
//! the existing SHPH handshake and secure-session implementation.

use base64::Engine as _;
use futures_util::{SinkExt, StreamExt};
use ring::aead;
use ring::rand::{SecureRandom, SystemRandom};
use rustls::{pki_types::ServerName, ClientConfig, RootCertStore};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use shph_core::{open_readonly_no_reparse, Result, ShphError};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio_tungstenite::tungstenite::{
    client::IntoClientRequest,
    http::HeaderValue,
    protocol::{Message, WebSocketConfig},
};
use zeroize::Zeroizing;

const ONION_AAD: &[u8] = b"sierra-node-onion-v1";
const ONION_NONCE_BYTES: usize = 12;
const MAX_ONION_ROUTE_BYTES: u64 = 1024 * 1024;
const MAX_ONION_KEY_FILE_BYTES: u64 = 16 * 1024;
const MAX_ONION_MESSAGE_BYTES: usize = 1024 * 1024;
const MAX_WEBSOCKET_MESSAGE_BYTES: usize = 8 * 1024 * 1024;
const MAX_MESH_ENDPOINTS: usize = 64;
const MAX_MESH_PEER_FILE_BYTES: u64 = 1024 * 1024;
const MAX_MULE_PROXY_HELLO_BYTES: usize = 16 * 1024;
const SNAP_WEBSOCKET_SUBPROTOCOL: &str = "sierranode.snap.v2";
const SNAP_SHROUD_REQUEST_MAGIC: &[u8; 8] = b"SNP-SHR1";
const SNAP_SHROUD_ACK_MAGIC: &[u8; 8] = b"SNP-ACK1";
const SNAP_SHROUD_CELL_MAGIC: &[u8; 8] = b"SNP-CEL1";
const SNAP_SHROUD_VERSION: u8 = 1;
const SNAP_SHROUD_CELL_HEADER_BYTES: usize = 12;

type SnapTlsStream = tokio_rustls::client::TlsStream<tokio::net::TcpStream>;
type SnapWebSocketStream = tokio_tungstenite::WebSocketStream<SnapTlsStream>;

#[derive(Clone, Copy)]
enum TlsBridgeFraming {
    RawTcp,
    WebSocket,
    SnapShroud,
}

enum SnapBridgeStream {
    RawTcp(Box<SnapTlsStream>),
    WebSocket(Box<SnapWebSocketStream>),
    SnapShroud(Box<SnapTlsStream>, SnapShroudProfile),
}

#[derive(Clone, Copy)]
struct SnapShroudProfile {
    id: u8,
    cell_size: usize,
    max_payload: usize,
    chaff_interval: Duration,
}

#[derive(Debug, PartialEq, Eq)]
enum SnapShroudFrame {
    Data(Vec<u8>),
    Chaff,
}

/// Operator-supplied bridge settings copied from a validated SNAP candidate.
#[derive(Debug, Clone, Default)]
pub struct SnapBridgeConfig {
    pub adapter: String,
    pub peer_host: String,
    pub peer_port: u16,
    pub relay_host: Option<String>,
    pub relay_port: Option<u16>,
    pub key_file: Option<String>,
    pub route_file: Option<String>,
    pub tls_enabled: bool,
    pub sni: Option<String>,
    pub tls_ca_file: Option<String>,
    pub tls_cert_sha256: Option<String>,
    pub ws_path: Option<String>,
    pub shroud_profile: Option<String>,
}

/// Keeps a TLS bridge relay alive until its local SHPH stream has closed.
///
/// The duplicate stream lets session shutdown signal EOF to the relay before
/// waiting briefly for buffered adapter bytes to drain. A peer that does not
/// close promptly cannot block session teardown indefinitely.
pub struct SnapBridgeLifecycle {
    shutdown_stream: TcpStream,
    worker: Option<JoinHandle<()>>,
}

impl SnapBridgeLifecycle {
    fn new(shutdown_stream: TcpStream, worker: JoinHandle<()>) -> Self {
        Self {
            shutdown_stream,
            worker: Some(worker),
        }
    }
}

impl Drop for SnapBridgeLifecycle {
    fn drop(&mut self) {
        let _ = self.shutdown_stream.shutdown(std::net::Shutdown::Both);
        if let Some(worker) = self.worker.take() {
            let deadline = std::time::Instant::now() + Duration::from_secs(1);
            while !worker.is_finished() && std::time::Instant::now() < deadline {
                thread::sleep(Duration::from_millis(5));
            }
            if worker.is_finished() {
                let _ = worker.join();
            }
        }
    }
}

/// Set up one configured adapter and return a stream carrying SHPH bytes.
pub fn connect_snap_bridge_stream(
    config: &SnapBridgeConfig,
    timeout: Duration,
) -> Result<(TcpStream, Option<SnapBridgeLifecycle>)> {
    match config.adapter.as_str() {
        "bridge-onion-tcp" => connect_onion_bridge(config, timeout).map(|stream| (stream, None)),
        "bridge-tls" | "edge-relay" => {
            connect_tls_bridge(config, timeout, TlsBridgeFraming::RawTcp)
        }
        "bridge-ws" => connect_tls_bridge(config, timeout, TlsBridgeFraming::WebSocket),
        "shroud-tcp" => connect_tls_bridge(config, timeout, TlsBridgeFraming::SnapShroud),
        "mesh-dtn-local" => connect_mesh_dtn_local(config, timeout).map(|stream| (stream, None)),
        "mule-usb" => connect_mule_usb(config, timeout).map(|stream| (stream, None)),
        other => Err(ShphError::Unsupported(format!(
            "SNAP TCP adapter '{other}' is not implemented"
        ))),
    }
}

fn connect_tls_bridge(
    config: &SnapBridgeConfig,
    timeout: Duration,
    framing: TlsBridgeFraming,
) -> Result<(TcpStream, Option<SnapBridgeLifecycle>)> {
    if !config.tls_enabled {
        return Err(ShphError::Config(
            "SNAP TLS bridge requires tls_enabled=true".into(),
        ));
    }
    let sni = config
        .sni
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| ShphError::Config("SNAP TLS bridge requires sni".into()))?;
    let server_name = ServerName::try_from(sni.to_owned())
        .map_err(|_| ShphError::Config("SNAP TLS bridge sni is invalid".into()))?;
    let peer_ip = config.peer_host.parse::<IpAddr>().map_err(|_| {
        ShphError::Config("SNAP TLS bridge destination must be a literal IP address".into())
    })?;
    if config.peer_port == 0 {
        return Err(ShphError::Config(
            "SNAP TLS bridge destination port must be non-zero".into(),
        ));
    }
    let peer_addr = SocketAddr::new(peer_ip, config.peer_port);
    let tls_config = Arc::new(build_tls_client_config(config)?);
    let certificate_pin = config
        .tls_cert_sha256
        .as_deref()
        .map(parse_sha256_pin)
        .transpose()?;
    let shroud_profile = resolve_snap_shroud_profile(config.shroud_profile.as_deref())?;
    let websocket_host = sni.to_owned();
    let websocket_path = config.ws_path.clone().unwrap_or_else(|| "/".into());
    let (client_stream, tunnel_stream) = local_tcp_pair().map_err(ShphError::Io)?;
    tunnel_stream.set_nonblocking(true).map_err(ShphError::Io)?;
    let lifecycle_stream = client_stream.try_clone().map_err(ShphError::Io)?;
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    let thread_timeout = timeout;

    let worker = thread::Builder::new()
        .name("shph-snap-tls-bridge".into())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(_) => {
                    let _ = ready_tx.send(Err(ShphError::Transport(
                        "SNAP TLS bridge runtime could not start".into(),
                    )));
                    return;
                }
            };
            let tunnel_stream = match runtime.block_on(async {
                tokio::net::TcpStream::from_std(tunnel_stream).map_err(ShphError::Io)
            }) {
                Ok(stream) => stream,
                Err(error) => {
                    let _ = ready_tx.send(Err(error));
                    return;
                }
            };
            let setup = async {
                let raw = tokio::net::TcpStream::connect(peer_addr)
                    .await
                    .map_err(ShphError::Io)?;
                let mut tls = tokio_rustls::TlsConnector::from(tls_config)
                    .connect(server_name, raw)
                    .await
                    .map_err(|_| {
                        ShphError::Auth("SNAP TLS bridge certificate verification failed".into())
                    })?;
                if let Some(expected_pin) = certificate_pin {
                    let certificate = tls
                        .get_ref()
                        .1
                        .peer_certificates()
                        .and_then(|certificates| certificates.first())
                        .ok_or_else(|| {
                            ShphError::Auth("SNAP TLS bridge certificate is missing".into())
                        })?;
                    let digest: [u8; 32] = Sha256::digest(certificate.as_ref()).into();
                    if digest != expected_pin {
                        return Err(ShphError::Auth(
                            "SNAP TLS bridge certificate pin mismatch".into(),
                        ));
                    }
                }
                match framing {
                    TlsBridgeFraming::RawTcp => Ok(SnapBridgeStream::RawTcp(Box::new(tls))),
                    TlsBridgeFraming::WebSocket => {
                        establish_snap_websocket(tls, &websocket_host, &websocket_path)
                            .await
                            .map(Box::new)
                            .map(SnapBridgeStream::WebSocket)
                    }
                    TlsBridgeFraming::SnapShroud => {
                        establish_snap_shroud(&mut tls, shroud_profile).await?;
                        Ok(SnapBridgeStream::SnapShroud(Box::new(tls), shroud_profile))
                    }
                }
            };
            let bridge_stream = match runtime
                .block_on(async { tokio::time::timeout(thread_timeout, setup).await })
            {
                Ok(Ok(stream)) => stream,
                Ok(Err(error)) => {
                    let _ = ready_tx.send(Err(error));
                    return;
                }
                Err(_) => {
                    let _ = ready_tx.send(Err(ShphError::Timeout));
                    return;
                }
            };
            if ready_tx.send(Ok(())).is_err() {
                return;
            }
            runtime.block_on(async move {
                let mut local = tunnel_stream;
                match bridge_stream {
                    SnapBridgeStream::RawTcp(mut tls) => {
                        let _ = tokio::io::copy_bidirectional(&mut local, &mut tls).await;
                    }
                    SnapBridgeStream::WebSocket(websocket) => {
                        let _ = relay_snap_websocket(local, *websocket).await;
                    }
                    SnapBridgeStream::SnapShroud(tls, profile) => {
                        let _ = relay_snap_shroud(local, *tls, profile).await;
                    }
                }
            });
        })
        .map_err(ShphError::Io)?;
    let lifecycle = SnapBridgeLifecycle::new(lifecycle_stream, worker);

    match ready_rx.recv_timeout(timeout) {
        Ok(Ok(())) => Ok((client_stream, Some(lifecycle))),
        Ok(Err(error)) => {
            let _ = client_stream.shutdown(std::net::Shutdown::Both);
            Err(error)
        }
        Err(mpsc::RecvTimeoutError::Timeout) => {
            let _ = client_stream.shutdown(std::net::Shutdown::Both);
            Err(ShphError::Timeout)
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            let _ = client_stream.shutdown(std::net::Shutdown::Both);
            Err(ShphError::Transport(
                "SNAP TLS bridge setup ended unexpectedly".into(),
            ))
        }
    }
}

async fn establish_snap_websocket(
    tls: SnapTlsStream,
    host: &str,
    path: &str,
) -> Result<SnapWebSocketStream> {
    let mut request = format!("wss://{host}{path}")
        .into_client_request()
        .map_err(|_| ShphError::Protocol("SNAP WebSocket request is invalid".into()))?;
    request.headers_mut().insert(
        "sec-websocket-protocol",
        HeaderValue::from_static(SNAP_WEBSOCKET_SUBPROTOCOL),
    );
    let mut config = WebSocketConfig::default();
    config.max_message_size = Some(MAX_WEBSOCKET_MESSAGE_BYTES);
    config.max_frame_size = Some(MAX_WEBSOCKET_MESSAGE_BYTES);
    let (websocket, response) =
        tokio_tungstenite::client_async_with_config(request, tls, Some(config))
            .await
            .map_err(|_| ShphError::Protocol("SNAP WebSocket bridge handshake failed".into()))?;
    let selected_protocol = response
        .headers()
        .get("sec-websocket-protocol")
        .and_then(|value| value.to_str().ok());
    if selected_protocol != Some(SNAP_WEBSOCKET_SUBPROTOCOL) {
        return Err(ShphError::Protocol(
            "SNAP WebSocket bridge selected an unexpected subprotocol".into(),
        ));
    }
    Ok(websocket)
}

async fn relay_snap_websocket(
    local: tokio::net::TcpStream,
    websocket: SnapWebSocketStream,
) -> Result<()> {
    let (mut local_reader, mut local_writer) = tokio::io::split(local);
    let (sink, mut frames) = websocket.split();
    let sink = Arc::new(tokio::sync::Mutex::new(sink));
    let outgoing_sink = Arc::clone(&sink);
    let outgoing = async move {
        let mut buffer = vec![0u8; 16 * 1024];
        loop {
            let count = tokio::io::AsyncReadExt::read(&mut local_reader, &mut buffer)
                .await
                .map_err(|_| ShphError::Transport("SNAP WebSocket tunnel read failed".into()))?;
            if count == 0 {
                outgoing_sink
                    .lock()
                    .await
                    .send(Message::Close(None))
                    .await
                    .map_err(|_| ShphError::Transport("SNAP WebSocket close send failed".into()))?;
                return Ok::<(), ShphError>(());
            }
            outgoing_sink
                .lock()
                .await
                .send(Message::Binary(buffer[..count].to_vec().into()))
                .await
                .map_err(|_| ShphError::Transport("SNAP WebSocket frame send failed".into()))?;
        }
    };
    let incoming_sink = Arc::clone(&sink);
    let incoming = async move {
        while let Some(frame) = frames.next().await {
            match frame
                .map_err(|_| ShphError::Transport("SNAP WebSocket frame receive failed".into()))?
            {
                Message::Binary(payload) => {
                    local_writer.write_all(&payload).await.map_err(|_| {
                        ShphError::Transport("SNAP WebSocket tunnel write failed".into())
                    })?
                }
                Message::Ping(payload) => incoming_sink
                    .lock()
                    .await
                    .send(Message::Pong(payload))
                    .await
                    .map_err(|_| ShphError::Transport("SNAP WebSocket pong send failed".into()))?,
                Message::Close(frame) => {
                    let _ = incoming_sink.lock().await.send(Message::Close(frame)).await;
                    local_writer.shutdown().await.map_err(|_| {
                        ShphError::Transport("SNAP WebSocket tunnel shutdown failed".into())
                    })?;
                    return Ok::<(), ShphError>(());
                }
                Message::Pong(_) => {}
                Message::Text(_) => {
                    return Err(ShphError::Protocol(
                        "SNAP WebSocket bridge sent a text frame".into(),
                    ));
                }
                _ => {}
            }
        }
        Ok::<(), ShphError>(())
    };
    let (outgoing, incoming) = tokio::join!(outgoing, incoming);
    outgoing.and(incoming)
}

fn resolve_snap_shroud_profile(name: Option<&str>) -> Result<SnapShroudProfile> {
    let normalized = name.unwrap_or("balanced").trim().to_ascii_lowercase();
    let (id, cell_size, max_payload, chaff_ms) = match normalized.as_str() {
        "low-latency" | "interactive" => (2, 512, 384, 100),
        "balanced" | "default" | "stealth-safe" => (1, 1024, 768, 250),
        "bulk" | "bulk-transfer" => (3, 4096, 3072, 500),
        _ => {
            return Err(ShphError::Config(
                "SNAP shroud_profile is not supported by the versioned SNAP-Shroud framing".into(),
            ))
        }
    };
    Ok(SnapShroudProfile {
        id,
        cell_size,
        max_payload,
        chaff_interval: Duration::from_millis(chaff_ms),
    })
}

async fn establish_snap_shroud(
    stream: &mut SnapTlsStream,
    profile: SnapShroudProfile,
) -> Result<()> {
    let mut nonce = [0u8; 4];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| ShphError::Crypto("SNAP-Shroud nonce generation failed".into()))?;
    let mut request = Vec::with_capacity(16);
    request.extend_from_slice(SNAP_SHROUD_REQUEST_MAGIC);
    request.push(SNAP_SHROUD_VERSION);
    request.push(profile.id);
    request.extend_from_slice(&(profile.cell_size as u16).to_be_bytes());
    request.extend_from_slice(&nonce);
    stream.write_all(&request).await.map_err(ShphError::Io)?;
    stream.flush().await.map_err(ShphError::Io)?;

    let mut response = [0u8; 16];
    tokio::io::AsyncReadExt::read_exact(stream, &mut response)
        .await
        .map_err(|_| ShphError::Protocol("SNAP-Shroud handshake response was truncated".into()))?;
    if &response[..8] != SNAP_SHROUD_ACK_MAGIC
        || response[8] != SNAP_SHROUD_VERSION
        || response[9] != profile.id
        || u16::from_be_bytes([response[10], response[11]]) as usize != profile.cell_size
        || response[12..] != nonce
    {
        return Err(ShphError::Protocol(
            "SNAP-Shroud bridge rejected the versioned framing handshake".into(),
        ));
    }
    Ok(())
}

fn encode_snap_shroud_cell(
    profile: SnapShroudProfile,
    frame_type: u8,
    payload: &[u8],
) -> Result<Vec<u8>> {
    if payload.len() > profile.max_payload
        || payload.len() + SNAP_SHROUD_CELL_HEADER_BYTES > profile.cell_size
        || !matches!(frame_type, 1 | 2)
        || (frame_type == 2 && !payload.is_empty())
    {
        return Err(ShphError::Protocol(
            "SNAP-Shroud cell exceeds its versioned frame bounds".into(),
        ));
    }
    let mut cell = vec![0u8; profile.cell_size];
    cell[..8].copy_from_slice(SNAP_SHROUD_CELL_MAGIC);
    cell[8] = SNAP_SHROUD_VERSION;
    cell[9] = frame_type;
    cell[10..12].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    cell[SNAP_SHROUD_CELL_HEADER_BYTES..SNAP_SHROUD_CELL_HEADER_BYTES + payload.len()]
        .copy_from_slice(payload);
    Ok(cell)
}

fn decode_snap_shroud_cell(profile: SnapShroudProfile, cell: &[u8]) -> Result<SnapShroudFrame> {
    if cell.len() != profile.cell_size
        || &cell[..8] != SNAP_SHROUD_CELL_MAGIC
        || cell[8] != SNAP_SHROUD_VERSION
    {
        return Err(ShphError::Protocol(
            "SNAP-Shroud cell magic or version is invalid".into(),
        ));
    }
    let payload_len = u16::from_be_bytes([cell[10], cell[11]]) as usize;
    if payload_len > profile.max_payload || payload_len + SNAP_SHROUD_CELL_HEADER_BYTES > cell.len()
    {
        return Err(ShphError::Protocol(
            "SNAP-Shroud cell payload length is invalid".into(),
        ));
    }
    let payload_end = SNAP_SHROUD_CELL_HEADER_BYTES + payload_len;
    if cell[payload_end..].iter().any(|byte| *byte != 0) {
        return Err(ShphError::Protocol(
            "SNAP-Shroud cell padding is invalid".into(),
        ));
    }
    match cell[9] {
        1 => Ok(SnapShroudFrame::Data(
            cell[SNAP_SHROUD_CELL_HEADER_BYTES..payload_end].to_vec(),
        )),
        2 if payload_len == 0 => Ok(SnapShroudFrame::Chaff),
        _ => Err(ShphError::Protocol(
            "SNAP-Shroud frame type is invalid".into(),
        )),
    }
}

async fn write_snap_shroud_cell<W>(
    stream: &mut W,
    profile: SnapShroudProfile,
    frame_type: u8,
    payload: &[u8],
) -> Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let cell = encode_snap_shroud_cell(profile, frame_type, payload)?;
    stream.write_all(&cell).await.map_err(ShphError::Io)?;
    stream.flush().await.map_err(ShphError::Io)?;
    Ok(())
}

async fn read_snap_shroud_cell<R>(
    stream: &mut R,
    profile: SnapShroudProfile,
) -> Result<Option<SnapShroudFrame>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut cell = vec![0u8; profile.cell_size];
    let first = tokio::io::AsyncReadExt::read(stream, &mut cell[..1])
        .await
        .map_err(ShphError::Io)?;
    if first == 0 {
        return Ok(None);
    }
    tokio::io::AsyncReadExt::read_exact(stream, &mut cell[1..])
        .await
        .map_err(|_| ShphError::Protocol("SNAP-Shroud cell was truncated".into()))?;
    decode_snap_shroud_cell(profile, &cell).map(Some)
}

async fn relay_snap_shroud(
    local: tokio::net::TcpStream,
    tls: SnapTlsStream,
    profile: SnapShroudProfile,
) -> Result<()> {
    let (mut local_reader, mut local_writer) = tokio::io::split(local);
    let (mut tls_reader, mut tls_writer) = tokio::io::split(tls);
    let outgoing = async move {
        let mut buffer = vec![0u8; profile.max_payload];
        let mut chaff_timer = tokio::time::interval(profile.chaff_interval);
        chaff_timer.tick().await;
        loop {
            tokio::select! {
                read = tokio::io::AsyncReadExt::read(&mut local_reader, &mut buffer) => {
                    let count = read.map_err(ShphError::Io)?;
                    if count == 0 {
                        tls_writer.shutdown().await.map_err(ShphError::Io)?;
                        return Ok::<(), ShphError>(());
                    }
                    write_snap_shroud_cell(&mut tls_writer, profile, 1, &buffer[..count]).await?;
                }
                _ = chaff_timer.tick() => {
                    write_snap_shroud_cell(&mut tls_writer, profile, 2, &[]).await?;
                }
            }
        }
    };
    let incoming = async move {
        loop {
            match read_snap_shroud_cell(&mut tls_reader, profile).await? {
                Some(SnapShroudFrame::Data(payload)) => {
                    local_writer
                        .write_all(&payload)
                        .await
                        .map_err(ShphError::Io)?;
                }
                Some(SnapShroudFrame::Chaff) => {}
                None => {
                    local_writer.shutdown().await.map_err(ShphError::Io)?;
                    return Ok::<(), ShphError>(());
                }
            }
        }
    };
    let (outgoing, incoming) = tokio::join!(outgoing, incoming);
    outgoing.and(incoming)
}

fn build_tls_client_config(config: &SnapBridgeConfig) -> Result<ClientConfig> {
    let roots = if let Some(path) = config.tls_ca_file.as_deref() {
        let bytes = read_bounded_file(
            Path::new(path),
            MAX_ONION_ROUTE_BYTES * 4,
            "SNAP tls_ca_file",
        )?;
        let certificates = parse_ca_certificates(&bytes)?;
        let mut roots = RootCertStore::empty();
        for certificate in certificates {
            roots
                .add(rustls::pki_types::CertificateDer::from(certificate))
                .map_err(|_| {
                    ShphError::Config("SNAP tls_ca_file contains an invalid certificate".into())
                })?;
        }
        if roots.is_empty() {
            return Err(ShphError::Config(
                "SNAP tls_ca_file contains no trusted certificates".into(),
            ));
        }
        roots
    } else {
        RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned())
    };
    Ok(ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth())
}

fn parse_ca_certificates(bytes: &[u8]) -> Result<Vec<Vec<u8>>> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    if !bytes
        .windows(BEGIN.len())
        .any(|window| window == BEGIN.as_bytes())
    {
        if bytes.is_empty() {
            return Err(ShphError::Config("SNAP tls_ca_file is empty".into()));
        }
        return Ok(vec![bytes.to_vec()]);
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| ShphError::Config("SNAP tls_ca_file is not valid PEM text".into()))?;
    let mut remaining = text;
    let mut certificates = Vec::new();
    while let Some(begin_index) = remaining.find(BEGIN) {
        if !remaining[..begin_index].trim().is_empty() {
            return Err(ShphError::Config(
                "SNAP tls_ca_file contains data outside certificate blocks".into(),
            ));
        }
        let body = &remaining[begin_index + BEGIN.len()..];
        let end_index = body.find(END).ok_or_else(|| {
            ShphError::Config("SNAP tls_ca_file has an unterminated PEM block".into())
        })?;
        let encoded: String = body[..end_index]
            .chars()
            .filter(|character| !character.is_ascii_whitespace())
            .collect();
        let certificate = base64::engine::general_purpose::STANDARD
            .decode(encoded.as_bytes())
            .map_err(|_| ShphError::Config("SNAP tls_ca_file has invalid PEM base64".into()))?;
        if certificate.is_empty() || certificates.len() >= 128 {
            return Err(ShphError::Config(
                "SNAP tls_ca_file has an invalid certificate count".into(),
            ));
        }
        certificates.push(certificate);
        remaining = &body[end_index + END.len()..];
    }
    if !remaining.trim().is_empty() || certificates.is_empty() {
        return Err(ShphError::Config(
            "SNAP tls_ca_file contains an invalid certificate bundle".into(),
        ));
    }
    Ok(certificates)
}

fn parse_sha256_pin(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64 || !value.is_ascii() {
        return Err(ShphError::Config(
            "SNAP tls_cert_sha256 must be a 64-character hexadecimal value".into(),
        ));
    }
    let mut pin = [0u8; 32];
    for (index, byte) in pin.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).map_err(|_| {
            ShphError::Config("SNAP tls_cert_sha256 contains invalid hexadecimal".into())
        })?;
    }
    Ok(pin)
}

fn local_tcp_pair() -> std::io::Result<(TcpStream, TcpStream)> {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let client = TcpStream::connect(listener.local_addr()?)?;
    let (server, _) = listener.accept()?;
    if server.peer_addr()? != client.local_addr()? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "local SNAP tunnel endpoint was not paired with its initiating socket",
        ));
    }
    Ok((client, server))
}

#[derive(Debug)]
struct OnionHop {
    ip: IpAddr,
    port: u16,
    key: Zeroizing<Vec<u8>>,
}

#[derive(Serialize)]
struct OnionLayer<'a> {
    v: u8,
    next_ip: &'a str,
    next_port: u16,
    next_is_relay: bool,
    data_b64: String,
}

fn connect_onion_bridge(config: &SnapBridgeConfig, timeout: Duration) -> Result<TcpStream> {
    let peer_ip = config.peer_host.parse::<IpAddr>().map_err(|_| {
        ShphError::Config("SNAP onion destination must be a literal IP address".into())
    })?;
    if config.peer_port == 0 {
        return Err(ShphError::Config(
            "SNAP onion destination port must be non-zero".into(),
        ));
    }
    let hops = load_route_hops(config)?;
    let first = hops
        .first()
        .ok_or_else(|| ShphError::Config("SNAP onion route has no relays".into()))?;
    let relay_addr = SocketAddr::new(first.ip, first.port);
    let mut stream = TcpStream::connect_timeout(&relay_addr, timeout).map_err(ShphError::Io)?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(ShphError::Io)?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(ShphError::Io)?;

    let packet = build_onion_packet(&hops, &peer_ip.to_string(), config.peer_port)?;
    if packet.len() > MAX_ONION_MESSAGE_BYTES {
        return Err(ShphError::Protocol(
            "SNAP onion setup message exceeds its size limit".into(),
        ));
    }
    let length = u32::try_from(packet.len())
        .map_err(|_| ShphError::Protocol("SNAP onion message length overflow".into()))?;
    stream
        .write_all(&length.to_be_bytes())
        .map_err(ShphError::Io)?;
    stream.write_all(&packet).map_err(ShphError::Io)?;
    stream.flush().map_err(ShphError::Io)?;

    let mut status = [0u8; 1];
    stream.read_exact(&mut status).map_err(ShphError::Io)?;
    match status[0] {
        1 => {
            stream.set_read_timeout(None).map_err(ShphError::Io)?;
            stream.set_write_timeout(None).map_err(ShphError::Io)?;
            Ok(stream)
        }
        0 => Err(ShphError::Transport(
            "operator-configured SNAP onion bridge rejected tunnel setup".into(),
        )),
        _ => Err(ShphError::Protocol(
            "SNAP onion bridge returned an invalid setup status".into(),
        )),
    }
}

fn connect_mesh_dtn_local(config: &SnapBridgeConfig, timeout: Duration) -> Result<TcpStream> {
    if config.peer_port == 0 {
        return Err(ShphError::Config(
            "SNAP mesh destination port must be non-zero".into(),
        ));
    }
    if timeout.is_zero() {
        return Err(ShphError::Timeout);
    }

    let mut endpoints = vec![(config.peer_host.clone(), config.peer_port)];
    for endpoint in load_mesh_peer_endpoints()? {
        if !endpoints.contains(&endpoint) && endpoints.len() < MAX_MESH_ENDPOINTS {
            endpoints.push(endpoint);
        }
    }

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(ShphError::Io)?;
    let started = std::time::Instant::now();
    let per_attempt = timeout / endpoints.len().max(1) as u32;
    let mut last_error = None;
    for (host, port) in endpoints {
        let remaining = timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            break;
        }
        let attempt_timeout = remaining.min(per_attempt).min(Duration::from_secs(6));
        if attempt_timeout.is_zero() {
            break;
        }
        let result = runtime.block_on(async {
            tokio::time::timeout(
                attempt_timeout,
                tokio::net::TcpStream::connect((host.as_str(), port)),
            )
            .await
            .map_err(|_| ShphError::Timeout)?
            .map_err(ShphError::Io)
        });
        match result {
            Ok(stream) => {
                let stream = stream.into_std().map_err(ShphError::Io)?;
                stream.set_nonblocking(false).map_err(ShphError::Io)?;
                stream.set_nodelay(true).map_err(ShphError::Io)?;
                return Ok(stream);
            }
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or(ShphError::Timeout))
}

fn load_mesh_peer_endpoints() -> Result<Vec<(String, u16)>> {
    let configured =
        std::env::var_os("SIERRANODE_MESH_DTN_PEERS_FILE").filter(|value| !value.is_empty());
    let path = match configured {
        Some(path) => PathBuf::from(path),
        None => std::env::current_dir()
            .map_err(ShphError::Io)?
            .join("artifacts")
            .join("snap")
            .join("mesh_peers.json"),
    };
    if !path.exists() {
        return Ok(Vec::new());
    }
    let bytes = read_bounded_file(&path, MAX_MESH_PEER_FILE_BYTES, "SNAP mesh peer file")?;
    let Ok(root) = serde_json::from_slice::<Value>(&bytes) else {
        return Ok(Vec::new());
    };
    let peers = root
        .as_array()
        .or_else(|| root.get("peers").and_then(Value::as_array));
    let Some(peers) = peers else {
        return Ok(Vec::new());
    };

    let mut endpoints = Vec::new();
    for peer in peers.iter().take(MAX_MESH_ENDPOINTS) {
        let Some(fields) = peer.as_object() else {
            continue;
        };
        let Some(host) = fields.get("ip").and_then(Value::as_str).map(str::trim) else {
            continue;
        };
        if host.parse::<IpAddr>().is_err() {
            continue;
        }
        let port = fields
            .get("port")
            .and_then(|value| {
                value
                    .as_u64()
                    .or_else(|| value.as_str()?.trim().parse::<u64>().ok())
            })
            .filter(|port| (1..=u16::MAX as u64).contains(port));
        if let Some(port) = port {
            endpoints.push((host.to_owned(), port as u16));
        }
    }
    Ok(endpoints)
}

fn connect_mule_usb(config: &SnapBridgeConfig, timeout: Duration) -> Result<TcpStream> {
    let proxy_address = std::env::var("SIERRANODE_MULE_PROXY_ADDR").map_err(|_| {
        ShphError::Config("SNAP mule-usb requires SIERRANODE_MULE_PROXY_ADDR".into())
    })?;
    let (proxy_host, proxy_port) = parse_mule_proxy_address(&proxy_address)?;
    let mut stream = connect_tcp_with_timeout(&proxy_host, proxy_port, timeout)?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(ShphError::Io)?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(ShphError::Io)?;

    let request = serde_json::json!({
        "v": 1,
        "op": "connect",
        "target_ip": config.peer_host,
        "target_port": config.peer_port,
        "timeout_sec": timeout.as_secs_f64(),
    });
    let mut request = serde_json::to_vec(&request).map_err(ShphError::Serialization)?;
    request.push(b'\n');
    if request.len() > MAX_MULE_PROXY_HELLO_BYTES {
        return Err(ShphError::Protocol(
            "SNAP mule-usb request exceeds its size limit".into(),
        ));
    }
    stream.write_all(&request).map_err(ShphError::Io)?;
    stream.flush().map_err(ShphError::Io)?;
    let response = read_bounded_line(&mut stream, MAX_MULE_PROXY_HELLO_BYTES)?;
    let response: Value = serde_json::from_slice(&response)
        .map_err(|_| ShphError::Protocol("SNAP mule-usb response is invalid JSON".into()))?;
    let fields = response
        .as_object()
        .ok_or_else(|| ShphError::Protocol("SNAP mule-usb response must be an object".into()))?;
    if fields.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err(ShphError::Transport(
            "operator-configured SNAP mule proxy rejected tunnel setup".into(),
        ));
    }
    stream.set_read_timeout(None).map_err(ShphError::Io)?;
    stream.set_write_timeout(None).map_err(ShphError::Io)?;
    stream.set_nodelay(true).map_err(ShphError::Io)?;
    Ok(stream)
}

fn parse_mule_proxy_address(value: &str) -> Result<(String, u16)> {
    let value = value.trim();
    let (host, port_text) = value
        .rsplit_once(':')
        .ok_or_else(|| ShphError::Config("SIERRANODE_MULE_PROXY_ADDR must be host:port".into()))?;
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host)
        .trim();
    let port = port_text
        .trim()
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0);
    if host.is_empty()
        || host.contains('@')
        || host.contains('/')
        || host
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
        || port.is_none()
    {
        return Err(ShphError::Config(
            "SIERRANODE_MULE_PROXY_ADDR must be host:port".into(),
        ));
    }
    Ok((host.to_owned(), port.expect("validated proxy port")))
}

fn connect_tcp_with_timeout(host: &str, port: u16, timeout: Duration) -> Result<TcpStream> {
    if timeout.is_zero() {
        return Err(ShphError::Timeout);
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(ShphError::Io)?;
    let stream = runtime.block_on(async {
        tokio::time::timeout(timeout, tokio::net::TcpStream::connect((host, port)))
            .await
            .map_err(|_| ShphError::Timeout)?
            .map_err(ShphError::Io)
    })?;
    let stream = stream.into_std().map_err(ShphError::Io)?;
    stream.set_nonblocking(false).map_err(ShphError::Io)?;
    stream.set_nodelay(true).map_err(ShphError::Io)?;
    Ok(stream)
}

fn read_bounded_line(stream: &mut TcpStream, max_bytes: usize) -> Result<Vec<u8>> {
    let mut line = Vec::with_capacity(max_bytes.min(1024));
    while line.len() < max_bytes {
        let mut byte = [0u8; 1];
        let read = stream.read(&mut byte).map_err(ShphError::Io)?;
        if read == 0 {
            break;
        }
        if byte[0] == b'\n' {
            return Ok(line);
        }
        line.push(byte[0]);
    }
    if line.len() == max_bytes {
        return Err(ShphError::Protocol(
            "SNAP mule-usb response exceeds its size limit".into(),
        ));
    }
    if line.is_empty() {
        return Err(ShphError::Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "SNAP mule-usb proxy closed before ready response",
        )));
    }
    Ok(line)
}

fn load_route_hops(config: &SnapBridgeConfig) -> Result<Vec<OnionHop>> {
    let (route, route_dir) = if let Some(route_file) = config.route_file.as_deref() {
        let path = PathBuf::from(route_file);
        let bytes = read_bounded_file(&path, MAX_ONION_ROUTE_BYTES, "SNAP route_file")?;
        let route: Value = serde_json::from_slice(&bytes)
            .map_err(|_| ShphError::Config("SNAP route_file is invalid JSON".into()))?;
        (
            route,
            path.parent()
                .unwrap_or_else(|| Path::new("."))
                .to_path_buf(),
        )
    } else {
        let relay_host = config
            .relay_host
            .as_deref()
            .ok_or_else(|| ShphError::Config("SNAP onion relay host is required".into()))?;
        let relay_port = config
            .relay_port
            .ok_or_else(|| ShphError::Config("SNAP onion relay port is required".into()))?;
        let key_file = config
            .key_file
            .as_deref()
            .ok_or_else(|| ShphError::Config("SNAP onion relay key_file is required".into()))?;
        let mut relays = Vec::with_capacity(1);
        relays.push(serde_json::json!({
            "ip": relay_host,
            "port": relay_port,
            "key_file": key_file,
        }));
        (
            serde_json::json!({"version": 1, "relays": relays}),
            PathBuf::new(),
        )
    };

    let object = route
        .as_object()
        .ok_or_else(|| ShphError::Config("SNAP route_file root must be an object".into()))?;
    if object
        .get("version")
        .and_then(Value::as_u64)
        .is_some_and(|version| version != 1)
    {
        return Err(ShphError::Config(
            "SNAP route_file version must be 1".into(),
        ));
    }
    let relays = object
        .get("relays")
        .and_then(Value::as_array)
        .filter(|items| !items.is_empty() && items.len() <= shph_snap_route_hop_limit())
        .ok_or_else(|| {
            ShphError::Config("SNAP route_file must contain between 1 and 8 relays".into())
        })?;
    let mut hops = Vec::with_capacity(relays.len());
    for (index, entry) in relays.iter().enumerate() {
        let fields = entry.as_object().ok_or_else(|| {
            ShphError::Config(format!("SNAP route relay {} must be an object", index + 1))
        })?;
        let ip = fields
            .get("ip")
            .and_then(Value::as_str)
            .ok_or_else(|| ShphError::Config("SNAP route relay ip is required".into()))?
            .trim()
            .parse::<IpAddr>()
            .map_err(|_| ShphError::Config("SNAP route relay ip must be literal".into()))?;
        let port = fields
            .get("port")
            .and_then(Value::as_u64)
            .filter(|port| (1..=u16::MAX as u64).contains(port))
            .ok_or_else(|| ShphError::Config("SNAP route relay port is invalid".into()))?
            as u16;
        let key_path = fields
            .get("key_file")
            .and_then(Value::as_str)
            .filter(|path| !path.trim().is_empty())
            .ok_or_else(|| {
                ShphError::Config("SNAP route relay requires key_file; key_b64 is disabled".into())
            })?;
        let key_path = PathBuf::from(key_path);
        let key_path = if key_path.is_absolute() {
            key_path
        } else {
            route_dir.join(key_path)
        };
        let key_bytes =
            read_bounded_file(&key_path, MAX_ONION_KEY_FILE_BYTES, "SNAP relay key_file")?;
        let key_text = std::str::from_utf8(&key_bytes).map_err(|_| {
            ShphError::Config("SNAP relay key_file must contain base64 text".into())
        })?;
        let key = Zeroizing::new(
            base64::engine::general_purpose::STANDARD
                .decode(key_text.trim().as_bytes())
                .map_err(|_| ShphError::Config("SNAP relay key_file has invalid base64".into()))?,
        );
        if key.len() != 32 {
            return Err(ShphError::Config(
                "SNAP relay key_file must decode to exactly 32 bytes".into(),
            ));
        }
        hops.push(OnionHop { ip, port, key });
    }
    Ok(hops)
}

fn shph_snap_route_hop_limit() -> usize {
    8
}

fn read_bounded_file(path: &Path, max_bytes: u64, label: &str) -> Result<Vec<u8>> {
    let file = open_readonly_no_reparse(path)
        .map_err(|error| ShphError::Config(format!("unsafe {label}: {error}")))?;
    if file.metadata()?.len() > max_bytes {
        return Err(ShphError::Config(format!("{label} exceeds its size limit")));
    }
    let mut bytes = Vec::new();
    file.take(max_bytes + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        return Err(ShphError::Config(format!("{label} exceeds its size limit")));
    }
    Ok(bytes)
}

fn build_onion_packet(hops: &[OnionHop], final_ip: &str, final_port: u16) -> Result<Vec<u8>> {
    let mut blob = Vec::new();
    for index in (0..hops.len()).rev() {
        let (next_ip, next_port, next_is_relay) = if index + 1 < hops.len() {
            (hops[index + 1].ip.to_string(), hops[index + 1].port, true)
        } else {
            (final_ip.to_owned(), final_port, false)
        };
        let layer = OnionLayer {
            v: 1,
            next_ip: &next_ip,
            next_port,
            next_is_relay,
            data_b64: base64::engine::general_purpose::STANDARD.encode(&blob),
        };
        let plaintext = serde_json::to_vec(&layer).map_err(ShphError::Serialization)?;
        blob = encrypt_onion_layer(&hops[index].key, &plaintext)?;
        if blob.len() > MAX_ONION_MESSAGE_BYTES {
            return Err(ShphError::Protocol(
                "SNAP onion route produces an oversized setup message".into(),
            ));
        }
    }
    Ok(blob)
}

fn encrypt_onion_layer(key_bytes: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    if key_bytes.len() != 32 {
        return Err(ShphError::Config(
            "SNAP onion relay key must be 32 bytes".into(),
        ));
    }
    let key = aead::UnboundKey::new(&aead::AES_256_GCM, key_bytes)
        .map_err(|_| ShphError::Crypto("invalid SNAP onion key".into()))?;
    let key = aead::LessSafeKey::new(key);
    let mut nonce_bytes = [0u8; ONION_NONCE_BYTES];
    SystemRandom::new()
        .fill(&mut nonce_bytes)
        .map_err(|_| ShphError::Crypto("SNAP onion nonce generation failed".into()))?;
    let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);
    let mut ciphertext = plaintext.to_vec();
    key.seal_in_place_append_tag(nonce, aead::Aad::from(ONION_AAD), &mut ciphertext)
        .map_err(|_| ShphError::Crypto("SNAP onion layer encryption failed".into()))?;
    let mut output = Vec::with_capacity(ONION_NONCE_BYTES + ciphertext.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::{
        build_onion_packet, decode_snap_shroud_cell, encode_snap_shroud_cell, encrypt_onion_layer,
        resolve_snap_shroud_profile, OnionHop, SnapShroudFrame, ONION_AAD, ONION_NONCE_BYTES,
        SNAP_SHROUD_CELL_MAGIC,
    };
    use base64::Engine as _;
    use ring::aead;
    use serde_json::Value;
    use std::net::IpAddr;
    use zeroize::Zeroizing;

    fn decrypt_layer(key_bytes: &[u8], blob: &[u8]) -> Vec<u8> {
        assert!(blob.len() >= ONION_NONCE_BYTES + 16);
        let key = aead::UnboundKey::new(&aead::AES_256_GCM, key_bytes).unwrap();
        let key = aead::LessSafeKey::new(key);
        let nonce = aead::Nonce::try_assume_unique_for_key(&blob[..ONION_NONCE_BYTES]).unwrap();
        let mut ciphertext = blob[ONION_NONCE_BYTES..].to_vec();
        let plaintext = key
            .open_in_place(nonce, aead::Aad::from(ONION_AAD), &mut ciphertext)
            .unwrap();
        plaintext.to_vec()
    }

    #[test]
    fn onion_layers_match_python_v1_aes_gcm_envelopes() {
        let key = Zeroizing::new(vec![7; 32]);
        let encrypted = encrypt_onion_layer(&key, br#"{"ok":true}"#).unwrap();
        let decrypted = decrypt_layer(&key, &encrypted);
        assert_eq!(decrypted, br#"{"ok":true}"#);
    }

    #[test]
    fn onion_packet_wraps_each_hop_and_hides_the_final_destination() {
        let first_key = Zeroizing::new(vec![1; 32]);
        let last_key = Zeroizing::new(vec![2; 32]);
        let hops = vec![
            OnionHop {
                ip: "127.0.0.1".parse::<IpAddr>().unwrap(),
                port: 9001,
                key: first_key.clone(),
            },
            OnionHop {
                ip: "127.0.0.2".parse::<IpAddr>().unwrap(),
                port: 9002,
                key: last_key.clone(),
            },
        ];
        let packet = build_onion_packet(&hops, "198.51.100.9", 7443).unwrap();
        let first = decrypt_layer(&first_key, &packet);
        let first: Value = serde_json::from_slice(&first).unwrap();
        assert_eq!(first["next_ip"], "127.0.0.2");
        assert_eq!(first["next_port"], 9002);
        assert_eq!(first["next_is_relay"], true);
        assert!(!first.to_string().contains("198.51.100.9"));

        let inner = base64::engine::general_purpose::STANDARD
            .decode(first["data_b64"].as_str().unwrap())
            .unwrap();
        let last = decrypt_layer(&last_key, &inner);
        let last: Value = serde_json::from_slice(&last).unwrap();
        assert_eq!(last["next_ip"], "198.51.100.9");
        assert_eq!(last["next_port"], 7443);
        assert_eq!(last["next_is_relay"], false);
    }

    #[test]
    fn snap_shroud_v1_cells_use_distinct_magic_and_strict_bounds() {
        let profile = resolve_snap_shroud_profile(Some("balanced")).unwrap();
        let cell = encode_snap_shroud_cell(profile, 1, b"SHPH frame").unwrap();
        assert_eq!(&cell[..8], SNAP_SHROUD_CELL_MAGIC);
        assert_ne!(&cell[..2], b"S2");
        assert_ne!(&cell[..4], b"PH1\0");
        assert_eq!(
            decode_snap_shroud_cell(profile, &cell).unwrap(),
            SnapShroudFrame::Data(b"SHPH frame".to_vec())
        );

        let chaff = encode_snap_shroud_cell(profile, 2, &[]).unwrap();
        assert!(matches!(
            decode_snap_shroud_cell(profile, &chaff).unwrap(),
            SnapShroudFrame::Chaff
        ));
        assert_eq!(
            resolve_snap_shroud_profile(Some("stealth-safe"))
                .unwrap()
                .id,
            profile.id
        );
        assert!(resolve_snap_shroud_profile(Some("unlisted-profile")).is_err());

        let mut wrong_version = cell.clone();
        wrong_version[8] = 2;
        assert!(decode_snap_shroud_cell(profile, &wrong_version).is_err());
        let mut wrong_padding = cell;
        *wrong_padding.last_mut().unwrap() = 1;
        assert!(decode_snap_shroud_cell(profile, &wrong_padding).is_err());
        assert!(encode_snap_shroud_cell(profile, 2, b"not chaff").is_err());
    }
}
