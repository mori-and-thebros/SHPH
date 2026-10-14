//! Standards-compliant QUIC transport.
//!
//! This module uses Quinn for RFC 9000 transport behavior and TLS 1.3
//! protection. The existing SHPH authenticated hybrid handshake runs inside a
//! reliable QUIC bidirectional stream, while tunnel payloads use RFC 9221
//! application datagrams. The legacy `TransportMode::Quic` API remains the
//! experimental UDP shim for compatibility; callers must opt into this module
//! explicitly.

use crate::ja4::{self, Ja4Observer, Ja4ObserverConfig};
use crate::phantom_one::{
    PhantomOneConfig, PhantomOneDecoder, PhantomOneEncoder, PhantomOneFrameType,
    PHANTOM_ONE_HEADER_BYTES,
};
use crate::shroud2::{
    decode_batched_datagram, decode_datagram_in_place, encode_batched_datagram,
    MorphologyBatchPushResult, MorphologyBatcher, MorphologyEngine,
};
use bytes::Bytes;
use quinn::rustls::server::ResolvesServerCert;
use quinn::{
    ClientConfig, Connection, Endpoint, RecvStream, SendStream, ServerConfig, TransportConfig,
    VarInt,
};
use shph_core::{
    absorb_responder_pq, build_hello_with_profile, finalize_initiator_pq, verify_and_derive,
    verify_hello_signature, HandshakeProfile, HandshakeState, Hello, IdentityKeyPair, PeerPolicy,
    ReceiveCipher, Result, SendCipher, ShphError,
};
use shph_obfuscation::ProfileTier;
use std::net::SocketAddr;
use std::sync::{mpsc, Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use tokio::time::timeout;
use zeroize::{Zeroize, Zeroizing};

const MAX_HANDSHAKE_MESSAGE_BYTES: usize = 16 * 1024;
const MAX_CONTROL_MESSAGE_BYTES: usize = 64 * 1024;
const MAX_TUN_DATAGRAM_BYTES: usize = 65_535;
pub(crate) const SHPH_AEAD_OVERHEAD_BYTES: usize = 12 + 16;
const MAX_PHANTOM_ONE_STREAM_ENVELOPE_BYTES: usize = 16 * 1024;
const MAX_PHANTOM_ONE_STREAM_RECORD_BYTES: usize =
    MAX_PHANTOM_ONE_STREAM_ENVELOPE_BYTES + SHPH_AEAD_OVERHEAD_BYTES;
const PHANTOM_ONE_STREAM_INTRO: &[u8] = b"SHPH/phantom-one-stream/1";
const PHANTOM_ONE_STREAM_RESET_CODE: VarInt = VarInt::from_u32(0x100);
const PHANTOM_ONE_CAPABILITY_MAGIC: &[u8] = b"SHPH-PH1-CAP/1";
const PHANTOM_ONE_CAPABILITY_DISABLED: u8 = u8::MAX;
const PHANTOM_ONE_CAPABILITY_BYTES: usize = PHANTOM_ONE_CAPABILITY_MAGIC.len() + 1;
const MAX_DATAGRAM_BUFFER_BYTES: usize = 1024 * 1024;
const MAX_CONCURRENT_STREAMS: u64 = 1024;
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_DATAGRAM_BUFFER_BYTES: usize = 256 * 1024;
const MIN_IDLE_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);
const STANDARDS_QUIC_ALPN: &[u8] = b"shph/standards-quic/1";

/// A bounded transport configuration for the standards QUIC path.
#[derive(Debug, Clone)]
pub struct StandardsQuicConfig {
    pub idle_timeout: Duration,
    pub max_datagram_buffer_bytes: usize,
    pub max_concurrent_bidirectional_streams: u64,
    pub max_concurrent_unidirectional_streams: u64,
}

impl Default for StandardsQuicConfig {
    fn default() -> Self {
        Self {
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            max_datagram_buffer_bytes: DEFAULT_DATAGRAM_BUFFER_BYTES,
            max_concurrent_bidirectional_streams: 16,
            max_concurrent_unidirectional_streams: 0,
        }
    }
}

impl StandardsQuicConfig {
    fn transport_config(&self) -> Result<Arc<TransportConfig>> {
        if self.max_datagram_buffer_bytes == 0
            || self.max_datagram_buffer_bytes > MAX_DATAGRAM_BUFFER_BYTES
        {
            return Err(ShphError::Config(format!(
                "QUIC datagram buffer must be between 1 and {MAX_DATAGRAM_BUFFER_BYTES} bytes"
            )));
        }
        if self.max_concurrent_bidirectional_streams > MAX_CONCURRENT_STREAMS
            || self.max_concurrent_unidirectional_streams > MAX_CONCURRENT_STREAMS
        {
            return Err(ShphError::Config(format!(
                "QUIC stream limits cannot exceed {MAX_CONCURRENT_STREAMS}"
            )));
        }
        if self.idle_timeout < MIN_IDLE_TIMEOUT || self.idle_timeout > MAX_IDLE_TIMEOUT {
            return Err(ShphError::Config(format!(
                "QUIC idle timeout must be between {} and {} seconds",
                MIN_IDLE_TIMEOUT.as_secs(),
                MAX_IDLE_TIMEOUT.as_secs()
            )));
        }
        let idle_timeout = self
            .idle_timeout
            .try_into()
            .map_err(|_| ShphError::Config("invalid QUIC idle timeout".into()))?;
        let mut transport = TransportConfig::default();
        transport
            .max_idle_timeout(Some(idle_timeout))
            .max_concurrent_bidi_streams(
                VarInt::from_u64(self.max_concurrent_bidirectional_streams)
                    .map_err(|_| ShphError::Config("invalid QUIC bidi stream limit".into()))?,
            )
            .max_concurrent_uni_streams(
                VarInt::from_u64(self.max_concurrent_unidirectional_streams)
                    .map_err(|_| ShphError::Config("invalid QUIC uni stream limit".into()))?,
            )
            .datagram_receive_buffer_size(Some(self.max_datagram_buffer_bytes))
            .datagram_send_buffer_size(self.max_datagram_buffer_bytes);
        Ok(Arc::new(transport))
    }
}

/// A server endpoint and the certificate bytes clients should trust.
pub struct StandardsQuicServer {
    pub endpoint: Endpoint,
    pub certificate_der: Vec<u8>,
}

/// Persistent TLS material for a standards-QUIC server.
///
/// The certificate is public and may be distributed to clients out of band.
/// The PKCS#8 private key must remain owner-controlled by the caller.
pub struct StandardsQuicServerMaterial {
    certificate_der: Vec<u8>,
    private_key_der: Zeroizing<Vec<u8>>,
}

impl StandardsQuicServerMaterial {
    pub fn new(certificate_der: Vec<u8>, private_key_der: Vec<u8>) -> Result<Self> {
        if certificate_der.is_empty() {
            return Err(ShphError::Config(
                "QUIC server certificate cannot be empty".into(),
            ));
        }
        if private_key_der.is_empty() {
            return Err(ShphError::Config(
                "QUIC server private key cannot be empty".into(),
            ));
        }
        Ok(Self {
            certificate_der,
            private_key_der: Zeroizing::new(private_key_der),
        })
    }

    pub fn certificate_der(&self) -> &[u8] {
        &self.certificate_der
    }

    pub fn private_key_der(&self) -> &[u8] {
        &self.private_key_der
    }
}

/// Generate a self-signed certificate and PKCS#8 key for a controlled lab.
///
/// Callers should persist the returned material and reuse it for the
/// lifetime of the deployment. Regenerating it on every reconnect invalidates
/// clients that pin the certificate bytes.
pub fn generate_server_material() -> Result<StandardsQuicServerMaterial> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .map_err(|err| ShphError::Config(format!("generate QUIC certificate: {err}")))?;
    StandardsQuicServerMaterial::new(cert.cert.der().to_vec(), cert.key_pair.serialize_der())
}

/// An established standards QUIC session.
pub struct StandardsQuicConnection {
    pub connection: Connection,
    pub handshake: HandshakeState,
    control_send: SendStream,
    control_recv: RecvStream,
    phantom_one: Option<PhantomOneState>,
    phantom_one_negotiated: bool,
}

const BLOCKING_QUIC_COMMAND_CAPACITY: usize = 16;
const BLOCKING_QUIC_RECEIVE_CAPACITY: usize = 64;
const BLOCKING_QUIC_SEND_TIMEOUT: Duration = Duration::from_secs(30);
const BLOCKING_QUIC_POLL_INTERVAL: Duration = Duration::from_millis(10);

enum BlockingQuicCommand {
    Send {
        payload: Vec<u8>,
        reply: mpsc::SyncSender<Result<()>>,
    },
}

struct BlockingQuicShared {
    command_tx: mpsc::SyncSender<BlockingQuicCommand>,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl Drop for BlockingQuicShared {
    fn drop(&mut self) {
        self.shutdown_tx.send_replace(true);
        if let Ok(worker) = self.worker.get_mut() {
            if let Some(worker) = worker.take() {
                let _ = worker.join();
            }
        }
    }
}

/// A synchronous session adapter for code that already uses `SecureSession`.
///
/// Quinn runs on a private Tokio runtime thread. The session remains gated
/// until `activate` is called, allowing the caller to enforce its local SHPH
/// peer policy before the data plane starts. QUIC DATAGRAM retains its normal
/// unreliable delivery semantics.
pub struct BlockingStandardsQuicSession {
    activation: Option<mpsc::SyncSender<()>>,
    sender: BlockingStandardsQuicSender,
    receiver: Option<BlockingStandardsQuicReceiver>,
}

pub struct BlockingStandardsQuicSender {
    shared: Arc<BlockingQuicShared>,
}

pub struct BlockingStandardsQuicReceiver {
    shared: Arc<BlockingQuicShared>,
    incoming: mpsc::Receiver<Result<Vec<u8>>>,
    poll_timeout: Duration,
}

struct PhantomOneState {
    profile: ProfileTier,
    send_cipher: SendCipher,
    recv_cipher: ReceiveCipher,
    encoder: PhantomOneEncoder,
    decoder: PhantomOneDecoder,
    application_send: Option<SendStream>,
    application_recv: Option<RecvStream>,
}

/// Create a self-signed server endpoint for lab or controlled deployments.
///
/// The returned certificate must be distributed out of band and supplied to
/// [`connect`] via [`client_endpoint`]. It is not a replacement for an
/// operator-managed PKI deployment.
pub fn server_endpoint(
    bind_addr: SocketAddr,
    config: StandardsQuicConfig,
) -> Result<StandardsQuicServer> {
    let material = generate_server_material()?;
    server_endpoint_with_material(bind_addr, &material, config)
}

/// Create a standards QUIC server from stable, caller-managed TLS material.
pub fn server_endpoint_with_material(
    bind_addr: SocketAddr,
    material: &StandardsQuicServerMaterial,
    config: StandardsQuicConfig,
) -> Result<StandardsQuicServer> {
    build_server_endpoint(
        bind_addr,
        material.certificate_der.clone(),
        material.private_key_der(),
        config,
        None,
    )
}

/// Create a standards QUIC server with an optional passive JA4 observer.
///
/// The observer receives bounded metadata from the real rustls ClientHello.
/// It does not rewrite the handshake or affect certificate selection. Because
/// rustls does not expose the complete extension list through this hook, live
/// observations are explicitly marked as partial in [`ja4::Ja4Observation`].
pub fn server_endpoint_with_ja4_observer(
    bind_addr: SocketAddr,
    config: StandardsQuicConfig,
    observer: Arc<dyn Ja4Observer>,
    observer_config: Ja4ObserverConfig,
) -> Result<StandardsQuicServer> {
    let material = generate_server_material()?;
    server_endpoint_with_material_and_ja4_observer(
        bind_addr,
        &material,
        config,
        observer,
        observer_config,
    )
}

/// Create a standards QUIC server from stable TLS material with an observer.
pub fn server_endpoint_with_material_and_ja4_observer(
    bind_addr: SocketAddr,
    material: &StandardsQuicServerMaterial,
    config: StandardsQuicConfig,
    observer: Arc<dyn Ja4Observer>,
    observer_config: Ja4ObserverConfig,
) -> Result<StandardsQuicServer> {
    build_server_endpoint(
        bind_addr,
        material.certificate_der.clone(),
        material.private_key_der(),
        config,
        Some((observer, observer_config)),
    )
}

fn build_server_endpoint(
    bind_addr: SocketAddr,
    certificate_der: Vec<u8>,
    private_key_der: &[u8],
    config: StandardsQuicConfig,
    observer: Option<(Arc<dyn Ja4Observer>, Ja4ObserverConfig)>,
) -> Result<StandardsQuicServer> {
    if certificate_der.is_empty() || private_key_der.is_empty() {
        return Err(ShphError::Config(
            "QUIC server certificate and private key cannot be empty".into(),
        ));
    }
    let certificate = quinn::rustls::pki_types::CertificateDer::from(certificate_der.clone());
    let private_key = quinn::rustls::pki_types::PrivatePkcs8KeyDer::from(private_key_der.to_vec());
    let tls_config = build_server_tls_config(certificate, private_key.into(), observer)?;
    let quic_config = quinn::crypto::rustls::QuicServerConfig::try_from(Arc::new(tls_config))
        .map_err(|err| ShphError::Config(format!("configure QUIC TLS provider: {err}")))?;
    let mut server_config = ServerConfig::with_crypto(Arc::new(quic_config));
    server_config
        .max_incoming(256)
        .incoming_buffer_size(256 * 1024)
        .incoming_buffer_size_total(4 * 1024 * 1024);
    server_config.transport = config.transport_config()?;
    let endpoint = Endpoint::server(server_config, bind_addr).map_err(ShphError::Io)?;
    Ok(StandardsQuicServer {
        endpoint,
        certificate_der,
    })
}

/// Create a client endpoint that trusts exactly the supplied server
/// certificate.
pub fn client_endpoint(
    bind_addr: SocketAddr,
    server_certificate_der: &[u8],
    config: StandardsQuicConfig,
) -> Result<Endpoint> {
    let tls_config = build_client_tls_config(server_certificate_der)?;
    let quic_config = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(tls_config))
        .map_err(|err| ShphError::Config(format!("configure QUIC client TLS provider: {err}")))?;
    let mut client_config = ClientConfig::new(Arc::new(quic_config));
    client_config.transport_config(config.transport_config()?);
    let mut endpoint = Endpoint::client(bind_addr).map_err(ShphError::Io)?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

fn build_server_tls_config(
    certificate: quinn::rustls::pki_types::CertificateDer<'static>,
    private_key: quinn::rustls::pki_types::PrivateKeyDer<'static>,
    observer: Option<(Arc<dyn Ja4Observer>, Ja4ObserverConfig)>,
) -> Result<quinn::rustls::ServerConfig> {
    let provider = Arc::new(quinn::rustls::crypto::ring::default_provider());
    let certified_key =
        quinn::rustls::sign::CertifiedKey::from_der(vec![certificate], private_key, &provider)
            .map_err(|err| {
                ShphError::Config(format!("configure QUIC server certificate: {err}"))
            })?;
    let resolver: Arc<dyn ResolvesServerCert> = match observer {
        None => Arc::new(quinn::rustls::sign::SingleCertAndKey::from(certified_key)),
        Some((observer, observer_config)) => {
            let resolver = Arc::new(quinn::rustls::sign::SingleCertAndKey::from(certified_key));
            ja4::wrap_server_cert_resolver(resolver, observer, observer_config)
        }
    };
    let mut tls_config = quinn::rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&quinn::rustls::version::TLS13])
        .map_err(|err| ShphError::Config(format!("configure QUIC TLS versions: {err}")))?
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    tls_config.alpn_protocols = vec![STANDARDS_QUIC_ALPN.to_vec()];
    tls_config.max_early_data_size = 0;
    Ok(tls_config)
}

fn build_client_tls_config(server_certificate_der: &[u8]) -> Result<quinn::rustls::ClientConfig> {
    let provider = Arc::new(quinn::rustls::crypto::ring::default_provider());
    let mut roots = quinn::rustls::RootCertStore::empty();
    roots
        .add(quinn::rustls::pki_types::CertificateDer::from(
            server_certificate_der.to_vec(),
        ))
        .map_err(|err| ShphError::Config(format!("load QUIC server certificate: {err}")))?;
    let mut tls_config = quinn::rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&quinn::rustls::version::TLS13])
        .map_err(|err| ShphError::Config(format!("configure QUIC TLS versions: {err}")))?
        .with_root_certificates(Arc::new(roots))
        .with_no_client_auth();
    tls_config.alpn_protocols = vec![STANDARDS_QUIC_ALPN.to_vec()];
    tls_config.enable_early_data = false;
    Ok(tls_config)
}

/// Establish a standards QUIC connection and run the SHPH application
/// handshake before returning any data-plane handle.
pub async fn connect(
    endpoint: &Endpoint,
    peer_addr: SocketAddr,
    server_name: &str,
    local_identity: &IdentityKeyPair,
    policy: &PeerPolicy,
    profile: HandshakeProfile,
    handshake_timeout: Duration,
) -> Result<StandardsQuicConnection> {
    timeout(
        handshake_timeout,
        connect_inner(
            endpoint,
            peer_addr,
            server_name,
            local_identity,
            policy,
            profile,
        ),
    )
    .await
    .map_err(|_| ShphError::Timeout)?
}

async fn connect_inner(
    endpoint: &Endpoint,
    peer_addr: SocketAddr,
    server_name: &str,
    local_identity: &IdentityKeyPair,
    policy: &PeerPolicy,
    profile: HandshakeProfile,
) -> Result<StandardsQuicConnection> {
    let connection = endpoint
        .connect(peer_addr, server_name)
        .map_err(|err| match err {
            quinn::ConnectError::InvalidServerName(_)
            | quinn::ConnectError::InvalidRemoteAddress(_)
            | quinn::ConnectError::NoDefaultClientConfig => {
                ShphError::Config("invalid standards QUIC connection parameters".into())
            }
            error => ShphError::Transport(error.to_string()),
        })?
        .await
        .map_err(map_quic_connection_error)?;
    let (mut control_send, mut control_recv) = connection
        .open_bi()
        .await
        .map_err(map_quic_connection_error)?;
    let mut material = build_hello_with_profile(local_identity, profile)?;
    write_message(
        &mut control_send,
        &serde_json::to_vec(&material.local_hello).map_err(ShphError::Serialization)?,
        MAX_HANDSHAKE_MESSAGE_BYTES,
    )
    .await?;
    let peer_hello = read_hello(&mut control_recv).await?;
    verify_hello_signature(local_identity, &material, &peer_hello, policy)?;
    if profile.uses_pqc() {
        let ciphertext = finalize_initiator_pq(local_identity, &mut material, &peer_hello, policy)?;
        write_message(
            &mut control_send,
            &ciphertext,
            shph_core::ML_KEM_768_CIPHERTEXT_BYTES,
        )
        .await?;
    }
    let handshake = verify_and_derive(local_identity, &material, &peer_hello, true, policy)?;
    Ok(StandardsQuicConnection {
        connection,
        handshake,
        control_send,
        control_recv,
        phantom_one: None,
        phantom_one_negotiated: false,
    })
}

fn map_quic_connection_error(error: quinn::ConnectionError) -> ShphError {
    if let quinn::ConnectionError::TransportError(transport_error) = &error {
        let code = u64::from(transport_error.code);
        if transport_error.reason.starts_with("TLS error:") || (0x100..0x200).contains(&code) {
            return ShphError::Auth(
                "standards QUIC TLS peer authentication or protocol negotiation failed".into(),
            );
        }
        if transport_error.code == quinn::TransportErrorCode::CONNECTION_REFUSED
            || transport_error.code == quinn::TransportErrorCode::NO_VIABLE_PATH
        {
            return ShphError::Transport(error.to_string());
        }
        return ShphError::Protocol("standards QUIC transport protocol failure".into());
    }
    match error {
        quinn::ConnectionError::VersionMismatch => {
            ShphError::Protocol("standards QUIC version negotiation failed".into())
        }
        error => ShphError::Transport(error.to_string()),
    }
}

impl BlockingStandardsQuicSession {
    /// Establish a standards-QUIC connection on a private runtime thread and
    /// return it inactive. `activate` must be called after the caller has
    /// enforced its local peer policy.
    pub fn connect(
        peer_addr: SocketAddr,
        server_name: String,
        server_certificate_der: Vec<u8>,
        local_identity: IdentityKeyPair,
        policy: PeerPolicy,
        profile: HandshakeProfile,
        handshake_timeout: Duration,
    ) -> Result<(Self, HandshakeState)> {
        if handshake_timeout.is_zero() {
            return Err(ShphError::Config(
                "standards QUIC handshake timeout must be greater than zero".into(),
            ));
        }

        let (startup_tx, startup_rx) = mpsc::sync_channel(1);
        let (activation_tx, activation_rx) = mpsc::sync_channel(1);
        let (command_tx, command_rx) = mpsc::sync_channel(BLOCKING_QUIC_COMMAND_CAPACITY);
        let (incoming_tx, incoming_rx) = mpsc::sync_channel(BLOCKING_QUIC_RECEIVE_CAPACITY);
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let worker_shutdown_tx = shutdown_tx.clone();

        let worker = thread::Builder::new()
            .name("shph-standards-quic".into())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        let _ = startup_tx.send(Err(ShphError::Internal(format!(
                            "start standards QUIC runtime: {error}"
                        ))));
                        return;
                    }
                };

                let setup = runtime.block_on(async {
                    let endpoint = client_endpoint(
                        "0.0.0.0:0".parse().expect("valid ephemeral endpoint"),
                        &server_certificate_der,
                        StandardsQuicConfig::default(),
                    )?;
                    let connection = connect(
                        &endpoint,
                        peer_addr,
                        &server_name,
                        &local_identity,
                        &policy,
                        profile,
                        handshake_timeout,
                    )
                    .await?;
                    Ok::<_, ShphError>((endpoint, connection))
                });

                let (endpoint, connection) = match setup {
                    Ok(setup) => setup,
                    Err(error) => {
                        let _ = startup_tx.send(Err(error));
                        return;
                    }
                };
                let state = connection.handshake.clone();
                if startup_tx.send(Ok(state)).is_err() {
                    endpoint.close(0u32.into(), b"session setup cancelled");
                    return;
                }
                if activation_rx.recv().is_err() {
                    endpoint.close(0u32.into(), b"peer policy rejected");
                    return;
                }

                let receive_error_tx = incoming_tx.clone();
                let result = runtime.block_on(run_blocking_quic_data_plane(
                    connection,
                    command_rx,
                    incoming_tx,
                    shutdown_rx,
                ));
                if let Err(error) = result {
                    let _ = receive_error_tx.send(Err(error));
                }
                endpoint.close(0u32.into(), b"session closed");
                let _ = runtime.block_on(async {
                    tokio::time::timeout(Duration::from_secs(1), endpoint.wait_idle()).await
                });
            })
            .map_err(ShphError::Io)?;

        let startup_wait = handshake_timeout.saturating_add(Duration::from_secs(2));
        let state = match startup_rx.recv_timeout(startup_wait) {
            Ok(Ok(state)) => state,
            Ok(Err(error)) => {
                drop(activation_tx);
                let _ = worker.join();
                return Err(error);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                shutdown_tx.send_replace(true);
                drop(activation_tx);
                let _ = worker.join();
                return Err(ShphError::Timeout);
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                drop(activation_tx);
                let _ = worker.join();
                return Err(ShphError::Internal(
                    "standards QUIC worker exited during setup".into(),
                ));
            }
        };

        let shared = Arc::new(BlockingQuicShared {
            command_tx,
            shutdown_tx: worker_shutdown_tx,
            worker: Mutex::new(Some(worker)),
        });
        let session = Self {
            activation: Some(activation_tx),
            sender: BlockingStandardsQuicSender {
                shared: Arc::clone(&shared),
            },
            receiver: Some(BlockingStandardsQuicReceiver {
                shared,
                incoming: incoming_rx,
                poll_timeout: Duration::from_millis(100),
            }),
        };
        Ok((session, state))
    }

    /// Release the authenticated data plane after local peer-policy checks.
    pub fn activate(&mut self) -> Result<()> {
        let activation = self.activation.take().ok_or(ShphError::AlreadyConnected)?;
        activation.send(()).map_err(|_| ShphError::ConnectionClosed)
    }

    pub fn send_frame(&mut self, payload: &[u8]) -> Result<()> {
        if self.activation.is_some() {
            return Err(ShphError::Auth(
                "standards QUIC data plane is not active before peer policy enforcement".into(),
            ));
        }
        self.sender.send_frame(payload)
    }

    pub fn set_poll_timeout(&mut self, timeout: Duration) -> Result<()> {
        self.receiver
            .as_mut()
            .ok_or(ShphError::ConnectionClosed)?
            .set_poll_timeout(timeout)
    }

    pub fn recv_frame(&mut self) -> Result<Vec<u8>> {
        if self.activation.is_some() {
            return Err(ShphError::Auth(
                "standards QUIC data plane is not active before peer policy enforcement".into(),
            ));
        }
        self.receiver
            .as_mut()
            .ok_or(ShphError::ConnectionClosed)?
            .recv_frame()
    }

    pub fn into_split(
        mut self,
    ) -> Result<(BlockingStandardsQuicSender, BlockingStandardsQuicReceiver)> {
        if self.activation.is_some() {
            return Err(ShphError::Auth(
                "standards QUIC session must pass peer policy before split".into(),
            ));
        }
        let receiver = self.receiver.take().ok_or(ShphError::ConnectionClosed)?;
        Ok((self.sender, receiver))
    }
}

impl BlockingStandardsQuicSender {
    pub fn send_frame(&mut self, payload: &[u8]) -> Result<()> {
        if payload.len() > MAX_TUN_DATAGRAM_BYTES {
            return Err(ShphError::Protocol(
                "QUIC datagram exceeds 65535 bytes".into(),
            ));
        }
        let (reply_tx, reply_rx) = mpsc::sync_channel(1);
        self.shared
            .command_tx
            .send(BlockingQuicCommand::Send {
                payload: payload.to_vec(),
                reply: reply_tx,
            })
            .map_err(|_| ShphError::ConnectionClosed)?;
        match reply_rx.recv_timeout(BLOCKING_QUIC_SEND_TIMEOUT) {
            Ok(result) => result,
            Err(mpsc::RecvTimeoutError::Timeout) => Err(ShphError::Timeout),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(ShphError::ConnectionClosed),
        }
    }
}

impl BlockingStandardsQuicReceiver {
    pub fn set_poll_timeout(&mut self, timeout: Duration) -> Result<()> {
        self.poll_timeout = timeout
            .max(Duration::from_millis(1))
            .min(Duration::from_secs(60));
        Ok(())
    }

    pub fn recv_frame(&mut self) -> Result<Vec<u8>> {
        let _keep_worker_alive = &self.shared;
        match self.incoming.recv_timeout(self.poll_timeout) {
            Ok(result) => result,
            Err(mpsc::RecvTimeoutError::Timeout) => Err(ShphError::Timeout),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(ShphError::ConnectionClosed),
        }
    }
}

async fn run_blocking_quic_data_plane(
    connection: StandardsQuicConnection,
    command_rx: mpsc::Receiver<BlockingQuicCommand>,
    incoming_tx: mpsc::SyncSender<Result<Vec<u8>>>,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let receive_connection = connection.connection.clone();
    let send = run_blocking_quic_sender(connection, command_rx, shutdown_rx.clone());
    let receive = run_blocking_quic_receiver(receive_connection, incoming_tx, shutdown_rx);
    tokio::pin!(send, receive);
    tokio::select! {
        result = &mut send => result,
        result = &mut receive => result,
    }
}

async fn run_blocking_quic_sender(
    connection: StandardsQuicConnection,
    command_rx: mpsc::Receiver<BlockingQuicCommand>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    loop {
        if *shutdown_rx.borrow() {
            return Ok(());
        }
        match command_rx.try_recv() {
            Ok(BlockingQuicCommand::Send { payload, reply }) => {
                let payload = Zeroizing::new(payload);
                let result = tokio::select! {
                    result = connection.send_datagram_wait(&payload) => result,
                    changed = shutdown_rx.changed() => {
                        let _ = reply.send(Err(ShphError::ConnectionClosed));
                        let _ = changed;
                        return Ok(());
                    }
                };
                let stop_session = result
                    .as_ref()
                    .is_err_and(|error| !matches!(error, ShphError::Protocol(_)));
                let _ = reply.send(result);
                if stop_session {
                    return Err(ShphError::ConnectionClosed);
                }
            }
            Err(mpsc::TryRecvError::Disconnected) => return Ok(()),
            Err(mpsc::TryRecvError::Empty) => {}
        }

        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() {
                    return Ok(());
                }
            }
            _ = tokio::time::sleep(BLOCKING_QUIC_POLL_INTERVAL) => {}
        }
    }
}

async fn run_blocking_quic_receiver(
    connection: Connection,
    incoming_tx: mpsc::SyncSender<Result<Vec<u8>>>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let mut pending: Option<Result<Vec<u8>>> = None;
    loop {
        if *shutdown_rx.borrow() {
            return Ok(());
        }
        if let Some(datagram) = pending.take() {
            let terminal = datagram.is_err();
            match incoming_tx.try_send(datagram) {
                Ok(()) if terminal => return Ok(()),
                Ok(()) => {}
                Err(mpsc::TrySendError::Full(datagram)) => pending = Some(datagram),
                Err(mpsc::TrySendError::Disconnected(_)) => return Ok(()),
            }
        }

        if pending.is_some() {
            tokio::select! {
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        return Ok(());
                    }
                }
                _ = tokio::time::sleep(BLOCKING_QUIC_POLL_INTERVAL) => {}
            }
            continue;
        }

        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() {
                    return Ok(());
                }
            }
            result = connection.read_datagram() => {
                pending = Some(result.map_err(map_quic_connection_error).and_then(|datagram| {
                    if datagram.len() > MAX_TUN_DATAGRAM_BYTES {
                        Err(ShphError::Protocol(
                            "received QUIC datagram exceeds 65535 bytes".into(),
                        ))
                    } else {
                        Ok(datagram.to_vec())
                    }
                }));
            }
        }
    }
}

/// Accept one standards QUIC connection and run the SHPH application
/// handshake before returning any data-plane handle.
pub async fn accept(
    server: &StandardsQuicServer,
    local_identity: &IdentityKeyPair,
    policy: &PeerPolicy,
    profile: HandshakeProfile,
    handshake_timeout: Duration,
) -> Result<StandardsQuicConnection> {
    timeout(
        handshake_timeout,
        accept_inner(server, local_identity, policy, profile),
    )
    .await
    .map_err(|_| ShphError::Timeout)?
}

async fn accept_inner(
    server: &StandardsQuicServer,
    local_identity: &IdentityKeyPair,
    policy: &PeerPolicy,
    profile: HandshakeProfile,
) -> Result<StandardsQuicConnection> {
    let incoming = loop {
        let incoming = server
            .endpoint
            .accept()
            .await
            .ok_or_else(|| ShphError::Transport("QUIC endpoint closed".into()))?;
        if incoming.may_retry() {
            incoming
                .retry()
                .map_err(|err| ShphError::Transport(err.to_string()))?;
            continue;
        }
        break incoming;
    };
    let connection = incoming
        .await
        .map_err(|err| ShphError::Transport(err.to_string()))?;
    let (mut control_send, mut control_recv) = connection
        .accept_bi()
        .await
        .map_err(|err| ShphError::Transport(err.to_string()))?;
    let peer_hello = read_hello(&mut control_recv).await?;
    let mut material = build_hello_with_profile(local_identity, profile)?;
    verify_hello_signature(local_identity, &material, &peer_hello, policy)?;
    write_message(
        &mut control_send,
        &serde_json::to_vec(&material.local_hello).map_err(ShphError::Serialization)?,
        MAX_HANDSHAKE_MESSAGE_BYTES,
    )
    .await?;
    if profile.uses_pqc() {
        let ciphertext =
            read_message(&mut control_recv, shph_core::ML_KEM_768_CIPHERTEXT_BYTES).await?;
        absorb_responder_pq(
            local_identity,
            &mut material,
            &peer_hello,
            &ciphertext,
            policy,
        )?;
    }
    let handshake = verify_and_derive(local_identity, &material, &peer_hello, false, policy)?;
    Ok(StandardsQuicConnection {
        connection,
        handshake,
        control_send,
        control_recv,
        phantom_one: None,
        phantom_one_negotiated: false,
    })
}

impl StandardsQuicConnection {
    /// Send one bounded reliable control-plane message on the handshake stream.
    pub async fn send_control(&mut self, payload: &[u8]) -> Result<()> {
        write_message(&mut self.control_send, payload, MAX_CONTROL_MESSAGE_BYTES).await
    }

    /// Receive one bounded reliable control-plane message.
    pub async fn recv_control(&mut self) -> Result<Vec<u8>> {
        read_message(&mut self.control_recv, MAX_CONTROL_MESSAGE_BYTES).await
    }

    /// Negotiate the optional authenticated Phantom One data plane.
    ///
    /// Both peers send a bounded capability record on the already-authenticated
    /// QUIC control stream, then verify that the exact profile agrees. A
    /// profile mismatch or an unsupported wire identifier fails closed; there
    /// is no implicit upgrade, downgrade, or profile substitution.
    pub async fn negotiate_phantom_one(
        &mut self,
        requested: Option<ProfileTier>,
        negotiation_timeout: Duration,
    ) -> Result<Option<ProfileTier>> {
        if let Some(state) = &self.phantom_one {
            let negotiated = if self.phantom_one_negotiated {
                Some(state.profile)
            } else {
                None
            };
            if negotiated != requested {
                return Err(ShphError::Protocol(
                    "Phantom One capability was already configured with a different profile".into(),
                ));
            }
            return Ok(negotiated);
        }
        if self.phantom_one_negotiated {
            return Err(ShphError::Protocol(
                "Phantom One capability was already negotiated without an enabled profile".into(),
            ));
        }
        if negotiation_timeout.is_zero() {
            return Err(ShphError::Config(
                "Phantom One capability timeout must be greater than zero".into(),
            ));
        }

        let result = timeout(
            negotiation_timeout,
            self.negotiate_phantom_one_inner(requested),
        )
        .await
        .map_err(|_| ShphError::Timeout)
        .and_then(|result| result);
        match result {
            Ok(profile) => Ok(profile),
            Err(error) => {
                self.connection
                    .close(0u32.into(), b"Phantom One capability negotiation failed");
                Err(error)
            }
        }
    }

    async fn negotiate_phantom_one_inner(
        &mut self,
        requested: Option<ProfileTier>,
    ) -> Result<Option<ProfileTier>> {
        let mut capability = Vec::with_capacity(PHANTOM_ONE_CAPABILITY_BYTES);
        capability.extend_from_slice(PHANTOM_ONE_CAPABILITY_MAGIC);
        capability.push(
            requested
                .map(ProfileTier::id)
                .unwrap_or(PHANTOM_ONE_CAPABILITY_DISABLED),
        );
        self.send_control(&capability).await?;
        let peer_capability = self.recv_control().await?;
        let peer_profile = decode_phantom_one_capability(&peer_capability)?;
        if peer_profile != requested {
            self.connection
                .close(0u32.into(), b"Phantom One capability mismatch");
            return Err(ShphError::Protocol(format!(
                "Phantom One profile mismatch (local {}, peer {})",
                profile_label(requested),
                profile_label(peer_profile)
            )));
        }

        if let Some(profile) = requested {
            self.enable_phantom_one(profile)?;
        }
        self.phantom_one_negotiated = true;
        Ok(requested)
    }

    /// Enable the authenticated Phantom One data-plane on this connection.
    ///
    /// Phantom One shares the handshake-derived SHPH key material and one
    /// directional sequence space across DATAGRAM and application-stream
    /// records. The control stream remains unwrapped.
    pub fn enable_phantom_one(&mut self, profile: ProfileTier) -> Result<()> {
        if let Some(state) = &self.phantom_one {
            if state.profile != profile {
                return Err(ShphError::Protocol(
                    "Phantom One profile cannot change after enablement".into(),
                ));
            }
            return Ok(());
        }

        let generation =
            crate::phantom_one_generation_from_transcript(&self.handshake.transcript_hash_hex)?;
        let config = PhantomOneConfig::for_profile(profile);
        let decoder = PhantomOneDecoder::with_config_and_window(generation, config, 64)?;
        self.phantom_one = Some(PhantomOneState {
            profile,
            send_cipher: SendCipher::new(self.handshake.session_keys.send_key),
            recv_cipher: ReceiveCipher::new_with_replay_window(
                self.handshake.session_keys.recv_key,
                128,
            ),
            encoder: PhantomOneEncoder::with_profile(generation, profile),
            decoder,
            application_send: None,
            application_recv: None,
        });
        Ok(())
    }

    /// Return the enabled Phantom One profile, if this connection uses it.
    pub fn phantom_one_profile(&self) -> Option<ProfileTier> {
        self.phantom_one.as_ref().map(|state| state.profile)
    }

    /// Return whether Phantom One was enabled through the authenticated
    /// standards-QUIC capability exchange.
    pub fn phantom_one_negotiated(&self) -> bool {
        self.phantom_one_negotiated
    }

    /// Send one authenticated Phantom One DATAGRAM.
    ///
    /// This uses RFC 9221 QUIC DATAGRAM delivery semantics. Loss remains
    /// possible by design; callers needing reliability should use the
    /// dedicated Phantom One application stream.
    pub async fn send_phantom_one_datagram(&mut self, payload: &[u8]) -> Result<()> {
        let path_mtu = self.phantom_one_datagram_path_mtu()?;
        let state = self.phantom_one_state_mut()?;
        let mut envelope = Zeroizing::new(state.encoder.encode(
            PhantomOneFrameType::Data,
            payload,
            path_mtu,
        )?);
        let ciphertext = state.send_cipher.encrypt(envelope.as_slice())?;
        envelope.zeroize();
        self.connection
            .send_datagram_wait(Bytes::from(ciphertext))
            .await
            .map_err(|err| ShphError::Transport(err.to_string()))
    }

    /// Receive and authenticate one Phantom One DATAGRAM.
    pub async fn recv_phantom_one_datagram(&mut self) -> Result<Vec<u8>> {
        let path_mtu = self.phantom_one_datagram_path_mtu()?;
        let ciphertext = self
            .connection
            .read_datagram()
            .await
            .map_err(|err| ShphError::Transport(err.to_string()))?;
        let state = self.phantom_one_state_mut()?;
        if ciphertext.len() > path_mtu + SHPH_AEAD_OVERHEAD_BYTES {
            return Err(ShphError::Protocol(
                "Phantom One QUIC DATAGRAM exceeds the negotiated bound".into(),
            ));
        }
        let mut plaintext = Zeroizing::new(state.recv_cipher.decrypt(&ciphertext)?);
        let frame = state.decoder.decode(&plaintext, path_mtu)?;
        if frame.frame_type != PhantomOneFrameType::Data {
            plaintext.zeroize();
            return Err(ShphError::Protocol(
                "unexpected Phantom One frame type on DATAGRAM".into(),
            ));
        }
        Ok(frame.payload.to_vec())
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn into_phantom_one_datagram_bridge(self) -> Result<PhantomOneDatagramBridge> {
        let state = self
            .phantom_one
            .ok_or_else(|| ShphError::Unsupported("Phantom One is not enabled".into()))?;
        if state.application_send.is_some() || state.application_recv.is_some() {
            return Err(ShphError::Protocol(
                "Phantom One application stream cannot coexist with the native-TUN datagram bridge"
                    .into(),
            ));
        }
        Ok(PhantomOneDatagramBridge {
            connection: self.connection,
            send_cipher: state.send_cipher,
            recv_cipher: state.recv_cipher,
            encoder: state.encoder,
            decoder: state.decoder,
        })
    }

    /// Open the one dedicated Phantom One bidirectional application stream.
    ///
    /// The stream starts with an authenticated Phantom One control record.
    /// The handshake control stream is never wrapped or reused for this path.
    pub async fn open_phantom_one_stream(&mut self) -> Result<()> {
        if self
            .phantom_one
            .as_ref()
            .ok_or_else(|| ShphError::Unsupported("Phantom One is not enabled".into()))?
            .application_send
            .is_some()
            || self
                .phantom_one
                .as_ref()
                .and_then(|state| state.application_recv.as_ref())
                .is_some()
        {
            return Err(ShphError::Protocol(
                "Phantom One application stream is already open".into(),
            ));
        }
        let (mut send, recv) = self
            .connection
            .open_bi()
            .await
            .map_err(|err| ShphError::Transport(err.to_string()))?;
        let result = {
            let state = self.phantom_one_state_mut()?;
            write_phantom_one_stream_record(
                &mut send,
                &mut state.send_cipher,
                &mut state.encoder,
                PhantomOneFrameType::Control,
                PHANTOM_ONE_STREAM_INTRO,
            )
            .await
        };
        if let Err(error) = result {
            let _ = send.reset(PHANTOM_ONE_STREAM_RESET_CODE);
            return Err(error);
        }
        self.phantom_one_state_mut()?.application_send = Some(send);
        self.phantom_one_state_mut()?.application_recv = Some(recv);
        Ok(())
    }

    /// Accept and authenticate the one dedicated Phantom One application stream.
    ///
    /// If the stream has already been claimed, the newly accepted stream is
    /// reset immediately and an error is returned. This keeps unexpected
    /// application streams from being silently treated as data.
    pub async fn accept_phantom_one_stream(&mut self) -> Result<()> {
        if self
            .phantom_one
            .as_ref()
            .ok_or_else(|| ShphError::Unsupported("Phantom One is not enabled".into()))?
            .application_recv
            .is_some()
            || self
                .phantom_one
                .as_ref()
                .and_then(|state| state.application_send.as_ref())
                .is_some()
        {
            let (mut send, mut recv) = self
                .connection
                .accept_bi()
                .await
                .map_err(|err| ShphError::Transport(err.to_string()))?;
            let _ = send.reset(PHANTOM_ONE_STREAM_RESET_CODE);
            let _ = recv.stop(PHANTOM_ONE_STREAM_RESET_CODE);
            return Err(ShphError::Protocol(
                "unexpected additional Phantom One application stream".into(),
            ));
        }
        let (mut send, mut recv) = self
            .connection
            .accept_bi()
            .await
            .map_err(|err| ShphError::Transport(err.to_string()))?;
        let result = {
            let state = self.phantom_one_state_mut()?;
            read_phantom_one_stream_record(&mut recv, &mut state.recv_cipher, &mut state.decoder)
                .await
                .and_then(|frame| {
                    if frame.frame_type == PhantomOneFrameType::Control
                        && frame.payload.as_slice() == PHANTOM_ONE_STREAM_INTRO
                    {
                        Ok(())
                    } else {
                        Err(ShphError::Protocol(
                            "invalid Phantom One application stream introduction".into(),
                        ))
                    }
                })
        };
        if let Err(error) = result {
            let _ = send.reset(PHANTOM_ONE_STREAM_RESET_CODE);
            let _ = recv.stop(PHANTOM_ONE_STREAM_RESET_CODE);
            return Err(error);
        }
        self.phantom_one_state_mut()?.application_send = Some(send);
        self.phantom_one_state_mut()?.application_recv = Some(recv);
        Ok(())
    }

    /// Send one bounded, reliable Phantom One application-stream record.
    pub async fn send_phantom_one_stream_record(&mut self, payload: &[u8]) -> Result<()> {
        let state = self.phantom_one_state_mut()?;
        let send = state.application_send.as_mut().ok_or_else(|| {
            ShphError::Unsupported("Phantom One application stream is not open".into())
        })?;
        write_phantom_one_stream_record(
            send,
            &mut state.send_cipher,
            &mut state.encoder,
            PhantomOneFrameType::Data,
            payload,
        )
        .await
    }

    /// Receive one bounded, reliable Phantom One application-stream record.
    pub async fn recv_phantom_one_stream_record(&mut self) -> Result<Vec<u8>> {
        let state = self.phantom_one_state_mut()?;
        let recv = state.application_recv.as_mut().ok_or_else(|| {
            ShphError::Unsupported("Phantom One application stream is not open".into())
        })?;
        let frame =
            read_phantom_one_stream_record(recv, &mut state.recv_cipher, &mut state.decoder)
                .await?;
        if frame.frame_type != PhantomOneFrameType::Data {
            return Err(ShphError::Protocol(
                "unexpected Phantom One frame type on application stream".into(),
            ));
        }
        Ok(frame.payload.to_vec())
    }

    /// Finish the local send side of the Phantom One application stream.
    pub fn finish_phantom_one_stream(&mut self) -> Result<()> {
        let state = self.phantom_one_state_mut()?;
        let send = state.application_send.as_mut().ok_or_else(|| {
            ShphError::Unsupported("Phantom One application stream is not open".into())
        })?;
        send.finish()
            .map_err(|err| ShphError::Transport(err.to_string()))
    }

    /// Accept and immediately reset one unexpected application stream.
    pub async fn reject_unexpected_application_stream(&self) -> Result<()> {
        let (mut send, mut recv) = self
            .connection
            .accept_bi()
            .await
            .map_err(|err| ShphError::Transport(err.to_string()))?;
        let _ = send.reset(PHANTOM_ONE_STREAM_RESET_CODE);
        let _ = recv.stop(PHANTOM_ONE_STREAM_RESET_CODE);
        Ok(())
    }

    /// Send one unreliable, congestion-controlled QUIC DATAGRAM.
    pub fn send_datagram(&self, payload: &[u8]) -> Result<()> {
        if payload.len() > MAX_TUN_DATAGRAM_BYTES {
            return Err(ShphError::Protocol(
                "QUIC datagram exceeds 65535 bytes".into(),
            ));
        }
        if self
            .connection
            .max_datagram_size()
            .is_none_or(|max| payload.len() > max)
        {
            return Err(ShphError::Protocol(
                "QUIC datagram exceeds negotiated peer maximum".into(),
            ));
        }
        self.connection
            .send_datagram(Bytes::copy_from_slice(payload))
            .map_err(|err| ShphError::Transport(err.to_string()))
    }

    /// Send one unreliable datagram while waiting for congestion-buffer space.
    pub async fn send_datagram_wait(&self, payload: &[u8]) -> Result<()> {
        if payload.len() > MAX_TUN_DATAGRAM_BYTES {
            return Err(ShphError::Protocol(
                "QUIC datagram exceeds 65535 bytes".into(),
            ));
        }
        if self
            .connection
            .max_datagram_size()
            .is_none_or(|max| payload.len() > max)
        {
            return Err(ShphError::Protocol(
                "QUIC datagram exceeds negotiated peer maximum".into(),
            ));
        }
        self.connection
            .send_datagram_wait(Bytes::copy_from_slice(payload))
            .await
            .map_err(|err| ShphError::Transport(err.to_string()))
    }

    /// Send an explicitly opt-in Shroud 2.0 lab envelope over QUIC DATAGRAM.
    ///
    /// This is a bounded morphology experiment. It does not alter the QUIC
    /// handshake, TLS fingerprint, congestion control, or loss recovery.
    pub async fn send_morphology_datagram(
        &self,
        morphology: &mut MorphologyEngine,
        payload: &[u8],
    ) -> Result<()> {
        let path_mtu = self
            .connection
            .max_datagram_size()
            .ok_or_else(|| ShphError::Unsupported("QUIC DATAGRAM is not negotiated".into()))?;
        let datagram = morphology.encode_datagram(payload, path_mtu)?;
        let delay = morphology.next_delay();
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
        self.connection
            .send_datagram_wait(Bytes::from(datagram))
            .await
            .map_err(|err| ShphError::Transport(err.to_string()))
    }

    /// Explicit bounded alternative to the legacy morphology send helper.
    pub async fn send_morphology_datagram_paced(
        &self,
        morphology: &mut MorphologyEngine,
        payload: &[u8],
        pacer: &crate::pacing::DatagramPacer,
        enqueued_at: std::time::Instant,
        cancel: tokio::sync::watch::Receiver<bool>,
    ) -> Result<()> {
        let limit = self
            .connection
            .max_datagram_size()
            .ok_or_else(|| ShphError::Unsupported("QUIC DATAGRAM is not negotiated".into()))?;
        let datagram = Zeroizing::new(morphology.encode_datagram(payload, limit)?);
        pacer
            .send(
                &self.connection,
                &datagram,
                enqueued_at,
                morphology.next_delay(),
                cancel,
            )
            .await
    }

    pub async fn send_morphology_datagram_paced_until(
        &self,
        morphology: &mut MorphologyEngine,
        payload: &[u8],
        pacer: &crate::pacing::DatagramPacer,
        enqueued_at: std::time::Instant,
        deadline: std::time::Instant,
        cancel: tokio::sync::watch::Receiver<bool>,
    ) -> Result<()> {
        let limit = self
            .connection
            .max_datagram_size()
            .ok_or_else(|| ShphError::Unsupported("QUIC DATAGRAM is not negotiated".into()))?;
        let datagram = Zeroizing::new(morphology.encode_datagram(payload, limit)?);
        pacer
            .send_until(
                &self.connection,
                &datagram,
                enqueued_at,
                deadline,
                morphology.next_delay(),
                cancel,
            )
            .await
    }

    /// Encode caller-observed workload signals and send through the bounded
    /// paced datagram path. The observation clock and queue age belong to the
    /// caller; this API does not inspect application traffic or spawn timers.
    pub async fn send_workload_morphology_datagram_paced(
        &self,
        morphology: &mut crate::shroud2::workload::WorkloadMorphology,
        payload: &[u8],
        observation: crate::shroud2::workload::WorkloadObservation,
        pacer: &crate::pacing::DatagramPacer,
        enqueued_at: std::time::Instant,
        cancel: tokio::sync::watch::Receiver<bool>,
    ) -> Result<()> {
        let limit = self
            .connection
            .max_datagram_size()
            .ok_or_else(|| ShphError::Unsupported("QUIC DATAGRAM is not negotiated".into()))?;
        let datagram = Zeroizing::new(morphology.encode(
            payload,
            limit,
            observation.observed_at,
            observation.queue_age,
        )?);
        let shaping_delay = morphology.next_delay();
        pacer
            .send(
                &self.connection,
                &datagram,
                enqueued_at,
                shaping_delay,
                cancel,
            )
            .await
    }

    /// Send one opt-in adaptive Shroud 3 envelope through bounded QUIC pacing.
    /// The caller supplies monotonic workload and queue-age observations.
    pub async fn send_shroud3_adaptive_datagram_paced(
        &self,
        morphology: &mut crate::shroud3::AdaptiveShroud3,
        payload: &[u8],
        observation: crate::shroud3::Shroud3Observation,
        pacer: &crate::pacing::DatagramPacer,
        enqueued_at: std::time::Instant,
        cancel: tokio::sync::watch::Receiver<bool>,
    ) -> Result<()> {
        let limit = self
            .connection
            .max_datagram_size()
            .ok_or_else(|| ShphError::Unsupported("QUIC DATAGRAM is not negotiated".into()))?;
        let datagram = Zeroizing::new(morphology.encode(payload, limit, observation)?);
        pacer
            .send(
                &self.connection,
                &datagram,
                enqueued_at,
                morphology.next_delay(),
                cancel,
            )
            .await
    }

    /// Send several small application messages in one authenticated Shroud2
    /// morphology datagram.
    ///
    /// This is for application messages carried by the opt-in morphology API.
    /// It must not be used for independent native-TUN IP packets because one
    /// lost QUIC DATAGRAM would lose every message in the batch.
    pub async fn send_morphology_batch<M: AsRef<[u8]>>(
        &self,
        morphology: &mut MorphologyEngine,
        messages: &[M],
    ) -> Result<()> {
        let path_mtu = self
            .connection
            .max_datagram_size()
            .ok_or_else(|| ShphError::Unsupported("QUIC DATAGRAM is not negotiated".into()))?;
        let datagram = encode_batched_datagram(morphology, messages, path_mtu)?;
        let delay = morphology.next_delay();
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
        self.connection
            .send_datagram_wait(Bytes::from(datagram))
            .await
            .map_err(|err| ShphError::Transport(err.to_string()))
    }

    /// Queue one application message and send a full batch when the bounded
    /// coalescer reaches its count or MTU limit.
    ///
    /// Call [`Self::flush_morphology_batch`] at the caller's latency boundary.
    /// This method intentionally does not add a timer or hidden sleep.
    pub async fn send_morphology_message(
        &self,
        morphology: &mut MorphologyEngine,
        batcher: &mut MorphologyBatcher,
        message: &[u8],
    ) -> Result<()> {
        let path_mtu = self
            .connection
            .max_datagram_size()
            .ok_or_else(|| ShphError::Unsupported("QUIC DATAGRAM is not negotiated".into()))?;
        match batcher.push(message, path_mtu)? {
            MorphologyBatchPushResult::Buffered => Ok(()),
            MorphologyBatchPushResult::Flush(messages) => {
                self.send_morphology_batch(morphology, &messages).await
            }
        }
    }

    /// Send any messages currently buffered by the bounded morphology
    /// coalescer.
    pub async fn flush_morphology_batch(
        &self,
        morphology: &mut MorphologyEngine,
        batcher: &mut MorphologyBatcher,
    ) -> Result<()> {
        if let Some(messages) = batcher.flush() {
            self.send_morphology_batch(morphology, &messages).await?;
        }
        Ok(())
    }

    /// Flush a morphology batch only when its caller-selected latency budget
    /// has expired. Returns whether a datagram was sent.
    pub async fn flush_morphology_batch_if_due(
        &self,
        morphology: &mut MorphologyEngine,
        batcher: &mut MorphologyBatcher,
    ) -> Result<bool> {
        if let Some(messages) = batcher.flush_if_due() {
            self.send_morphology_batch(morphology, &messages).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Receive and decode one explicitly opt-in Shroud 2.0 lab envelope.
    pub async fn recv_morphology_datagram(&self) -> Result<Vec<u8>> {
        let path_mtu = self
            .connection
            .max_datagram_size()
            .ok_or_else(|| ShphError::Unsupported("QUIC DATAGRAM is not negotiated".into()))?;
        let mut datagram = self
            .connection
            .read_datagram()
            .await
            .map_err(|err| ShphError::Transport(err.to_string()))?
            .to_vec();
        decode_datagram_in_place(&mut datagram, path_mtu)?;
        Ok(datagram)
    }

    /// Receive and decode one opt-in adaptive Shroud 3 datagram.
    pub async fn recv_shroud3_datagram(&self) -> Result<Vec<u8>> {
        let path_mtu = self
            .connection
            .max_datagram_size()
            .ok_or_else(|| ShphError::Unsupported("QUIC DATAGRAM is not negotiated".into()))?;
        let mut datagram = self
            .connection
            .read_datagram()
            .await
            .map_err(|err| ShphError::Transport(err.to_string()))?
            .to_vec();
        crate::shroud3::decode_in_place(&mut datagram, path_mtu)?;
        Ok(datagram)
    }

    /// Receive and split one authenticated Shroud2 application batch.
    pub async fn recv_morphology_batch(&self) -> Result<Vec<Vec<u8>>> {
        let path_mtu = self
            .connection
            .max_datagram_size()
            .ok_or_else(|| ShphError::Unsupported("QUIC DATAGRAM is not negotiated".into()))?;
        let datagram = self
            .connection
            .read_datagram()
            .await
            .map_err(|err| ShphError::Transport(err.to_string()))?;
        decode_batched_datagram(&datagram, path_mtu)
    }

    /// Receive one QUIC DATAGRAM, rejecting impossible IP-packet sizes.
    pub async fn recv_datagram(&self) -> Result<Bytes> {
        let datagram = self
            .connection
            .read_datagram()
            .await
            .map_err(|err| ShphError::Transport(err.to_string()))?;
        if datagram.len() > MAX_TUN_DATAGRAM_BYTES {
            return Err(ShphError::Protocol(
                "received QUIC datagram exceeds 65535 bytes".into(),
            ));
        }
        Ok(datagram)
    }

    fn phantom_one_state_mut(&mut self) -> Result<&mut PhantomOneState> {
        self.phantom_one
            .as_mut()
            .ok_or_else(|| ShphError::Unsupported("Phantom One is not enabled".into()))
    }

    fn phantom_one_datagram_path_mtu(&self) -> Result<usize> {
        let max_datagram = self
            .connection
            .max_datagram_size()
            .ok_or_else(|| ShphError::Unsupported("QUIC DATAGRAM is not negotiated".into()))?;
        let path_mtu = max_datagram
            .checked_sub(SHPH_AEAD_OVERHEAD_BYTES)
            .ok_or_else(|| {
                ShphError::Protocol("QUIC DATAGRAM is too small for SHPH AEAD".into())
            })?;
        if path_mtu < PHANTOM_ONE_HEADER_BYTES {
            return Err(ShphError::Protocol(
                "QUIC DATAGRAM is too small for a Phantom One header".into(),
            ));
        }
        Ok(path_mtu)
    }
}

#[cfg(target_os = "linux")]
pub(crate) struct PhantomOneDatagramBridge {
    connection: Connection,
    send_cipher: SendCipher,
    recv_cipher: ReceiveCipher,
    encoder: PhantomOneEncoder,
    decoder: PhantomOneDecoder,
}

#[cfg(target_os = "linux")]
pub(crate) struct PhantomOneDatagramSender {
    connection: Connection,
    send_cipher: SendCipher,
    encoder: PhantomOneEncoder,
}

#[cfg(target_os = "linux")]
pub(crate) struct PhantomOneDatagramReceiver {
    connection: Connection,
    recv_cipher: ReceiveCipher,
    decoder: PhantomOneDecoder,
}

#[cfg(target_os = "linux")]
impl PhantomOneDatagramBridge {
    pub(crate) fn split(self) -> (PhantomOneDatagramSender, PhantomOneDatagramReceiver) {
        let sender_connection = self.connection.clone();
        (
            PhantomOneDatagramSender {
                connection: sender_connection,
                send_cipher: self.send_cipher,
                encoder: self.encoder,
            },
            PhantomOneDatagramReceiver {
                connection: self.connection,
                recv_cipher: self.recv_cipher,
                decoder: self.decoder,
            },
        )
    }
}

#[cfg(target_os = "linux")]
impl PhantomOneDatagramSender {
    pub(crate) fn connection(&self) -> &Connection {
        &self.connection
    }

    pub(crate) async fn send(&mut self, payload: &[u8]) -> Result<()> {
        let path_mtu = phantom_one_path_mtu(&self.connection)?;
        let mut envelope = Zeroizing::new(self.encoder.encode(
            PhantomOneFrameType::Data,
            payload,
            path_mtu,
        )?);
        let ciphertext = self.send_cipher.encrypt(envelope.as_slice())?;
        envelope.zeroize();
        self.connection
            .send_datagram_wait(Bytes::from(ciphertext))
            .await
            .map_err(|err| ShphError::Transport(err.to_string()))
    }
}

#[cfg(target_os = "linux")]
impl PhantomOneDatagramReceiver {
    pub(crate) fn connection(&self) -> &Connection {
        &self.connection
    }

    pub(crate) async fn recv(&mut self) -> Result<Vec<u8>> {
        let path_mtu = phantom_one_path_mtu(&self.connection)?;
        let ciphertext = self
            .connection
            .read_datagram()
            .await
            .map_err(|err| ShphError::Transport(err.to_string()))?;
        if ciphertext.len() > path_mtu + SHPH_AEAD_OVERHEAD_BYTES {
            return Err(ShphError::Protocol(
                "Phantom One QUIC DATAGRAM exceeds the negotiated bound".into(),
            ));
        }
        let mut plaintext = Zeroizing::new(self.recv_cipher.decrypt(&ciphertext)?);
        let frame = self.decoder.decode(&plaintext, path_mtu)?;
        if frame.frame_type != PhantomOneFrameType::Data {
            plaintext.zeroize();
            return Err(ShphError::Protocol(
                "unexpected Phantom One frame type on DATAGRAM".into(),
            ));
        }
        Ok(frame.payload.to_vec())
    }
}

#[cfg(target_os = "linux")]
fn phantom_one_path_mtu(connection: &Connection) -> Result<usize> {
    let max_datagram = connection
        .max_datagram_size()
        .ok_or_else(|| ShphError::Unsupported("QUIC DATAGRAM is not negotiated".into()))?;
    let path_mtu = max_datagram
        .checked_sub(SHPH_AEAD_OVERHEAD_BYTES)
        .ok_or_else(|| ShphError::Protocol("QUIC DATAGRAM is too small for SHPH AEAD".into()))?;
    if path_mtu < PHANTOM_ONE_HEADER_BYTES {
        return Err(ShphError::Protocol(
            "QUIC DATAGRAM is too small for a Phantom One header".into(),
        ));
    }
    Ok(path_mtu)
}

fn decode_phantom_one_capability(payload: &[u8]) -> Result<Option<ProfileTier>> {
    if payload.len() != PHANTOM_ONE_CAPABILITY_BYTES
        || !payload.starts_with(PHANTOM_ONE_CAPABILITY_MAGIC)
    {
        return Err(ShphError::Protocol(
            "invalid Phantom One capability record".into(),
        ));
    }
    match payload[PHANTOM_ONE_CAPABILITY_MAGIC.len()] {
        PHANTOM_ONE_CAPABILITY_DISABLED => Ok(None),
        id => ProfileTier::from_id(id)
            .map(Some)
            .ok_or_else(|| ShphError::Protocol("unknown Phantom One capability profile".into())),
    }
}

fn profile_label(profile: Option<ProfileTier>) -> &'static str {
    profile.map(ProfileTier::as_str).unwrap_or("disabled")
}

#[cfg(target_os = "linux")]
pub(crate) fn send_datagram_lossy(
    connection: &Connection,
    payload: &[u8],
) -> std::result::Result<(), quinn::SendDatagramError> {
    if payload.len() > MAX_TUN_DATAGRAM_BYTES
        || connection
            .max_datagram_size()
            .is_some_and(|max| payload.len() > max)
    {
        return Err(quinn::SendDatagramError::TooLarge);
    }
    connection.send_datagram(Bytes::copy_from_slice(payload))
}

async fn write_message(stream: &mut SendStream, payload: &[u8], max: usize) -> Result<()> {
    if payload.is_empty() || payload.len() > max {
        return Err(ShphError::Protocol(
            "QUIC stream message exceeds bound".into(),
        ));
    }
    let length = u32::try_from(payload.len())
        .map_err(|_| ShphError::Protocol("QUIC stream message length overflow".into()))?;
    stream
        .write_all(&length.to_be_bytes())
        .await
        .map_err(|err| ShphError::Transport(err.to_string()))?;
    stream
        .write_all(payload)
        .await
        .map_err(|err| ShphError::Transport(err.to_string()))?;
    Ok(())
}

async fn read_message(stream: &mut RecvStream, max: usize) -> Result<Vec<u8>> {
    let mut length_bytes = [0u8; 4];
    stream
        .read_exact(&mut length_bytes)
        .await
        .map_err(|err| ShphError::Transport(err.to_string()))?;
    let length = u32::from_be_bytes(length_bytes) as usize;
    if length == 0 || length > max {
        return Err(ShphError::Protocol(
            "QUIC stream message length invalid".into(),
        ));
    }
    let mut payload = vec![0u8; length];
    stream
        .read_exact(&mut payload)
        .await
        .map_err(|err| ShphError::Transport(err.to_string()))?;
    Ok(payload)
}

async fn read_hello(stream: &mut RecvStream) -> Result<Hello> {
    let payload = read_message(stream, MAX_HANDSHAKE_MESSAGE_BYTES).await?;
    serde_json::from_slice(&payload).map_err(ShphError::Serialization)
}

async fn write_phantom_one_stream_record(
    stream: &mut SendStream,
    cipher: &mut SendCipher,
    encoder: &mut PhantomOneEncoder,
    frame_type: PhantomOneFrameType,
    payload: &[u8],
) -> Result<()> {
    let mut envelope = Zeroizing::new(encoder.encode(
        frame_type,
        payload,
        MAX_PHANTOM_ONE_STREAM_ENVELOPE_BYTES,
    )?);
    let ciphertext = Zeroizing::new(cipher.encrypt(envelope.as_slice())?);
    envelope.zeroize();
    write_message(
        stream,
        ciphertext.as_slice(),
        MAX_PHANTOM_ONE_STREAM_RECORD_BYTES,
    )
    .await
}

async fn read_phantom_one_stream_record(
    stream: &mut RecvStream,
    cipher: &mut ReceiveCipher,
    decoder: &mut PhantomOneDecoder,
) -> Result<crate::phantom_one::PhantomOneFrame> {
    let ciphertext = read_message_eof_aware(stream, MAX_PHANTOM_ONE_STREAM_RECORD_BYTES).await?;
    let mut envelope = Zeroizing::new(cipher.decrypt(&ciphertext)?);
    let frame = decoder.decode(&envelope, MAX_PHANTOM_ONE_STREAM_ENVELOPE_BYTES)?;
    envelope.zeroize();
    Ok(frame)
}

async fn read_message_eof_aware(stream: &mut RecvStream, max: usize) -> Result<Zeroizing<Vec<u8>>> {
    let mut length_bytes = [0u8; 4];
    stream
        .read_exact(&mut length_bytes)
        .await
        .map_err(map_stream_read_error)?;
    let length = u32::from_be_bytes(length_bytes) as usize;
    if length == 0 || length > max {
        return Err(ShphError::Protocol(
            "Phantom One stream record length invalid".into(),
        ));
    }
    let mut payload = Zeroizing::new(vec![0u8; length]);
    stream
        .read_exact(&mut payload)
        .await
        .map_err(map_stream_read_error)?;
    Ok(payload)
}

fn map_stream_read_error(error: quinn::ReadExactError) -> ShphError {
    match error {
        quinn::ReadExactError::FinishedEarly(_) => ShphError::ConnectionClosed,
        quinn::ReadExactError::ReadError(error) => ShphError::Transport(error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        accept, client_endpoint, connect, generate_server_material, server_endpoint,
        server_endpoint_with_ja4_observer, server_endpoint_with_material, StandardsQuicConfig,
        MAX_TUN_DATAGRAM_BYTES,
    };
    use crate::ja4::{Ja4ObserverConfig, RecordingJa4Observer};
    use shph_core::{HandshakeProfile, IdentityKeyPair, PeerPin, PeerPolicy};
    use shph_obfuscation::ProfileTier;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::time::Duration;

    #[test]
    fn standards_config_is_bounded() {
        let config = StandardsQuicConfig::default();
        assert_eq!(config.max_datagram_buffer_bytes, 256 * 1024);
        assert!(config.max_concurrent_bidirectional_streams <= 16);
        assert_eq!(MAX_TUN_DATAGRAM_BYTES, 65_535);
    }

    #[test]
    fn standards_config_rejects_unbounded_idle_timeout() {
        assert!(StandardsQuicConfig {
            idle_timeout: Duration::ZERO,
            ..Default::default()
        }
        .transport_config()
        .is_err());
        assert!(StandardsQuicConfig {
            idle_timeout: Duration::from_millis(999),
            ..Default::default()
        }
        .transport_config()
        .is_err());
        assert!(StandardsQuicConfig {
            idle_timeout: Duration::from_secs(24 * 60 * 60 + 1),
            ..Default::default()
        }
        .transport_config()
        .is_err());
        assert!(StandardsQuicConfig {
            idle_timeout: Duration::from_secs(1),
            ..Default::default()
        }
        .transport_config()
        .is_ok());
    }

    #[tokio::test]
    async fn persistent_server_material_reuses_the_same_certificate() {
        let material = generate_server_material().expect("generate server material");
        assert!(!material.certificate_der().is_empty());
        assert!(!material.private_key_der().is_empty());

        let first = server_endpoint_with_material(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            &material,
            StandardsQuicConfig::default(),
        )
        .expect("first endpoint");
        let second = server_endpoint_with_material(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            &material,
            StandardsQuicConfig::default(),
        )
        .expect("second endpoint");

        assert_eq!(first.certificate_der, second.certificate_der);
        assert_eq!(first.certificate_der, material.certificate_der());
        first.endpoint.close(0u32.into(), b"test complete");
        second.endpoint.close(0u32.into(), b"test complete");
        first.endpoint.wait_idle().await;
        second.endpoint.wait_idle().await;
    }

    #[test]
    fn persistent_server_material_rejects_empty_parts() {
        assert!(super::StandardsQuicServerMaterial::new(Vec::new(), vec![1]).is_err());
        assert!(super::StandardsQuicServerMaterial::new(vec![1], Vec::new()).is_err());
    }

    #[test]
    fn standards_tls_disables_replayable_early_data() {
        let cert =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("certificate");
        let certificate = quinn::rustls::pki_types::CertificateDer::from(cert.cert.der().to_vec());
        let private_key =
            quinn::rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
        let server_tls = super::build_server_tls_config(certificate, private_key.into(), None)
            .expect("server TLS config");
        assert_eq!(server_tls.max_early_data_size, 0);
        assert_eq!(
            server_tls.alpn_protocols,
            vec![b"shph/standards-quic/1".to_vec()]
        );

        let client_tls =
            super::build_client_tls_config(cert.cert.der().as_ref()).expect("client TLS config");
        assert!(!client_tls.enable_early_data);
        assert_eq!(
            client_tls.alpn_protocols,
            vec![b"shph/standards-quic/1".to_vec()]
        );
    }

    #[tokio::test]
    async fn loopback_handshake_control_and_datagram_roundtrip() {
        let server_identity = IdentityKeyPair::generate().expect("server identity");
        let client_identity = IdentityKeyPair::generate().expect("client identity");
        let server_policy = PeerPolicy::single(PeerPin::for_identity(&client_identity));
        let client_policy = PeerPolicy::single(PeerPin::for_identity(&server_identity));
        let server = server_endpoint(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            StandardsQuicConfig::default(),
        )
        .expect("server endpoint");
        let server_addr = server.endpoint.local_addr().expect("server address");
        let client = client_endpoint(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            &server.certificate_der,
            StandardsQuicConfig::default(),
        )
        .expect("client endpoint");

        let server_task = tokio::spawn(async move {
            accept(
                &server,
                &server_identity,
                &server_policy,
                HandshakeProfile::SecureDefault,
                Duration::from_secs(10),
            )
            .await
        });
        let mut client_connection = connect(
            &client,
            server_addr,
            "localhost",
            &client_identity,
            &client_policy,
            HandshakeProfile::SecureDefault,
            Duration::from_secs(10),
        )
        .await
        .expect("client QUIC/SHPH handshake");
        let mut server_connection = server_task
            .await
            .expect("server task")
            .expect("server QUIC/SHPH handshake");

        client_connection
            .send_control(b"control-plane")
            .await
            .expect("control send");
        assert_eq!(
            server_connection
                .recv_control()
                .await
                .expect("control receive"),
            b"control-plane"
        );

        client_connection
            .send_datagram(b"tun-packet")
            .expect("datagram send");
        let datagram =
            tokio::time::timeout(Duration::from_secs(5), server_connection.recv_datagram())
                .await
                .expect("datagram timeout")
                .expect("datagram receive");
        assert_eq!(&datagram[..], b"tun-packet");

        assert!(client_connection
            .send_datagram(&vec![0u8; MAX_TUN_DATAGRAM_BYTES + 1])
            .is_err());
        client.close(0u32.into(), b"test complete");
        server_connection
            .connection
            .close(0u32.into(), b"test complete");
        client.wait_idle().await;
    }

    #[tokio::test]
    async fn loopback_morphology_datagram_roundtrip() {
        let server_identity = IdentityKeyPair::generate().expect("server identity");
        let client_identity = IdentityKeyPair::generate().expect("client identity");
        let server_policy = PeerPolicy::single(PeerPin::for_identity(&client_identity));
        let client_policy = PeerPolicy::single(PeerPin::for_identity(&server_identity));
        let server = server_endpoint(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            StandardsQuicConfig::default(),
        )
        .expect("server endpoint");
        let server_addr = server.endpoint.local_addr().expect("server address");
        let client = client_endpoint(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            &server.certificate_der,
            StandardsQuicConfig::default(),
        )
        .expect("client endpoint");

        let server_task = tokio::spawn(async move {
            accept(
                &server,
                &server_identity,
                &server_policy,
                HandshakeProfile::ClassicalLab,
                Duration::from_secs(10),
            )
            .await
        });
        let client_connection = connect(
            &client,
            server_addr,
            "localhost",
            &client_identity,
            &client_policy,
            HandshakeProfile::ClassicalLab,
            Duration::from_secs(10),
        )
        .await
        .expect("client QUIC/SHPH handshake");
        let server_connection = server_task
            .await
            .expect("server task")
            .expect("server QUIC/SHPH handshake");

        let mut morphology = crate::shroud2::MorphologyEngine::from_seed(
            crate::shroud2::MorphologyProfile::WebBrowsingLab,
            42,
        );
        client_connection
            .send_morphology_datagram(&mut morphology, b"morphology-lab")
            .await
            .expect("morphology datagram send");
        let payload = tokio::time::timeout(
            Duration::from_secs(5),
            server_connection.recv_morphology_datagram(),
        )
        .await
        .expect("morphology datagram timeout")
        .expect("morphology datagram receive");
        assert_eq!(payload, b"morphology-lab");

        let messages = vec![
            b"one".to_vec(),
            b"two".to_vec(),
            b"small-application-message".to_vec(),
        ];
        let mut batcher = crate::shroud2::MorphologyBatcher::for_profile(
            crate::shroud2::MorphologyProfile::WebBrowsingLab,
        );
        for message in &messages {
            client_connection
                .send_morphology_message(&mut morphology, &mut batcher, message)
                .await
                .expect("morphology message send");
        }
        client_connection
            .flush_morphology_batch(&mut morphology, &mut batcher)
            .await
            .expect("morphology batch flush");
        let received = tokio::time::timeout(
            Duration::from_secs(5),
            server_connection.recv_morphology_batch(),
        )
        .await
        .expect("morphology batch timeout")
        .expect("morphology batch receive");
        assert_eq!(received, messages);

        client_connection
            .connection
            .close(0u32.into(), b"test complete");
        server_connection
            .connection
            .close(0u32.into(), b"test complete");
        client.wait_idle().await;
    }

    #[tokio::test]
    async fn paced_morphology_datagram_uses_carrier_and_honors_cancellation() {
        let (client, client_connection, server_connection) =
            established_pair(HandshakeProfile::SecureDefault).await;
        let mut morphology = crate::shroud2::MorphologyEngine::from_seed(
            crate::shroud2::MorphologyProfile::WebBrowsingLab,
            17,
        );
        let pacer = crate::pacing::DatagramPacer::new(2, Duration::from_secs(2)).expect("pacer");
        let (_cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
        client_connection
            .send_morphology_datagram_paced(
                &mut morphology,
                b"paced-morphology",
                &pacer,
                std::time::Instant::now(),
                cancel_rx,
            )
            .await
            .expect("paced morphology send");
        let payload = tokio::time::timeout(
            Duration::from_secs(2),
            server_connection.recv_morphology_datagram(),
        )
        .await
        .expect("paced receive timeout")
        .expect("paced receive");
        assert_eq!(payload, b"paced-morphology");
        assert_eq!(
            pacer
                .metrics()
                .sent
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );

        let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
        cancel_tx.send(true).expect("signal cancellation");
        let result = client_connection
            .send_morphology_datagram_paced(
                &mut morphology,
                b"cancelled-morphology",
                &pacer,
                std::time::Instant::now(),
                cancel_rx,
            )
            .await;
        assert!(matches!(
            result,
            Err(shph_core::ShphError::ConnectionClosed)
        ));
        assert_eq!(
            pacer
                .metrics()
                .cancelled
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );

        client_connection
            .connection
            .close(0u32.into(), b"test complete");
        server_connection
            .connection
            .close(0u32.into(), b"test complete");
        client.wait_idle().await;
    }

    #[tokio::test]
    async fn workload_adaptation_drives_paced_quic_datagrams() {
        let (client, client_connection, server_connection) =
            established_pair(HandshakeProfile::SecureDefault).await;
        let workload_config = crate::shroud2::workload::WorkloadConfig {
            minimum_dwell: Duration::ZERO,
            use_arrivals: false,
            use_queue_age: false,
            ..Default::default()
        };
        let mut morphology =
            crate::shroud2::workload::WorkloadMorphology::from_seed(workload_config, 23)
                .expect("workload morphology");
        let pacer = crate::pacing::DatagramPacer::new(2, Duration::from_secs(2)).expect("pacer");
        let application_payload = [0x6a; 256];
        for index in 0..5 {
            let (_cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
            client_connection
                .send_workload_morphology_datagram_paced(
                    &mut morphology,
                    &application_payload,
                    crate::shroud2::workload::WorkloadObservation {
                        observed_at: Duration::from_millis(index),
                        queue_age: Duration::ZERO,
                    },
                    &pacer,
                    std::time::Instant::now(),
                    cancel_rx,
                )
                .await
                .expect("workload morphology send");
        }
        assert_eq!(
            morphology.profile(),
            crate::shroud2::MorphologyProfile::TunedWebBrowsingLab
        );
        assert_eq!(morphology.metrics().switches, 1);

        for _ in 0..5 {
            let payload = tokio::time::timeout(
                Duration::from_secs(2),
                server_connection.recv_morphology_datagram(),
            )
            .await
            .expect("workload receive timeout")
            .expect("workload receive");
            assert_eq!(payload, application_payload);
        }
        assert_eq!(
            pacer
                .metrics()
                .sent
                .load(std::sync::atomic::Ordering::Relaxed),
            5
        );

        client_connection
            .connection
            .close(0u32.into(), b"test complete");
        server_connection
            .connection
            .close(0u32.into(), b"test complete");
        client.wait_idle().await;
    }

    #[tokio::test]
    async fn shroud3_adaptation_round_trips_over_authenticated_quic_and_rejects_s2() {
        let (client, client_connection, server_connection) =
            established_pair(HandshakeProfile::SecureDefault).await;
        let mut morphology = crate::shroud3::AdaptiveShroud3::new(crate::shroud3::Shroud3Config {
            minimum_dwell: Duration::ZERO,
            transition_confirmations: 1,
            ..Default::default()
        })
        .expect("Shroud 3 engine");
        let pacer = crate::pacing::DatagramPacer::new(4, Duration::from_secs(2)).expect("pacer");
        let application_payload = b"adaptive Shroud 3 over authenticated QUIC";
        for index in 0..3 {
            let (_cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
            client_connection
                .send_shroud3_adaptive_datagram_paced(
                    &mut morphology,
                    application_payload,
                    crate::shroud3::Shroud3Observation {
                        observed_at: Duration::from_millis(index),
                        queue_age: Duration::ZERO,
                    },
                    &pacer,
                    std::time::Instant::now(),
                    cancel_rx,
                )
                .await
                .expect("send Shroud 3 datagram");
            let payload = tokio::time::timeout(
                Duration::from_secs(2),
                server_connection.recv_shroud3_datagram(),
            )
            .await
            .expect("Shroud 3 receive timeout")
            .expect("decode Shroud 3 datagram");
            assert_eq!(payload, application_payload);
        }
        assert_eq!(morphology.metrics().observations, 3);
        assert_eq!(
            pacer
                .metrics()
                .sent
                .load(std::sync::atomic::Ordering::Relaxed),
            3
        );

        let shroud2 =
            crate::shroud2::encode_datagram(b"wrong version", 64, 1472).expect("Shroud 2 frame");
        client_connection
            .send_datagram_wait(&shroud2)
            .await
            .expect("send wrong version for rejection test");
        let error = tokio::time::timeout(
            Duration::from_secs(2),
            server_connection.recv_shroud3_datagram(),
        )
        .await
        .expect("version rejection timeout")
        .unwrap_err();
        assert!(matches!(error, shph_core::ShphError::Protocol(_)));

        client_connection
            .connection
            .close(0u32.into(), b"test complete");
        server_connection
            .connection
            .close(0u32.into(), b"test complete");
        client.wait_idle().await;
    }

    async fn established_pair(
        handshake_profile: HandshakeProfile,
    ) -> (
        quinn::Endpoint,
        super::StandardsQuicConnection,
        super::StandardsQuicConnection,
    ) {
        let server_identity = IdentityKeyPair::generate().expect("server identity");
        let client_identity = IdentityKeyPair::generate().expect("client identity");
        let server_policy = PeerPolicy::single(PeerPin::for_identity(&client_identity));
        let client_policy = PeerPolicy::single(PeerPin::for_identity(&server_identity));
        let server = server_endpoint(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            StandardsQuicConfig::default(),
        )
        .expect("server endpoint");
        let server_addr = server.endpoint.local_addr().expect("server address");
        let client = client_endpoint(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            &server.certificate_der,
            StandardsQuicConfig::default(),
        )
        .expect("client endpoint");
        let server_task = tokio::spawn(async move {
            accept(
                &server,
                &server_identity,
                &server_policy,
                handshake_profile,
                Duration::from_secs(10),
            )
            .await
        });
        let client_connection = connect(
            &client,
            server_addr,
            "localhost",
            &client_identity,
            &client_policy,
            handshake_profile,
            Duration::from_secs(10),
        )
        .await
        .expect("client QUIC/SHPH handshake");
        let server_connection = server_task
            .await
            .expect("server task")
            .expect("server QUIC/SHPH handshake");
        (client, client_connection, server_connection)
    }

    async fn negotiated_cover_pair(
        cover: crate::cover::CoverPolicy,
    ) -> (
        quinn::Endpoint,
        crate::envelope_policy::NegotiatedQuic,
        crate::envelope_policy::NegotiatedQuic,
    ) {
        use crate::envelope_policy::{EnvelopeOffer, NegotiatedQuic};
        use crate::phantom_one::PhantomOneConfig;

        let (client, client_transport, server_transport) =
            established_pair(HandshakeProfile::SecureDefault).await;
        let transcript = client_transport.handshake.transcript_hash_hex.clone();
        let offer = EnvelopeOffer::new(
            &transcript,
            PhantomOneConfig::new(0, 0).expect("zero-padding test config"),
            1360,
        )
        .expect("policy offer")
        .with_cover(Some(cover))
        .expect("cover policy");
        let (client_result, server_result) = tokio::join!(
            NegotiatedQuic::establish_with_offer(
                client_transport,
                offer.clone(),
                Duration::from_secs(2),
            ),
            NegotiatedQuic::establish_with_offer(server_transport, offer, Duration::from_secs(2),),
        );
        (
            client,
            client_result.expect("client policy agreement"),
            server_result.expect("server policy agreement"),
        )
    }

    #[tokio::test]
    async fn envelope_policy_quic_enforces_directional_budgets() {
        use crate::envelope_policy::{EnvelopeOffer, FrameBudget, NegotiatedQuic};
        use crate::phantom_one::PhantomOneConfig;

        let (client, client_transport, server_transport) =
            established_pair(HandshakeProfile::SecureDefault).await;
        let transcript = client_transport.handshake.transcript_hash_hex.clone();
        assert_eq!(transcript, server_transport.handshake.transcript_hash_hex);
        let client_offer = EnvelopeOffer::new(
            &transcript,
            PhantomOneConfig::for_profile(ProfileTier::Medium),
            1360,
        )
        .unwrap()
        .with_directional_budgets(
            FrameBudget {
                max_frames: 1,
                max_payload_bytes: 5,
            },
            FrameBudget {
                max_frames: 10,
                max_payload_bytes: 100,
            },
        )
        .unwrap();
        let server_offer = EnvelopeOffer::new(
            &transcript,
            PhantomOneConfig::for_profile(ProfileTier::Medium),
            1360,
        )
        .unwrap()
        .with_directional_budgets(
            FrameBudget {
                max_frames: 10,
                max_payload_bytes: 100,
            },
            FrameBudget {
                max_frames: 1,
                max_payload_bytes: 5,
            },
        )
        .unwrap();
        let (client_result, server_result) = tokio::join!(
            NegotiatedQuic::establish_with_offer(
                client_transport,
                client_offer,
                Duration::from_secs(2),
            ),
            NegotiatedQuic::establish_with_offer(
                server_transport,
                server_offer,
                Duration::from_secs(2),
            ),
        );
        let mut client_session = client_result.expect("client policy agreement");
        let mut server_session = server_result.expect("server policy agreement");

        client_session.send(b"hello").await.expect("first frame");
        assert!(matches!(
            client_session.send(b"again").await,
            Err(shph_core::ShphError::ResourceExhausted(_))
        ));
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), server_session.recv())
                .await
                .expect("receive timeout")
                .expect("receive data"),
            b"hello"
        );
        server_session.send(b"world").await.expect("reverse frame");
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), client_session.recv())
                .await
                .expect("reverse receive timeout")
                .expect("reverse receive"),
            b"world"
        );
        drop(client_session);
        drop(server_session);
        client.close(0u32.into(), b"test complete");
        client.wait_idle().await;
    }

    #[tokio::test]
    async fn envelope_policy_quic_negotiates_and_discards_cover_frames() {
        use crate::cover::CoverPolicy;
        use crate::envelope_policy::{EnvelopeOffer, NegotiatedQuic};
        use crate::phantom_one::PhantomOneConfig;

        let (client, client_transport, server_transport) =
            established_pair(HandshakeProfile::SecureDefault).await;
        let transcript = client_transport.handshake.transcript_hash_hex.clone();
        assert_eq!(transcript, server_transport.handshake.transcript_hash_hex);
        let cover = CoverPolicy {
            interval_ms: 100,
            idle_timeout_ms: 2_000,
            maximum_bytes: 4_096,
            overhead_percent: 100,
        };
        let offer = EnvelopeOffer::new(
            &transcript,
            PhantomOneConfig::for_profile(ProfileTier::Medium),
            1360,
        )
        .unwrap()
        .with_cover(Some(cover))
        .unwrap();
        let (client_result, server_result) = tokio::join!(
            NegotiatedQuic::establish_with_offer(
                client_transport,
                offer.clone(),
                Duration::from_secs(2),
            ),
            NegotiatedQuic::establish_with_offer(server_transport, offer, Duration::from_secs(2),),
        );
        let mut client_session = client_result.expect("client policy agreement");
        let mut server_session = server_result.expect("server policy agreement");

        let first_payload = vec![0x5a; 512];
        client_session
            .send(&first_payload)
            .await
            .expect("initial application frame");
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), server_session.recv())
                .await
                .expect("initial receive timeout")
                .expect("initial receive"),
            first_payload
        );

        tokio::time::sleep(Duration::from_millis(120)).await;
        assert!(client_session
            .send_cover_if_due(false, false, false)
            .await
            .expect("cover scheduling"));
        client_session
            .send(b"after-cover")
            .await
            .expect("application frame after cover");
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), server_session.recv())
                .await
                .expect("post-cover receive timeout")
                .expect("post-cover receive"),
            b"after-cover"
        );

        drop(client_session);
        drop(server_session);
        client.close(0u32.into(), b"test complete");
        client.wait_idle().await;
    }

    #[tokio::test]
    async fn envelope_policy_quic_accepts_cover_before_budgeted_application_data() {
        let policy = crate::cover::CoverPolicy {
            interval_ms: 100,
            idle_timeout_ms: 1_000,
            maximum_bytes: 4_096,
            overhead_percent: 10,
        };
        let (client, mut sender, mut receiver) = negotiated_cover_pair(policy).await;

        crate::envelope_policy::send_quic_cover_without_scheduler(&mut sender)
            .await
            .expect("send raw authenticated cover");
        let payload = vec![0x5a; 1024];
        sender.send(&payload).await.expect("send application data");
        let result = tokio::time::timeout(Duration::from_secs(2), receiver.recv())
            .await
            .expect("receive timeout")
            .expect("receive data after cover");
        assert_eq!(result, payload);

        drop(sender);
        drop(receiver);
        client.close(0u32.into(), b"test complete");
        client.wait_idle().await;
    }

    #[tokio::test]
    async fn envelope_policy_quic_enforces_cumulative_cover_overhead() {
        let policy = crate::cover::CoverPolicy {
            interval_ms: 100,
            idle_timeout_ms: 1_000,
            maximum_bytes: 4_096,
            overhead_percent: 10,
        };
        let (client, mut sender, mut receiver) = negotiated_cover_pair(policy).await;

        let payload = vec![0x5a; 1024];
        sender.send(&payload).await.expect("send application data");
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), receiver.recv())
                .await
                .expect("application receive timeout")
                .expect("application receive"),
            payload
        );

        crate::envelope_policy::send_quic_cover_without_scheduler(&mut sender)
            .await
            .expect("send first raw authenticated cover");
        sender
            .send(b"after-first-cover")
            .await
            .expect("send second application frame");
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), receiver.recv())
                .await
                .expect("post-cover receive timeout")
                .expect("post-cover receive"),
            b"after-first-cover"
        );

        crate::envelope_policy::send_quic_cover_without_scheduler(&mut sender)
            .await
            .expect("send second raw authenticated cover");
        sender
            .send(b"after-second-cover")
            .await
            .expect("send payload to evaluate cumulative cover budget");
        let result = tokio::time::timeout(Duration::from_secs(2), receiver.recv())
            .await
            .expect("cumulative cover receive timeout");
        assert!(matches!(result, Err(shph_core::ShphError::Protocol(_))));

        drop(sender);
        drop(receiver);
        client.close(0u32.into(), b"test complete");
        client.wait_idle().await;
    }

    #[tokio::test]
    async fn phantom_one_datagrams_bind_all_profiles() {
        let profiles = [
            ProfileTier::Low,
            ProfileTier::Medium,
            ProfileTier::High,
            ProfileTier::TunedLow,
            ProfileTier::TunedMedium,
            ProfileTier::TunedHigh,
        ];
        for profile in profiles {
            let (client, mut client_connection, mut server_connection) =
                established_pair(HandshakeProfile::SecureDefault).await;
            client_connection
                .enable_phantom_one(profile)
                .expect("enable client Phantom One");
            server_connection
                .enable_phantom_one(profile)
                .expect("enable server Phantom One");
            assert_eq!(client_connection.phantom_one_profile(), Some(profile));
            assert_eq!(server_connection.phantom_one_profile(), Some(profile));

            client_connection
                .send_phantom_one_datagram(b"authenticated-datagram")
                .await
                .expect("send Phantom One datagram");
            assert_eq!(
                tokio::time::timeout(
                    Duration::from_secs(5),
                    server_connection.recv_phantom_one_datagram()
                )
                .await
                .expect("Phantom One datagram timeout")
                .expect("receive Phantom One datagram"),
                b"authenticated-datagram"
            );

            client_connection
                .connection
                .close(0u32.into(), b"test complete");
            server_connection
                .connection
                .close(0u32.into(), b"test complete");
            client.wait_idle().await;
        }
    }

    #[tokio::test]
    async fn phantom_one_capability_negotiation_is_symmetric_and_bounded() {
        let (client, mut client_connection, mut server_connection) =
            established_pair(HandshakeProfile::SecureDefault).await;
        let (client_result, server_result) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(
                client_connection
                    .negotiate_phantom_one(Some(ProfileTier::TunedMedium), Duration::from_secs(2),),
                server_connection
                    .negotiate_phantom_one(Some(ProfileTier::TunedMedium), Duration::from_secs(2),),
            )
        })
        .await
        .expect("capability negotiation timeout");

        assert_eq!(
            client_result.expect("client capability negotiation"),
            Some(ProfileTier::TunedMedium)
        );
        assert_eq!(
            server_result.expect("server capability negotiation"),
            Some(ProfileTier::TunedMedium)
        );
        assert!(client_connection.phantom_one_negotiated());
        assert!(server_connection.phantom_one_negotiated());

        client_connection
            .send_phantom_one_datagram(b"negotiated-datagram")
            .await
            .expect("send negotiated datagram");
        assert_eq!(
            server_connection
                .recv_phantom_one_datagram()
                .await
                .expect("receive negotiated datagram"),
            b"negotiated-datagram"
        );

        client_connection
            .connection
            .close(0u32.into(), b"test complete");
        server_connection
            .connection
            .close(0u32.into(), b"test complete");
        client.wait_idle().await;
    }

    #[tokio::test]
    async fn phantom_one_capability_mismatch_fails_closed() {
        let (client, mut client_connection, mut server_connection) =
            established_pair(HandshakeProfile::SecureDefault).await;
        let (client_result, server_result) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(
                client_connection
                    .negotiate_phantom_one(Some(ProfileTier::Medium), Duration::from_secs(2),),
                server_connection
                    .negotiate_phantom_one(Some(ProfileTier::High), Duration::from_secs(2),),
            )
        })
        .await
        .expect("capability mismatch timeout");

        assert!(client_result.is_err());
        assert!(server_result.is_err());
        assert!(!client_connection.phantom_one_negotiated());
        assert!(!server_connection.phantom_one_negotiated());
        client.wait_idle().await;
    }

    #[tokio::test]
    async fn phantom_one_stream_is_authenticated_bounded_and_singleton() {
        let (client, mut client_connection, mut server_connection) =
            established_pair(HandshakeProfile::SecureDefault).await;
        client_connection
            .enable_phantom_one(ProfileTier::TunedMedium)
            .expect("enable client Phantom One");
        server_connection
            .enable_phantom_one(ProfileTier::TunedMedium)
            .expect("enable server Phantom One");

        client_connection
            .open_phantom_one_stream()
            .await
            .expect("open Phantom One application stream");
        server_connection
            .accept_phantom_one_stream()
            .await
            .expect("accept Phantom One application stream");
        assert!(client_connection.open_phantom_one_stream().await.is_err());

        client_connection
            .send_phantom_one_stream_record(b"client-stream-record")
            .await
            .expect("send client stream record");
        assert_eq!(
            server_connection
                .recv_phantom_one_stream_record()
                .await
                .expect("receive client stream record"),
            b"client-stream-record"
        );

        server_connection
            .send_phantom_one_stream_record(b"server-stream-record")
            .await
            .expect("send server stream record");
        assert_eq!(
            client_connection
                .recv_phantom_one_stream_record()
                .await
                .expect("receive server stream record"),
            b"server-stream-record"
        );

        client_connection
            .finish_phantom_one_stream()
            .expect("finish client stream");
        assert!(matches!(
            server_connection.recv_phantom_one_stream_record().await,
            Err(shph_core::ShphError::ConnectionClosed)
        ));

        client_connection
            .connection
            .close(0u32.into(), b"test complete");
        server_connection
            .connection
            .close(0u32.into(), b"test complete");
        client.wait_idle().await;
    }

    #[tokio::test]
    async fn phantom_one_rejects_unexpected_stream_introduction() {
        let (client, mut client_connection, mut server_connection) =
            established_pair(HandshakeProfile::SecureDefault).await;
        client_connection
            .enable_phantom_one(ProfileTier::Medium)
            .expect("enable client Phantom One");
        server_connection
            .enable_phantom_one(ProfileTier::Medium)
            .expect("enable server Phantom One");

        let (mut raw_send, mut raw_recv) = client_connection
            .connection
            .open_bi()
            .await
            .expect("open unexpected stream");
        raw_send
            .write_all(&1u32.to_be_bytes())
            .await
            .expect("write malformed introduction length");
        raw_send
            .write_all(&[0])
            .await
            .expect("write malformed introduction");
        assert!(server_connection.accept_phantom_one_stream().await.is_err());
        let _ = raw_send.reset(super::PHANTOM_ONE_STREAM_RESET_CODE);
        let _ = raw_recv.stop(super::PHANTOM_ONE_STREAM_RESET_CODE);

        client_connection
            .connection
            .close(0u32.into(), b"test complete");
        server_connection
            .connection
            .close(0u32.into(), b"test complete");
        client.wait_idle().await;
    }

    #[tokio::test]
    async fn optional_ja4_observer_records_real_client_hello() {
        let server_identity = IdentityKeyPair::generate().expect("server identity");
        let client_identity = IdentityKeyPair::generate().expect("client identity");
        let server_policy = PeerPolicy::single(PeerPin::for_identity(&client_identity));
        let client_policy = PeerPolicy::single(PeerPin::for_identity(&server_identity));
        let observer = Arc::new(RecordingJa4Observer::new(4).expect("observer"));
        let server = server_endpoint_with_ja4_observer(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            StandardsQuicConfig::default(),
            observer.clone(),
            Ja4ObserverConfig::default(),
        )
        .expect("server endpoint");
        let server_addr = server.endpoint.local_addr().expect("server address");
        let client = client_endpoint(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            &server.certificate_der,
            StandardsQuicConfig::default(),
        )
        .expect("client endpoint");

        let server_task = tokio::spawn(async move {
            accept(
                &server,
                &server_identity,
                &server_policy,
                HandshakeProfile::ClassicalLab,
                Duration::from_secs(10),
            )
            .await
        });
        let client_connection = connect(
            &client,
            server_addr,
            "localhost",
            &client_identity,
            &client_policy,
            HandshakeProfile::ClassicalLab,
            Duration::from_secs(10),
        )
        .await
        .expect("client QUIC/SHPH handshake");
        server_task
            .await
            .expect("server task")
            .expect("server QUIC/SHPH handshake");

        let observations = observer.snapshot();
        assert_eq!(observations.len(), 1);
        let observation = &observations[0];
        assert_eq!(observation.transport, crate::ja4::Ja4Transport::Quic);
        assert_eq!(
            observation.coverage,
            crate::ja4::Ja4ObservationCoverage::PublicRustlsSubset
        );
        assert!(observation.certificate_resolved);
        assert!(observation.sni_present);
        assert!(observation.server_name.is_none());
        assert!(observation.exact_fingerprint.is_none());
        assert!(observation.partial_fingerprint.starts_with("q13d"));
        assert_eq!(observation.metadata_sha256.len(), 64);

        client_connection
            .connection
            .close(0u32.into(), b"test complete");
        client.wait_idle().await;
    }
}
