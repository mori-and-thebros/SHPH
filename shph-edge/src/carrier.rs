use crate::{
    capability::ReplayCache,
    config::{validate_relay_path, EdgeConfig, DEFAULT_RELAY_PATH},
    file::read_bounded_regular_file,
    frontdoor::{
        is_octet_stream, FrontDoor, FrontDoorDecision, FrontDoorResponse, CAPABILITY_HEADER,
    },
    logging::{emit, MetadataEvent},
    relay::{
        connect_backend, forward_with_cancel, read_with_cancel, shutdown_with_cancel,
        write_all_with_cancel, RelayError,
    },
};
#[cfg(feature = "http3")]
use bytes::Buf;
use bytes::Bytes;
use http::{header, HeaderValue, Request, Response, StatusCode, Uri};
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::{
    body::{Frame, Incoming},
    service::service_fn,
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::{
    pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, ServerName},
    ClientConfig, RootCertStore, ServerConfig,
};
use std::{
    collections::VecDeque,
    convert::Infallible,
    io,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{mpsc, Notify, OwnedSemaphorePermit, Semaphore},
    task::{JoinHandle, JoinSet},
    time::{sleep, timeout},
};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;

pub const H2_PATH: &str = DEFAULT_RELAY_PATH;
const RESPONSE_QUEUE: usize = 32;
const MAX_PEM_FILE_BYTES: u64 = 1024 * 1024;
pub const MAX_CAPABILITY_TOKEN_FILE_BYTES: usize = 64 * 1024;
const MAX_CAPABILITY_TOKENS: usize = 1024;
const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);

type ClientBody = StreamBody<ReceiverStream<Result<Frame<Bytes>, Infallible>>>;
type ClientSender = hyper::client::conn::http2::SendRequest<ClientBody>;

struct Http2Pool {
    config: Arc<EdgeConfig>,
    edge_uri: Uri,
    tokens: Mutex<VecDeque<HeaderValue>>,
    ca_path: PathBuf,
    server_name: String,
    connections: Mutex<Vec<Arc<Http2PoolConnection>>>,
    acquire_lock: tokio::sync::Mutex<()>,
    notify: Arc<Notify>,
}

struct Http2PoolConnection {
    sender: ClientSender,
    stream_slots: Arc<Semaphore>,
    cancellation: CancellationToken,
    task: Mutex<Option<JoinHandle<Result<(), CarrierError>>>>,
}

struct PoolStreamPermit {
    permit: Option<OwnedSemaphorePermit>,
    notify: Arc<Notify>,
}

struct PooledHttp2Stream {
    connection: Arc<Http2PoolConnection>,
    _permit: PoolStreamPermit,
    token: HeaderValue,
}

impl PoolStreamPermit {
    fn new(permit: OwnedSemaphorePermit, notify: Arc<Notify>) -> Self {
        Self {
            permit: Some(permit),
            notify,
        }
    }
}

impl Drop for PoolStreamPermit {
    fn drop(&mut self) {
        if self.permit.take().is_some() {
            self.notify.notify_waiters();
        }
    }
}

impl PooledHttp2Stream {
    fn sender(&self) -> ClientSender {
        self.connection.sender.clone()
    }
}

impl Http2PoolConnection {
    fn is_usable(&self) -> bool {
        if self.sender.is_closed() || self.cancellation.is_cancelled() {
            return false;
        }
        self.task
            .lock()
            .map(|task| match task.as_ref() {
                Some(task) => !task.is_finished(),
                None => false,
            })
            .unwrap_or(false)
    }

    fn try_lease(self: &Arc<Self>, notify: Arc<Notify>) -> Option<PoolStreamPermit> {
        if !self.is_usable() {
            return None;
        }
        let permit = self.stream_slots.clone().try_acquire_owned().ok()?;
        Some(PoolStreamPermit::new(permit, notify))
    }
}

impl Drop for Http2PoolConnection {
    fn drop(&mut self) {
        self.cancellation.cancel();
        if let Ok(mut task) = self.task.lock() {
            if let Some(task) = task.take() {
                task.abort();
            }
        }
    }
}

impl Http2Pool {
    fn new(
        config: Arc<EdgeConfig>,
        edge_uri: Uri,
        token: String,
        ca_path: &Path,
    ) -> Result<Arc<Self>, CarrierError> {
        config
            .validate()
            .map_err(|error| CarrierError::Http(format!("invalid edge configuration: {error}")))?;
        validate_h2_uri_with_path(&edge_uri, &config.relay_path)?;
        let tokens = parse_capability_tokens(&token, config.limits.max_token_bytes)?;
        ServerName::try_from(config.tls.server_name.clone())
            .map_err(|_| CarrierError::Tls("invalid server name".into()))?;
        Ok(Arc::new(Self {
            server_name: config.tls.server_name.clone(),
            config,
            edge_uri,
            tokens: Mutex::new(tokens),
            ca_path: ca_path.to_owned(),
            connections: Mutex::new(Vec::new()),
            acquire_lock: tokio::sync::Mutex::new(()),
            notify: Arc::new(Notify::new()),
        }))
    }

    async fn acquire(
        self: &Arc<Self>,
        shutdown: &CancellationToken,
    ) -> Result<PooledHttp2Stream, CarrierError> {
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let _serial = tokio::select! {
                _ = shutdown.cancelled() => {
                    return Err(CarrierError::Http(
                        "HTTP/2 pool acquisition cancelled".into(),
                    ));
                }
                guard = self.acquire_lock.lock() => guard,
            };
            if self
                .tokens
                .lock()
                .map_err(|_| CarrierError::Http("HTTP/2 token pool lock poisoned".into()))?
                .is_empty()
            {
                return Err(CarrierError::Http(
                    "capability token bundle is exhausted".into(),
                ));
            }
            let can_create = {
                let mut connections = self
                    .connections
                    .lock()
                    .map_err(|_| CarrierError::Http("HTTP/2 pool lock poisoned".into()))?;
                connections.retain(|connection| connection.is_usable());
                if let Some((connection, lease)) = connections.iter().find_map(|connection| {
                    connection
                        .try_lease(self.notify.clone())
                        .map(|lease| (connection.clone(), lease))
                }) {
                    let token = self.take_token()?;
                    return Ok(PooledHttp2Stream {
                        connection,
                        _permit: lease,
                        token,
                    });
                }
                connections.len() < self.config.limits.max_http2_connections
            };

            if !can_create {
                drop(_serial);
                tokio::select! {
                    _ = shutdown.cancelled() => {
                        return Err(CarrierError::Http(
                            "HTTP/2 pool acquisition cancelled".into(),
                        ));
                    }
                    _ = notified => {}
                }
                continue;
            }

            let connection = tokio::select! {
                _ = shutdown.cancelled() => {
                    return Err(CarrierError::Http(
                        "HTTP/2 pool connection cancelled".into(),
                    ));
                }
                result = self.connect_connection() => result?,
            };
            if shutdown.is_cancelled() {
                drop(connection);
                return Err(CarrierError::Http(
                    "HTTP/2 pool connection cancelled".into(),
                ));
            }
            if connection.sender.is_closed() {
                return Err(CarrierError::Http(
                    "HTTP/2 connection closed during setup".into(),
                ));
            }
            let lease = connection
                .try_lease(self.notify.clone())
                .ok_or_else(|| CarrierError::Http("HTTP/2 stream lease unavailable".into()))?;
            self.connections
                .lock()
                .map_err(|_| CarrierError::Http("HTTP/2 pool lock poisoned".into()))?
                .push(connection.clone());
            let token = self.take_token()?;
            return Ok(PooledHttp2Stream {
                connection,
                _permit: lease,
                token,
            });
        }
    }

    fn take_token(&self) -> Result<HeaderValue, CarrierError> {
        self.tokens
            .lock()
            .map_err(|_| CarrierError::Http("HTTP/2 token pool lock poisoned".into()))?
            .pop_front()
            .ok_or_else(|| CarrierError::Http("capability token bundle is exhausted".into()))
    }

    async fn connect_connection(&self) -> Result<Arc<Http2PoolConnection>, CarrierError> {
        let authority = self.edge_uri.authority().ok_or(CarrierError::InvalidUri)?;
        let host = authority.host();
        let port = authority.port_u16().unwrap_or(443);
        let tcp = timeout(
            self.config.backend_connect_timeout(),
            TcpStream::connect((host, port)),
        )
        .await
        .map_err(|_| CarrierError::Timeout("edge connection"))??;
        if let Err(error) = tcp.set_nodelay(true) {
            tracing::debug!(carrier = "socks5", error = %error, "failed to enable TCP_NODELAY");
        }

        let mut tls = client_tls(&self.ca_path, &self.server_name)?;
        tls.alpn_protocols = vec![b"h2".to_vec()];
        let connector = TlsConnector::from(Arc::new(tls));
        let server_name = ServerName::try_from(self.server_name.clone())
            .map_err(|_| CarrierError::Tls("invalid server name".into()))?;
        let tls_stream = timeout(
            self.config.tls_handshake_timeout(),
            connector.connect(server_name, tcp),
        )
        .await
        .map_err(|_| CarrierError::Timeout("TLS handshake"))?
        .map_err(|error| CarrierError::Tls(error.to_string()))?;

        let max_streams = self.config.limits.max_streams_per_connection;
        let mut builder = hyper::client::conn::http2::Builder::new(TokioExecutor::new());
        builder
            .initial_max_send_streams(max_streams as usize)
            .max_concurrent_streams(max_streams);
        let (sender, connection) = timeout(
            self.config.tls_handshake_timeout(),
            builder.handshake::<_, ClientBody>(TokioIo::new(tls_stream)),
        )
        .await
        .map_err(|_| CarrierError::Timeout("HTTP/2 handshake"))?
        .map_err(|error| CarrierError::Http(error.to_string()))?;

        let cancellation = CancellationToken::new();
        let connection_shutdown = cancellation.clone();
        let notify = self.notify.clone();
        let task = tokio::spawn(async move {
            let result = tokio::select! {
                _ = connection_shutdown.cancelled() => Ok(()),
                result = connection => result.map_err(|error| CarrierError::Http(error.to_string())),
            };
            connection_shutdown.cancel();
            if let Err(error) = &result {
                tracing::debug!(carrier = "h2-client", error = %error, "connection ended");
            }
            notify.notify_waiters();
            result
        });

        Ok(Arc::new(Http2PoolConnection {
            sender,
            stream_slots: Arc::new(Semaphore::new(max_streams as usize)),
            cancellation,
            task: Mutex::new(Some(task)),
        }))
    }
}

async fn abort_task<T>(task: &mut JoinHandle<T>, cancellation: &CancellationToken) {
    cancellation.cancel();
    task.abort();
    let _ = task.await;
}

async fn send_frame_with_cancel(
    sender: &mpsc::Sender<Result<Frame<Bytes>, Infallible>>,
    data: Bytes,
    idle_timeout: Duration,
    cancellation: &CancellationToken,
) -> Result<(), RelayError> {
    tokio::select! {
        _ = cancellation.cancelled() => Err(RelayError::Cancelled),
        result = timeout(idle_timeout, sender.send(Ok(Frame::data(data)))) => {
            match result {
                Ok(Ok(())) => Ok(()),
                Ok(Err(_)) => Err(RelayError::Cancelled),
                Err(_) => Err(RelayError::IdleTimeout),
            }
        }
    }
}

pub trait Carrier: Send + Sync {
    fn kind(&self) -> CarrierKind;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CarrierKind {
    Http2,
    #[cfg(feature = "http3")]
    Http3,
}

impl CarrierKind {
    pub fn parse(value: &str) -> Result<Self, CarrierError> {
        match value {
            "h2" | "http2" => Ok(Self::Http2),
            #[cfg(feature = "http3")]
            "h3" | "http3" => Ok(Self::Http3),
            #[cfg(not(feature = "http3"))]
            "h3" | "http3" => Err(CarrierError::Unsupported("http/3 support was not compiled")),
            _ => Err(CarrierError::Unsupported("carrier must be h2 or h3")),
        }
    }
}

#[derive(Debug, Error)]
pub enum CarrierError {
    #[error("unsupported carrier: {0}")]
    Unsupported(&'static str),
    #[error("TLS configuration failed: {0}")]
    Tls(String),
    #[error("carrier I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("HTTP carrier failed: {0}")]
    Http(String),
    #[error("carrier operation timed out: {0}")]
    Timeout(&'static str),
    #[error("relay failed: {0}")]
    Relay(#[from] RelayError),
    #[error("invalid edge URI")]
    InvalidUri,
    #[error("edge URI must use https")]
    InvalidScheme,
    #[error("SOCKS5 handshake failed")]
    Socks,
}

#[derive(Debug)]
pub struct Http2Carrier {
    pub bind: SocketAddr,
}

impl Carrier for Http2Carrier {
    fn kind(&self) -> CarrierKind {
        CarrierKind::Http2
    }
}

#[derive(Debug)]
pub struct UnsupportedCarrier;

impl Carrier for UnsupportedCarrier {
    fn kind(&self) -> CarrierKind {
        CarrierKind::Http2
    }
}

#[derive(Debug)]
pub struct OpaqueStream<S> {
    inner: S,
}

impl<S> OpaqueStream<S> {
    pub fn new(inner: S) -> Self {
        Self { inner }
    }
    pub fn into_inner(self) -> S {
        self.inner
    }
}

#[cfg(feature = "http3")]
#[derive(Debug)]
pub struct Http3Carrier {
    pub bind: SocketAddr,
}

#[cfg(feature = "http3")]
impl Carrier for Http3Carrier {
    fn kind(&self) -> CarrierKind {
        CarrierKind::Http3
    }
}

type BoxBody = http_body_util::combinators::BoxBody<Bytes, Infallible>;

fn boxed_full(body: &'static [u8]) -> BoxBody {
    Full::new(Bytes::from_static(body))
        .map_err(|never| match never {})
        .boxed()
}

fn response_for_fallback(fallback: FrontDoorResponse) -> Response<BoxBody> {
    Response::builder()
        .status(fallback.status)
        .header(header::CONTENT_TYPE, fallback.content_type)
        .header(header::CACHE_CONTROL, "no-store")
        .body(boxed_full(fallback.body))
        .expect("static fallback response")
}

fn validate_content_length(headers: &http::HeaderMap, max_bytes: u64) -> Result<(), StatusCode> {
    let mut declared = None;
    for value in headers.get_all(header::CONTENT_LENGTH).iter() {
        let parsed = value
            .to_str()
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or(StatusCode::BAD_REQUEST)?;
        if parsed > max_bytes {
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }
        if declared.is_some_and(|previous| previous != parsed) {
            return Err(StatusCode::BAD_REQUEST);
        }
        declared = Some(parsed);
    }
    Ok(())
}

pub async fn serve_http2(
    config: Arc<EdgeConfig>,
    front_door: Arc<FrontDoor>,
) -> Result<(), CarrierError> {
    serve_http2_until(config, front_door, CancellationToken::new()).await
}

pub async fn serve_http2_until(
    config: Arc<EdgeConfig>,
    front_door: Arc<FrontDoor>,
    shutdown: CancellationToken,
) -> Result<(), CarrierError> {
    if shutdown.is_cancelled() {
        return Ok(());
    }
    config
        .validate()
        .map_err(|error| CarrierError::Http(format!("invalid edge configuration: {error}")))?;
    let (cert, key) = config
        .tls
        .cert
        .as_ref()
        .zip(config.tls.key.as_ref())
        .ok_or_else(|| {
            CarrierError::Tls("HTTP/2 edge serving requires TLS certificate and key".into())
        })?;
    let mut tls_config = load_server_tls(cert, key)?;
    tls_config.alpn_protocols = vec![b"h2".to_vec()];
    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));
    let listener = TcpListener::bind(config.listen).await?;
    let replay = Arc::new(Mutex::new(
        ReplayCache::new(config.limits.replay_capacity)
            .map_err(|_| CarrierError::Http("invalid replay capacity".into()))?,
    ));
    let active = Arc::new(tokio::sync::Semaphore::new(config.limits.max_connections));
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            joined = tasks.join_next(), if !tasks.is_empty() => {
                log_task_result("h2", joined);
            }
            accepted = listener.accept() => {
                let (stream, _) = match accepted {
                    Ok(value) => value,
                    Err(error) => {
                        shutdown_tasks(&mut tasks, &shutdown).await;
                        return Err(CarrierError::Io(error));
                    }
                };
                if let Err(error) = stream.set_nodelay(true) {
                    tracing::debug!(carrier = "h2", error = %error, "failed to enable TCP_NODELAY");
                }
                let permit = match active.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        tracing::debug!(carrier = "h2", "connection limit reached");
                        continue;
                    }
                };
                let config = config.clone();
                let front_door = front_door.clone();
                let replay = replay.clone();
                let tls_acceptor = tls_acceptor.clone();
                let connection_shutdown = shutdown.child_token();
                tasks.spawn(async move {
                    let _permit = permit;
                    serve_http2_connection(
                        stream,
                        config,
                        front_door,
                        replay,
                        tls_acceptor,
                        connection_shutdown,
                    )
                    .await
                });
            }
        }
    }
    shutdown_tasks(&mut tasks, &shutdown).await;
    Ok(())
}

async fn serve_http2_connection(
    stream: TcpStream,
    config: Arc<EdgeConfig>,
    front_door: Arc<FrontDoor>,
    replay: Arc<Mutex<ReplayCache>>,
    tls_acceptor: TlsAcceptor,
    shutdown: CancellationToken,
) -> Result<(), CarrierError> {
    let tls_stream = tokio::select! {
        _ = shutdown.cancelled() => return Ok(()),
        result = timeout(config.tls_handshake_timeout(), tls_acceptor.accept(stream)) => {
            result
                .map_err(|_| CarrierError::Timeout("TLS handshake"))?
                .map_err(|error| CarrierError::Tls(error.to_string()))?
        }
    };
    serve_http2_io(
        TokioIo::new(tls_stream),
        config,
        front_door,
        replay,
        shutdown,
    )
    .await
}

async fn serve_http2_io<I>(
    io: TokioIo<I>,
    config: Arc<EdgeConfig>,
    front_door: Arc<FrontDoor>,
    replay: Arc<Mutex<ReplayCache>>,
    shutdown: CancellationToken,
) -> Result<(), CarrierError>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let max_streams = config.limits.max_streams_per_connection;
    let service_config = config.clone();
    let request_shutdown = shutdown.clone();
    let service = service_fn(move |request: Request<Incoming>| {
        let config = service_config.clone();
        let front_door = front_door.clone();
        let replay = replay.clone();
        let shutdown = request_shutdown.clone();
        async move { handle_http2_request(request, config, front_door, replay, shutdown).await }
    });
    let connection = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
        .max_concurrent_streams(max_streams)
        .serve_connection(io, service);
    let result = tokio::select! {
        _ = shutdown.cancelled() => Ok(()),
        result = connection => result.map_err(|error| CarrierError::Http(error.to_string())),
    };
    shutdown.cancel();
    result
}

async fn handle_http2_request(
    request: Request<Incoming>,
    config: Arc<EdgeConfig>,
    front_door: Arc<FrontDoor>,
    replay: Arc<Mutex<ReplayCache>>,
    connection_shutdown: CancellationToken,
) -> Result<Response<BoxBody>, Infallible> {
    if connection_shutdown.is_cancelled() {
        return Ok(response_for_fallback(FrontDoorResponse {
            status: StatusCode::SERVICE_UNAVAILABLE,
            content_type: "text/plain; charset=utf-8",
            body: b"temporarily unavailable\n",
        }));
    }
    let method = request.method().clone();
    let uri = request.uri().clone();
    let headers = request.headers().clone();
    let decision = {
        let mut cache = match replay.lock() {
            Ok(cache) => cache,
            Err(_) => {
                tracing::error!(carrier = "h2", "replay cache lock poisoned");
                return Ok(response_for_fallback(FrontDoorResponse {
                    status: StatusCode::SERVICE_UNAVAILABLE,
                    content_type: "text/plain; charset=utf-8",
                    body: b"temporarily unavailable\n",
                }));
            }
        };
        front_door.decide(&method, &uri, &headers, &mut cache)
    };
    let FrontDoorDecision::Relay = decision else {
        return Ok(response_for_fallback(match decision {
            FrontDoorDecision::Fallback(response) => response,
            FrontDoorDecision::Relay => unreachable!("matched above"),
        }));
    };
    if !is_octet_stream(&headers) {
        return Ok(response_for_fallback(FrontDoorResponse::unauthorized()));
    }
    let max_bytes = config.limits.max_stream_bytes;
    if let Err(status) = validate_content_length(&headers, max_bytes) {
        return Ok(response_for_fallback(match status {
            StatusCode::PAYLOAD_TOO_LARGE => FrontDoorResponse {
                status,
                content_type: "text/plain; charset=utf-8",
                body: b"payload too large\n",
            },
            _ => FrontDoorResponse {
                status,
                content_type: "text/plain; charset=utf-8",
                body: b"bad request\n",
            },
        }));
    }
    let backend = match tokio::select! {
        _ = connection_shutdown.cancelled() => {
            return Ok(response_for_fallback(FrontDoorResponse {
                status: StatusCode::SERVICE_UNAVAILABLE,
                content_type: "text/plain; charset=utf-8",
                body: b"temporarily unavailable\n",
            }));
        }
        result = connect_backend(&config.backend, config.backend_connect_timeout()) => result,
    } {
        Ok(backend) => backend,
        Err(error) => {
            tracing::warn!(carrier = "h2", error = %error, "backend unavailable");
            return Ok(response_for_fallback(FrontDoorResponse {
                status: StatusCode::BAD_GATEWAY,
                content_type: "text/plain; charset=utf-8",
                body: b"bad gateway\n",
            }));
        }
    };
    let (sender, receiver) = mpsc::channel::<Result<Frame<Bytes>, Infallible>>(RESPONSE_QUEUE);
    let idle_timeout = config.backend_idle_timeout();
    let cancellation = CancellationToken::new();
    let request_cancellation = cancellation.clone();
    let backend_cancellation = cancellation.clone();
    let response_cancellation = cancellation.clone();
    tokio::spawn(async move {
        let (mut backend_read, mut backend_write) = tokio::io::split(backend);
        let (mut request_body, mut response_body) = tokio::io::duplex(16 * 1024);
        let request_task = async {
            let mut body = request.into_body();
            let mut total = 0u64;
            while let Some(frame) = tokio::select! {
                _ = request_cancellation.cancelled() => {
                    return Err(RelayError::Cancelled);
                }
                frame = timeout(idle_timeout, body.frame()) => {
                    frame.map_err(|_| RelayError::IdleTimeout)?
                }
            } {
                let frame = match frame {
                    Ok(frame) => frame,
                    Err(_) => {
                        return Err(RelayError::Io(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "request body error",
                        )))
                    }
                };
                let data = frame.into_data().map_err(|_| {
                    RelayError::Io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "request trailers are not supported",
                    ))
                })?;
                total = total
                    .checked_add(data.len() as u64)
                    .ok_or(RelayError::LimitExceeded)?;
                if total > max_bytes {
                    return Err(RelayError::LimitExceeded);
                }
                write_all_with_cancel(
                    &mut request_body,
                    &data,
                    idle_timeout,
                    &request_cancellation,
                )
                .await?;
            }
            shutdown_with_cancel(&mut request_body, idle_timeout, &request_cancellation).await?;
            Ok::<u64, RelayError>(total)
        };
        let body_to_backend = async {
            forward_with_cancel(
                &mut response_body,
                &mut backend_write,
                max_bytes,
                idle_timeout,
                backend_cancellation,
            )
            .await?;
            Ok::<(), RelayError>(())
        };
        let backend_to_response = async {
            let mut buf = vec![0u8; 16 * 1024];
            let mut total = 0u64;
            loop {
                let read = read_with_cancel(
                    &mut backend_read,
                    &mut buf,
                    idle_timeout,
                    &response_cancellation,
                )
                .await?;
                if read == 0 {
                    break;
                }
                total = total
                    .checked_add(read as u64)
                    .ok_or(RelayError::LimitExceeded)?;
                if total > max_bytes {
                    return Err(RelayError::LimitExceeded);
                }
                send_frame_with_cancel(
                    &sender,
                    Bytes::copy_from_slice(&buf[..read]),
                    idle_timeout,
                    &response_cancellation,
                )
                .await?;
            }
            Ok::<u64, RelayError>(total)
        };
        let relay = async {
            tokio::try_join!(request_task, body_to_backend, backend_to_response)
                .map(|(bytes_in, _, bytes_out)| (bytes_in, bytes_out))
        };
        let result = tokio::select! {
            _ = connection_shutdown.cancelled() => {
                cancellation.cancel();
                Err(RelayError::Cancelled)
            }
            result = relay => result
        };
        cancellation.cancel();
        match result {
            Ok((bytes_in, bytes_out)) => emit(MetadataEvent {
                event: "relay",
                carrier: "h2",
                outcome: "ok",
                bytes_in,
                bytes_out,
            }),
            Err(error) => tracing::debug!(carrier = "h2", error = %error, "relay stream ended"),
        }
    });
    let stream = ReceiverStream::new(receiver);
    let body = StreamBody::new(stream).boxed();
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CACHE_CONTROL, "no-store")
        .body(body)
        .expect("relay response"))
}

pub async fn open_socks5(
    config: Arc<EdgeConfig>,
    edge_uri: Uri,
    token: String,
    ca: &Path,
) -> Result<(), CarrierError> {
    open_socks5_until(config, edge_uri, token, ca, CancellationToken::new()).await
}

pub async fn open_socks5_until(
    config: Arc<EdgeConfig>,
    edge_uri: Uri,
    token: String,
    ca: &Path,
    shutdown: CancellationToken,
) -> Result<(), CarrierError> {
    if shutdown.is_cancelled() {
        return Ok(());
    }
    let pool = Http2Pool::new(config.clone(), edge_uri, token, ca)?;
    let listener = TcpListener::bind(config.socks.listen).await?;
    let active = Arc::new(tokio::sync::Semaphore::new(config.socks.max_connections));
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            joined = tasks.join_next(), if !tasks.is_empty() => {
                log_task_result("socks5", joined);
            }
            accepted = listener.accept() => {
                let (stream, _) = match accepted {
                    Ok(value) => value,
                    Err(error) => {
                        shutdown_tasks(&mut tasks, &shutdown).await;
                        return Err(CarrierError::Io(error));
                    }
                };
                if let Err(error) = stream.set_nodelay(true) {
                    tracing::debug!(carrier = "socks5", error = %error, "failed to enable TCP_NODELAY");
                }
                let permit = match active.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => continue,
                };
                let pool = pool.clone();
                let connection_shutdown = shutdown.child_token();
                tasks.spawn(async move {
                    let _permit = permit;
                    handle_socks5(stream, pool, connection_shutdown).await
                });
            }
        }
    }
    shutdown_tasks(&mut tasks, &shutdown).await;
    Ok(())
}

async fn handle_socks5(
    mut local: TcpStream,
    pool: Arc<Http2Pool>,
    shutdown: CancellationToken,
) -> Result<(), CarrierError> {
    let config = pool.config.clone();
    tokio::select! {
        _ = shutdown.cancelled() => {
            return Err(CarrierError::Relay(RelayError::Cancelled));
        }
        result = timeout(config.backend_idle_timeout(), socks5_handshake(&mut local)) => {
            result.map_err(|_| CarrierError::Timeout("SOCKS5 handshake"))??;
        }
    }
    let (mut local_read, mut local_write) = local.into_split();
    let pooled = pool.acquire(&shutdown).await?;
    let mut sender = pooled.sender();
    let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, Infallible>>(RESPONSE_QUEUE);
    let idle_timeout = config.backend_idle_timeout();
    let cancellation = shutdown.child_token();
    let request = Request::builder()
        .method("POST")
        .uri(pool.edge_uri.clone())
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(CAPABILITY_HEADER, pooled.token.clone())
        .body(StreamBody::new(ReceiverStream::new(rx)))
        .map_err(|error| CarrierError::Http(error.to_string()))?;
    let producer_cancellation = cancellation.clone();
    let mut producer = tokio::spawn(async move {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let read = read_with_cancel(
                &mut local_read,
                &mut buf,
                idle_timeout,
                &producer_cancellation,
            )
            .await?;
            if read == 0 {
                break;
            }
            send_frame_with_cancel(
                &tx,
                Bytes::copy_from_slice(&buf[..read]),
                idle_timeout,
                &producer_cancellation,
            )
            .await?;
        }
        Ok::<(), RelayError>(())
    });
    let response = tokio::select! {
        _ = shutdown.cancelled() => {
            abort_task(&mut producer, &cancellation).await;
            return Err(CarrierError::Relay(RelayError::Cancelled));
        }
        result = timeout(
            config.backend_connect_timeout(),
            sender.send_request(request),
        ) => {
            match result {
                Ok(Ok(response)) => response,
                Ok(Err(error)) => {
                    abort_task(&mut producer, &cancellation).await;
                    let _ = try_write_socks5_reply(
                        &mut local_write,
                        0x01,
                        idle_timeout,
                        &shutdown,
                    )
                    .await;
                    return Err(CarrierError::Http(error.to_string()));
                }
                Err(_) => {
                    abort_task(&mut producer, &cancellation).await;
                    let _ = try_write_socks5_reply(
                        &mut local_write,
                        0x01,
                        idle_timeout,
                        &shutdown,
                    )
                    .await;
                    return Err(CarrierError::Timeout("HTTP/2 request"));
                }
            }
        }
    };
    if response.status() != StatusCode::OK {
        abort_task(&mut producer, &cancellation).await;
        let _ = try_write_socks5_reply(&mut local_write, 0x05, idle_timeout, &shutdown).await;
        return Err(CarrierError::Http(format!(
            "edge rejected stream with {}",
            response.status()
        )));
    }
    if let Err(error) =
        write_socks5_reply_with_cancel(&mut local_write, 0x00, idle_timeout, &cancellation).await
    {
        abort_task(&mut producer, &cancellation).await;
        return Err(error);
    }
    let mut body = response.into_body();
    let copy_cancellation = cancellation.clone();
    let copy_back = async {
        let mut total = 0u64;
        while let Some(frame) = tokio::select! {
            _ = copy_cancellation.cancelled() => Err(RelayError::Cancelled),
            frame = timeout(idle_timeout, body.frame()) => {
                frame.map_err(|_| RelayError::IdleTimeout)
            }
        }? {
            let frame = frame.map_err(|_| {
                RelayError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "response body error",
                ))
            })?;
            let data = frame.into_data().map_err(|_| {
                RelayError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "response trailers are not supported",
                ))
            })?;
            total = total
                .checked_add(data.len() as u64)
                .ok_or(RelayError::LimitExceeded)?;
            if total > config.limits.max_stream_bytes {
                return Err(RelayError::LimitExceeded);
            }
            write_all_with_cancel(&mut local_write, &data, idle_timeout, &copy_cancellation)
                .await?;
        }
        shutdown_with_cancel(&mut local_write, idle_timeout, &copy_cancellation).await?;
        Ok::<(), RelayError>(())
    };
    let mut copy_back = Box::pin(copy_back);
    tokio::select! {
        _ = shutdown.cancelled() => {
            abort_task(&mut producer, &cancellation).await;
            return Err(CarrierError::Relay(RelayError::Cancelled));
        }
        producer_result = &mut producer => {
            let producer_result = match producer_result {
                Ok(Ok(())) => Ok(()),
                Ok(Err(error)) => Err(CarrierError::Relay(error)),
                Err(error) => Err(CarrierError::Http(format!(
                    "request body producer task failed: {error}"
                ))),
            };
            if let Err(error) = producer_result {
                cancellation.cancel();
                return Err(error);
            }
            if let Err(error) = copy_back.await.map_err(CarrierError::Relay) {
                cancellation.cancel();
                return Err(error);
            }
        }
        copy_result = &mut copy_back => {
            abort_task(&mut producer, &cancellation).await;
            copy_result.map_err(CarrierError::Relay)?;
        }
    }
    cancellation.cancel();
    drop(sender);
    drop(pooled);
    Ok(())
}

pub fn validate_h2_uri(uri: &Uri) -> Result<(), CarrierError> {
    validate_h2_uri_with_path(uri, H2_PATH)
}

pub fn validate_h2_uri_with_path(uri: &Uri, relay_path: &str) -> Result<(), CarrierError> {
    validate_relay_path(relay_path).map_err(|_| CarrierError::InvalidUri)?;
    if uri.scheme_str() != Some("https") {
        return Err(CarrierError::InvalidScheme);
    }
    let authority = uri.authority().ok_or(CarrierError::InvalidUri)?;
    if authority.host().is_empty()
        || authority.as_str().contains('@')
        || uri.path() != relay_path
        || uri.query().is_some()
    {
        return Err(CarrierError::InvalidUri);
    }
    Ok(())
}

fn parse_capability_tokens(
    raw: &str,
    max_token_bytes: usize,
) -> Result<VecDeque<HeaderValue>, CarrierError> {
    if raw.len() > MAX_CAPABILITY_TOKEN_FILE_BYTES {
        return Err(CarrierError::InvalidUri);
    }
    let mut tokens = VecDeque::new();
    for line in raw.lines() {
        let token = line.trim();
        if token.is_empty() {
            continue;
        }
        if token.len() > max_token_bytes || token.bytes().any(|byte| byte <= 0x20 || byte == 0x7f) {
            return Err(CarrierError::InvalidUri);
        }
        if tokens.len() >= MAX_CAPABILITY_TOKENS {
            return Err(CarrierError::InvalidUri);
        }
        tokens.push_back(HeaderValue::try_from(token).map_err(|_| CarrierError::InvalidUri)?);
    }
    if tokens.is_empty() {
        return Err(CarrierError::InvalidUri);
    }
    Ok(tokens)
}

async fn socks5_handshake(stream: &mut TcpStream) -> Result<(), CarrierError> {
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).await?;
    if header[0] != 5 || header[1] > 16 {
        return Err(CarrierError::Socks);
    }
    let mut methods = vec![0u8; header[1] as usize];
    stream.read_exact(&mut methods).await?;
    if !methods.contains(&0) {
        stream.write_all(&[5, 0xff]).await?;
        return Err(CarrierError::Socks);
    }
    stream.write_all(&[5, 0]).await?;
    let mut request = [0u8; 4];
    stream.read_exact(&mut request).await?;
    if request[0] != 5 || request[1] != 1 || request[2] != 0 || !matches!(request[3], 1 | 3 | 4) {
        return Err(CarrierError::Socks);
    }
    let target_len = match request[3] {
        1 => 4,
        3 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            if len[0] == 0 {
                return Err(CarrierError::Socks);
            }
            len[0] as usize
        }
        4 => 16,
        _ => return Err(CarrierError::Socks),
    };
    let mut target = vec![0u8; target_len + 2];
    stream.read_exact(&mut target).await?;
    if request[3] == 3
        && target[..target_len]
            .iter()
            .any(|byte| *byte <= 0x20 || *byte == 0x7f)
    {
        return Err(CarrierError::Socks);
    }
    Ok(())
}

async fn try_write_socks5_reply(
    stream: &mut (impl AsyncWrite + Unpin),
    reply: u8,
    idle_timeout: Duration,
    shutdown: &CancellationToken,
) -> Result<(), CarrierError> {
    tokio::select! {
        _ = shutdown.cancelled() => Err(CarrierError::Relay(RelayError::Cancelled)),
        result = timeout(idle_timeout, write_socks5_reply(stream, reply)) => {
            result.map_err(|_| CarrierError::Timeout("SOCKS5 reply"))?
        }
    }
}

async fn write_socks5_reply_with_cancel(
    stream: &mut (impl AsyncWrite + Unpin),
    reply: u8,
    idle_timeout: Duration,
    cancellation: &CancellationToken,
) -> Result<(), CarrierError> {
    tokio::select! {
        _ = cancellation.cancelled() => Err(CarrierError::Relay(RelayError::Cancelled)),
        result = timeout(idle_timeout, write_socks5_reply(stream, reply)) => {
            result.map_err(|_| CarrierError::Timeout("SOCKS5 reply"))?
        }
    }
}

async fn write_socks5_reply(
    stream: &mut (impl AsyncWrite + Unpin),
    reply: u8,
) -> Result<(), CarrierError> {
    stream
        .write_all(&[5, reply, 0, 1, 0, 0, 0, 0, 0, 0])
        .await?;
    stream.flush().await?;
    Ok(())
}

fn load_server_tls(cert_path: &Path, key_path: &Path) -> Result<ServerConfig, CarrierError> {
    let certs = load_certs(cert_path)?;
    let key = load_key(key_path)?;
    ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|error| CarrierError::Tls(error.to_string()))
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, CarrierError> {
    let pem = read_bounded_pem_file(path)?;
    CertificateDer::pem_slice_iter(&pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| CarrierError::Tls(error.to_string()))
}

fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>, CarrierError> {
    let pem = read_bounded_pem_file(path)?;
    PrivateKeyDer::from_pem_slice(&pem).map_err(|error| CarrierError::Tls(error.to_string()))
}

fn read_bounded_pem_file(path: &Path) -> Result<Vec<u8>, CarrierError> {
    read_bounded_regular_file(path, MAX_PEM_FILE_BYTES).map_err(|error| {
        if error.kind() == io::ErrorKind::InvalidInput
            && error.to_string() == "file exceeds the configured size limit"
        {
            CarrierError::Tls(format!(
                "PEM file exceeds {} byte limit",
                MAX_PEM_FILE_BYTES
            ))
        } else if error.kind() == io::ErrorKind::InvalidInput
            && error.to_string() == "path must reference a regular file"
        {
            CarrierError::Tls("PEM path must be a regular file".into())
        } else {
            CarrierError::Io(error)
        }
    })
}

fn client_tls(ca_path: &Path, server_name: &str) -> Result<ClientConfig, CarrierError> {
    let roots = load_certs(ca_path)?;
    let mut store = RootCertStore::empty();
    for cert in roots {
        store
            .add(cert)
            .map_err(|error| CarrierError::Tls(error.to_string()))?;
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| CarrierError::Tls(error.to_string()))?
        .with_root_certificates(store)
        .with_no_client_auth()
        .pipe(|config| {
            if server_name.is_empty() {
                Err(CarrierError::Tls("server name is required".into()))
            } else {
                Ok(config)
            }
        })
}

trait Pipe: Sized {
    fn pipe<T>(self, f: impl FnOnce(Self) -> T) -> T {
        f(self)
    }
}
impl<T> Pipe for T {}

fn log_task_result(
    carrier: &'static str,
    joined: Option<Result<Result<(), CarrierError>, tokio::task::JoinError>>,
) {
    match joined {
        Some(Ok(Ok(()))) | None => {}
        Some(Ok(Err(error))) => {
            tracing::debug!(carrier, error = %error, "connection ended");
        }
        Some(Err(error)) => {
            tracing::debug!(carrier, error = %error, "connection task ended unexpectedly");
        }
    }
}

async fn shutdown_tasks(
    tasks: &mut JoinSet<Result<(), CarrierError>>,
    shutdown: &CancellationToken,
) {
    shutdown.cancel();
    let mut grace = Box::pin(sleep(SHUTDOWN_GRACE));
    while !tasks.is_empty() {
        tokio::select! {
            joined = tasks.join_next() => log_task_result("shutdown", joined),
            _ = &mut grace => {
                tasks.abort_all();
                while let Some(joined) = tasks.join_next().await {
                    log_task_result("shutdown", Some(joined));
                }
            }
        }
    }
}

#[cfg(feature = "http3")]
pub async fn serve_http3(
    config: Arc<EdgeConfig>,
    front_door: Arc<FrontDoor>,
) -> Result<(), CarrierError> {
    serve_http3_until(config, front_door, CancellationToken::new()).await
}

#[cfg(feature = "http3")]
pub async fn serve_http3_until(
    config: Arc<EdgeConfig>,
    front_door: Arc<FrontDoor>,
    shutdown: CancellationToken,
) -> Result<(), CarrierError> {
    if shutdown.is_cancelled() {
        return Ok(());
    }
    config
        .validate()
        .map_err(|error| CarrierError::Http(format!("invalid edge configuration: {error}")))?;
    let (cert, key) = config
        .tls
        .cert
        .as_ref()
        .zip(config.tls.key.as_ref())
        .ok_or_else(|| {
            CarrierError::Tls("HTTP/3 edge serving requires TLS certificate and key".into())
        })?;
    let server_config = quic_server_config(cert, key, config.limits.max_streams_per_connection)?;
    let endpoint = quinn::Endpoint::server(server_config, config.listen)?;
    let replay = Arc::new(Mutex::new(
        ReplayCache::new(config.limits.replay_capacity)
            .map_err(|_| CarrierError::Http("invalid replay capacity".into()))?,
    ));
    let active = Arc::new(tokio::sync::Semaphore::new(config.limits.max_connections));
    let mut tasks = JoinSet::new();

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            joined = tasks.join_next(), if !tasks.is_empty() => {
                log_task_result("h3", joined);
            }
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break; };
                if !incoming.remote_address_validated() && incoming.may_retry() {
                    if let Err(error) = incoming.retry() {
                        tracing::debug!(carrier = "h3", error = %error, "failed to issue QUIC address validation retry");
                    }
                    continue;
                }
                let permit = match active.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        incoming.refuse();
                        tracing::debug!(carrier = "h3", "connection limit reached");
                        continue;
                    }
                };
                let config = config.clone();
                let front_door = front_door.clone();
                let replay = replay.clone();
                let connection_shutdown = shutdown.child_token();
                tasks.spawn(async move {
                    let _permit = permit;
                    serve_http3_connection(
                        incoming,
                        config,
                        front_door,
                        replay,
                        connection_shutdown,
                    )
                    .await
                });
            }
        }
    }

    endpoint.close(quinn::VarInt::from_u32(0), b"shutdown");
    shutdown_tasks(&mut tasks, &shutdown).await;
    tokio::time::timeout(SHUTDOWN_GRACE, endpoint.wait_idle())
        .await
        .map_err(|_| CarrierError::Timeout("HTTP/3 endpoint shutdown"))?;
    Ok(())
}

#[cfg(feature = "http3")]
async fn serve_http3_connection(
    incoming: quinn::Incoming,
    config: Arc<EdgeConfig>,
    front_door: Arc<FrontDoor>,
    replay: Arc<Mutex<ReplayCache>>,
    shutdown: CancellationToken,
) -> Result<(), CarrierError> {
    let connection = tokio::select! {
        _ = shutdown.cancelled() => return Ok(()),
        result = timeout(config.tls_handshake_timeout(), incoming) => {
            result
                .map_err(|_| CarrierError::Timeout("HTTP/3 QUIC handshake"))?
                .map_err(|error| CarrierError::Http(error.to_string()))?
        }
    };
    let mut h3_connection = h3::server::builder()
        .max_field_section_size(16 * 1024)
        .build(h3_quinn::Connection::new(connection))
        .await
        .map_err(|error| CarrierError::Http(error.to_string()))?;
    let mut request_tasks = JoinSet::new();
    let result = loop {
        tokio::select! {
            _ = shutdown.cancelled() => break Ok(()),
            joined = request_tasks.join_next(), if !request_tasks.is_empty() => {
                log_task_result("h3-request", joined);
            }
            resolver = timeout(config.backend_idle_timeout(), h3_connection.accept()) => {
                let resolver = resolver
                    .map_err(|_| CarrierError::Timeout("HTTP/3 request"))?
                    .map_err(|error| CarrierError::Http(error.to_string()))?;
                let Some(resolver) = resolver else {
                    break Ok(());
                };
                let (request, stream) = tokio::select! {
                    _ = shutdown.cancelled() => break Ok(()),
                    result = timeout(config.backend_idle_timeout(), resolver.resolve_request()) => {
                        result
                            .map_err(|_| CarrierError::Timeout("HTTP/3 request headers"))?
                            .map_err(|error| CarrierError::Http(error.to_string()))?
                    }
                };
                let config = config.clone();
                let front_door = front_door.clone();
                let replay = replay.clone();
                let request_shutdown = shutdown.clone();
                request_tasks.spawn(async move {
                    handle_http3_request(
                        request,
                        stream,
                        config,
                        front_door,
                        replay,
                        request_shutdown,
                    )
                    .await
                });
            }
        }
    };
    shutdown_tasks(&mut request_tasks, &shutdown).await;
    result
}

#[cfg(feature = "http3")]
async fn handle_http3_request<S>(
    request: Request<()>,
    mut stream: h3::server::RequestStream<S, Bytes>,
    config: Arc<EdgeConfig>,
    front_door: Arc<FrontDoor>,
    replay: Arc<Mutex<ReplayCache>>,
    shutdown: CancellationToken,
) -> Result<(), CarrierError>
where
    S: h3::quic::BidiStream<Bytes> + Send + 'static,
    S::SendStream: Send,
    S::RecvStream: Send,
{
    let method = request.method().clone();
    let uri = request.uri().clone();
    let headers = request.headers().clone();
    let decision = {
        let mut cache = replay
            .lock()
            .map_err(|_| CarrierError::Http("replay cache lock poisoned".into()))?;
        front_door.decide(&method, &uri, &headers, &mut cache)
    };
    let FrontDoorDecision::Relay = decision else {
        let fallback = match decision {
            FrontDoorDecision::Fallback(response) => response,
            FrontDoorDecision::Relay => unreachable!("matched above"),
        };
        stream
            .send_response(
                Response::builder()
                    .status(fallback.status)
                    .header(header::CONTENT_TYPE, fallback.content_type)
                    .header(header::CACHE_CONTROL, "no-store")
                    .body(())
                    .map_err(|error| CarrierError::Http(error.to_string()))?,
            )
            .await
            .map_err(|error| CarrierError::Http(error.to_string()))?;
        stream
            .send_data(Bytes::from_static(fallback.body))
            .await
            .map_err(|error| CarrierError::Http(error.to_string()))?;
        stream
            .finish()
            .await
            .map_err(|error| CarrierError::Http(error.to_string()))?;
        return Ok(());
    };
    if !is_octet_stream(&headers) {
        stream
            .send_response(
                Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .header(header::CACHE_CONTROL, "no-store")
                    .body(())
                    .map_err(|error| CarrierError::Http(error.to_string()))?,
            )
            .await
            .map_err(|error| CarrierError::Http(error.to_string()))?;
        stream
            .finish()
            .await
            .map_err(|error| CarrierError::Http(error.to_string()))?;
        return Ok(());
    }
    if let Err(status) = validate_content_length(&headers, config.limits.max_stream_bytes) {
        return send_http3_status(stream, status).await;
    }

    let backend = tokio::select! {
        _ = shutdown.cancelled() => return Ok(()),
        result = connect_backend(&config.backend, config.backend_connect_timeout()) => result,
    }
    .map_err(CarrierError::Relay)?;
    stream
        .send_response(
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .header(header::CACHE_CONTROL, "no-store")
                .body(())
                .map_err(|error| CarrierError::Http(error.to_string()))?,
        )
        .await
        .map_err(|error| CarrierError::Http(error.to_string()))?;

    let (mut send, mut recv) = stream.split();
    let (mut backend_read, mut backend_write) = tokio::io::split(backend);
    let idle_timeout = config.backend_idle_timeout();
    let max_bytes = config.limits.max_stream_bytes;
    let request_to_backend = async {
        let mut total = 0u64;
        loop {
            let data = timeout(idle_timeout, recv.recv_data())
                .await
                .map_err(|_| CarrierError::Timeout("HTTP/3 request body"))?
                .map_err(|error| CarrierError::Http(error.to_string()))?;
            let Some(mut data) = data else { break };
            let size = data.remaining();
            total = total
                .checked_add(size as u64)
                .ok_or(RelayError::LimitExceeded)?;
            if total > max_bytes {
                return Err(CarrierError::Relay(RelayError::LimitExceeded));
            }
            let bytes = data.copy_to_bytes(size);
            timeout(idle_timeout, backend_write.write_all(&bytes))
                .await
                .map_err(|_| CarrierError::Timeout("HTTP/3 backend write"))??;
        }
        timeout(idle_timeout, backend_write.shutdown())
            .await
            .map_err(|_| CarrierError::Timeout("HTTP/3 backend shutdown"))??;
        Ok::<u64, CarrierError>(total)
    };
    let backend_to_response = async {
        let mut buffer = vec![0u8; 16 * 1024];
        let mut total = 0u64;
        loop {
            let read = timeout(idle_timeout, backend_read.read(&mut buffer))
                .await
                .map_err(|_| CarrierError::Timeout("HTTP/3 backend read"))??;
            if read == 0 {
                break;
            }
            total = total
                .checked_add(read as u64)
                .ok_or(RelayError::LimitExceeded)?;
            if total > max_bytes {
                return Err(CarrierError::Relay(RelayError::LimitExceeded));
            }
            timeout(
                idle_timeout,
                send.send_data(Bytes::copy_from_slice(&buffer[..read])),
            )
            .await
            .map_err(|_| CarrierError::Timeout("HTTP/3 response write"))?
            .map_err(|error| CarrierError::Http(error.to_string()))?;
        }
        timeout(idle_timeout, send.finish())
            .await
            .map_err(|_| CarrierError::Timeout("HTTP/3 response finish"))?
            .map_err(|error| CarrierError::Http(error.to_string()))?;
        Ok::<u64, CarrierError>(total)
    };
    let (bytes_in, bytes_out) = tokio::try_join!(
        async {
            tokio::select! {
                _ = shutdown.cancelled() => Err(CarrierError::Relay(RelayError::Cancelled)),
                result = request_to_backend => result,
            }
        },
        async {
            tokio::select! {
                _ = shutdown.cancelled() => Err(CarrierError::Relay(RelayError::Cancelled)),
                result = backend_to_response => result,
            }
        }
    )?;
    emit(MetadataEvent {
        event: "relay",
        carrier: "h3",
        outcome: "ok",
        bytes_in,
        bytes_out,
    });
    Ok(())
}

#[cfg(feature = "http3")]
async fn send_http3_status<S>(
    mut stream: h3::server::RequestStream<S, Bytes>,
    status: StatusCode,
) -> Result<(), CarrierError>
where
    S: h3::quic::BidiStream<Bytes> + Send + 'static,
    S::SendStream: Send,
    S::RecvStream: Send,
{
    stream
        .send_response(
            Response::builder()
                .status(status)
                .header(header::CACHE_CONTROL, "no-store")
                .body(())
                .map_err(|error| CarrierError::Http(error.to_string()))?,
        )
        .await
        .map_err(|error| CarrierError::Http(error.to_string()))?;
    stream
        .finish()
        .await
        .map_err(|error| CarrierError::Http(error.to_string()))
}

#[cfg(feature = "http3")]
fn quic_server_config(
    cert_path: &Path,
    key_path: &Path,
    max_streams: u32,
) -> Result<quinn::ServerConfig, CarrierError> {
    let mut tls = load_server_tls(cert_path, key_path)?;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
        .map_err(|error| CarrierError::Tls(error.to_string()))?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let transport = Arc::get_mut(&mut config.transport)
        .ok_or_else(|| CarrierError::Http("QUIC transport configuration is shared".into()))?;
    transport.max_concurrent_bidi_streams(max_streams.into());
    transport.max_concurrent_uni_streams(3u32.into());
    transport.max_idle_timeout(Some(Duration::from_secs(60).try_into().map_err(
        |error| CarrierError::Http(format!("invalid QUIC idle timeout: {error}")),
    )?));
    Ok(config)
}

#[cfg(feature = "http3")]
fn quic_client_config(
    ca_path: &Path,
    server_name: &str,
) -> Result<quinn::ClientConfig, CarrierError> {
    let mut tls = client_tls(ca_path, server_name)?;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
        .map_err(|error| CarrierError::Tls(error.to_string()))?;
    let mut config = quinn::ClientConfig::new(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(Duration::from_secs(60).try_into().map_err(
        |error| CarrierError::Http(format!("invalid QUIC idle timeout: {error}")),
    )?));
    config.transport_config(Arc::new(transport));
    Ok(config)
}

#[cfg(feature = "http3")]
pub async fn open_socks5_http3_until(
    config: Arc<EdgeConfig>,
    edge_uri: Uri,
    token: String,
    ca: &Path,
    shutdown: CancellationToken,
) -> Result<(), CarrierError> {
    if shutdown.is_cancelled() {
        return Ok(());
    }
    config
        .validate()
        .map_err(|error| CarrierError::Http(format!("invalid edge configuration: {error}")))?;
    validate_h2_uri_with_path(&edge_uri, &config.relay_path)?;
    let tokens = Arc::new(Mutex::new(parse_capability_tokens(
        &token,
        config.limits.max_token_bytes,
    )?));
    let listener = TcpListener::bind(config.socks.listen).await?;
    let active = Arc::new(tokio::sync::Semaphore::new(config.socks.max_connections));
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            joined = tasks.join_next(), if !tasks.is_empty() => {
                log_task_result("socks5-h3", joined);
            }
            accepted = listener.accept() => {
                let (stream, _) = match accepted {
                    Ok(value) => value,
                    Err(error) => {
                        shutdown_tasks(&mut tasks, &shutdown).await;
                        return Err(CarrierError::Io(error));
                    }
                };
                let permit = match active.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => continue,
                };
                let config = config.clone();
                let edge_uri = edge_uri.clone();
                let ca = ca.to_owned();
                let tokens = tokens.clone();
                let shutdown = shutdown.child_token();
                tasks.spawn(async move {
                    let _permit = permit;
                    handle_socks5_http3(
                        stream,
                        config,
                        edge_uri,
                        tokens,
                        &ca,
                        shutdown,
                    )
                    .await
                });
            }
        }
    }
    shutdown_tasks(&mut tasks, &shutdown).await;
    Ok(())
}

#[cfg(feature = "http3")]
async fn handle_socks5_http3(
    mut local: TcpStream,
    config: Arc<EdgeConfig>,
    edge_uri: Uri,
    tokens: Arc<Mutex<VecDeque<HeaderValue>>>,
    ca: &Path,
    shutdown: CancellationToken,
) -> Result<(), CarrierError> {
    tokio::select! {
        _ = shutdown.cancelled() => return Err(CarrierError::Relay(RelayError::Cancelled)),
        result = timeout(config.backend_idle_timeout(), socks5_handshake(&mut local)) => {
            result.map_err(|_| CarrierError::Timeout("SOCKS5 handshake"))??;
        }
    }
    let token = tokens
        .lock()
        .map_err(|_| CarrierError::Http("HTTP/3 token pool lock poisoned".into()))?
        .pop_front()
        .ok_or_else(|| CarrierError::Http("HTTP/3 capability token bundle is exhausted".into()))?;
    let (mut local_read, mut local_write) = local.into_split();
    let authority = edge_uri.authority().ok_or(CarrierError::InvalidUri)?;
    let host = authority.host().to_owned();
    let port = authority.port_u16().unwrap_or(443);
    let remote = timeout(
        config.backend_connect_timeout(),
        tokio::net::lookup_host((host.as_str(), port)),
    )
    .await
    .map_err(|_| CarrierError::Timeout("HTTP/3 DNS lookup"))??
    .next()
    .ok_or_else(|| CarrierError::Http("edge host did not resolve".into()))?;
    let mut endpoint = quinn::Endpoint::client(SocketAddr::from(([0, 0, 0, 0], 0)))?;
    endpoint.set_default_client_config(quic_client_config(ca, &config.tls.server_name)?);
    let connecting = endpoint
        .connect(remote, &config.tls.server_name)
        .map_err(|error| CarrierError::Http(error.to_string()))?;
    let quic = timeout(config.tls_handshake_timeout(), connecting)
        .await
        .map_err(|_| CarrierError::Timeout("HTTP/3 QUIC handshake"))?
        .map_err(|error| CarrierError::Http(error.to_string()))?;
    let (mut h3_connection, mut send_request) = h3::client::builder()
        .max_field_section_size(16 * 1024)
        .build(h3_quinn::Connection::new(quic))
        .await
        .map_err(|error| CarrierError::Http(error.to_string()))?;
    let driver =
        tokio::spawn(async move { std::future::poll_fn(|cx| h3_connection.poll_close(cx)).await });
    let request = Request::builder()
        .method("POST")
        .uri(edge_uri)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(CAPABILITY_HEADER, token)
        .body(())
        .map_err(|error| CarrierError::Http(error.to_string()))?;
    let stream = timeout(
        config.backend_connect_timeout(),
        send_request.send_request(request),
    )
    .await
    .map_err(|_| CarrierError::Timeout("HTTP/3 request setup"))?
    .map_err(|error| CarrierError::Http(error.to_string()))?;
    let (mut send, mut recv) = stream.split();
    let idle_timeout = config.backend_idle_timeout();
    let max_bytes = config.limits.max_stream_bytes;
    let local_to_edge = async {
        let mut buffer = vec![0u8; 16 * 1024];
        let mut total = 0u64;
        loop {
            let read = timeout(idle_timeout, local_read.read(&mut buffer))
                .await
                .map_err(|_| CarrierError::Timeout("HTTP/3 local read"))??;
            if read == 0 {
                break;
            }
            total = total
                .checked_add(read as u64)
                .ok_or(RelayError::LimitExceeded)?;
            if total > max_bytes {
                return Err(CarrierError::Relay(RelayError::LimitExceeded));
            }
            timeout(
                idle_timeout,
                send.send_data(Bytes::copy_from_slice(&buffer[..read])),
            )
            .await
            .map_err(|_| CarrierError::Timeout("HTTP/3 request write"))?
            .map_err(|error| CarrierError::Http(error.to_string()))?;
        }
        timeout(idle_timeout, send.finish())
            .await
            .map_err(|_| CarrierError::Timeout("HTTP/3 request finish"))?
            .map_err(|error| CarrierError::Http(error.to_string()))?;
        Ok::<(), CarrierError>(())
    };
    let edge_to_local = async {
        let response = timeout(idle_timeout, recv.recv_response())
            .await
            .map_err(|_| CarrierError::Timeout("HTTP/3 response headers"))?
            .map_err(|error| CarrierError::Http(error.to_string()))?;
        if response.status() != StatusCode::OK {
            let _ = timeout(idle_timeout, write_socks5_reply(&mut local_write, 0x05)).await;
            return Err(CarrierError::Http(format!(
                "edge rejected relay request with status {}",
                response.status()
            )));
        }
        timeout(idle_timeout, write_socks5_reply(&mut local_write, 0x00))
            .await
            .map_err(|_| CarrierError::Timeout("SOCKS5 success reply"))??;
        while let Some(mut data) = timeout(idle_timeout, recv.recv_data())
            .await
            .map_err(|_| CarrierError::Timeout("HTTP/3 response body"))?
            .map_err(|error| CarrierError::Http(error.to_string()))?
        {
            let size = data.remaining();
            let bytes = data.copy_to_bytes(size);
            timeout(idle_timeout, local_write.write_all(&bytes))
                .await
                .map_err(|_| CarrierError::Timeout("HTTP/3 local write"))??;
        }
        timeout(idle_timeout, local_write.shutdown())
            .await
            .map_err(|_| CarrierError::Timeout("HTTP/3 local shutdown"))??;
        Ok::<(), CarrierError>(())
    };
    let result = tokio::select! {
        _ = shutdown.cancelled() => Err(CarrierError::Relay(RelayError::Cancelled)),
        result = async { tokio::try_join!(local_to_edge, edge_to_local) } => result.map(|_| ()),
    };
    endpoint.close(quinn::VarInt::from_u32(0), b"done");
    driver.abort();
    let _ = driver.await;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn h2_uri_requires_exact_owned_relay_endpoint() {
        let valid: Uri = "https://edge.example/phantom-one/v1".parse().expect("URI");
        assert!(validate_h2_uri(&valid).is_ok());

        for value in [
            "http://edge.example/phantom-one/v1",
            "https://edge.example/",
            "https://edge.example/phantom-one/v1/",
            "https://edge.example/phantom-one/v1?x=1",
            "https://user:pass@edge.example/phantom-one/v1",
        ] {
            let uri: Uri = value.parse().expect("URI");
            assert!(validate_h2_uri(&uri).is_err(), "{value} must be rejected");
        }
    }

    #[test]
    fn h2_uri_accepts_a_valid_custom_relay_path_only() {
        let valid: Uri = "https://edge.example/owned/relay-v2".parse().expect("URI");
        assert!(validate_h2_uri_with_path(&valid, "/owned/relay-v2").is_ok());
        assert!(validate_h2_uri_with_path(&valid, "/phantom-one/v1").is_err());
        assert!(validate_h2_uri_with_path(
            &"https://edge.example/owned/relay-v2?x=1"
                .parse()
                .expect("URI"),
            "/owned/relay-v2"
        )
        .is_err());
    }

    #[test]
    fn carrier_parser_has_an_explicit_http3_feature_boundary() {
        #[cfg(feature = "http3")]
        assert!(matches!(CarrierKind::parse("h3"), Ok(CarrierKind::Http3)));
        #[cfg(not(feature = "http3"))]
        assert!(matches!(
            CarrierKind::parse("h3"),
            Err(CarrierError::Unsupported("http/3 support was not compiled"))
        ));
    }

    #[test]
    fn capability_token_bundle_is_bounded_and_line_oriented() {
        let tokens =
            parse_capability_tokens(" first-token \n\nsecond-token\n", 64).expect("tokens");
        assert_eq!(tokens.len(), 2);
        assert_eq!(tokens[0].as_bytes(), b"first-token");
        assert_eq!(tokens[1].as_bytes(), b"second-token");
        assert!(parse_capability_tokens("token\nbad token", 64).is_err());
        assert!(parse_capability_tokens("", 64).is_err());
        assert!(parse_capability_tokens(&"x".repeat(65), 64).is_err());
    }

    #[test]
    fn content_length_validation_rejects_conflicts_and_overflow() {
        let mut conflicting = http::HeaderMap::new();
        conflicting.append(header::CONTENT_LENGTH, HeaderValue::from_static("10"));
        conflicting.append(header::CONTENT_LENGTH, HeaderValue::from_static("11"));
        assert_eq!(
            validate_content_length(&conflicting, 64),
            Err(StatusCode::BAD_REQUEST)
        );

        let mut oversized = http::HeaderMap::new();
        oversized.insert(header::CONTENT_LENGTH, HeaderValue::from_static("65"));
        assert_eq!(
            validate_content_length(&oversized, 64),
            Err(StatusCode::PAYLOAD_TOO_LARGE)
        );

        let mut invalid = http::HeaderMap::new();
        invalid.insert(header::CONTENT_LENGTH, HeaderValue::from_static("-1"));
        assert_eq!(
            validate_content_length(&invalid, 64),
            Err(StatusCode::BAD_REQUEST)
        );
    }

    #[test]
    fn octet_stream_validation_rejects_duplicate_content_types() {
        let mut headers = http::HeaderMap::new();
        headers.append(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );
        headers.append(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );
        assert!(!is_octet_stream(&headers));
    }

    #[tokio::test]
    async fn armed_pool_notification_observes_a_released_stream_slot() {
        let slots = Arc::new(Semaphore::new(1));
        let permit = slots.clone().acquire_owned().await.expect("slot");
        let notify = Arc::new(Notify::new());
        let stream_permit = PoolStreamPermit::new(permit, notify.clone());

        let notified = notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        drop(stream_permit);

        tokio::time::timeout(Duration::from_secs(1), notified)
            .await
            .expect("released slot should wake an armed waiter");
        assert!(slots.try_acquire().is_ok());
    }

    #[tokio::test]
    async fn socks5_handshake_rejects_empty_domain_without_waiting() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("listener address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let result = socks5_handshake(&mut stream).await;
            assert!(matches!(result, Err(CarrierError::Socks)));
        });

        let mut client = TcpStream::connect(address).await.expect("connect");
        client.write_all(&[5, 1, 0]).await.expect("methods");
        let mut method_reply = [0u8; 2];
        client
            .read_exact(&mut method_reply)
            .await
            .expect("method reply");
        assert_eq!(method_reply, [5, 0]);
        client
            .write_all(&[5, 1, 0, 3, 0])
            .await
            .expect("empty domain request");

        tokio::time::timeout(Duration::from_secs(1), server)
            .await
            .expect("handshake should reject promptly")
            .expect("server task");
    }

    #[tokio::test]
    async fn socks_listener_shutdown_reaps_without_waiting_for_accept() {
        let mut config = EdgeConfig {
            listen: "127.0.0.1:0".parse().expect("listen address"),
            backend: "127.0.0.1:443".into(),
            audience: "edge-a".into(),
            public_key: String::new(),
            relay_path: DEFAULT_RELAY_PATH.into(),
            tls: crate::config::TlsConfig {
                server_name: "edge.example".into(),
                ..Default::default()
            },
            limits: Default::default(),
            socks: Default::default(),
        };
        config.socks.listen = "127.0.0.1:0".parse().expect("socks address");
        let shutdown = CancellationToken::new();
        let cancel = shutdown.clone();
        let cancel_task = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            cancel.cancel();
        });

        tokio::time::timeout(
            Duration::from_secs(1),
            open_socks5_until(
                Arc::new(config),
                "https://edge.example/phantom-one/v1"
                    .parse()
                    .expect("edge URI"),
                "token".into(),
                Path::new("unused"),
                shutdown,
            ),
        )
        .await
        .expect("listener should stop promptly")
        .expect("listener shutdown");
        cancel_task.await.expect("cancellation task");
    }
}
