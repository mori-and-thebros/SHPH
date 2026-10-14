use crate::{
    capability::ReplayCache,
    config::{validate_relay_path, EdgeConfig, DEFAULT_RELAY_PATH},
    file::{read_bounded_private_file, read_bounded_regular_file},
    frontdoor::{
        is_octet_stream, FrontDoor, FrontDoorDecision, FrontDoorPreparation, FrontDoorResponse,
        CAPABILITY_HEADER,
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
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
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
    time::{sleep, sleep_until, timeout, Instant},
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
#[cfg(feature = "http3")]
const MAX_HTTP3_REMOTE_ADDRESSES: usize = 16;

type ClientBody = StreamBody<ReceiverStream<Result<Frame<Bytes>, Infallible>>>;
type ClientSender = hyper::client::conn::http2::SendRequest<ClientBody>;

#[derive(Clone)]
struct Http2Activity(Arc<Mutex<Http2ActivityState>>);

struct Http2ActivityState {
    last_activity: Instant,
    active_streams: usize,
}

struct Http2StreamGuard(Http2Activity);

impl Http2Activity {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(Http2ActivityState {
            last_activity: Instant::now(),
            active_streams: 0,
        })))
    }

    fn touch(&self) {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .last_activity = Instant::now();
    }

    fn begin_stream(&self) -> Http2StreamGuard {
        let mut state = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.last_activity = Instant::now();
        state.active_streams += 1;
        Http2StreamGuard(self.clone())
    }

    async fn wait_until_idle(&self, idle_timeout: Duration) {
        loop {
            let (last_activity, active_streams) = {
                let state = self
                    .0
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                (state.last_activity, state.active_streams)
            };
            if active_streams > 0 {
                sleep(Duration::from_millis(100)).await;
                continue;
            }
            sleep_until(last_activity + idle_timeout).await;
            let state = self
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if state.active_streams == 0
                && Instant::now().saturating_duration_since(state.last_activity) >= idle_timeout
            {
                return;
            }
        }
    }
}

impl Drop for Http2StreamGuard {
    fn drop(&mut self) {
        let mut state = self
            .0
             .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.active_streams = state.active_streams.saturating_sub(1);
        state.last_activity = Instant::now();
    }
}

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
            .timer(TokioTimer::new())
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
    activity: Option<&Http2Activity>,
) -> Result<(), RelayError> {
    tokio::select! {
        _ = cancellation.cancelled() => Err(RelayError::Cancelled),
        result = timeout(idle_timeout, sender.send(Ok(Frame::data(data)))) => {
            match result {
                Ok(Ok(())) => {
                    if let Some(activity) = activity {
                        activity.touch();
                    }
                    Ok(())
                },
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

async fn decide_with_replay(
    front_door: &FrontDoor,
    method: &http::Method,
    uri: &Uri,
    headers: &http::HeaderMap,
    replay: &tokio::sync::Mutex<ReplayCache>,
    shutdown: &CancellationToken,
) -> FrontDoorDecision {
    if shutdown.is_cancelled() {
        return FrontDoorDecision::Fallback(FrontDoorResponse::service_unavailable());
    }
    let verified = match front_door.prepare(method, uri, headers) {
        FrontDoorPreparation::Verified(verified) => verified,
        FrontDoorPreparation::Fallback(decision) => return decision,
    };
    let mut replay = tokio::select! {
        _ = shutdown.cancelled() => {
            return FrontDoorDecision::Fallback(FrontDoorResponse::service_unavailable());
        }
        replay = replay.lock() => replay,
    };
    front_door.commit_verified(verified, &mut replay)
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

fn add_bounded_stream_bytes(total: &mut u64, bytes: usize, limit: u64) -> Result<(), RelayError> {
    let bytes = u64::try_from(bytes).map_err(|_| RelayError::LimitExceeded)?;
    let updated = total.checked_add(bytes).ok_or(RelayError::LimitExceeded)?;
    if updated > limit {
        return Err(RelayError::LimitExceeded);
    }
    *total = updated;
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
    if front_door.replay_capacity() != config.limits.replay_capacity {
        return Err(CarrierError::Http(
            "front-door replay capacity does not match edge configuration".into(),
        ));
    }
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
    let replay = front_door.replay_cache();
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
    replay: Arc<tokio::sync::Mutex<ReplayCache>>,
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
    replay: Arc<tokio::sync::Mutex<ReplayCache>>,
    shutdown: CancellationToken,
) -> Result<(), CarrierError>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let max_streams = config.limits.max_streams_per_connection;
    let service_config = config.clone();
    let request_shutdown = shutdown.clone();
    let activity = Http2Activity::new();
    let service_activity = activity.clone();
    let service = service_fn(move |request: Request<Incoming>| {
        let config = service_config.clone();
        let front_door = front_door.clone();
        let replay = replay.clone();
        let shutdown = request_shutdown.clone();
        let activity = service_activity.clone();
        activity.touch();
        let stream_guard = activity.begin_stream();
        async move {
            let response = handle_http2_request(
                request,
                config,
                front_door,
                replay,
                shutdown,
                activity.clone(),
            )
            .await?;
            Ok::<_, Infallible>(response.map(move |body| {
                let body_activity = activity;
                body.map_frame(move |frame| {
                    body_activity.touch();
                    let _ = &stream_guard;
                    frame
                })
                .boxed()
            }))
        }
    });
    let mut builder = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
    builder
        .timer(TokioTimer::new())
        .max_concurrent_streams(max_streams)
        .keep_alive_interval(Some(Duration::from_secs(15)))
        .keep_alive_timeout(Duration::from_secs(10));
    let connection = builder.serve_connection(io, service);
    tokio::pin!(connection);
    let idle_timeout = config.http2_idle_timeout();
    let result = tokio::select! {
        biased;
        _ = shutdown.cancelled() => Ok(()),
        result = &mut connection => result.map_err(|error| CarrierError::Http(error.to_string())),
        _ = activity.wait_until_idle(idle_timeout) => {
            tracing::debug!(carrier = "h2", "idle connection closed");
            Ok(())
        },
    };
    shutdown.cancel();
    result
}

async fn handle_http2_request(
    request: Request<Incoming>,
    config: Arc<EdgeConfig>,
    front_door: Arc<FrontDoor>,
    replay: Arc<tokio::sync::Mutex<ReplayCache>>,
    connection_shutdown: CancellationToken,
    activity: Http2Activity,
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
    let decision = decide_with_replay(
        &front_door,
        &method,
        &uri,
        &headers,
        replay.as_ref(),
        &connection_shutdown,
    )
    .await;
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
    let request_activity = activity.clone();
    let response_activity = activity.clone();
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
                request_activity.touch();
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
                add_bounded_stream_bytes(&mut total, data.len(), max_bytes)?;
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
                    Some(&response_activity),
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
                None,
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
            add_bounded_stream_bytes(&mut total, data.len(), config.limits.max_stream_bytes)?;
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
    let pem = read_bounded_private_pem_file(path)?;
    PrivateKeyDer::from_pem_slice(&pem).map_err(|error| CarrierError::Tls(error.to_string()))
}

fn read_bounded_pem_file(path: &Path) -> Result<Vec<u8>, CarrierError> {
    read_bounded_regular_file(path, MAX_PEM_FILE_BYTES).map_err(map_pem_file_error)
}

fn read_bounded_private_pem_file(path: &Path) -> Result<Vec<u8>, CarrierError> {
    read_bounded_private_file(path, MAX_PEM_FILE_BYTES).map_err(map_pem_file_error)
}

fn map_pem_file_error(error: io::Error) -> CarrierError {
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
    if front_door.replay_capacity() != config.limits.replay_capacity {
        return Err(CarrierError::Http(
            "front-door replay capacity does not match edge configuration".into(),
        ));
    }
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
    let replay = front_door.replay_cache();
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
    replay: Arc<tokio::sync::Mutex<ReplayCache>>,
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
    replay: Arc<tokio::sync::Mutex<ReplayCache>>,
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
    let decision = decide_with_replay(
        &front_door,
        &method,
        &uri,
        &headers,
        replay.as_ref(),
        &shutdown,
    )
    .await;
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
            add_bounded_stream_bytes(&mut total, size, max_bytes)?;
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
struct Http3ClientDriver<T> {
    endpoint: quinn::Endpoint,
    driver: Option<tokio::task::JoinHandle<T>>,
}

#[cfg(feature = "http3")]
impl<T> Http3ClientDriver<T> {
    async fn stop(mut self, reason: &[u8]) {
        self.endpoint.close(quinn::VarInt::from_u32(0), reason);
        if let Some(driver) = self.driver.take() {
            driver.abort();
            let _ = driver.await;
        }
    }
}

#[cfg(feature = "http3")]
impl<T> Drop for Http3ClientDriver<T> {
    fn drop(&mut self) {
        self.endpoint
            .close(quinn::VarInt::from_u32(0), b"client task dropped");
        if let Some(driver) = &self.driver {
            driver.abort();
        }
    }
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
    let remote_addresses = timeout(
        config.backend_connect_timeout(),
        tokio::net::lookup_host((host.as_str(), port)),
    )
    .await
    .map_err(|_| CarrierError::Timeout("HTTP/3 DNS lookup"))??
    .collect::<Vec<_>>();
    let (endpoint, quic) = connect_http3_quic(
        remote_addresses,
        ca,
        &config.tls.server_name,
        config.tls_handshake_timeout(),
    )
    .await?;
    let (mut h3_connection, mut send_request) = h3::client::builder()
        .max_field_section_size(16 * 1024)
        .build(h3_quinn::Connection::new(quic))
        .await
        .map_err(|error| CarrierError::Http(error.to_string()))?;
    let request = Request::builder()
        .method("POST")
        .uri(edge_uri)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(CAPABILITY_HEADER, token)
        .body(())
        .map_err(|error| CarrierError::Http(error.to_string()))?;
    let driver =
        tokio::spawn(async move { std::future::poll_fn(|cx| h3_connection.poll_close(cx)).await });
    let client_driver = Http3ClientDriver {
        endpoint,
        driver: Some(driver),
    };
    let stream = match timeout(
        config.backend_connect_timeout(),
        send_request.send_request(request),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => {
            client_driver.stop(b"request setup failed").await;
            return Err(CarrierError::Http(error.to_string()));
        }
        Err(_) => {
            client_driver.stop(b"request setup timed out").await;
            return Err(CarrierError::Timeout("HTTP/3 request setup"));
        }
    };
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
        let mut total = 0u64;
        while let Some(mut data) = timeout(idle_timeout, recv.recv_data())
            .await
            .map_err(|_| CarrierError::Timeout("HTTP/3 response body"))?
            .map_err(|error| CarrierError::Http(error.to_string()))?
        {
            let size = data.remaining();
            add_bounded_stream_bytes(&mut total, size, max_bytes)?;
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
    client_driver.stop(b"done").await;
    result
}

#[cfg(feature = "http3")]
fn prioritize_http3_remote_addresses(addresses: Vec<SocketAddr>) -> Vec<SocketAddr> {
    let mut prioritized = Vec::new();
    for prefer_ipv4 in [true, false] {
        for address in &addresses {
            if address.is_ipv4() == prefer_ipv4 && !prioritized.contains(address) {
                prioritized.push(*address);
                if prioritized.len() == MAX_HTTP3_REMOTE_ADDRESSES {
                    return prioritized;
                }
            }
        }
    }
    prioritized
}

#[cfg(feature = "http3")]
fn http3_client_bind_address(remote: SocketAddr) -> SocketAddr {
    match remote {
        SocketAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], 0)),
        SocketAddr::V6(_) => SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 0)),
    }
}

#[cfg(feature = "http3")]
async fn connect_http3_quic(
    addresses: Vec<SocketAddr>,
    ca: &Path,
    server_name: &str,
    handshake_timeout: Duration,
) -> Result<(quinn::Endpoint, quinn::Connection), CarrierError> {
    let candidates = prioritize_http3_remote_addresses(addresses);
    if candidates.is_empty() {
        return Err(CarrierError::Http("edge host did not resolve".into()));
    }
    let client_config = quic_client_config(ca, server_name)?;
    let deadline = tokio::time::Instant::now() + handshake_timeout;
    let mut last_error = CarrierError::Http("all HTTP/3 addresses failed".into());

    for remote in candidates {
        let mut endpoint = match quinn::Endpoint::client(http3_client_bind_address(remote)) {
            Ok(endpoint) => endpoint,
            Err(error) => {
                last_error = CarrierError::Io(error);
                continue;
            }
        };
        endpoint.set_default_client_config(client_config.clone());
        let connecting = match endpoint.connect(remote, server_name) {
            Ok(connecting) => connecting,
            Err(error) => {
                endpoint.close(quinn::VarInt::from_u32(0), b"connect setup failed");
                last_error = CarrierError::Http(error.to_string());
                continue;
            }
        };
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            endpoint.close(quinn::VarInt::from_u32(0), b"connect timed out");
            return Err(CarrierError::Timeout("HTTP/3 QUIC handshake"));
        }
        match timeout(remaining, connecting).await {
            Ok(Ok(connection)) => return Ok((endpoint, connection)),
            Ok(Err(error)) => {
                endpoint.close(quinn::VarInt::from_u32(0), b"connect attempt failed");
                last_error = CarrierError::Http(error.to_string());
            }
            Err(_) => {
                endpoint.close(quinn::VarInt::from_u32(0), b"connect timed out");
                return Err(CarrierError::Timeout("HTTP/3 QUIC handshake"));
            }
        }
    }

    Err(last_error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{CapabilityClaims, CapabilityIssuer};
    use std::time::Duration;

    fn signed_capability_headers(issuer: &CapabilityIssuer, nonce: [u8; 16]) -> http::HeaderMap {
        let now = crate::capability::unix_now().expect("clock");
        let token = issuer
            .issue(&CapabilityClaims::new("edge-a", now, now + 60, nonce))
            .expect("token");
        let mut headers = http::HeaderMap::new();
        headers.insert(CAPABILITY_HEADER, token.parse().expect("header value"));
        headers
    }

    fn spawn_frontdoor_decision(
        front_door: Arc<FrontDoor>,
        replay: Arc<tokio::sync::Mutex<ReplayCache>>,
        headers: http::HeaderMap,
    ) -> tokio::task::JoinHandle<FrontDoorDecision> {
        tokio::spawn(async move {
            let method = http::Method::POST;
            let uri = H2_PATH.parse().expect("URI");
            let shutdown = CancellationToken::new();
            decide_with_replay(
                &front_door,
                &method,
                &uri,
                &headers,
                replay.as_ref(),
                &shutdown,
            )
            .await
        })
    }

    #[tokio::test]
    async fn shared_frontdoor_replay_state_rejects_cross_carrier_replay() {
        let (issuer, _) = CapabilityIssuer::generate(Duration::from_secs(300)).expect("issuer");
        let verifier = crate::capability::CapabilityVerifier::new(
            issuer.public_key(),
            "edge-a",
            Duration::from_secs(300),
            Duration::from_secs(5),
        )
        .expect("verifier");
        let front_door = Arc::new(FrontDoor::new(verifier, 4096));
        let h2_replay = front_door.replay_cache();
        let h3_replay = front_door.replay_cache();
        assert!(Arc::ptr_eq(&h2_replay, &h3_replay));

        let headers = signed_capability_headers(&issuer, [7; 16]);
        let method = http::Method::POST;
        let uri = H2_PATH.parse().expect("URI");
        let shutdown = CancellationToken::new();
        assert_eq!(
            decide_with_replay(
                &front_door,
                &method,
                &uri,
                &headers,
                h2_replay.as_ref(),
                &shutdown,
            )
            .await,
            FrontDoorDecision::Relay
        );
        assert_eq!(
            decide_with_replay(
                &front_door,
                &method,
                &uri,
                &headers,
                h3_replay.as_ref(),
                &shutdown,
            )
            .await,
            FrontDoorDecision::Fallback(FrontDoorResponse::unauthorized())
        );
    }

    #[test]
    fn bounded_stream_accounting_enforces_limit_and_overflow() {
        let mut total = 0;
        add_bounded_stream_bytes(&mut total, 10, 10).expect("exact limit");
        assert_eq!(total, 10);
        assert!(matches!(
            add_bounded_stream_bytes(&mut total, 1, 10),
            Err(RelayError::LimitExceeded)
        ));
        assert_eq!(total, 10);
        total = u64::MAX;
        assert!(matches!(
            add_bounded_stream_bytes(&mut total, 1, u64::MAX),
            Err(RelayError::LimitExceeded)
        ));
        assert_eq!(total, u64::MAX);
    }

    #[cfg(feature = "http3")]
    #[test]
    fn http3_address_selection_prefers_ipv4_but_supports_ipv6_only() {
        let ipv6: SocketAddr = "[2001:db8::1]:443".parse().expect("IPv6 address");
        let ipv4: SocketAddr = "192.0.2.1:443".parse().expect("IPv4 address");

        assert_eq!(
            prioritize_http3_remote_addresses(vec![ipv6, ipv4]),
            vec![ipv4, ipv6]
        );
        assert_eq!(
            http3_client_bind_address(ipv4),
            "0.0.0.0:0".parse().unwrap()
        );
        assert_eq!(http3_client_bind_address(ipv6), "[::]:0".parse().unwrap());
        assert!(prioritize_http3_remote_addresses(Vec::new()).is_empty());
    }

    #[tokio::test]
    async fn replay_lock_waits_after_verification_and_serializes_duplicates() {
        let (issuer, _) = CapabilityIssuer::generate(Duration::from_secs(300)).expect("issuer");
        let (other_issuer, _) =
            CapabilityIssuer::generate(Duration::from_secs(300)).expect("other issuer");
        let verifier = crate::capability::CapabilityVerifier::new(
            issuer.public_key(),
            "edge-a",
            Duration::from_secs(300),
            Duration::from_secs(5),
        )
        .expect("verifier");
        let front_door = Arc::new(FrontDoor::new(verifier, 4096));
        let replay = Arc::new(tokio::sync::Mutex::new(
            ReplayCache::new(4).expect("replay cache"),
        ));
        let held = replay.lock().await;

        let invalid = spawn_frontdoor_decision(
            front_door.clone(),
            replay.clone(),
            signed_capability_headers(&other_issuer, [1; 16]),
        );
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), invalid)
                .await
                .expect("invalid signature should not wait for replay lock")
                .expect("request task"),
            FrontDoorDecision::Fallback(FrontDoorResponse::unauthorized())
        );

        let first = spawn_frontdoor_decision(
            front_door.clone(),
            replay.clone(),
            signed_capability_headers(&issuer, [2; 16]),
        );
        let second = spawn_frontdoor_decision(
            front_door.clone(),
            replay.clone(),
            signed_capability_headers(&issuer, [3; 16]),
        );
        tokio::task::yield_now().await;
        assert!(!first.is_finished());
        assert!(!second.is_finished());
        drop(held);

        for request in [first, second] {
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(1), request)
                    .await
                    .expect("valid request should leave replay-lock wait")
                    .expect("request task"),
                FrontDoorDecision::Relay
            );
        }

        let duplicate_headers = signed_capability_headers(&issuer, [4; 16]);
        let held = replay.lock().await;
        let duplicate_first = spawn_frontdoor_decision(
            front_door.clone(),
            replay.clone(),
            duplicate_headers.clone(),
        );
        let duplicate_second =
            spawn_frontdoor_decision(front_door.clone(), replay.clone(), duplicate_headers);
        tokio::task::yield_now().await;
        drop(held);

        let outcomes = [
            tokio::time::timeout(Duration::from_secs(1), duplicate_first)
                .await
                .expect("first duplicate request should finish")
                .expect("request task"),
            tokio::time::timeout(Duration::from_secs(1), duplicate_second)
                .await
                .expect("second duplicate request should finish")
                .expect("request task"),
        ];
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, FrontDoorDecision::Relay))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| {
                    **outcome == FrontDoorDecision::Fallback(FrontDoorResponse::unauthorized())
                })
                .count(),
            1
        );
        assert_eq!(replay.lock().await.len(), 3);
    }

    #[tokio::test]
    async fn already_cancelled_requests_skip_verification_and_replay_commit() {
        let (issuer, _) = CapabilityIssuer::generate(Duration::from_secs(300)).expect("issuer");
        let verifier = crate::capability::CapabilityVerifier::new(
            issuer.public_key(),
            "edge-a",
            Duration::from_secs(300),
            Duration::from_secs(5),
        )
        .expect("verifier");
        let front_door = Arc::new(
            FrontDoor::new(verifier, 4096)
                .with_max_verifications_per_second(1)
                .expect("verification limit"),
        );
        let replay = Arc::new(tokio::sync::Mutex::new(
            ReplayCache::new(2).expect("replay cache"),
        ));
        let headers = signed_capability_headers(&issuer, [5; 16]);
        let method = http::Method::POST;
        let uri = H2_PATH.parse().expect("URI");
        let shutdown = CancellationToken::new();
        shutdown.cancel();

        assert_eq!(
            decide_with_replay(
                &front_door,
                &method,
                &uri,
                &headers,
                replay.as_ref(),
                &shutdown,
            )
            .await,
            FrontDoorDecision::Fallback(FrontDoorResponse::service_unavailable())
        );
        assert_eq!(
            decide_with_replay(
                &front_door,
                &method,
                &uri,
                &headers,
                replay.as_ref(),
                &CancellationToken::new(),
            )
            .await,
            FrontDoorDecision::Relay
        );
        assert_eq!(replay.lock().await.len(), 1);
    }

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
    async fn http2_server_handles_a_local_fallback_request() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("listener address");
        let client_stream = TcpStream::connect(address).await.expect("client stream");
        let (server_stream, _) = listener.accept().await.expect("server stream");
        let (issuer, _) = CapabilityIssuer::generate(Duration::from_secs(300)).expect("issuer");
        let verifier = crate::capability::CapabilityVerifier::new(
            issuer.public_key(),
            "edge-a",
            Duration::from_secs(300),
            Duration::from_secs(5),
        )
        .expect("verifier");
        let front_door = Arc::new(FrontDoor::new(verifier, 4096));
        let replay = front_door.replay_cache();
        let config = Arc::new(EdgeConfig {
            listen: address,
            backend: "127.0.0.1:1".into(),
            audience: "edge-a".into(),
            public_key: String::new(),
            relay_path: DEFAULT_RELAY_PATH.into(),
            tls: Default::default(),
            limits: Default::default(),
            socks: Default::default(),
        });
        let shutdown = CancellationToken::new();
        let server_shutdown = shutdown.clone();
        let server_task = tokio::spawn(async move {
            serve_http2_io(
                TokioIo::new(server_stream),
                config,
                front_door,
                replay,
                server_shutdown,
            )
            .await
        });

        let mut builder = hyper::client::conn::http2::Builder::new(TokioExecutor::new());
        builder.timer(TokioTimer::new());
        let (mut sender, connection) = timeout(
            Duration::from_secs(2),
            builder.handshake::<_, Full<Bytes>>(TokioIo::new(client_stream)),
        )
        .await
        .expect("client handshake timeout")
        .expect("client handshake");
        let client_task = tokio::spawn(connection);
        let request = Request::builder()
            .method("GET")
            .uri("https://edge.example/")
            .body(Full::new(Bytes::new()))
            .expect("request");
        let response = timeout(Duration::from_secs(2), sender.send_request(request))
            .await
            .expect("request timeout")
            .expect("fallback response");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        response.into_body().collect().await.expect("fallback body");

        shutdown.cancel();
        drop(sender);
        client_task.abort();
        timeout(Duration::from_secs(2), server_task)
            .await
            .expect("server shutdown timeout")
            .expect("server task")
            .expect("server connection");
    }

    #[tokio::test]
    async fn h2_denial_responses_match_and_replays_never_reach_backend() {
        use crate::capability::{unix_now, CapabilityClaims};

        let backend_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("backend listener");
        let backend_address = backend_listener.local_addr().expect("backend address");
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("edge listener");
        let address = listener.local_addr().expect("edge address");
        let client_stream = TcpStream::connect(address).await.expect("client stream");
        let (server_stream, _) = listener.accept().await.expect("server stream");
        let (issuer, _) = CapabilityIssuer::generate(Duration::from_secs(300)).expect("issuer");
        let verifier = crate::capability::CapabilityVerifier::new(
            issuer.public_key(),
            "edge-a",
            Duration::from_secs(300),
            Duration::from_secs(5),
        )
        .expect("verifier");
        let front_door = Arc::new(FrontDoor::new(verifier, 4096));
        let config = Arc::new(EdgeConfig {
            listen: address,
            backend: backend_address.to_string(),
            audience: "edge-a".into(),
            public_key: String::new(),
            relay_path: DEFAULT_RELAY_PATH.into(),
            tls: Default::default(),
            limits: Default::default(),
            socks: Default::default(),
        });
        let replay = front_door.replay_cache();
        let shutdown = CancellationToken::new();
        let server_shutdown = shutdown.clone();
        let server_task = tokio::spawn(async move {
            serve_http2_io(
                TokioIo::new(server_stream),
                config,
                front_door,
                replay,
                server_shutdown,
            )
            .await
        });

        let mut builder = hyper::client::conn::http2::Builder::new(TokioExecutor::new());
        builder.timer(TokioTimer::new());
        let (mut sender, connection) = timeout(
            Duration::from_secs(2),
            builder.handshake::<_, Full<Bytes>>(TokioIo::new(client_stream)),
        )
        .await
        .expect("client handshake timeout")
        .expect("client handshake");
        let client_task = tokio::spawn(connection);

        let now = unix_now().expect("clock");
        let expired = issuer
            .issue(&CapabilityClaims::new(
                "edge-a",
                now - 120,
                now - 60,
                [0x31; 16],
            ))
            .expect("expired capability");
        let mut invalid = signed_capability_headers(&issuer, [0x32; 16]);
        let token = invalid
            .get(CAPABILITY_HEADER)
            .expect("signed capability")
            .to_str()
            .expect("ASCII capability")
            .to_owned();
        let mut token_parts = token.split('.').map(str::to_owned).collect::<Vec<_>>();
        assert_eq!(token_parts.len(), 4);
        let replacement = if token_parts[3].starts_with('A') {
            'B'
        } else {
            'A'
        };
        token_parts[3].replace_range(0..1, &replacement.to_string());
        invalid.insert(
            CAPABILITY_HEADER,
            token_parts.join(".").parse().expect("tampered header"),
        );

        let cases = [
            ("missing", None),
            ("invalid-signature", Some(invalid)),
            (
                "expired",
                Some({
                    let mut headers = http::HeaderMap::new();
                    headers.insert(CAPABILITY_HEADER, expired.parse().expect("expired header"));
                    headers
                }),
            ),
        ];
        let case_count = cases.len();
        let mut response_times = Vec::with_capacity(case_count + 2);
        let mut denial_shapes = Vec::with_capacity(case_count + 1);
        for (name, capability_headers) in cases {
            let mut request = Request::builder()
                .method("POST")
                .uri(format!("https://edge.example{DEFAULT_RELAY_PATH}"))
                .header(header::CONTENT_TYPE, "application/octet-stream");
            if let Some(headers) = capability_headers {
                if let Some(value) = headers.get(CAPABILITY_HEADER) {
                    request = request.header(CAPABILITY_HEADER, value);
                }
            }
            let started = std::time::Instant::now();
            let response = timeout(
                Duration::from_secs(2),
                sender.send_request(request.body(Full::new(Bytes::new())).expect("request")),
            )
            .await
            .unwrap_or_else(|_| panic!("{name} probe response timeout"))
            .unwrap_or_else(|_| panic!("{name} probe response failed"));
            let status = response.status();
            let headers = response.headers().clone();
            let body = response
                .into_body()
                .collect()
                .await
                .unwrap_or_else(|_| panic!("{name} fallback body"))
                .to_bytes();
            response_times.push(started.elapsed());

            assert_eq!(status, StatusCode::UNAUTHORIZED, "{name} status");
            assert_eq!(headers[header::CONTENT_TYPE], "text/plain; charset=utf-8");
            assert_eq!(body.as_ref(), b"unauthorized\n", "{name} body");
            assert!(!sender.is_closed(), "{name} closed the HTTP/2 connection");
            denial_shapes.push((status, headers[header::CONTENT_TYPE].clone(), body.to_vec()));
        }

        assert_eq!(response_times.len(), case_count);

        let (stop_backend_sender, mut stop_backend_receiver) =
            tokio::sync::oneshot::channel::<()>();
        let backend_task = tokio::spawn(async move {
            let mut accepted_connections = 0usize;
            loop {
                tokio::select! {
                    _ = &mut stop_backend_receiver => break,
                    accepted = backend_listener.accept() => {
                        let (mut backend, _) = accepted.expect("backend accept");
                        accepted_connections += 1;
                        if accepted_connections == 1 {
                            let mut request = Vec::new();
                            timeout(Duration::from_secs(2), backend.read_to_end(&mut request))
                                .await
                                .expect("authorized request body timeout")
                                .expect("authorized request body");
                            assert!(request.is_empty());
                            backend
                                .write_all(b"authorized backend response")
                                .await
                                .expect("backend response");
                        }
                        backend.shutdown().await.expect("backend shutdown");
                    }
                }
            }
            accepted_connections
        });

        let valid_headers = signed_capability_headers(&issuer, [0x33; 16]);
        let valid_token = valid_headers
            .get(CAPABILITY_HEADER)
            .expect("valid capability")
            .clone();
        let first_request = Request::builder()
            .method("POST")
            .uri(format!("https://edge.example{DEFAULT_RELAY_PATH}"))
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .header(CAPABILITY_HEADER, valid_token.clone())
            .body(Full::new(Bytes::new()))
            .expect("authorized request");
        let first_response = timeout(Duration::from_secs(2), sender.send_request(first_request))
            .await
            .expect("authorized response timeout")
            .expect("authorized response");
        assert_eq!(first_response.status(), StatusCode::OK);
        let first_body = first_response
            .into_body()
            .collect()
            .await
            .expect("authorized response body")
            .to_bytes();
        assert_eq!(first_body.as_ref(), b"authorized backend response");
        assert!(
            !sender.is_closed(),
            "valid capability closed the HTTP/2 connection"
        );

        let replay_request = Request::builder()
            .method("POST")
            .uri(format!("https://edge.example{DEFAULT_RELAY_PATH}"))
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .header(CAPABILITY_HEADER, valid_token)
            .body(Full::new(Bytes::new()))
            .expect("replay request");
        let replay_started = std::time::Instant::now();
        let replay_response = timeout(Duration::from_secs(2), sender.send_request(replay_request))
            .await
            .expect("replay response timeout")
            .expect("replay response");
        let replay_status = replay_response.status();
        let replay_headers = replay_response.headers().clone();
        let replay_body = replay_response
            .into_body()
            .collect()
            .await
            .expect("replay response body")
            .to_bytes();
        response_times.push(replay_started.elapsed());
        assert_eq!(replay_status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            replay_headers[header::CONTENT_TYPE],
            "text/plain; charset=utf-8"
        );
        assert_eq!(replay_body.as_ref(), b"unauthorized\n");
        assert!(
            !sender.is_closed(),
            "replayed capability closed the HTTP/2 connection"
        );
        denial_shapes.push((
            replay_status,
            replay_headers[header::CONTENT_TYPE].clone(),
            replay_body.to_vec(),
        ));
        assert!(denial_shapes.windows(2).all(|pair| pair[0] == pair[1]));

        let _ = stop_backend_sender.send(());
        let accepted_connections = timeout(Duration::from_secs(2), backend_task)
            .await
            .expect("backend observer shutdown timeout")
            .expect("backend observer task");
        assert_eq!(accepted_connections, 1, "replay reached the backend");
        assert_eq!(response_times.len(), case_count + 1);
        shutdown.cancel();
        drop(sender);
        client_task.abort();
        timeout(Duration::from_secs(2), server_task)
            .await
            .expect("server shutdown timeout")
            .expect("server task")
            .expect("server connection");
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
    async fn http2_idle_deadline_restarts_after_connection_activity() {
        let activity = Http2Activity::new();
        let wait_activity = activity.clone();
        let mut idle_wait = tokio::spawn(async move {
            wait_activity
                .wait_until_idle(Duration::from_millis(60))
                .await;
        });

        sleep(Duration::from_millis(20)).await;
        activity.touch();

        assert!(timeout(Duration::from_millis(45), &mut idle_wait)
            .await
            .is_err());
        timeout(Duration::from_millis(100), idle_wait)
            .await
            .expect("idle deadline should close after activity stops")
            .expect("idle monitor task");
    }

    #[tokio::test]
    async fn http2_idle_deadline_waits_for_active_streams_to_finish() {
        let activity = Http2Activity::new();
        let stream_guard = activity.begin_stream();
        let wait_activity = activity.clone();
        let idle_wait = tokio::spawn(async move {
            wait_activity
                .wait_until_idle(Duration::from_millis(60))
                .await;
        });

        sleep(Duration::from_millis(80)).await;
        assert!(!idle_wait.is_finished());
        drop(stream_guard);

        timeout(Duration::from_millis(200), idle_wait)
            .await
            .expect("idle deadline should close after active stream ends")
            .expect("idle monitor task");
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
