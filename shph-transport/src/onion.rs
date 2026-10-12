//! Experimental, explicitly configured nested-TLS onion circuits.
//!
//! Each relay link uses a fresh TLS 1.3 connection authenticated against a
//! locally pinned relay certificate. A relay terminates only its own TLS
//! layer, opens one literal allowlisted next-hop socket, and forwards the
//! remaining nested TLS stream. The final TCP tunnel carries the unchanged
//! end-to-end SHPH handshake. This is a bounded prototype, not an anonymity or
//! production security claim; the protocol and implementation require review.

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fmt;
use std::io;
use std::net::{SocketAddr, TcpListener as StdTcpListener, TcpStream as StdTcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use zeroize::{Zeroize, Zeroizing};

const RELAY_ALPN: &[u8] = b"shph-onion/1";
const OPEN_MAGIC: &[u8; 8] = b"SHONION1";
const OPEN_REQUEST_BYTES: usize = 8 + 32 + 1 + 16 + 2;
const OPEN_OK: &[u8; 4] = b"OPEN";
const OPEN_DENIED: &[u8; 4] = b"NOPE";
const MAX_RELAY_HOPS: usize = 3;
const MAX_TARGETS: usize = 64;
const MAX_CIRCUITS: usize = 512;
const MAX_CERTIFICATE_BYTES: usize = 16 * 1024;
const MAX_CIRCUIT_BYTES: u64 = 64 * 1024 * 1024;
const RELAY_COPY_BUFFER_BYTES: usize = 8 * 1024;
const LOCAL_BRIDGE_ADDRESS: &str = "127.0.0.1:0";

trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> AsyncReadWrite for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

type BoxedIo = Box<dyn AsyncReadWrite>;

/// One relay identity and its independent per-hop authorization token.
pub struct RelayHop {
    endpoint: SocketAddr,
    server_name: String,
    pinned_certificate_der: Vec<u8>,
    token: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for RelayHop {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayHop")
            .field("endpoint", &self.endpoint)
            .field("server_name", &self.server_name)
            .field("certificate_sha256", &self.certificate_sha256())
            .field("token", &"[REDACTED]")
            .finish()
    }
}

impl Clone for RelayHop {
    fn clone(&self) -> Self {
        Self {
            endpoint: self.endpoint,
            server_name: self.server_name.clone(),
            pinned_certificate_der: self.pinned_certificate_der.clone(),
            token: Zeroizing::new(*self.token),
        }
    }
}

impl RelayHop {
    pub fn new(
        endpoint: SocketAddr,
        server_name: impl Into<String>,
        pinned_certificate_der: Vec<u8>,
        token: [u8; 32],
    ) -> shph_core::Result<Self> {
        let server_name = server_name.into();
        if endpoint.port() == 0
            || endpoint.ip().is_unspecified()
            || server_name.trim().is_empty()
            || server_name.len() > 253
            || pinned_certificate_der.is_empty()
            || pinned_certificate_der.len() > MAX_CERTIFICATE_BYTES
        {
            return Err(shph_core::ShphError::Config(
                "invalid onion relay descriptor".into(),
            ));
        }
        Ok(Self {
            endpoint,
            server_name,
            pinned_certificate_der,
            token: Zeroizing::new(token),
        })
    }

    pub fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }

    pub fn certificate_sha256(&self) -> [u8; 32] {
        Sha256::digest(&self.pinned_certificate_der).into()
    }
}

/// Fixed, operator-selected path. Socket addresses are numeric so neither the
/// client nor a relay performs destination DNS resolution for this prototype.
#[derive(Debug, Clone)]
pub struct OnionPath {
    relays: Vec<RelayHop>,
    destination: SocketAddr,
}

impl OnionPath {
    pub fn new(relays: Vec<RelayHop>, destination: SocketAddr) -> shph_core::Result<Self> {
        if !(2..=MAX_RELAY_HOPS).contains(&relays.len())
            || destination.port() == 0
            || destination.ip().is_unspecified()
        {
            return Err(shph_core::ShphError::Config(
                "onion path requires two or three pinned relays and a literal destination".into(),
            ));
        }
        let mut endpoints = HashSet::with_capacity(relays.len() + 1);
        for relay in &relays {
            if !endpoints.insert(relay.endpoint) {
                return Err(shph_core::ShphError::Config(
                    "onion path contains a repeated relay endpoint".into(),
                ));
            }
        }
        if endpoints.contains(&destination) {
            return Err(shph_core::ShphError::Config(
                "onion destination must differ from every relay endpoint".into(),
            ));
        }
        Ok(Self {
            relays,
            destination,
        })
    }

    pub fn relay_count(&self) -> usize {
        self.relays.len()
    }
}

/// Hard bounds applied to every accepted relay tunnel.
#[derive(Debug, Clone, Copy)]
pub struct RelayLimits {
    pub max_circuits: usize,
    pub setup_timeout: Duration,
    pub max_lifetime: Duration,
    pub max_bytes_per_circuit: u64,
}

impl Default for RelayLimits {
    fn default() -> Self {
        Self {
            max_circuits: 32,
            setup_timeout: Duration::from_secs(10),
            max_lifetime: Duration::from_secs(300),
            max_bytes_per_circuit: MAX_CIRCUIT_BYTES,
        }
    }
}

impl RelayLimits {
    fn validate(self) -> shph_core::Result<Self> {
        if self.max_circuits == 0
            || self.max_circuits > MAX_CIRCUITS
            || self.setup_timeout < Duration::from_millis(100)
            || self.setup_timeout > Duration::from_secs(30)
            || self.max_lifetime < Duration::from_secs(1)
            || self.max_lifetime > Duration::from_secs(3600)
            || self.max_bytes_per_circuit == 0
            || self.max_bytes_per_circuit > 1024 * 1024 * 1024
        {
            return Err(shph_core::ShphError::Config(
                "onion relay limits exceed supported bounds".into(),
            ));
        }
        Ok(self)
    }
}

/// Per-relay route policy. Targets are exact numeric sockets; there is no
/// generic proxy mode or implicit destination fallback.
pub struct RelayServerConfig {
    allowed_targets: HashSet<SocketAddr>,
    token: Zeroizing<[u8; 32]>,
    limits: RelayLimits,
}

impl fmt::Debug for RelayServerConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayServerConfig")
            .field("allowed_targets", &self.allowed_targets)
            .field("token", &"[REDACTED]")
            .field("limits", &self.limits)
            .finish()
    }
}

impl RelayServerConfig {
    pub fn new(
        token: [u8; 32],
        allowed_targets: impl IntoIterator<Item = SocketAddr>,
        limits: RelayLimits,
    ) -> shph_core::Result<Self> {
        let mut target_set = HashSet::new();
        for target in allowed_targets {
            if target.port() == 0 || target.ip().is_unspecified() {
                return Err(shph_core::ShphError::Config(
                    "onion relay targets must use specific numeric addresses".into(),
                ));
            }
            if !target_set.contains(&target) && target_set.len() >= MAX_TARGETS {
                return Err(shph_core::ShphError::ResourceExhausted(
                    "onion relay target allowlist exceeds 64 entries".into(),
                ));
            }
            target_set.insert(target);
        }
        if target_set.is_empty() {
            return Err(shph_core::ShphError::Config(
                "onion relay requires at least one allowed target".into(),
            ));
        }
        Ok(Self {
            allowed_targets: target_set,
            token: Zeroizing::new(token),
            limits: limits.validate()?,
        })
    }
}

/// Build a TLS 1.3 relay acceptor for DER-encoded certificate and PKCS#8 key.
pub fn relay_tls_acceptor(
    certificate_der: Vec<u8>,
    private_key_pkcs8_der: Vec<u8>,
) -> shph_core::Result<TlsAcceptor> {
    if certificate_der.is_empty()
        || certificate_der.len() > MAX_CERTIFICATE_BYTES
        || private_key_pkcs8_der.is_empty()
        || private_key_pkcs8_der.len() > MAX_CERTIFICATE_BYTES
    {
        return Err(shph_core::ShphError::Config(
            "onion relay TLS material is outside supported bounds".into(),
        ));
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let private_key = PrivateKeyDer::try_from(private_key_pkcs8_der)
        .map_err(|_| shph_core::ShphError::Config("onion relay key must be PKCS#8 DER".into()))?;
    let mut server = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| {
            shph_core::ShphError::Config(format!("configure onion relay TLS: {error}"))
        })?
        .with_no_client_auth()
        .with_single_cert(vec![CertificateDer::from(certificate_der)], private_key)
        .map_err(|error| {
            shph_core::ShphError::Config(format!("load onion relay TLS certificate: {error}"))
        })?;
    server.alpn_protocols = vec![RELAY_ALPN.to_vec()];
    server.max_early_data_size = 0;
    Ok(TlsAcceptor::from(Arc::new(server)))
}

/// Run an operator-owned relay until the watch channel is set or closed.
/// Shutdown stops accepts, drains active tunnels briefly, then cancels the
/// remaining bounded tasks.
pub async fn serve_relay(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    config: RelayServerConfig,
    mut shutdown: watch::Receiver<bool>,
) -> shph_core::Result<()> {
    let config = Arc::new(config);
    let permits = Arc::new(Semaphore::new(config.limits.max_circuits));
    let mut tasks = JoinSet::new();
    let mut stopping = false;
    loop {
        if stopping && tasks.is_empty() {
            return Ok(());
        }
        tokio::select! {
            changed = shutdown.changed(), if !stopping => {
                if changed.is_err() || *shutdown.borrow() {
                    stopping = true;
                }
            }
            accepted = listener.accept(), if !stopping => {
                let (stream, _) = accepted.map_err(shph_core::ShphError::Io)?;
                let permit = match Arc::clone(&permits).try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => continue,
                };
                let acceptor = acceptor.clone();
                let config = Arc::clone(&config);
                tasks.spawn(async move {
                    handle_relay_stream(stream, acceptor, config, permit).await;
                });
            }
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
        }
        if stopping {
            let drain = async { while tasks.join_next().await.is_some() {} };
            if timeout(Duration::from_secs(2), drain).await.is_err() {
                tasks.abort_all();
                while tasks.join_next().await.is_some() {}
            }
        }
    }
}

async fn handle_relay_stream(
    stream: TcpStream,
    acceptor: TlsAcceptor,
    config: Arc<RelayServerConfig>,
    _permit: OwnedSemaphorePermit,
) {
    let setup = async {
        let mut tls = acceptor.accept(stream).await.ok()?;
        if tls.get_ref().1.alpn_protocol() != Some(RELAY_ALPN) {
            return None;
        }
        let mut request = Zeroizing::new([0u8; OPEN_REQUEST_BYTES]);
        tls.read_exact(&mut request[..]).await.ok()?;
        let target = parse_open_request(&request, &config.token)?;
        if !config.allowed_targets.contains(&target) {
            tls.write_all(OPEN_DENIED).await.ok()?;
            let _ = tls.shutdown().await;
            return None;
        }
        let upstream = match timeout(config.limits.setup_timeout, TcpStream::connect(target)).await
        {
            Ok(Ok(stream)) => stream,
            _ => {
                tls.write_all(OPEN_DENIED).await.ok()?;
                let _ = tls.shutdown().await;
                return None;
            }
        };
        tls.write_all(OPEN_OK).await.ok()?;
        Some((tls, upstream))
    };
    let Ok(Some((tls, upstream))) = timeout(config.limits.setup_timeout, setup).await else {
        return;
    };
    let _ = timeout(
        config.limits.max_lifetime,
        relay_copy(tls, upstream, config.limits.max_bytes_per_circuit),
    )
    .await;
}

fn parse_open_request(
    request: &[u8; OPEN_REQUEST_BYTES],
    expected_token: &[u8; 32],
) -> Option<SocketAddr> {
    if &request[..8] != OPEN_MAGIC
        || !shph_core::crypto::constant_time_eq(&request[8..40], expected_token)
    {
        return None;
    }
    let family = request[40];
    let address = &request[41..57];
    let port = u16::from_be_bytes([request[57], request[58]]);
    if port == 0 {
        return None;
    }
    let ip = match family {
        4 if address[4..].iter().all(|byte| *byte == 0) => {
            std::net::IpAddr::from([address[0], address[1], address[2], address[3]])
        }
        6 => std::net::IpAddr::from(<[u8; 16]>::try_from(address).ok()?),
        _ => return None,
    };
    if ip.is_unspecified() {
        return None;
    }
    Some(SocketAddr::new(ip, port))
}

async fn relay_copy(
    tls: tokio_rustls::server::TlsStream<TcpStream>,
    upstream: TcpStream,
    byte_limit: u64,
) -> io::Result<()> {
    let copied = Arc::new(AtomicU64::new(0));
    let (mut client_read, mut client_write) = tokio::io::split(tls);
    let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream);
    let client_to_upstream = copy_direction(
        &mut client_read,
        &mut upstream_write,
        Arc::clone(&copied),
        byte_limit,
    );
    let upstream_to_client =
        copy_direction(&mut upstream_read, &mut client_write, copied, byte_limit);
    tokio::try_join!(client_to_upstream, upstream_to_client)?;
    Ok(())
}

async fn copy_direction<R, W>(
    reader: &mut R,
    writer: &mut W,
    copied: Arc<AtomicU64>,
    byte_limit: u64,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = [0u8; RELAY_COPY_BUFFER_BYTES];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            writer.shutdown().await?;
            return Ok(());
        }
        let mut current = copied.load(Ordering::Relaxed);
        let allowed = loop {
            let remaining = byte_limit.saturating_sub(current);
            if remaining == 0 {
                return Err(io::Error::other("onion circuit byte quota exhausted"));
            }
            let allowed = read.min(remaining.min(usize::MAX as u64) as usize);
            match copied.compare_exchange_weak(
                current,
                current + allowed as u64,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break allowed,
                Err(observed) => current = observed,
            }
        };
        writer.write_all(&buffer[..allowed]).await?;
        if allowed != read || copied.load(Ordering::Relaxed) >= byte_limit {
            return Err(io::Error::other("onion circuit byte quota exhausted"));
        }
    }
}

fn relay_client_config(certificate_der: &[u8]) -> shph_core::Result<Arc<ClientConfig>> {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(certificate_der.to_vec()))
        .map_err(|error| {
            shph_core::ShphError::Config(format!("invalid pinned onion relay certificate: {error}"))
        })?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut client = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| {
            shph_core::ShphError::Config(format!("configure onion client TLS: {error}"))
        })?
        .with_root_certificates(Arc::new(roots))
        .with_no_client_auth();
    client.alpn_protocols = vec![RELAY_ALPN.to_vec()];
    client.enable_early_data = false;
    Ok(Arc::new(client))
}

/// Establish a bounded path with no alternate relay or direct-connect retry.
async fn connect_stream(path: &OnionPath, setup_timeout: Duration) -> shph_core::Result<BoxedIo> {
    if setup_timeout < Duration::from_millis(100) || setup_timeout > Duration::from_secs(60) {
        return Err(shph_core::ShphError::InvalidArgument(
            "onion setup timeout must be between 100 ms and 60 seconds".into(),
        ));
    }
    timeout(setup_timeout, connect_stream_inner(path))
        .await
        .map_err(|_| shph_core::ShphError::Timeout)?
}

async fn connect_stream_inner(path: &OnionPath) -> shph_core::Result<BoxedIo> {
    let first = path
        .relays
        .first()
        .ok_or_else(|| shph_core::ShphError::Config("onion path has no entry relay".into()))?;
    let tcp = TcpStream::connect(first.endpoint).await.map_err(|error| {
        shph_core::ShphError::Transport(format!("onion entry connect failed: {error}"))
    })?;
    tcp.set_nodelay(true).map_err(shph_core::ShphError::Io)?;
    let mut stream: BoxedIo = Box::new(tcp);
    for (index, hop) in path.relays.iter().enumerate() {
        let connector = TlsConnector::from(relay_client_config(&hop.pinned_certificate_der)?);
        let server_name = ServerName::try_from(hop.server_name.clone()).map_err(|_| {
            shph_core::ShphError::Config("invalid onion relay TLS server name".into())
        })?;
        let tls = connector
            .connect(server_name, stream)
            .await
            .map_err(|error| {
                shph_core::ShphError::Transport(format!(
                    "onion relay identity check failed: {error}"
                ))
            })?;
        if tls.get_ref().1.alpn_protocol() != Some(RELAY_ALPN) {
            return Err(shph_core::ShphError::Protocol(
                "onion relay did not negotiate the required protocol".into(),
            ));
        }
        stream = Box::new(tls);
        let target = path
            .relays
            .get(index + 1)
            .map(|next| next.endpoint)
            .unwrap_or(path.destination);
        send_open_request(&mut stream, target, &hop.token).await?;
    }
    Ok(stream)
}

async fn send_open_request(
    stream: &mut BoxedIo,
    target: SocketAddr,
    token: &[u8; 32],
) -> shph_core::Result<()> {
    let mut request = Zeroizing::new([0u8; OPEN_REQUEST_BYTES]);
    request[..8].copy_from_slice(OPEN_MAGIC);
    request[8..40].copy_from_slice(token);
    match target.ip() {
        std::net::IpAddr::V4(ip) => {
            request[40] = 4;
            request[41..45].copy_from_slice(&ip.octets());
        }
        std::net::IpAddr::V6(ip) => {
            request[40] = 6;
            request[41..57].copy_from_slice(&ip.octets());
        }
    }
    request[57..59].copy_from_slice(&target.port().to_be_bytes());
    stream
        .write_all(&request[..])
        .await
        .map_err(shph_core::ShphError::Io)?;
    request.zeroize();
    let mut response = [0u8; 4];
    stream
        .read_exact(&mut response)
        .await
        .map_err(shph_core::ShphError::Io)?;
    if &response != OPEN_OK {
        return Err(shph_core::ShphError::Transport(
            "onion relay refused the pinned path".into(),
        ));
    }
    Ok(())
}

/// Bridge a nested async TLS circuit to a standard local TCP stream so the
/// existing synchronous SHPH handshake and secure-session implementation can
/// run without changing their wire format. The local listener binds only to
/// loopback and lives only for this one session.
pub fn connect_onion_bridge(
    path: OnionPath,
    setup_timeout: Duration,
) -> shph_core::Result<StdTcpStream> {
    let listener = StdTcpListener::bind(LOCAL_BRIDGE_ADDRESS).map_err(shph_core::ShphError::Io)?;
    let local_address = listener.local_addr().map_err(shph_core::ShphError::Io)?;
    let client = StdTcpStream::connect(local_address).map_err(shph_core::ShphError::Io)?;
    client.set_nodelay(true).map_err(shph_core::ShphError::Io)?;
    let (bridge, _) = listener.accept().map_err(shph_core::ShphError::Io)?;
    bridge
        .set_nonblocking(true)
        .map_err(shph_core::ShphError::Io)?;
    std::thread::Builder::new()
        .name("shph-onion-bridge".into())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(_) => return,
            };
            runtime.block_on(async move {
                let Ok(mut local) = TcpStream::from_std(bridge) else {
                    return;
                };
                let Ok(mut remote) = connect_stream(&path, setup_timeout).await else {
                    return;
                };
                let _ = tokio::io::copy_bidirectional(&mut local, &mut remote).await;
            });
        })
        .map_err(shph_core::ShphError::Io)?;
    Ok(client)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn loopback() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
    }

    fn valid_loopback(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    fn certificate() -> (Vec<u8>, Vec<u8>) {
        let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .expect("generate local relay certificate");
        (
            generated.cert.der().to_vec(),
            generated.key_pair.serialize_der(),
        )
    }

    async fn start_relay(
        target: SocketAddr,
        token: [u8; 32],
    ) -> (RelayHop, watch::Sender<bool>, tokio::task::JoinHandle<()>) {
        start_relay_with_limits(target, token, RelayLimits::default()).await
    }

    async fn start_relay_with_limits(
        target: SocketAddr,
        token: [u8; 32],
        limits: RelayLimits,
    ) -> (RelayHop, watch::Sender<bool>, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind(loopback()).await.expect("bind relay");
        let endpoint = listener.local_addr().expect("relay address");
        let (certificate, key) = certificate();
        let hop = RelayHop::new(endpoint, "localhost", certificate.clone(), token).unwrap();
        let acceptor = relay_tls_acceptor(certificate, key).unwrap();
        let config = RelayServerConfig::new(token, [target], limits).unwrap();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let task = tokio::spawn(async move {
            serve_relay(listener, acceptor, config, shutdown_rx)
                .await
                .expect("relay service");
        });
        (hop, shutdown_tx, task)
    }

    async fn stop_relays(relays: Vec<(watch::Sender<bool>, tokio::task::JoinHandle<()>)>) {
        for (shutdown, _) in &relays {
            let _ = shutdown.send(true);
        }
        for (_, task) in relays {
            tokio::time::timeout(Duration::from_secs(3), task)
                .await
                .expect("relay shutdown deadline")
                .expect("relay task");
        }
    }

    #[tokio::test]
    async fn three_pinned_relays_carry_an_inner_tcp_stream_and_reconnect() {
        let destination = TcpListener::bind(loopback())
            .await
            .expect("destination listener");
        let destination_address = destination.local_addr().unwrap();
        let destination_task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = destination.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut payload = [0u8; 64];
                    if let Ok(length) = stream.read(&mut payload).await {
                        let _ = stream.write_all(&payload[..length]).await;
                    }
                });
            }
        });

        let tokens = [[1u8; 32], [2u8; 32], [3u8; 32]];
        let (exit, exit_shutdown, exit_task) = start_relay(destination_address, tokens[2]).await;
        let (middle, middle_shutdown, middle_task) = start_relay(exit.endpoint(), tokens[1]).await;
        let (entry, entry_shutdown, entry_task) = start_relay(middle.endpoint(), tokens[0]).await;
        let path = OnionPath::new(vec![entry, middle, exit], destination_address).unwrap();

        for message in [b"first circuit".as_slice(), b"reconnected circuit"] {
            let mut stream = connect_stream(&path, Duration::from_secs(3))
                .await
                .expect("establish three-relay path");
            stream.write_all(message).await.expect("send inner bytes");
            let mut reply = vec![0u8; message.len()];
            stream
                .read_exact(&mut reply)
                .await
                .expect("read inner reply");
            assert_eq!(reply, message);
        }

        stop_relays(vec![
            (entry_shutdown, entry_task),
            (middle_shutdown, middle_task),
            (exit_shutdown, exit_task),
        ])
        .await;
        destination_task.abort();
    }

    #[test]
    fn onion_path_requires_two_to_three_distinct_pinned_relays() {
        let (certificate, _) = certificate();
        let hop = RelayHop::new(
            valid_loopback(12001),
            "localhost",
            certificate.clone(),
            [9u8; 32],
        )
        .unwrap();
        let destination = valid_loopback(12009);
        assert!(OnionPath::new(Vec::new(), destination).is_err());
        assert!(OnionPath::new(vec![hop.clone()], destination).is_err());
        assert!(OnionPath::new(vec![hop.clone(), hop.clone()], destination).is_err());
        assert!(OnionPath::new(
            vec![hop.clone(), hop.clone(), hop.clone(), hop.clone()],
            destination,
        )
        .is_err());
        let second =
            RelayHop::new(valid_loopback(12002), "localhost", certificate, [8u8; 32]).unwrap();
        assert!(OnionPath::new(
            vec![
                RelayHop::new(
                    valid_loopback(12001),
                    "localhost",
                    hop.pinned_certificate_der.clone(),
                    [7u8; 32]
                )
                .unwrap(),
                second,
            ],
            valid_loopback(12001)
        )
        .is_err());
    }

    #[tokio::test]
    async fn onion_relay_rejects_wrong_pin_and_wrong_hop_token() {
        let destination = TcpListener::bind(loopback())
            .await
            .expect("destination listener");
        let destination_address = destination.local_addr().unwrap();
        let (good_first, first_shutdown, first_task) =
            start_relay(destination_address, [11u8; 32]).await;
        let (second, second_shutdown, second_task) =
            start_relay(destination_address, [12u8; 32]).await;
        let forbidden_target_path = OnionPath::new(
            vec![good_first.clone(), second.clone()],
            destination_address,
        )
        .unwrap();
        assert!(
            connect_stream(&forbidden_target_path, Duration::from_secs(3))
                .await
                .is_err()
        );

        let (wrong_cert, _) = certificate();
        let wrong_pin =
            RelayHop::new(good_first.endpoint(), "localhost", wrong_cert, [11u8; 32]).unwrap();
        let path = OnionPath::new(vec![wrong_pin, second.clone()], destination_address).unwrap();
        assert!(connect_stream(&path, Duration::from_secs(3)).await.is_err());

        let wrong_token_first = RelayHop::new(
            good_first.endpoint(),
            "localhost",
            good_first.pinned_certificate_der.clone(),
            [99u8; 32],
        )
        .unwrap();
        let path = OnionPath::new(vec![wrong_token_first, second], destination_address).unwrap();
        assert!(connect_stream(&path, Duration::from_secs(3)).await.is_err());
        assert!(
            timeout(Duration::from_millis(25), destination.accept())
                .await
                .is_err(),
            "onion failure must not open the destination directly"
        );
        stop_relays(vec![
            (first_shutdown, first_task),
            (second_shutdown, second_task),
        ])
        .await;
        drop(destination);
    }

    #[tokio::test]
    async fn onion_relay_circuit_exhaustion_closes_excess_connections() {
        let destination = TcpListener::bind(loopback())
            .await
            .expect("destination listener");
        let destination_address = destination.local_addr().expect("destination address");
        let limits = RelayLimits {
            max_circuits: 1,
            setup_timeout: Duration::from_secs(3),
            ..RelayLimits::default()
        };
        let (hop, shutdown, task) =
            start_relay_with_limits(destination_address, [61u8; 32], limits).await;

        // The first plain TCP client occupies the only permit while its TLS
        // handshake remains stalled. The next accepted socket must be dropped.
        let first = TcpStream::connect(hop.endpoint())
            .await
            .expect("first stalled connection");
        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut excess = TcpStream::connect(hop.endpoint())
            .await
            .expect("excess connection");
        let mut byte = [0u8; 1];
        let excess_result = timeout(Duration::from_secs(1), excess.read(&mut byte))
            .await
            .expect("excess connection close deadline");
        assert!(matches!(excess_result, Err(_) | Ok(0)));

        drop(first);
        drop(excess);
        stop_relays(vec![(shutdown, task)]).await;
        drop(destination);
    }

    #[tokio::test]
    async fn onion_relay_closes_malformed_tls_setup_without_connecting_target() {
        let destination = TcpListener::bind(loopback())
            .await
            .expect("destination listener");
        let destination_address = destination.local_addr().expect("destination address");
        let (hop, shutdown, task) = start_relay(destination_address, [62u8; 32]).await;
        let tcp = TcpStream::connect(hop.endpoint())
            .await
            .expect("relay TCP connection");
        let connector =
            TlsConnector::from(relay_client_config(&hop.pinned_certificate_der).unwrap());
        let server_name = ServerName::try_from(hop.server_name.clone()).unwrap();
        let mut tls = connector
            .connect(server_name, tcp)
            .await
            .expect("pinned TLS connection");
        let malformed = [0u8; OPEN_REQUEST_BYTES];
        tls.write_all(&malformed)
            .await
            .expect("send malformed setup");
        let mut response = [0u8; 1];
        let close_result = timeout(Duration::from_secs(1), tls.read(&mut response))
            .await
            .expect("malformed setup close deadline");
        assert!(matches!(close_result, Err(_) | Ok(0)));
        assert!(
            timeout(Duration::from_millis(50), destination.accept())
                .await
                .is_err(),
            "malformed setup must not connect to an allowed target"
        );

        stop_relays(vec![(shutdown, task)]).await;
        drop(destination);
    }

    #[tokio::test]
    async fn onion_relay_shutdown_aborts_a_stalled_setup_within_the_drain_bound() {
        let destination = TcpListener::bind(loopback())
            .await
            .expect("destination listener");
        let destination_address = destination.local_addr().expect("destination address");
        let (hop, shutdown, task) = start_relay(destination_address, [63u8; 32]).await;
        let mut stalled_client = TcpStream::connect(hop.endpoint())
            .await
            .expect("stalled TLS setup");
        tokio::time::sleep(Duration::from_millis(50)).await;

        let _ = shutdown.send(true);
        timeout(Duration::from_secs(3), task)
            .await
            .expect("relay shutdown deadline")
            .expect("relay task join");
        let mut byte = [0u8; 1];
        let closed = timeout(Duration::from_secs(1), stalled_client.read(&mut byte))
            .await
            .expect("stalled client close deadline");
        assert!(matches!(closed, Err(_) | Ok(0)));
        drop(destination);
    }

    #[tokio::test]
    async fn onion_relay_lifetime_closes_a_stalled_destination_path() {
        let destination = TcpListener::bind(loopback())
            .await
            .expect("destination listener");
        let destination_address = destination.local_addr().expect("destination address");
        let destination_task = tokio::spawn(async move {
            let (mut stream, _) = destination
                .accept()
                .await
                .expect("accept destination client");
            let mut byte = [0u8; 1];
            let _ = stream.read(&mut byte).await;
        });
        let limits = RelayLimits {
            max_lifetime: Duration::from_secs(1),
            ..RelayLimits::default()
        };
        let (exit, exit_shutdown, exit_task) =
            start_relay_with_limits(destination_address, [64u8; 32], limits).await;
        let (entry, entry_shutdown, entry_task) =
            start_relay_with_limits(exit.endpoint(), [65u8; 32], limits).await;
        let path = OnionPath::new(vec![entry, exit], destination_address).unwrap();
        let mut circuit = connect_stream(&path, Duration::from_secs(3))
            .await
            .expect("establish circuit to stalled destination");
        let mut byte = [0u8; 1];
        let result = timeout(Duration::from_secs(3), circuit.read(&mut byte))
            .await
            .expect("relay lifetime close deadline");
        assert!(matches!(result, Err(_) | Ok(0)));

        stop_relays(vec![
            (entry_shutdown, entry_task),
            (exit_shutdown, exit_task),
        ])
        .await;
        destination_task.abort();
    }

    #[test]
    fn onion_open_request_is_canonical_and_target_authorization_is_literal() {
        let token = [41u8; 32];
        let target = valid_loopback(12345);
        let mut request = [0u8; OPEN_REQUEST_BYTES];
        request[..8].copy_from_slice(OPEN_MAGIC);
        request[8..40].copy_from_slice(&token);
        request[40] = 4;
        request[41..45].copy_from_slice(&[127, 0, 0, 1]);
        request[57..59].copy_from_slice(&target.port().to_be_bytes());
        assert_eq!(parse_open_request(&request, &token), Some(target));

        let mut malformed = request;
        malformed[45] = 1;
        assert_eq!(parse_open_request(&malformed, &token), None);
        malformed = request;
        malformed[40] = 9;
        assert_eq!(parse_open_request(&malformed, &token), None);
        malformed = request;
        malformed[57] = 0;
        malformed[58] = 0;
        assert_eq!(parse_open_request(&malformed, &token), None);
        assert_eq!(parse_open_request(&request, &[42u8; 32]), None);
    }

    #[tokio::test]
    async fn relay_forwarding_stops_at_the_shared_byte_quota() {
        let (mut source, mut client) = tokio::io::duplex(32);
        let (mut upstream, mut destination) = tokio::io::duplex(32);
        let quota = Arc::new(AtomicU64::new(0));
        let forwarding =
            tokio::spawn(async move { copy_direction(&mut source, &mut upstream, quota, 4).await });
        client.write_all(b"eight-bytes").await.unwrap();

        let mut forwarded = [0u8; 4];
        destination.read_exact(&mut forwarded).await.unwrap();
        assert_eq!(&forwarded, b"eigh");
        let mut rest = Vec::new();
        destination.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty());
        assert!(forwarding.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn three_relays_preserve_the_end_to_end_shph_identity_and_payload_channel() {
        use crate::{
            accept_secure_session_lab_with_profile, connect_secure_session_onion, HandshakeProfile,
            IdentityKeyPair, PeerPolicy, QuicLabConfig, TransportMode,
        };
        use shph_core::PeerPin;

        let destination_address = {
            let reservation = StdTcpListener::bind("127.0.0.1:0").expect("reserve SHPH address");
            reservation.local_addr().expect("SHPH address")
        };
        let server_identity = IdentityKeyPair::generate().expect("destination identity");
        let client_identity = IdentityKeyPair::generate().expect("client identity");
        let server_policy = PeerPolicy::single(PeerPin::for_identity(&client_identity));
        let client_policy = PeerPolicy::single(PeerPin::for_identity(&server_identity));
        let server_identity_for_task = server_identity.clone();
        let server_task = tokio::task::spawn_blocking(move || {
            let (mut session, _) = accept_secure_session_lab_with_profile(
                &destination_address.to_string(),
                &server_identity_for_task,
                &server_policy,
                5,
                TransportMode::Tcp,
                QuicLabConfig::default(),
                HandshakeProfile::ClassicalLab,
            )?;
            session.activate()?;
            session.recv_frame()
        });

        let tokens = [[21u8; 32], [22u8; 32], [23u8; 32]];
        let (exit, exit_shutdown, exit_task) = start_relay(destination_address, tokens[2]).await;
        let (middle, middle_shutdown, middle_task) = start_relay(exit.endpoint(), tokens[1]).await;
        let (entry, entry_shutdown, entry_task) = start_relay(middle.endpoint(), tokens[0]).await;
        let path = OnionPath::new(vec![entry, middle, exit], destination_address).unwrap();
        let client_identity_for_task = client_identity.clone();
        let client_policy_for_task = client_policy.clone();
        let client_task = tokio::task::spawn_blocking(move || {
            let (mut session, state) = connect_secure_session_onion(
                path,
                &client_identity_for_task,
                &client_policy_for_task,
                Duration::from_secs(5),
                QuicLabConfig::default(),
                HandshakeProfile::ClassicalLab,
            )?;
            session.activate()?;
            session.send_frame(b"authenticated payload through three relays")?;
            Ok::<_, shph_core::ShphError>(state)
        });

        let state = tokio::time::timeout(Duration::from_secs(10), client_task)
            .await
            .expect("client SHPH handshake timeout")
            .expect("client task")
            .expect("client onion SHPH handshake");
        assert_eq!(
            state.peer_fingerprint_hex,
            server_identity.fingerprint_hex()
        );
        let payload = tokio::time::timeout(Duration::from_secs(10), server_task)
            .await
            .expect("server SHPH receive timeout")
            .expect("server task")
            .expect("server onion SHPH receive");
        assert_eq!(payload, b"authenticated payload through three relays");

        stop_relays(vec![
            (entry_shutdown, entry_task),
            (middle_shutdown, middle_task),
            (exit_shutdown, exit_task),
        ])
        .await;
    }
}
