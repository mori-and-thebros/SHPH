//! Standards-compliant QUIC transport.
//!
//! This module uses Quinn for RFC 9000 transport behavior and TLS 1.3
//! protection. The existing SHPH authenticated hybrid handshake runs inside a
//! reliable QUIC bidirectional stream, while tunnel payloads use RFC 9221
//! application datagrams. The legacy `TransportMode::Quic` API remains the
//! experimental UDP shim for compatibility; callers must opt into this module
//! explicitly.

use crate::ja4::{self, Ja4Observer, Ja4ObserverConfig};
use crate::shroud2::{
    decode_batched_datagram, decode_datagram, encode_batched_datagram, encode_datagram,
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
    Result, ShphError,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;

const MAX_HANDSHAKE_MESSAGE_BYTES: usize = 16 * 1024;
const MAX_CONTROL_MESSAGE_BYTES: usize = 64 * 1024;
const MAX_TUN_DATAGRAM_BYTES: usize = 65_535;
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

/// An established standards QUIC session.
pub struct StandardsQuicConnection {
    pub connection: Connection,
    pub handshake: HandshakeState,
    control_send: SendStream,
    control_recv: RecvStream,
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
    build_server_endpoint(bind_addr, config, None)
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
    build_server_endpoint(bind_addr, config, Some((observer, observer_config)))
}

fn build_server_endpoint(
    bind_addr: SocketAddr,
    config: StandardsQuicConfig,
    observer: Option<(Arc<dyn Ja4Observer>, Ja4ObserverConfig)>,
) -> Result<StandardsQuicServer> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .map_err(|err| ShphError::Config(format!("generate QUIC certificate: {err}")))?;
    let certificate_der = cert.cert.der().to_vec();
    let certificate = quinn::rustls::pki_types::CertificateDer::from(certificate_der.clone());
    let private_key =
        quinn::rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
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
        .map_err(|err| ShphError::Transport(err.to_string()))?
        .await
        .map_err(|err| ShphError::Transport(err.to_string()))?;
    let (mut control_send, mut control_recv) = connection
        .open_bi()
        .await
        .map_err(|err| ShphError::Transport(err.to_string()))?;
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
    })
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
        let target_size = morphology.target_size(payload.len(), path_mtu)?;
        let datagram = encode_datagram(payload, target_size, path_mtu)?;
        let delay = morphology.next_delay();
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
        self.connection
            .send_datagram_wait(Bytes::from(datagram))
            .await
            .map_err(|err| ShphError::Transport(err.to_string()))
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
        let datagram = self
            .connection
            .read_datagram()
            .await
            .map_err(|err| ShphError::Transport(err.to_string()))?;
        decode_datagram(&datagram, path_mtu)
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

#[cfg(test)]
mod tests {
    use super::{
        accept, client_endpoint, connect, server_endpoint, server_endpoint_with_ja4_observer,
        StandardsQuicConfig, MAX_TUN_DATAGRAM_BYTES,
    };
    use crate::ja4::{Ja4ObserverConfig, RecordingJa4Observer};
    use shph_core::{HandshakeProfile, IdentityKeyPair, PeerPin, PeerPolicy};
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
