//! Standards-compliant QUIC transport.
//!
//! This module uses Quinn for RFC 9000 transport behavior and TLS 1.3
//! protection. The existing SHPH authenticated hybrid handshake runs inside a
//! reliable QUIC bidirectional stream, while tunnel payloads use RFC 9221
//! application datagrams. The legacy `TransportMode::Quic` API remains the
//! experimental UDP shim for compatibility; callers must opt into this module
//! explicitly.

use bytes::Bytes;
use quinn::{
    ClientConfig, Connection, Endpoint, RecvStream, SendStream, ServerConfig, TransportConfig,
    VarInt,
};
use shph_core::{
    absorb_responder_pq, build_hello_with_profile, finalize_initiator_pq, verify_and_derive,
    verify_hello_signature, HandshakeProfile, HandshakeState, Hello, IdentityKeyPair, Result,
    ShphError,
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
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .map_err(|err| ShphError::Config(format!("generate QUIC certificate: {err}")))?;
    let certificate_der = cert.cert.der().to_vec();
    let certificate = quinn::rustls::pki_types::CertificateDer::from(certificate_der.clone());
    let private_key =
        quinn::rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let mut server_config =
        ServerConfig::with_single_cert(vec![certificate], private_key.into())
            .map_err(|err| ShphError::Config(format!("configure QUIC server TLS: {err}")))?;
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
    let mut roots = quinn::rustls::RootCertStore::empty();
    roots
        .add(quinn::rustls::pki_types::CertificateDer::from(
            server_certificate_der.to_vec(),
        ))
        .map_err(|err| ShphError::Config(format!("load QUIC server certificate: {err}")))?;
    let mut client_config = ClientConfig::with_root_certificates(Arc::new(roots))
        .map_err(|err| ShphError::Config(format!("configure QUIC client TLS: {err}")))?;
    client_config.transport_config(config.transport_config()?);
    let mut endpoint = Endpoint::client(bind_addr).map_err(ShphError::Io)?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

/// Establish a standards QUIC connection and run the SHPH application
/// handshake before returning any data-plane handle.
pub async fn connect(
    endpoint: &Endpoint,
    peer_addr: SocketAddr,
    server_name: &str,
    local_identity: &IdentityKeyPair,
    profile: HandshakeProfile,
    handshake_timeout: Duration,
) -> Result<StandardsQuicConnection> {
    timeout(
        handshake_timeout,
        connect_inner(endpoint, peer_addr, server_name, local_identity, profile),
    )
    .await
    .map_err(|_| ShphError::Timeout)?
}

async fn connect_inner(
    endpoint: &Endpoint,
    peer_addr: SocketAddr,
    server_name: &str,
    local_identity: &IdentityKeyPair,
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
    verify_hello_signature(local_identity, &material, &peer_hello)?;
    if profile.uses_pqc() {
        let ciphertext = finalize_initiator_pq(local_identity, &mut material, &peer_hello)?;
        write_message(
            &mut control_send,
            &ciphertext,
            shph_core::ML_KEM_768_CIPHERTEXT_BYTES,
        )
        .await?;
    }
    let handshake = verify_and_derive(local_identity, &material, &peer_hello, true)?;
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
    profile: HandshakeProfile,
    handshake_timeout: Duration,
) -> Result<StandardsQuicConnection> {
    timeout(
        handshake_timeout,
        accept_inner(server, local_identity, profile),
    )
    .await
    .map_err(|_| ShphError::Timeout)?
}

async fn accept_inner(
    server: &StandardsQuicServer,
    local_identity: &IdentityKeyPair,
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
    verify_hello_signature(local_identity, &material, &peer_hello)?;
    write_message(
        &mut control_send,
        &serde_json::to_vec(&material.local_hello).map_err(ShphError::Serialization)?,
        MAX_HANDSHAKE_MESSAGE_BYTES,
    )
    .await?;
    if profile.uses_pqc() {
        let ciphertext =
            read_message(&mut control_recv, shph_core::ML_KEM_768_CIPHERTEXT_BYTES).await?;
        absorb_responder_pq(&mut material, &ciphertext)?;
    }
    let handshake = verify_and_derive(local_identity, &material, &peer_hello, false)?;
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
        accept, client_endpoint, connect, server_endpoint, StandardsQuicConfig,
        MAX_TUN_DATAGRAM_BYTES,
    };
    use shph_core::{HandshakeProfile, IdentityKeyPair};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;

    #[test]
    fn standards_config_is_bounded() {
        let config = StandardsQuicConfig::default();
        assert_eq!(config.max_datagram_buffer_bytes, 256 * 1024);
        assert!(config.max_concurrent_bidirectional_streams <= 16);
        assert_eq!(MAX_TUN_DATAGRAM_BYTES, 65_535);
    }

    #[tokio::test]
    async fn loopback_handshake_control_and_datagram_roundtrip() {
        let server_identity = IdentityKeyPair::generate().expect("server identity");
        let client_identity = IdentityKeyPair::generate().expect("client identity");
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
}
