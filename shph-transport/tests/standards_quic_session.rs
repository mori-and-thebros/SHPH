use shph_core::{HandshakeProfile, IdentityKeyPair, PeerPin, PeerPolicy, Result, ShphError};
use shph_transport::{
    connect_standards_quic_session,
    standards_quic::{accept, server_endpoint, StandardsQuicConfig},
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn synchronous_secure_session_uses_pinned_standards_quic_data_plane() {
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
    let server_certificate = server.certificate_der.clone();
    let (acknowledgement_received_tx, acknowledgement_received_rx) = std::sync::mpsc::channel();
    let server_task = tokio::spawn(async move {
        let connection = tokio::time::timeout(
            Duration::from_secs(5),
            accept(
                &server,
                &server_identity,
                &server_policy,
                HandshakeProfile::SecureDefault,
                Duration::from_secs(5),
            ),
        )
        .await
        .expect("server accept timeout")
        .expect("server SHPH handshake");
        let request = tokio::time::timeout(Duration::from_secs(5), connection.recv_datagram())
            .await
            .expect("request timeout")
            .expect("request datagram");
        assert_eq!(&request[..], b"request");
        connection
            .send_datagram_wait(b"reply")
            .await
            .expect("reply datagram");
        let acknowledgement =
            tokio::time::timeout(Duration::from_secs(5), connection.recv_datagram())
                .await
                .expect("acknowledgement timeout")
                .expect("acknowledgement datagram");
        assert_eq!(&acknowledgement[..], b"received");
        acknowledgement_received_tx
            .send(())
            .expect("signal that the acknowledgement was received");
    });

    let client_task = tokio::task::spawn_blocking(move || -> Result<()> {
        let (mut session, _) = connect_standards_quic_session(
            server_addr,
            "localhost",
            &server_certificate,
            &client_identity,
            &client_policy,
            HandshakeProfile::SecureDefault,
            Duration::from_secs(5),
        )?;
        assert!(matches!(
            session.send_frame(b"before-policy"),
            Err(ShphError::Auth(_))
        ));
        session.activate()?;
        let (mut sender, mut receiver) = session.into_split()?;
        receiver.set_poll_timeout(Duration::from_secs(5))?;
        sender.send_frame(b"request")?;
        assert_eq!(receiver.recv_frame()?, b"reply");
        sender.send_frame(b"received")?;
        acknowledgement_received_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("server received acknowledgement before client shutdown");
        Ok(())
    });

    client_task
        .await
        .expect("client worker join")
        .expect("client session");
    server_task.await.expect("server worker join");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn standards_quic_certificate_rejection_is_terminal_authentication_error() {
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
    let server_task = tokio::spawn(async move {
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            accept(
                &server,
                &server_identity,
                &server_policy,
                HandshakeProfile::SecureDefault,
                Duration::from_secs(5),
            ),
        )
        .await;
        assert!(result.is_err() || result.is_ok_and(|accepted| accepted.is_err()));
    });

    let wrong_certificate = shph_transport::standards_quic::generate_server_material()
        .expect("untrusted certificate")
        .certificate_der()
        .to_vec();
    let client_task = tokio::task::spawn_blocking(move || {
        connect_standards_quic_session(
            server_addr,
            "localhost",
            &wrong_certificate,
            &client_identity,
            &client_policy,
            HandshakeProfile::SecureDefault,
            Duration::from_secs(5),
        )
    });
    let error = match client_task.await.expect("client worker join") {
        Ok(_) => panic!("untrusted certificate unexpectedly established a session"),
        Err(error) => error,
    };
    assert!(matches!(error, ShphError::Auth(_)), "{error}");
    server_task.await.expect("server worker join");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn standards_quic_rejects_unpinned_shph_identity_as_terminal_authentication_error() {
    let server_identity = IdentityKeyPair::generate().expect("server identity");
    let client_identity = IdentityKeyPair::generate().expect("client identity");
    let wrong_identity = IdentityKeyPair::generate().expect("wrong peer identity");
    let server_policy = PeerPolicy::single(PeerPin::for_identity(&client_identity));
    let client_policy = PeerPolicy::single(PeerPin::for_identity(&wrong_identity));
    let server = server_endpoint(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        StandardsQuicConfig::default(),
    )
    .expect("server endpoint");
    let server_addr = server.endpoint.local_addr().expect("server address");
    let server_certificate = server.certificate_der.clone();
    let server_task = tokio::spawn(async move {
        let _ = tokio::time::timeout(
            Duration::from_secs(2),
            accept(
                &server,
                &server_identity,
                &server_policy,
                HandshakeProfile::SecureDefault,
                Duration::from_secs(2),
            ),
        )
        .await;
    });

    let client_task = tokio::task::spawn_blocking(move || {
        connect_standards_quic_session(
            server_addr,
            "localhost",
            &server_certificate,
            &client_identity,
            &client_policy,
            HandshakeProfile::SecureDefault,
            Duration::from_secs(5),
        )
    });
    let error = match client_task.await.expect("client worker join") {
        Ok(_) => panic!("un-pinned SHPH identity unexpectedly established a session"),
        Err(error) => error,
    };
    assert!(matches!(error, ShphError::Auth(_)), "{error}");
    server_task.await.expect("server worker join");
}
