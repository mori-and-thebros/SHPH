use shph_core::{build_hello, verify_and_derive, IdentityKeyPair};

#[test]
fn handshake_roundtrip_derives_complementary_keys() {
    let initiator = IdentityKeyPair::generate().expect("initiator key generation");
    let responder = IdentityKeyPair::generate().expect("responder key generation");

    let init_hello = build_hello(&initiator).expect("build init hello");
    let resp_hello = build_hello(&responder).expect("build resp hello");

    let init_state = verify_and_derive(&initiator, &init_hello, &resp_hello.local_hello, true)
        .expect("initiator verify");
    let resp_state = verify_and_derive(&responder, &resp_hello, &init_hello.local_hello, false)
        .expect("responder verify");

    assert_eq!(
        init_state.session_keys.send_key,
        resp_state.session_keys.recv_key
    );
    assert_eq!(
        init_state.session_keys.recv_key,
        resp_state.session_keys.send_key
    );
    assert_eq!(init_state.peer_fingerprint_hex, responder.fingerprint_hex());
    assert_eq!(resp_state.peer_fingerprint_hex, initiator.fingerprint_hex());
}

#[test]
fn handshake_rejects_bad_protocol() {
    let local = IdentityKeyPair::generate().expect("local key generation");
    let peer = IdentityKeyPair::generate().expect("peer key generation");
    let local_hello = build_hello(&local).expect("build local hello");
    let mut peer_hello = build_hello(&peer).expect("build peer hello").local_hello;
    peer_hello.proto = "invalid".to_string();

    let result = verify_and_derive(&local, &local_hello, &peer_hello, true);
    assert!(result.is_err());
}
