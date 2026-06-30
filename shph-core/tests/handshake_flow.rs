use base64::Engine as _;
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

// --- Ed25519 handshake authentication regression tests ---

#[test]
fn real_signature_verifies_and_roundtrips() {
    // Sanity: a freshly built hello verifies against its own signing key.
    let id = IdentityKeyPair::generate().unwrap();
    let mat = build_hello(&id).unwrap();
    // Re-derive the signed payload the way build_hello does and verify the sig.
    let _ = mat; // build_hello already signed internally; verify via verify_and_derive below.
    let peer = IdentityKeyPair::generate().unwrap();
    let peer_mat = build_hello(&peer).unwrap();
    let state = verify_and_derive(&id, &mat, &peer_mat.local_hello, true);
    assert!(state.is_ok(), "real Ed25519 signature must verify");
}

#[test]
fn forged_signature_is_rejected() {
    // An attacker who does NOT hold the peer's Ed25519 private key cannot
    // produce a valid signature, even if they know the peer's public keys.
    let victim = IdentityKeyPair::generate().unwrap();
    let attacker = IdentityKeyPair::generate().unwrap();
    let victim_mat = build_hello(&victim).unwrap();

    // Attacker builds their OWN hello but tries to impersonate the victim by
    // copying the victim's identity + signing public key into it. The victim's
    // signature was over the victim's OWN ephemeral/nonce, not the attacker's,
    // so verification must fail.
    let mut forged = build_hello(&attacker).unwrap().local_hello;
    forged.identity_pub_b64 = victim_mat.local_hello.identity_pub_b64.clone();
    forged.sign_pub_b64 = victim_mat.local_hello.sign_pub_b64.clone();
    forged.sig = victim_mat.local_hello.sig.clone();

    let res = verify_and_derive(&victim, &victim_mat, &forged, true);
    assert!(
        res.is_err(),
        "a signature over different transcript fields must NOT verify (MITM resistance)"
    );
}

#[test]
fn tampered_signature_bytes_rejected() {
    let id = IdentityKeyPair::generate().unwrap();
    let peer = IdentityKeyPair::generate().unwrap();
    let peer_mat = build_hello(&peer).unwrap();
    let mut hello = peer_mat.local_hello;

    // Decode the signature, flip one byte, re-encode.
    let mut sig_raw = base64::engine::general_purpose::STANDARD
        .decode(hello.sig.as_bytes())
        .unwrap();
    sig_raw[0] ^= 0xff;
    hello.sig = base64::engine::general_purpose::STANDARD.encode(sig_raw);

    let local_mat = build_hello(&id).unwrap();
    let res = verify_and_derive(&id, &local_mat, &hello, true);
    assert!(
        res.is_err(),
        "a tampered Ed25519 signature must be rejected"
    );
}

#[test]
fn wrong_peer_signing_key_rejected() {
    // A signature valid for one signing key must not verify under a different
    // signing key presented as the peer's.
    let id = IdentityKeyPair::generate().unwrap();
    let peer = IdentityKeyPair::generate().unwrap();
    let other = IdentityKeyPair::generate().unwrap();
    let mut hello = build_hello(&peer).unwrap().local_hello;
    // Swap in a different signing public key; the sig no longer matches it.
    hello.sign_pub_b64 =
        base64::engine::general_purpose::STANDARD.encode(other.signing_public_bytes());

    let local_mat = build_hello(&id).unwrap();
    let res = verify_and_derive(&id, &local_mat, &hello, true);
    assert!(
        res.is_err(),
        "signature must not verify under a swapped signing public key"
    );
}
