use base64::Engine as _;
use shph_core::{
    absorb_responder_pq, build_hello, build_hello_with_profile, deterministic_role,
    finalize_initiator_pq, verify_and_derive, HandshakeMaterial, HandshakeProfile, HandshakeRole,
    IdentityKeyPair, PeerPin, PeerPolicy,
};

/// Perform the in-memory hybrid PQ exchange exactly as the transports do:
/// each side builds its hello, the initiator encapsulates against the
/// responder's PQ public key, the responder decapsulates the resulting
/// ciphertext, then both derive keys. Returns `(init_state, resp_state)`.
fn hybrid_exchange(
    initiator: &IdentityKeyPair,
    responder: &IdentityKeyPair,
) -> (
    shph_core::HandshakeState,
    shph_core::HandshakeState,
    HandshakeMaterial,
    HandshakeMaterial,
) {
    let mut init_mat = build_hello(initiator).expect("build init hello");
    let mut resp_mat = build_hello(responder).expect("build resp hello");

    // Initiator encapsulates against the responder's PQ public key.
    let init_policy = PeerPolicy::single(PeerPin::for_identity(responder));
    let resp_policy = PeerPolicy::single(PeerPin::for_identity(initiator));
    // The transport sends the signed hello before it creates the follow-up
    // ciphertext frame. Keep that wire representation separate from the
    // initiator's local material, which records the ciphertext for derivation.
    let initiator_hello = init_mat.local_hello.clone();
    let ct = finalize_initiator_pq(
        initiator,
        &mut init_mat,
        &resp_mat.local_hello,
        &init_policy,
    )
    .expect("initiator finalize");
    // Responder decapsulates the initiator's ciphertext.
    absorb_responder_pq(
        responder,
        &mut resp_mat,
        &initiator_hello,
        &ct,
        &resp_policy,
    )
    .expect("responder absorb");

    let init_state = verify_and_derive(
        initiator,
        &init_mat,
        &resp_mat.local_hello,
        true,
        &init_policy,
    )
    .expect("init verify");
    let resp_state = verify_and_derive(
        responder,
        &resp_mat,
        &initiator_hello,
        false,
        &resp_policy,
    )
    .expect("resp verify");
    (init_state, resp_state, init_mat, resp_mat)
}

#[test]
fn handshake_roundtrip_derives_complementary_keys() {
    let initiator = IdentityKeyPair::generate().expect("initiator key generation");
    let responder = IdentityKeyPair::generate().expect("responder key generation");

    let (init_state, resp_state, _, _) = hybrid_exchange(&initiator, &responder);

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
fn deterministic_peer_id_tie_breaking_is_complementary() {
    let lower = [0x10u8; 32];
    let higher = [0x20u8; 32];
    assert_eq!(
        deterministic_role(&lower, &higher),
        HandshakeRole::Initiator
    );
    assert_eq!(
        deterministic_role(&higher, &lower),
        HandshakeRole::Responder
    );
}

#[test]
fn handshake_rejects_bad_protocol() {
    let local = IdentityKeyPair::generate().expect("local key generation");
    let peer = IdentityKeyPair::generate().expect("peer key generation");
    let local_hello = build_hello(&local).expect("build local hello");
    let mut peer_hello = build_hello(&peer).expect("build peer hello").local_hello;
    peer_hello.proto = "invalid".to_string();

    let result = verify_and_derive(
        &local,
        &local_hello,
        &peer_hello,
        true,
        &PeerPolicy::single(PeerPin::for_identity(&peer)),
    );
    assert!(result.is_err());
}

// --- Hybrid post-quantum regression tests ---

#[test]
fn real_signature_verifies_and_roundtrips() {
    let id = IdentityKeyPair::generate().unwrap();
    let peer = IdentityKeyPair::generate().unwrap();
    let (_init_state, _resp_state, _, _) = hybrid_exchange(&id, &peer);
    // Reaching here means both signatures verified under the full hybrid flow.
}

#[test]
fn hybrid_session_keys_match_across_sides() {
    // Stronger than complementary: with fixed identities the derived keys are
    // deterministic given the same ephemeral + PQ material, so a full
    // end-to-end exchange must produce identical directional keys on both sides.
    let a = IdentityKeyPair::generate().unwrap();
    let b = IdentityKeyPair::generate().unwrap();
    let (i, r, _, _) = hybrid_exchange(&a, &b);
    assert_eq!(i.session_keys.send_key, r.session_keys.recv_key);
    assert_eq!(i.session_keys.recv_key, r.session_keys.send_key);
    assert_eq!(i.transcript_hash_hex, r.transcript_hash_hex);
}

#[test]
fn missing_pq_shared_secret_blocks_downgrade() {
    // A peer that strips the PQ ciphertext must NOT be able to derive a hybrid
    // session key: verify_and_derive fails closed when pq_shared is None.
    let local = IdentityKeyPair::generate().unwrap();
    let peer = IdentityKeyPair::generate().unwrap();
    let local_mat = build_hello(&local).unwrap();
    let peer_mat = build_hello(&peer).unwrap();
    let res = verify_and_derive(
        &local,
        &local_mat,
        &peer_mat.local_hello,
        true,
        &PeerPolicy::single(PeerPin::for_identity(&peer)),
    );
    assert!(
        res.is_err(),
        "derivation without the PQ shared secret must fail (downgrade resistance)"
    );
}

#[test]
fn corrupted_pq_ciphertext_changes_the_bound_kdf_transcript() {
    // If an attacker tampers with the initiator's PQ ciphertext, the responder
    // decapsulates a different shared secret and the derived keys diverge.
    let initiator = IdentityKeyPair::generate().unwrap();
    let responder = IdentityKeyPair::generate().unwrap();
    let mut init_mat = build_hello(&initiator).unwrap();
    let mut resp_mat = build_hello(&responder).unwrap();
    let initiator_hello = init_mat.local_hello.clone();

    let init_policy = PeerPolicy::single(PeerPin::for_identity(&responder));
    let resp_policy = PeerPolicy::single(PeerPin::for_identity(&initiator));
    let mut ct = finalize_initiator_pq(
        &initiator,
        &mut init_mat,
        &resp_mat.local_hello,
        &init_policy,
    )
    .expect("initiator finalize");
    // Tamper: flip a byte in the ciphertext the responder will decapsulate.
    ct[0] ^= 0xff;
    absorb_responder_pq(
        &responder,
        &mut resp_mat,
        &initiator_hello,
        &ct,
        &resp_policy,
    )
    .expect("responder absorb (decap is permissive)");

    let init_state = verify_and_derive(
        &initiator,
        &init_mat,
        &resp_mat.local_hello,
        true,
        &init_policy,
    )
    .expect("init verify");
    let resp_state = verify_and_derive(
        &responder,
        &resp_mat,
        &initiator_hello,
        false,
        &resp_policy,
    )
    .expect("resp verify");
    assert_ne!(
        init_state.session_keys.send_key, resp_state.session_keys.recv_key,
        "tampered PQ ciphertext must break the shared key"
    );
    assert_ne!(
        init_state.transcript_hash_hex, resp_state.transcript_hash_hex,
        "the exact PQ ciphertext must be bound into each side's KDF transcript"
    );
}

// --- Ed25519 handshake authentication regression tests ---

#[test]
fn forged_signature_is_rejected() {
    let victim = IdentityKeyPair::generate().unwrap();
    let attacker = IdentityKeyPair::generate().unwrap();
    let victim_mat = build_hello(&victim).unwrap();

    let mut forged = build_hello(&attacker).unwrap().local_hello;
    forged.identity_pub_b64 = victim_mat.local_hello.identity_pub_b64.clone();
    forged.sign_pub_b64 = victim_mat.local_hello.sign_pub_b64.clone();
    forged.sig = victim_mat.local_hello.sig.clone();

    let res = verify_and_derive(
        &victim,
        &victim_mat,
        &forged,
        true,
        &PeerPolicy::single(PeerPin::for_identity(&attacker)),
    );
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

    let mut sig_raw = base64::engine::general_purpose::STANDARD
        .decode(hello.sig.as_bytes())
        .unwrap();
    sig_raw[0] ^= 0xff;
    hello.sig = base64::engine::general_purpose::STANDARD.encode(sig_raw);

    let local_mat = build_hello(&id).unwrap();
    let res = verify_and_derive(
        &id,
        &local_mat,
        &hello,
        true,
        &PeerPolicy::single(PeerPin::for_identity(&peer)),
    );
    assert!(
        res.is_err(),
        "a tampered Ed25519 signature must be rejected"
    );
}

#[test]
fn wrong_peer_signing_key_rejected() {
    let id = IdentityKeyPair::generate().unwrap();
    let peer = IdentityKeyPair::generate().unwrap();
    let other = IdentityKeyPair::generate().unwrap();
    let mut hello = build_hello(&peer).unwrap().local_hello;
    hello.sign_pub_b64 =
        base64::engine::general_purpose::STANDARD.encode(other.signing_public_bytes());

    let local_mat = build_hello(&id).unwrap();
    let res = verify_and_derive(
        &id,
        &local_mat,
        &hello,
        true,
        &PeerPolicy::single(PeerPin::for_identity(&peer)),
    );
    assert!(
        res.is_err(),
        "signature must not verify under a swapped signing public key"
    );
}

#[test]
fn responder_policy_rejection_precedes_pq_decapsulation() {
    let responder = IdentityKeyPair::generate().unwrap();
    let expected_peer = IdentityKeyPair::generate().unwrap();
    let attacker = IdentityKeyPair::generate().unwrap();
    let mut responder_material = build_hello(&responder).unwrap();
    let attacker_material = build_hello(&attacker).unwrap();
    let policy = PeerPolicy::single(PeerPin::for_identity(&expected_peer));

    let result = absorb_responder_pq(
        &responder,
        &mut responder_material,
        &attacker_material.local_hello,
        &[0u8; 7],
        &policy,
    );

    assert!(
        matches!(result, Err(shph_core::ShphError::Auth(_))),
        "policy rejection must happen before malformed PQ ciphertext reaches decapsulation"
    );
    assert!(responder_material.pq_shared.is_none());
}

fn classical_exchange(
    initiator: &IdentityKeyPair,
    responder: &IdentityKeyPair,
) -> (shph_core::HandshakeState, shph_core::HandshakeState) {
    let init_mat = build_hello_with_profile(initiator, HandshakeProfile::ClassicalLab).unwrap();
    let resp_mat = build_hello_with_profile(responder, HandshakeProfile::ClassicalLab).unwrap();
    let init_state = verify_and_derive(
        initiator,
        &init_mat,
        &resp_mat.local_hello,
        true,
        &PeerPolicy::single(PeerPin::for_identity(responder)),
    )
    .unwrap();
    let resp_state = verify_and_derive(
        responder,
        &resp_mat,
        &init_mat.local_hello,
        false,
        &PeerPolicy::single(PeerPin::for_identity(initiator)),
    )
    .unwrap();
    (init_state, resp_state)
}

#[test]
fn classical_lab_roundtrip_derives_complementary_keys() {
    let initiator = IdentityKeyPair::generate().unwrap();
    let responder = IdentityKeyPair::generate().unwrap();
    let (init_state, resp_state) = classical_exchange(&initiator, &responder);

    assert_eq!(
        init_state.session_keys.send_key,
        resp_state.session_keys.recv_key
    );
    assert_eq!(
        init_state.session_keys.recv_key,
        resp_state.session_keys.send_key
    );
}

#[test]
fn classical_lab_has_no_pq_material() {
    let identity = IdentityKeyPair::generate().unwrap();
    let material = build_hello_with_profile(&identity, HandshakeProfile::ClassicalLab).unwrap();
    assert!(material.local_pqc.is_none());
    assert!(material.local_hello.pqc_pub_b64.is_none());
    assert!(material.local_hello.pqc_ct_b64.is_none());
}

#[test]
fn profile_mismatch_is_rejected() {
    let local = IdentityKeyPair::generate().unwrap();
    let peer = IdentityKeyPair::generate().unwrap();
    let local_material = build_hello(&local).unwrap();
    let peer_material = build_hello_with_profile(&peer, HandshakeProfile::ClassicalLab).unwrap();

    let result = verify_and_derive(
        &local,
        &local_material,
        &peer_material.local_hello,
        true,
        &PeerPolicy::single(PeerPin::for_identity(&peer)),
    );
    assert!(result.is_err(), "secure-default must reject classical-lab");
}

#[test]
fn classical_lab_rejects_pq_exchange_attempt() {
    let local = IdentityKeyPair::generate().unwrap();
    let peer = IdentityKeyPair::generate().unwrap();
    let mut local_material =
        build_hello_with_profile(&local, HandshakeProfile::ClassicalLab).unwrap();
    let peer_material = build_hello_with_profile(&peer, HandshakeProfile::ClassicalLab).unwrap();

    let result = finalize_initiator_pq(
        &local,
        &mut local_material,
        &peer_material.local_hello,
        &PeerPolicy::single(PeerPin::for_identity(&peer)),
    );
    assert!(result.is_err());
}
