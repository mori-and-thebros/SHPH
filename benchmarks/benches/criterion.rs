use criterion::{criterion_group, criterion_main, Criterion};
use shph_core::roadmap::TransportAdapterConfig;
use shph_core::{
    absorb_responder_pq, build_hello_with_profile, decode_cell, encode_data_cell,
    finalize_initiator_pq, hkdf_sha256_into, HandshakeProfile, IdentityKeyPair, PeerPin,
    PeerPolicy, ReceiveCipher, ReplayWindow, SendCipher, StatelessCookieAuthority, BALANCED,
};
use shph_identity::{IdentityEndpoint, IdentityRecord, VerificationPolicy};
use shph_obfuscation::{apply_profile, remove_profile, ProfilePadder, ProfileTier};
use shph_transport::ja4::{Ja4ClientHello, Ja4TlsVersion, Ja4Transport};
use shph_transport::shroud2::{
    decode_batched_datagram, decode_datagram, encode_batched_datagram, encode_datagram,
    wasserstein_distance, EmpiricalHistogram, MorphologyBatcher, MorphologyEngine,
    MorphologyProfile,
};
use shph_transport::{PeerRateLimiterProbe, TcpUnderlay};
use std::hint::black_box;
use std::net::SocketAddr;

const BENCHMARK_NOW: u64 = 1_800_000_000;
const PATH_MTU: usize = 1_472;

fn fixed_identity(identity_seed: u8, signing_seed: u8) -> IdentityKeyPair {
    IdentityKeyPair::from_seeds([identity_seed; 32], [signing_seed; 32])
}

fn complete_handshake(profile: HandshakeProfile) -> (String, String) {
    let initiator = fixed_identity(0x11, 0x21);
    let responder = fixed_identity(0x12, 0x22);
    let initiator_pin = PeerPin::for_identity(&initiator);
    let responder_pin = PeerPin::for_identity(&responder);
    let initiator_policy = PeerPolicy::single(responder_pin);
    let responder_policy = PeerPolicy::single(initiator_pin);
    let mut initiator_material =
        build_hello_with_profile(&initiator, profile).expect("initiator hello");
    let mut responder_material =
        build_hello_with_profile(&responder, profile).expect("responder hello");
    let initiator_hello = initiator_material.local_hello.clone();

    if profile.uses_pqc() {
        let ciphertext = finalize_initiator_pq(
            &initiator,
            &mut initiator_material,
            &responder_material.local_hello,
            &initiator_policy,
        )
        .expect("initiator PQ encapsulation");
        absorb_responder_pq(
            &responder,
            &mut responder_material,
            &initiator_hello,
            &ciphertext,
            &responder_policy,
        )
        .expect("responder PQ decapsulation");
    }

    let initiator_state = shph_core::verify_and_derive_with_profile(
        &initiator,
        &initiator_material,
        &responder_material.local_hello,
        true,
        &initiator_policy,
    )
    .expect("initiator key derivation");
    let responder_state = shph_core::verify_and_derive_with_profile(
        &responder,
        &responder_material,
        &initiator_hello,
        false,
        &responder_policy,
    )
    .expect("responder key derivation");
    (
        initiator_state.transcript_hash_hex,
        responder_state.transcript_hash_hex,
    )
}

fn identity_record() -> (IdentityRecord, Vec<u8>) {
    let identity = fixed_identity(0x31, 0x41);
    let record = IdentityRecord::from_current_identity(
        &identity,
        1,
        BENCHMARK_NOW - 60,
        BENCHMARK_NOW + 3_600,
        vec![
            IdentityEndpoint::new("tcp", "198.51.100.10:443", 10).expect("endpoint"),
            IdentityEndpoint::new("quic", "198.51.100.10:443", 20).expect("endpoint"),
        ],
        vec!["transport:tcp".into(), "kem:ml-kem-768".into()],
    )
    .expect("identity record");
    let bytes = record.to_json_bytes().expect("identity JSON");
    (record, bytes)
}

fn bench_core_crypto(c: &mut Criterion) {
    let payload = vec![0x42; 1_024];
    let mut group = c.benchmark_group("core/crypto");
    group.bench_function("aead_encrypt_1k", |b| {
        b.iter(|| {
            let mut sender = SendCipher::new([0x51; 32]);
            black_box(sender.encrypt(black_box(&payload)).expect("encrypt"))
        })
    });
    let ciphertext = {
        let mut sender = SendCipher::new([0x52; 32]);
        sender.encrypt(&payload).expect("ciphertext")
    };
    group.bench_function("aead_decrypt_1k", |b| {
        b.iter(|| {
            let mut receiver = ReceiveCipher::new([0x52; 32]);
            black_box(receiver.decrypt(black_box(&ciphertext)).expect("decrypt"))
        })
    });
    group.bench_function("hkdf_64_bytes", |b| {
        b.iter(|| {
            let mut output = [0u8; 64];
            hkdf_sha256_into(
                black_box(&[0x77; 64]),
                &[b"shph/criterion", b"local-deterministic"],
                &mut output,
            )
            .expect("HKDF");
            black_box(output)
        })
    });
    group.finish();
}

fn bench_replay_and_cookie(c: &mut Criterion) {
    let mut group = c.benchmark_group("core/defensive-paths");
    group.bench_function("replay_window_128_sequential_batch", |b| {
        b.iter(|| {
            let mut window = ReplayWindow::new(128);
            let mut accepted = 0usize;
            for nonce in 0..256u64 {
                accepted += usize::from(window.check_and_insert(nonce));
            }
            black_box(accepted)
        })
    });

    let peer: SocketAddr = "198.51.100.20:443".parse().expect("peer address");
    let mut authority = StatelessCookieAuthority::new().expect("cookie authority");
    let cookie = authority.issue(peer).expect("cookie");
    group.bench_function("cookie_verify", |b| {
        b.iter(|| black_box(authority.verify(peer, black_box(&cookie)).expect("verify")))
    });
    group.bench_function("cookie_issue", |b| {
        b.iter(|| black_box(authority.issue(peer).expect("issue")))
    });
    group.finish();
}

fn bench_defensive_rejections(c: &mut Criterion) {
    let mut group = c.benchmark_group("defensive/rejections");
    let valid_cell =
        encode_data_cell(BALANCED, b"criterion-defensive").expect("defensive baseline cell");

    let truncated = &valid_cell[..valid_cell.len() - 1];
    group.bench_function("shroud_truncated_cell", |b| {
        b.iter(|| black_box(decode_cell(BALANCED, black_box(truncated)).is_err()))
    });

    let mut noncanonical = valid_cell.clone();
    let last = noncanonical.len() - 1;
    noncanonical[last] = 1;
    group.bench_function("shroud_noncanonical_padding", |b| {
        b.iter(|| black_box(decode_cell(BALANCED, black_box(&noncanonical)).is_err()))
    });

    let oversized = vec![0u8; PATH_MTU + 1];
    group.bench_function("shroud2_oversized_datagram", |b| {
        b.iter(|| black_box(decode_datagram(black_box(&oversized), PATH_MTU).is_err()))
    });

    let peer: SocketAddr = "198.51.100.42:443".parse().expect("defensive peer");
    let mut authority = StatelessCookieAuthority::new().expect("cookie authority");
    let mut forged = authority.issue(peer).expect("cookie issue");
    forged[0] ^= 1;
    group.bench_function("cookie_forged_tag", |b| {
        b.iter(|| black_box(!authority.verify(peer, black_box(&forged)).expect("verify")))
    });

    let mut replay = ReplayWindow::new(128);
    assert!(replay.check_and_insert(1));
    group.bench_function("replay_duplicate_nonce", |b| {
        b.iter(|| black_box(!replay.check_and_insert(1)))
    });

    let limiter_peer: SocketAddr = "198.51.100.44:443".parse().expect("limiter peer");
    let mut limiter = PeerRateLimiterProbe::new();
    for _ in 0..8 {
        assert!(limiter.check(limiter_peer));
    }
    group.bench_function("per_source_rate_limit_after_cap", |b| {
        b.iter(|| black_box(!limiter.check(limiter_peer)))
    });
    group.finish();
}

fn bench_handshake(c: &mut Criterion) {
    let mut group = c.benchmark_group("core/handshake");
    for profile in [
        HandshakeProfile::ClassicalLab,
        HandshakeProfile::SecureDefault,
    ] {
        let label = profile.as_str();
        group.bench_function(format!("full_{label}"), |b| {
            b.iter(|| black_box(complete_handshake(profile)))
        });
    }

    let identity = fixed_identity(0x61, 0x71);
    let hello = build_hello_with_profile(&identity, HandshakeProfile::SecureDefault)
        .expect("hello")
        .local_hello;
    group.bench_function("serialize_secure_hello_padding_32", |b| {
        b.iter(|| {
            black_box(
                shph_core::serialize_hello_frame_with_padding_len(black_box(&hello), 32)
                    .expect("serialize hello"),
            )
        })
    });
    group.finish();
}

fn bench_framing_and_profiles(c: &mut Criterion) {
    let mut group = c.benchmark_group("transport/framing");
    group.bench_function("fixed_cell_encode_balanced", |b| {
        let payload = vec![0x5a; 256];
        b.iter(|| black_box(encode_data_cell(BALANCED, black_box(&payload)).expect("encode")))
    });
    let payload = vec![0x5a; 256];
    let cell = encode_data_cell(BALANCED, &payload).expect("cell");
    group.bench_function("fixed_cell_decode_balanced", |b| {
        b.iter(|| black_box(decode_cell(BALANCED, black_box(&cell)).expect("decode")))
    });
    for profile in [ProfileTier::Low, ProfileTier::Medium, ProfileTier::High] {
        let label = profile.as_str();
        let payload = vec![0x5a; profile.max_payload_bytes().min(256)];
        group.bench_function(format!("profile_apply_{label}"), |b| {
            b.iter(|| black_box(apply_profile(profile, black_box(&payload)).expect("apply")))
        });
        group.bench_function(format!("profile_apply_stateful_{label}"), |b| {
            let mut padder = ProfilePadder::from_seed(profile, [0x42; 32]);
            let mut framed = Vec::new();
            b.iter(|| {
                padder
                    .apply_into(black_box(&payload), &mut framed)
                    .expect("apply stateful");
                black_box(framed.len())
            })
        });
        let framed = apply_profile(profile, &payload).expect("profile frame");
        group.bench_function(format!("profile_remove_{label}"), |b| {
            b.iter(|| black_box(remove_profile(profile, black_box(&framed)).expect("remove")))
        });
    }
    group.finish();
}

fn bench_morphology(c: &mut Criterion) {
    let payload = vec![0x33; 1_024];
    let mut group = c.benchmark_group("transport/shroud2");
    for profile in [
        MorphologyProfile::LowLatency,
        MorphologyProfile::WebBrowsingLab,
        MorphologyProfile::VideoStreamingBalancedPayloadLab,
        MorphologyProfile::BulkLab,
        MorphologyProfile::TunedLowLatency,
        MorphologyProfile::TunedWebBrowsingLab,
        MorphologyProfile::TunedVideoStreamingLab,
        MorphologyProfile::TunedBulkLab,
    ] {
        let label = format!("{profile:?}").to_ascii_lowercase();
        group.bench_function(format!("target_size_{label}"), |b| {
            let mut engine = MorphologyEngine::from_seed(profile, 0x5348_524f_5544);
            b.iter(|| black_box(engine.target_size(payload.len(), PATH_MTU).expect("target")))
        });
        group.bench_function(format!("encode_decode_{label}_os_random_tail"), |b| {
            let mut engine = MorphologyEngine::from_seed(profile, 0x5348_524f_5544);
            b.iter(|| {
                let target = engine.target_size(payload.len(), PATH_MTU).expect("target");
                let datagram =
                    encode_datagram(black_box(&payload), target, PATH_MTU).expect("encode");
                black_box(decode_datagram(&datagram, PATH_MTU).expect("decode"))
            })
        });
        group.bench_function(format!("encode_decode_{label}_session_rng_tail"), |b| {
            let mut engine = MorphologyEngine::from_seed(profile, 0x5348_524f_5544);
            b.iter(|| {
                let datagram = engine
                    .encode_datagram(black_box(&payload), PATH_MTU)
                    .expect("session-rng encode");
                black_box(decode_datagram(&datagram, PATH_MTU).expect("decode"))
            })
        });
    }

    let messages = [
        vec![0x11; 32],
        vec![0x22; 128],
        vec![0x33; 256],
        vec![0x44; 64],
    ];
    group.bench_function("batch_encode_decode_four_messages", |b| {
        let mut engine = MorphologyEngine::from_seed(MorphologyProfile::WebBrowsingLab, 0x42415443);
        b.iter(|| {
            let datagram =
                encode_batched_datagram(&mut engine, &messages, PATH_MTU).expect("batch encode");
            black_box(decode_batched_datagram(&datagram, PATH_MTU).expect("batch decode"))
        })
    });
    group.bench_function("batcher_push_flush", |b| {
        b.iter(|| {
            let mut batcher = MorphologyBatcher::for_profile(MorphologyProfile::WebBrowsingLab);
            for message in &messages {
                let _ = batcher.push(message, PATH_MTU).expect("batch push");
            }
            black_box(batcher.flush())
        })
    });
    group.bench_function("histogram_wasserstein", |b| {
        let current = EmpiricalHistogram::new(vec![128, 256, 512, 1_024], vec![1.0, 2.0, 3.0, 4.0])
            .expect("current histogram");
        let target = EmpiricalHistogram::new(vec![128, 256, 512, 1_024], vec![4.0, 3.0, 2.0, 1.0])
            .expect("target histogram");
        b.iter(|| black_box(wasserstein_distance(&current, &target)))
    });
    group.finish();
}

fn bench_adapter_validation_and_observability(c: &mut Criterion) {
    let mut group = c.benchmark_group("transport/adapter-validation");
    let offline = TransportAdapterConfig::OfflineMesh {
        node_id: "node-a".into(),
        peer_id: "node-b".into(),
        spool_dir: "C:\\shph\\offline-spool".into(),
        poll_interval_ms: 250,
        max_idle_entries: 1_024,
    };
    group.bench_function("offline_mesh_config_validate", |b| {
        b.iter(|| {
            offline.validate().expect("validate offline-mesh config");
            black_box(())
        })
    });

    let data_mule = TransportAdapterConfig::DataMule {
        inbox_dir: "C:\\shph\\data-mule\\inbox".into(),
        outbox_dir: "C:\\shph\\data-mule\\outbox".into(),
        poll_interval_ms: 250,
        max_file_bytes: 32 * 1024,
        max_total_bytes: 4 * 1024 * 1024,
        max_age_ms: 24 * 60 * 60 * 1_000,
    };
    group.bench_function("data_mule_config_validate", |b| {
        b.iter(|| {
            data_mule.validate().expect("validate data-mule config");
            black_box(())
        })
    });

    group.bench_function("socks5_underlay_parse", |b| {
        b.iter(|| {
            black_box(
                TcpUnderlay::parse(Some("socks5://127.0.0.1:10808"))
                    .expect("parse SOCKS5 underlay"),
            )
        })
    });

    let hello = Ja4ClientHello {
        transport: Ja4Transport::Tcp,
        tls_version: Ja4TlsVersion::Tls1_3,
        server_name_present: true,
        cipher_suites: vec![0x1301, 0x1302, 0x0a0a],
        extension_types: vec![0, 10, 16, 0x0a0a],
        first_alpn: Some(b"h2".to_vec()),
        signature_schemes: vec![0x0804, 0x0403],
    };
    group.bench_function("ja4_fingerprint", |b| {
        b.iter(|| black_box(hello.fingerprint()))
    });
    group.finish();
}

fn bench_identity(c: &mut Criterion) {
    let (record, bytes) = identity_record();
    let policy = VerificationPolicy::at(BENCHMARK_NOW);
    let mut group = c.benchmark_group("identity");
    group.bench_function("record_verify", |b| {
        b.iter(|| black_box(record.verify(policy).expect("verify record")))
    });
    group.bench_function("record_json_parse_and_verify", |b| {
        b.iter(|| {
            let decoded = IdentityRecord::from_json_bytes(black_box(&bytes)).expect("parse");
            black_box(decoded.verify(policy).expect("verify"))
        })
    });
    group.bench_function("record_json_serialize", |b| {
        b.iter(|| black_box(record.to_json_bytes().expect("serialize")))
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_core_crypto,
    bench_replay_and_cookie,
    bench_defensive_rejections,
    bench_handshake,
    bench_framing_and_profiles,
    bench_morphology,
    bench_adapter_validation_and_observability,
    bench_identity
);
criterion_main!(benches);
