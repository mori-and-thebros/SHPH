use shph_core::{
    Endpoint, HandshakeState, KeyStoreConfig, SessionKeys, TransportType, TunnelConfig,
};

fn state(send_key: [u8; 32], recv_key: [u8; 32]) -> HandshakeState {
    HandshakeState {
        peer_fingerprint_hex: "public-fingerprint".into(),
        peer_identity_pubkey_b64: "public-identity".into(),
        peer_signing_pubkey_b64: "public-signing-key".into(),
        session_keys: SessionKeys {
            send_nonce: 7,
            recv_nonce: 11,
            send_key,
            recv_key,
        },
        transcript_hash_hex: "public-transcript-hash".into(),
    }
}

#[test]
fn session_and_nested_handshake_debug_do_not_depend_on_secret_keys() {
    let first = state([0x41; 32], [0x42; 32]);
    let second = state([0xC1; 32], [0xD2; 32]);

    for (left, right) in [
        (
            format!("{:?}", first.session_keys),
            format!("{:?}", second.session_keys),
        ),
        (
            format!("{:#?}", first.session_keys),
            format!("{:#?}", second.session_keys),
        ),
        (format!("{first:?}"), format!("{second:?}")),
        (format!("{first:#?}"), format!("{second:#?}")),
    ] {
        assert_eq!(left, right);
        assert_eq!(left.matches("[REDACTED]").count(), 2);
        assert!(left.contains("send_nonce: 7"));
        assert!(left.contains("recv_nonce: 11"));
    }
    assert!(format!("{first:?}").contains("public-fingerprint"));
}

#[test]
fn keystore_config_debug_hides_password_value_and_presence() {
    let absent = KeyStoreConfig::default();
    for password in ["", "unique-secret-password", "another-secret"] {
        let present = KeyStoreConfig {
            password: Some(password.into()),
        };
        assert_eq!(format!("{present:?}"), format!("{absent:?}"));
        assert_eq!(format!("{present:#?}"), format!("{absent:#?}"));
        assert!(format!("{present:?}").contains("[REDACTED]"));
    }
}

#[test]
fn tunnel_config_debug_hides_psk_value_and_presence() {
    let without_psk = TunnelConfig {
        name: "test-tunnel".into(),
        local_addr: "127.0.0.1:0".into(),
        remote_endpoint: Endpoint {
            host: "127.0.0.1".into(),
            port: 7231,
        },
        transport: TransportType::ShroudTcp,
        psk: None,
        tls_ca: None,
        tls_pin: None,
    };

    for psk in ["unique-psk-secret", "another-psk-secret"] {
        let with_psk = TunnelConfig {
            psk: Some(psk.into()),
            ..without_psk.clone()
        };
        assert_eq!(format!("{with_psk:?}"), format!("{without_psk:?}"));
        assert_eq!(format!("{with_psk:#?}"), format!("{without_psk:#?}"));
        assert!(!format!("{with_psk:?}").contains(psk));
        assert!(format!("{with_psk:?}").contains("[REDACTED]"));
    }
}
