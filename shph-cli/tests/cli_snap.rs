use base64::Engine as _;
use futures_util::{SinkExt, StreamExt};
use serde_json::Value;
use shph_core::{HandshakeProfile, IdentityKeyPair, PeerPin, PeerPolicy};
use shph_transport::standards_quic::{accept, server_endpoint, StandardsQuicConfig};
use std::fs;
use std::io::{copy, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Duration;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

static TEST_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

fn test_dir() -> PathBuf {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let counter = TEST_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "shph-cli-snap-{}-{timestamp}-{counter}",
        std::process::id()
    ))
}

fn run(config: &PathBuf, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_shph"))
        .arg("--config")
        .arg(config)
        .args(args)
        .output()
        .expect("run shph")
}

fn normalized_process_output(output: &Output) -> String {
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let bytes = combined.as_bytes();
    let mut normalized = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == 0x1b && bytes.get(index + 1) == Some(&b'[') {
            index += 2;
            while index < bytes.len() {
                let byte = bytes[index];
                index += 1;
                if (0x40..=0x7e).contains(&byte) {
                    break;
                }
            }
        } else {
            normalized.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8_lossy(&normalized).into_owned()
}

fn output_key(config: &PathBuf, command: &str) -> String {
    let output = run(config, &[command]);
    assert!(
        output.status.success(),
        "{command} stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("key output utf8")
        .trim()
        .to_owned()
}

#[test]
fn snap_validate_accepts_json_and_toml_and_plan_uses_local_pin() {
    let dir = test_dir();
    fs::create_dir_all(&dir).expect("create test directory");
    let client_config = dir.join("client.toml");
    let peer_config = dir.join("peer.toml");
    let init_client = run(&client_config, &["init", "--new"]);
    assert!(
        init_client.status.success(),
        "client init stderr: {}",
        String::from_utf8_lossy(&init_client.stderr)
    );
    let init_peer = run(&peer_config, &["init", "--new"]);
    assert!(
        init_peer.status.success(),
        "peer init stderr: {}",
        String::from_utf8_lossy(&init_peer.stderr)
    );

    let peer_key = output_key(&peer_config, "show-public-key");
    let signing_key = output_key(&peer_config, "show-signing-public-key");
    let add_peer = run(
        &client_config,
        &[
            "add-peer",
            "peer1",
            "127.0.0.1",
            "443",
            &peer_key,
            "--sign-pubkey",
            &signing_key,
        ],
    );
    assert!(
        add_peer.status.success(),
        "add-peer stderr: {}",
        String::from_utf8_lossy(&add_peer.stderr)
    );

    let json_profile = dir.join("profile.json");
    let toml_profile = dir.join("profile.toml");
    fs::write(
        &json_profile,
        r#"{"version":1,"profile_name":"test","peer_alias":"peer1"}"#,
    )
    .expect("write JSON profile");
    fs::write(
        &toml_profile,
        "version = 1\nprofile_name = \"test\"\npeer_alias = \"peer1\"\n",
    )
    .expect("write TOML profile");

    for profile in [&json_profile, &toml_profile] {
        let output = Command::new(env!("CARGO_BIN_EXE_shph"))
            .arg("--json")
            .arg("snap")
            .arg("validate")
            .arg(profile)
            .output()
            .expect("validate SNAP profile");
        assert!(
            output.status.success(),
            "validate stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: Value = serde_json::from_slice(&output.stdout).expect("validate JSON");
        assert_eq!(report["valid"], true);
        assert_eq!(report["peer_alias"], "peer1");
    }

    let json_plan = Command::new(env!("CARGO_BIN_EXE_shph"))
        .arg("--config")
        .arg(&client_config)
        .arg("--json")
        .arg("snap")
        .arg("plan")
        .arg(&json_profile)
        .output()
        .expect("plan JSON profile");
    assert!(
        json_plan.status.success(),
        "plan stderr: {}",
        String::from_utf8_lossy(&json_plan.stderr)
    );
    let json_plan: Value = serde_json::from_slice(&json_plan.stdout).expect("plan JSON");

    let toml_plan = Command::new(env!("CARGO_BIN_EXE_shph"))
        .arg("--config")
        .arg(&client_config)
        .arg("--json")
        .arg("snap")
        .arg("plan")
        .arg(&toml_profile)
        .output()
        .expect("plan TOML profile");
    assert!(toml_plan.status.success());
    let toml_plan: Value = serde_json::from_slice(&toml_plan.stdout).expect("plan JSON");
    assert_eq!(json_plan["profile_hash"], toml_plan["profile_hash"]);
    assert_eq!(json_plan["peer_alias"], "peer1");
    assert_eq!(json_plan["candidates"][0]["target_host"], "127.0.0.1");
    assert_eq!(json_plan["candidates"][0]["target_port"], 443);

    let unpinned = dir.join("unpinned.json");
    fs::write(&unpinned, r#"{"version":1,"peer_alias":"missing-peer"}"#)
        .expect("write unpinned profile");
    let rejected = Command::new(env!("CARGO_BIN_EXE_shph"))
        .arg("--config")
        .arg(&client_config)
        .arg("snap")
        .arg("plan")
        .arg(&unpinned)
        .output()
        .expect("plan unpinned profile");
    assert!(!rejected.status.success());

    fs::remove_dir_all(dir).expect("remove test directory");
}

#[test]
fn snap_validate_resolves_and_checks_profile_relative_bridge_files() {
    let dir = test_dir();
    fs::create_dir_all(&dir).expect("create test directory");
    fs::write(
        dir.join("relay.key"),
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n",
    )
    .expect("write test relay key");
    fs::write(
        dir.join("route.json"),
        r#"{"version":1,"relays":[{"ip":"127.0.0.1","port":9000,"key_file":"relay.key"}]}"#,
    )
    .expect("write test route");

    let profile_path = dir.join("bridge.json");
    fs::write(
        &profile_path,
        r#"{
            "version":1,
            "profile_name":"relative-files",
            "peer_alias":"peer1",
            "bridges":[{
                "ip":"127.0.0.1",
                "port":9000,
                "key_file":"relay.key",
                "route_file":"route.json",
                "operator_service_contract":{
                    "owner":"SHPH test suite",
                    "service_id":"loopback-relay",
                    "authorization_ref":"test-fixture:relative-files"
                }
            }]
        }"#,
    )
    .expect("write bridge profile");

    let valid = Command::new(env!("CARGO_BIN_EXE_shph"))
        .arg("--json")
        .arg("snap")
        .arg("validate")
        .arg(&profile_path)
        .output()
        .expect("validate relative bridge files");
    assert!(
        valid.status.success(),
        "validate stderr: {}",
        String::from_utf8_lossy(&valid.stderr)
    );

    let undeclared_profile = dir.join("undeclared-bridge.json");
    fs::write(
        &undeclared_profile,
        r#"{"version":1,"profile_name":"undeclared-bridge","peer_alias":"peer1","bridges":[{"ip":"127.0.0.1","port":9000,"key_file":"relay.key"}]}"#,
    )
    .expect("write bridge profile without operator contract");
    let undeclared = Command::new(env!("CARGO_BIN_EXE_shph"))
        .arg("snap")
        .arg("validate")
        .arg(&undeclared_profile)
        .output()
        .expect("reject bridge without operator contract");
    assert!(!undeclared.status.success());
    assert!(String::from_utf8_lossy(&undeclared.stderr).contains("operator_service_contract"));

    let malformed_route = dir.join("malformed.json");
    fs::write(&malformed_route, r#"{"relays":[]}"#).expect("write malformed route");
    let malformed_profile = dir.join("malformed-profile.json");
    fs::write(
        &malformed_profile,
        r#"{"version":1,"profile_name":"bad-route","peer_alias":"peer1","bridges":[{"ip":"127.0.0.1","port":9000,"key_file":"relay.key","route_file":"malformed.json"}]}"#,
    )
    .expect("write malformed profile");
    let invalid = Command::new(env!("CARGO_BIN_EXE_shph"))
        .arg("snap")
        .arg("validate")
        .arg(&malformed_profile)
        .output()
        .expect("reject malformed route");
    assert!(!invalid.status.success());

    let missing_key_profile = dir.join("missing-key.json");
    fs::write(
        &missing_key_profile,
        r#"{"version":1,"profile_name":"missing-key","peer_alias":"peer1","bridges":[{"ip":"127.0.0.1","port":9000,"key_file":"missing.key"}]}"#,
    )
    .expect("write missing-key profile");
    let missing = Command::new(env!("CARGO_BIN_EXE_shph"))
        .arg("snap")
        .arg("validate")
        .arg(&missing_key_profile)
        .output()
        .expect("reject missing key");
    assert!(!missing.status.success());

    fs::remove_dir_all(dir).expect("remove test directory");
}

#[test]
fn snap_session_retries_direct_candidates_and_exchanges_authenticated_payload() {
    let dir = test_dir();
    fs::create_dir_all(&dir).expect("create test directory");
    let client_dir = dir.join("client");
    let server_dir = dir.join("server");
    fs::create_dir_all(&client_dir).expect("create client directory");
    fs::create_dir_all(&server_dir).expect("create server directory");
    let client_config = client_dir.join("config.toml");
    let server_config = server_dir.join("config.toml");
    for config in [&client_config, &server_config] {
        let init = run(config, &["init", "--new"]);
        assert!(
            init.status.success(),
            "init stderr: {}",
            String::from_utf8_lossy(&init.stderr)
        );
    }

    let server_socket = TcpListener::bind("127.0.0.1:0").expect("reserve loopback port");
    let server_endpoint = server_socket.local_addr().expect("server address");
    drop(server_socket);
    let unused_socket = TcpListener::bind("127.0.0.1:0").expect("reserve failed candidate");
    let unused_port = unused_socket
        .local_addr()
        .expect("failed candidate address")
        .port();
    drop(unused_socket);
    assert_ne!(server_endpoint.port(), unused_port);

    let client_key = output_key(&client_config, "show-public-key");
    let client_signing_key = output_key(&client_config, "show-signing-public-key");
    let server_key = output_key(&server_config, "show-public-key");
    let server_signing_key = output_key(&server_config, "show-signing-public-key");
    let add_server_pin = run(
        &client_config,
        &[
            "add-peer",
            "server",
            "127.0.0.1",
            &server_endpoint.port().to_string(),
            &server_key,
            "--sign-pubkey",
            &server_signing_key,
        ],
    );
    assert!(add_server_pin.status.success());
    let add_client_pin = run(
        &server_config,
        &[
            "add-peer",
            "client",
            "127.0.0.1",
            "55555",
            &client_key,
            "--sign-pubkey",
            &client_signing_key,
        ],
    );
    assert!(add_client_pin.status.success());

    let profile_path = dir.join("active.json");
    let profile = format!(
        r#"{{
            "version": 1,
            "profile_name": "loopback-retry",
            "peer_alias": "server",
            "connect_timeout_sec": 2.0,
            "retry_policy": {{
                "rounds": 1,
                "max_total_attempts": 2,
                "max_elapsed_sec": 8.0,
            "jitter_ratio": 0.0
            }},
            "direct_endpoints": [
                {{"ip":"127.0.0.1","port":{unused_port},"priority":1}},
                {{"ip":"127.0.0.1","port":{server_port},"priority":2}}
            ]
        }}"#,
        server_port = server_endpoint.port()
    );
    fs::write(&profile_path, profile).expect("write SNAP profile");

    let configured_profile_path = dir.join("configured.json");
    fs::write(
        &configured_profile_path,
        format!(
            r#"{{"version":1,"profile_name":"session-profile","peer_alias":"server","direct_endpoints":[{{"ip":"127.0.0.1","port":{unused_port}}}]}}"#
        ),
    )
    .expect("write configured SNAP profile");

    let configured_profile_for_config =
        configured_profile_path.to_string_lossy().replace('\\', "/");
    let endpoint = format!("127.0.0.1:{}", server_endpoint.port());
    let mut client_toml = fs::read_to_string(&client_config).expect("read client config");
    client_toml.push_str(&format!(
        "\n[session]\nrole = \"connect\"\npeer = \"{endpoint}\"\nsnap_profile = \"{configured_profile_for_config}\"\ntimeout_secs = 5\nstartup_payload = \"snap-native-payload\"\n"
    ));
    fs::write(&client_config, client_toml).expect("write configured client");

    let server = Command::new(env!("CARGO_BIN_EXE_shph"))
        .arg("--config")
        .arg(&server_config)
        .args(["recv-once", "--bind", &endpoint, "--timeout-secs", "10"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("start loopback SHPH receiver");
    thread::sleep(Duration::from_millis(200));

    let client = Command::new(env!("CARGO_BIN_EXE_shph"))
        .arg("--config")
        .arg(&client_config)
        .args(["up", "--no-tun", "--snap-profile"])
        .arg(&profile_path)
        .env("RUST_LOG", "info")
        .output()
        .expect("run SNAP connect session");
    let receiver = server.wait_with_output().expect("wait for receiver");
    assert!(
        client.status.success(),
        "client stdout: {}\nclient stderr: {}",
        String::from_utf8_lossy(&client.stdout),
        String::from_utf8_lossy(&client.stderr)
    );
    assert!(
        receiver.status.success(),
        "receiver stdout: {}\nreceiver stderr: {}\nclient stdout: {}\nclient stderr: {}",
        String::from_utf8_lossy(&receiver.stdout),
        String::from_utf8_lossy(&receiver.stderr),
        String::from_utf8_lossy(&client.stdout),
        String::from_utf8_lossy(&client.stderr)
    );
    let receiver_stdout = String::from_utf8_lossy(&receiver.stdout);
    assert!(receiver_stdout.contains("snap-native-payload"));
    let client_stdout = normalized_process_output(&client);
    assert!(client_stdout.contains("SNAP profile: loopback-retry"));
    assert!(!client_stdout.contains("session-profile"));
    assert!(
        client_stdout.contains("RetryableFailure"),
        "client stdout: {client_stdout}"
    );
    assert!(
        client_stdout.contains("Connected"),
        "client stdout: {client_stdout}"
    );
    assert!(!client_stdout.contains(&unused_port.to_string()));

    fs::remove_dir_all(dir).expect("remove test directory");
}

#[test]
fn snap_onion_bridge_carries_authenticated_shph_session_to_pinned_peer() {
    run_snap_onion_bridge_roundtrip(false, false);
}

#[test]
fn snap_onion_bridge_wrong_peer_is_terminal_before_allowed_fallback() {
    run_snap_onion_bridge_roundtrip(true, false);
}

#[test]
fn snap_onion_bridge_reconnects_after_setup_failure_and_shuts_down() {
    run_snap_onion_bridge_roundtrip(false, true);
}

fn run_snap_onion_bridge_roundtrip(wrong_peer: bool, reconnect: bool) {
    let dir = test_dir();
    let client_dir = dir.join("client");
    let server_dir = dir.join("server");
    fs::create_dir_all(&client_dir).expect("create client directory");
    fs::create_dir_all(&server_dir).expect("create server directory");
    let client_config = client_dir.join("config.toml");
    let server_config = server_dir.join("config.toml");
    let wrong_server_dir = dir.join("wrong-server");
    let wrong_server_config = wrong_server_dir.join("config.toml");
    if wrong_peer {
        fs::create_dir_all(&wrong_server_dir).expect("create wrong peer directory");
    }
    for config in std::iter::once(&client_config)
        .chain(std::iter::once(&server_config))
        .chain(wrong_peer.then_some(&wrong_server_config))
    {
        let init = run(config, &["init", "--new"]);
        assert!(
            init.status.success(),
            "init stderr: {}",
            String::from_utf8_lossy(&init.stderr)
        );
    }

    let peer_socket = TcpListener::bind("127.0.0.1:0").expect("reserve peer port");
    let peer_addr = peer_socket.local_addr().expect("peer address");
    drop(peer_socket);
    let wrong_peer_addr = if wrong_peer {
        let socket = TcpListener::bind("127.0.0.1:0").expect("reserve wrong peer port");
        let addr = socket.local_addr().expect("wrong peer address");
        drop(socket);
        Some(addr)
    } else {
        None
    };
    let (bridge_addr, bridge_listener) = if reconnect {
        let listener = TcpListener::bind("127.0.0.77:0").expect("reserve delayed bridge port");
        let address = listener.local_addr().expect("delayed bridge address");
        drop(listener);
        (address, None)
    } else {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock bridge");
        let address = listener.local_addr().expect("bridge address");
        (address, Some(listener))
    };

    let client_public = output_key(&client_config, "show-public-key");
    let client_signing = output_key(&client_config, "show-signing-public-key");
    let server_public = output_key(&server_config, "show-public-key");
    let server_signing = output_key(&server_config, "show-signing-public-key");
    assert!(run(
        &client_config,
        &[
            "add-peer",
            "server",
            "127.0.0.1",
            &peer_addr.port().to_string(),
            &server_public,
            "--sign-pubkey",
            &server_signing,
        ],
    )
    .status
    .success());
    if let Some(wrong_server_config) = wrong_peer.then_some(&wrong_server_config) {
        assert!(run(
            wrong_server_config,
            &[
                "add-peer",
                "client",
                "127.0.0.1",
                "55555",
                &client_public,
                "--sign-pubkey",
                &client_signing,
            ],
        )
        .status
        .success());
    }
    assert!(run(
        &server_config,
        &[
            "add-peer",
            "client",
            "127.0.0.1",
            "55555",
            &client_public,
            "--sign-pubkey",
            &client_signing,
        ],
    )
    .status
    .success());

    let key_file = dir.join("relay.key");
    fs::write(&key_file, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n")
        .expect("write bridge key");
    let key_file = key_file.to_string_lossy().replace('\\', "/");
    let profile_path = dir.join("onion-bridge.json");
    let mut bridge_profile = serde_json::json!({
        "label": "loopback",
        "ip": bridge_addr.ip().to_string(),
        "port": bridge_addr.port(),
        "key_file": key_file,
        "adapter": "bridge-onion-tcp",
        "transport": "onion-tcp",
        "priority": 1,
        "operator_service_contract": {
            "owner": "SHPH test suite",
            "service_id": "loopback-onion",
            "authorization_ref": "test-fixture:onion-bridge"
        }
    });
    if wrong_peer {
        bridge_profile["allowed_fallback"] = serde_json::json!(["direct-tcp"]);
    }
    let profile = serde_json::json!({
        "version": 1,
        "profile_name": "loopback-onion-bridge",
        "peer_alias": "server",
        "mode": if wrong_peer { "auto" } else { "bridges-only" },
        "retry_policy": {
            "rounds": 1,
            "max_total_attempts": if wrong_peer { 2 } else { 1 },
            "max_elapsed_sec": 8.0,
            "jitter_ratio": 0.0
        },
        "direct_endpoints": if wrong_peer {
            serde_json::json!([{
                "ip": "127.0.0.1",
                "port": peer_addr.port(),
                "priority": 2
            }])
        } else {
            serde_json::json!([])
        },
        "bridges": [bridge_profile]
    });
    fs::write(&profile_path, profile.to_string()).expect("write onion bridge SNAP profile");

    let endpoint = format!("127.0.0.1:{}", peer_addr.port());
    let profile_for_config = profile_path.to_string_lossy().replace('\\', "/");
    let mut client_toml = fs::read_to_string(&client_config).expect("read client config");
    if reconnect {
        client_toml.push_str(&format!(
            "\n[session]\nrole = \"connect\"\npeer = \"{endpoint}\"\nsnap_profile = \"{profile_for_config}\"\ntimeout_secs = 6\n"
        ));
    } else {
        client_toml.push_str(&format!(
            "\n[session]\nrole = \"connect\"\npeer = \"{endpoint}\"\nsnap_profile = \"{profile_for_config}\"\ntimeout_secs = 6\nstartup_payload = \"{}\"\n",
            if wrong_peer {
                "must-not-reach-onion-fallback"
            } else {
                "snap-onion-bridge-payload"
            }
        ));
    }
    if reconnect {
        client_toml.push_str(
            "\n[session.reconnect]\nenabled = true\nmax_attempts = 2\ninitial_delay_ms = 8000\nmax_delay_ms = 8000\n",
        );
    }
    fs::write(&client_config, client_toml).expect("configure onion bridge client");

    let bridge_upstream_addr = wrong_peer_addr.unwrap_or(peer_addr);
    let (bridge_start_tx, bridge_start_rx) = std::sync::mpsc::channel();
    let bridge = thread::spawn(move || {
        if reconnect {
            bridge_start_rx
                .recv()
                .expect("wait for reconnecting bridge client startup");
            thread::sleep(Duration::from_secs(3));
        }
        let bridge_listener = bridge_listener
            .unwrap_or_else(|| TcpListener::bind(bridge_addr).expect("bind delayed mock bridge"));
        let (mut client_stream, _) = bridge_listener.accept().expect("accept bridge client");
        client_stream
            .set_read_timeout(Some(Duration::from_secs(8)))
            .expect("set bridge read timeout");
        let mut length = [0u8; 4];
        client_stream
            .read_exact(&mut length)
            .expect("read bridge setup length");
        let length = u32::from_be_bytes(length) as usize;
        assert!((1..=1024 * 1024).contains(&length));
        let mut setup = vec![0u8; length];
        client_stream
            .read_exact(&mut setup)
            .expect("read bridge setup packet");
        assert!(!setup.is_empty());
        let mut peer = TcpStream::connect(bridge_upstream_addr).expect("connect SHPH peer");
        client_stream.write_all(&[1]).expect("accept bridge setup");

        let mut client_reader = client_stream.try_clone().expect("clone bridge stream");
        let mut peer_writer = peer.try_clone().expect("clone peer stream");
        let outbound = thread::spawn(move || {
            let _ = copy(&mut client_reader, &mut peer_writer);
            let _ = peer_writer.shutdown(Shutdown::Write);
        });
        let _ = copy(&mut peer, &mut client_stream);
        let _ = client_stream.shutdown(Shutdown::Write);
        outbound.join().expect("join bridge outbound copy");
    });

    let server = Command::new(env!("CARGO_BIN_EXE_shph"))
        .arg("--config")
        .arg(&server_config)
        .args([
            "recv-once",
            "--bind",
            &endpoint,
            "--timeout-secs",
            if wrong_peer {
                "3"
            } else if reconnect {
                "30"
            } else {
                "8"
            },
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("start SHPH receiver behind mock bridge");
    let wrong_server = wrong_peer_addr.map(|wrong_peer_addr| {
        let wrong_endpoint = format!("127.0.0.1:{}", wrong_peer_addr.port());
        Command::new(env!("CARGO_BIN_EXE_shph"))
            .arg("--config")
            .arg(&wrong_server_config)
            .args([
                "recv-once",
                "--bind",
                &wrong_endpoint,
                "--timeout-secs",
                "3",
            ])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("start wrong-identity SHPH receiver behind mock bridge")
    });
    if reconnect {
        bridge_start_tx
            .send(())
            .expect("start delayed onion bridge listener");
    } else {
        thread::sleep(Duration::from_millis(150));
    }
    let client = if reconnect {
        let mut client = Command::new(env!("CARGO_BIN_EXE_shph"))
            .arg("--config")
            .arg(&client_config)
            .args(["up", "--no-tun", "--snap-profile"])
            .arg(&profile_path)
            .env("RUST_LOG", "info")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start reconnecting onion bridge SNAP session");
        client
            .stdin
            .take()
            .expect("onion bridge client stdin")
            .write_all(b"snap-onion-bridge-payload\n")
            .expect("write onion bridge payload");
        client
            .wait_with_output()
            .expect("wait for reconnecting onion bridge SNAP session")
    } else {
        Command::new(env!("CARGO_BIN_EXE_shph"))
            .arg("--config")
            .arg(&client_config)
            .args(["up", "--no-tun", "--snap-profile"])
            .arg(&profile_path)
            .env("RUST_LOG", "info")
            .output()
            .expect("run onion bridge SNAP session")
    };
    let receiver = server.wait_with_output().expect("wait for SHPH receiver");
    let wrong_receiver = wrong_server.map(|server| {
        server
            .wait_with_output()
            .expect("wait for wrong-identity SHPH receiver")
    });
    let bridge_result = bridge.join();

    if wrong_peer {
        let client_stdout = normalized_process_output(&client);
        let receiver_stdout = String::from_utf8_lossy(&receiver.stdout);
        assert!(
            !client.status.success(),
            "wrong pinned identity was accepted: {client_stdout}"
        );
        assert!(
            client_stdout.contains("TerminalFailure"),
            "client stdout: {client_stdout}\nclient stderr: {}",
            String::from_utf8_lossy(&client.stderr)
        );
        assert!(
            String::from_utf8_lossy(&client.stderr)
                .contains("peer identity and signing key are not pinned"),
            "expected pinned-identity rejection, got: {}",
            String::from_utf8_lossy(&client.stderr)
        );
        assert!(
            !client_stdout.contains("attempt=2"),
            "wrong-peer authentication must not fall through to the allowed direct candidate: {client_stdout}"
        );
        assert!(
            !receiver_stdout.contains("must-not-reach-onion-fallback"),
            "the allowed direct fallback received application data: {receiver_stdout}"
        );
        assert!(bridge_result.is_ok(), "onion bridge thread panicked");
        assert!(wrong_receiver.is_some());
        fs::remove_dir_all(dir).expect("remove test directory");
        return;
    }

    assert!(
        client.status.success(),
        "client stdout: {}\nclient stderr: {}",
        String::from_utf8_lossy(&client.stdout),
        String::from_utf8_lossy(&client.stderr)
    );
    assert!(
        receiver.status.success(),
        "receiver stdout: {}\nreceiver stderr: {}\nclient stdout: {}\nclient stderr: {}",
        String::from_utf8_lossy(&receiver.stdout),
        String::from_utf8_lossy(&receiver.stderr),
        String::from_utf8_lossy(&client.stdout),
        String::from_utf8_lossy(&client.stderr)
    );
    assert!(String::from_utf8_lossy(&receiver.stdout).contains("snap-onion-bridge-payload"));
    let client_stdout = normalized_process_output(&client);
    assert!(client_stdout.contains("Connected"));
    if reconnect {
        assert!(
            client_stdout.contains("Transport loop: closed"),
            "{client_stdout}"
        );
        assert!(
            client_stdout.contains("Reconnect: attempt 1/2 failed"),
            "{client_stdout}"
        );
        assert!(
            client_stdout.contains("RetryableFailure"),
            "{client_stdout}"
        );
    }
    assert!(bridge_result.is_ok(), "onion bridge thread panicked");
    fs::remove_dir_all(dir).expect("remove test directory");
}

#[test]
fn snap_tls_bridge_carries_authenticated_shph_session_to_pinned_peer() {
    run_snap_tls_bridge_roundtrip("bridge-tls");
}

#[test]
fn snap_edge_relay_carries_authenticated_shph_session_to_pinned_peer() {
    run_snap_tls_bridge_roundtrip("edge-relay");
}

#[test]
fn snap_websocket_bridge_carries_authenticated_shph_session_to_pinned_peer() {
    run_snap_tls_bridge_roundtrip("bridge-ws");
}

#[test]
fn snap_shroud_adapter_carries_authenticated_shph_session_to_pinned_peer() {
    run_snap_tls_bridge_roundtrip("shroud-tcp");
}

#[test]
fn snap_tls_family_adapters_reconnect_after_setup_failure_and_shut_down() {
    for adapter in ["bridge-tls", "edge-relay", "bridge-ws", "shroud-tcp"] {
        run_snap_tls_bridge_reconnect(adapter);
    }
}

#[test]
fn snap_tls_bridge_wrong_peer_is_terminal_before_allowed_fallback() {
    run_snap_tls_bridge_wrong_peer_is_terminal("bridge-tls");
}

#[test]
fn snap_edge_relay_wrong_peer_is_terminal_before_allowed_fallback() {
    run_snap_tls_bridge_wrong_peer_is_terminal("edge-relay");
}

#[test]
fn snap_websocket_bridge_wrong_peer_is_terminal_before_allowed_fallback() {
    run_snap_tls_bridge_wrong_peer_is_terminal("bridge-ws");
}

#[test]
fn snap_shroud_adapter_wrong_peer_is_terminal_before_allowed_fallback() {
    run_snap_tls_bridge_wrong_peer_is_terminal("shroud-tcp");
}

fn run_snap_tls_bridge_wrong_peer_is_terminal(adapter: &str) {
    run_snap_tls_bridge_roundtrip_with_wrong_peer(adapter, true);
}

#[allow(clippy::result_large_err)]
fn run_snap_tls_bridge_roundtrip(adapter: &str) {
    run_snap_tls_bridge_roundtrip_with_wrong_peer(adapter, false);
}

fn run_snap_tls_bridge_reconnect(adapter: &str) {
    run_snap_tls_bridge_roundtrip_inner(adapter, false, true);
}

#[allow(clippy::result_large_err)]
fn run_snap_tls_bridge_roundtrip_with_wrong_peer(adapter: &str, wrong_peer: bool) {
    run_snap_tls_bridge_roundtrip_inner(adapter, wrong_peer, false);
}

#[allow(clippy::result_large_err)]
fn run_snap_tls_bridge_roundtrip_inner(adapter: &str, wrong_peer: bool, reconnect: bool) {
    let dir = test_dir();
    let client_dir = dir.join("client");
    let server_dir = dir.join("server");
    fs::create_dir_all(&client_dir).expect("create client directory");
    fs::create_dir_all(&server_dir).expect("create server directory");
    let client_config = client_dir.join("config.toml");
    let server_config = server_dir.join("config.toml");
    let wrong_server_dir = dir.join("wrong-server");
    let wrong_server_config = wrong_server_dir.join("config.toml");
    if wrong_peer {
        fs::create_dir_all(&wrong_server_dir).expect("create wrong peer directory");
    }
    for config in std::iter::once(&client_config)
        .chain(std::iter::once(&server_config))
        .chain(wrong_peer.then_some(&wrong_server_config))
    {
        let init = run(config, &["init", "--new"]);
        assert!(
            init.status.success(),
            "init stderr: {}",
            String::from_utf8_lossy(&init.stderr)
        );
    }

    let peer_socket = TcpListener::bind("127.0.0.1:0").expect("reserve peer port");
    let peer_addr = peer_socket.local_addr().expect("peer address");
    drop(peer_socket);
    let wrong_peer_addr = if wrong_peer {
        let socket = TcpListener::bind("127.0.0.1:0").expect("reserve wrong peer port");
        let addr = socket.local_addr().expect("wrong peer address");
        drop(socket);
        Some(addr)
    } else {
        None
    };
    let (bridge_addr, bridge_listener) = if reconnect {
        let listener = TcpListener::bind("127.0.0.77:0").expect("reserve delayed TLS bridge port");
        let address = listener.local_addr().expect("delayed TLS bridge address");
        drop(listener);
        (address, None)
    } else {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind TLS bridge");
        listener
            .set_nonblocking(true)
            .expect("set TLS bridge listener nonblocking");
        let address = listener.local_addr().expect("bridge address");
        (address, Some(listener))
    };

    let certified_key = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
        .expect("generate loopback bridge certificate");
    let certificate_der = certified_key.cert.der().to_vec();
    let ca_file = dir.join("bridge-ca.der");
    fs::write(&ca_file, &certificate_der).expect("write bridge CA certificate");
    let server_certificate = rustls::pki_types::CertificateDer::from(certificate_der);
    let server_private_key = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(certified_key.key_pair.serialize_der()),
    );
    let bridge_tls_config = std::sync::Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![server_certificate], server_private_key)
            .expect("build loopback TLS bridge config"),
    );

    let client_public = output_key(&client_config, "show-public-key");
    let client_signing = output_key(&client_config, "show-signing-public-key");
    let server_public = output_key(&server_config, "show-public-key");
    let server_signing = output_key(&server_config, "show-signing-public-key");
    assert!(run(
        &client_config,
        &[
            "add-peer",
            "server",
            "127.0.0.1",
            &peer_addr.port().to_string(),
            &server_public,
            "--sign-pubkey",
            &server_signing,
        ],
    )
    .status
    .success());
    if let Some(wrong_server_config) = wrong_peer.then_some(&wrong_server_config) {
        assert!(run(
            wrong_server_config,
            &[
                "add-peer",
                "client",
                "127.0.0.1",
                "55555",
                &client_public,
                "--sign-pubkey",
                &client_signing,
            ],
        )
        .status
        .success());
    }
    assert!(run(
        &server_config,
        &[
            "add-peer",
            "client",
            "127.0.0.1",
            "55555",
            &client_public,
            "--sign-pubkey",
            &client_signing,
        ],
    )
    .status
    .success());

    let key_file = dir.join("bridge.key");
    fs::write(&key_file, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n")
        .expect("write bridge key required by profile schema");
    let key_file = key_file.to_string_lossy().replace('\\', "/");
    let ca_file = ca_file.to_string_lossy().replace('\\', "/");
    let profile_path = dir.join(format!("{adapter}.json"));
    let mut bridge_profile = serde_json::json!({
        "label": format!("loopback-{adapter}"),
        "ip": bridge_addr.ip().to_string(),
        "port": bridge_addr.port(),
        "key_file": key_file,
        "adapter": adapter,
        "transport": "onion-tcp",
        "tls_enabled": true,
        "sni": "localhost",
        "priority": 1,
        "edge_label": "owned-loopback",
        "tls_ca_file": ca_file,
        "operator_service_contract": {
            "owner": "SHPH test suite",
            "service_id": format!("loopback-{adapter}"),
            "authorization_ref": format!("test-fixture:loopback-{adapter}")
        }
    });
    if wrong_peer {
        bridge_profile["allowed_fallback"] = serde_json::json!(["direct-tcp"]);
    }
    if adapter == "bridge-ws" {
        bridge_profile["ws_path"] = serde_json::json!("/shph");
    }
    if adapter == "shroud-tcp" {
        bridge_profile["shroud_profile"] = serde_json::json!("balanced");
    }
    let profile = serde_json::json!({
        "version": 1,
        "profile_name": format!("loopback-{adapter}"),
        "peer_alias": "server",
        "mode": if wrong_peer { "auto" } else { "bridges-only" },
        "retry_policy": {
            "rounds": 1,
            "max_total_attempts": if wrong_peer { 2 } else { 1 },
            "max_elapsed_sec": 8.0,
            "jitter_ratio": 0.0
        },
        "direct_endpoints": if wrong_peer {
            serde_json::json!([{
                "ip": "127.0.0.1",
                "port": peer_addr.port(),
                "priority": 2
            }])
        } else {
            serde_json::json!([])
        },
        "bridges": [bridge_profile],
        "edge_profiles": {
            "owned-loopback": {"host": bridge_addr.ip().to_string(), "port": bridge_addr.port()}
        }
    });
    fs::write(&profile_path, profile.to_string()).expect("write TLS bridge SNAP profile");

    let endpoint = format!("127.0.0.1:{}", peer_addr.port());
    let bridge_upstream_addr = wrong_peer_addr.unwrap_or(peer_addr);
    let profile_for_config = profile_path.to_string_lossy().replace('\\', "/");
    let mut client_toml = fs::read_to_string(&client_config).expect("read client config");
    if reconnect {
        client_toml.push_str(&format!(
            "\n[session]\nrole = \"connect\"\npeer = \"{endpoint}\"\nsnap_profile = \"{profile_for_config}\"\ntimeout_secs = 6\n\n[session.reconnect]\nenabled = true\nmax_attempts = 2\ninitial_delay_ms = 8000\nmax_delay_ms = 8000\n"
        ));
    } else {
        client_toml.push_str(&format!(
            "\n[session]\nrole = \"connect\"\npeer = \"{endpoint}\"\nsnap_profile = \"{profile_for_config}\"\ntimeout_secs = 6\nstartup_payload = \"{}\"\n",
            if wrong_peer {
                format!("must-not-reach-fallback-{adapter}")
            } else {
                format!("snap-{adapter}-payload")
            }
        ));
    }
    fs::write(&client_config, client_toml).expect("configure TLS bridge client");

    let peer_addr_for_bridge = bridge_upstream_addr;
    let bridge_adapter = adapter.to_owned();
    let (bridge_start_tx, bridge_start_rx) = std::sync::mpsc::channel();
    let bridge = thread::spawn(move || {
        let bridge_listener = bridge_listener.unwrap_or_else(|| {
            bridge_start_rx
                .recv()
                .expect("wait for reconnecting TLS bridge client startup");
            thread::sleep(Duration::from_secs(3));
            let listener = TcpListener::bind(bridge_addr).expect("bind delayed TLS bridge");
            listener
                .set_nonblocking(true)
                .expect("set delayed TLS bridge listener nonblocking");
            listener
        });
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("start TLS bridge runtime");
        runtime.block_on(async move {
            let listener = tokio::net::TcpListener::from_std(bridge_listener)
                .expect("convert TLS bridge listener");
            let (socket, _) = tokio::time::timeout(
                Duration::from_secs(if reconnect { 16 } else { 8 }),
                listener.accept(),
            )
                .await
                .expect("wait for TLS bridge client")
                .expect("accept TLS bridge client");
            let mut tls = tokio_rustls::TlsAcceptor::from(bridge_tls_config)
                .accept(socket)
                .await
                .expect("accept authenticated TLS connection");
            let mut peer = tokio::net::TcpStream::connect(peer_addr_for_bridge)
                .await
                .expect("connect pinned SHPH peer");
            if bridge_adapter == "bridge-ws" {
                let websocket =
                    tokio_tungstenite::accept_hdr_async(
                        tls,
                        |_request: &tokio_tungstenite::tungstenite::handshake::server::Request,
                         mut response: tokio_tungstenite::tungstenite::handshake::server::Response| {
                        response.headers_mut().insert(
                            "sec-websocket-protocol",
                            tokio_tungstenite::tungstenite::http::HeaderValue::from_static(
                                "sierranode.snap.v2",
                            ),
                        );
                        Ok(response)
                    },
                    )
                    .await
                    .expect("accept SNAP WebSocket bridge handshake");
                let (sink, mut frames) = websocket.split();
                let sink = std::sync::Arc::new(tokio::sync::Mutex::new(sink));
                let outgoing_sink = std::sync::Arc::clone(&sink);
                let (mut peer_reader, mut peer_writer) = tokio::io::split(peer);
                let outgoing = async move {
                    let mut buffer = vec![0u8; 16 * 1024];
                    loop {
                        let count = tokio::io::AsyncReadExt::read(&mut peer_reader, &mut buffer)
                            .await
                            .expect("read SHPH peer bytes");
                        if count == 0 {
                            let _ = outgoing_sink
                                .lock()
                                .await
                                .send(tokio_tungstenite::tungstenite::Message::Close(None))
                                .await;
                            return;
                        }
                        outgoing_sink
                            .lock()
                            .await
                            .send(tokio_tungstenite::tungstenite::Message::Binary(
                                buffer[..count].to_vec().into(),
                            ))
                            .await
                            .expect("send SHPH bytes as WebSocket binary frame");
                    }
                };
                let incoming_sink = std::sync::Arc::clone(&sink);
                let incoming = async move {
                    while let Some(frame) = frames.next().await {
                        match frame.expect("read SNAP WebSocket frame") {
                            tokio_tungstenite::tungstenite::Message::Binary(payload) => {
                                tokio::io::AsyncWriteExt::write_all(&mut peer_writer, &payload)
                                    .await
                                    .expect("write SHPH peer bytes");
                            }
                            tokio_tungstenite::tungstenite::Message::Ping(payload) => {
                                incoming_sink
                                    .lock()
                                    .await
                                    .send(tokio_tungstenite::tungstenite::Message::Pong(payload))
                                    .await
                                    .expect("send WebSocket pong");
                            }
                            tokio_tungstenite::tungstenite::Message::Close(frame) => {
                                let _ = incoming_sink
                                    .lock()
                                    .await
                                    .send(tokio_tungstenite::tungstenite::Message::Close(frame))
                                    .await;
                                let _ = tokio::io::AsyncWriteExt::shutdown(&mut peer_writer).await;
                                return;
                            }
                            tokio_tungstenite::tungstenite::Message::Pong(_) => {}
                            _ => panic!("unexpected SNAP WebSocket message"),
                        }
                    }
                };
                tokio::join!(outgoing, incoming);
            } else if bridge_adapter == "shroud-tcp" {
                let mut request = [0u8; 16];
                tokio::io::AsyncReadExt::read_exact(&mut tls, &mut request)
                    .await
                    .expect("read SNAP-Shroud versioned handshake");
                assert_eq!(&request[..8], b"SNP-SHR1");
                assert_eq!(request[8], 1);
                assert_eq!(request[9], 1);
                assert_eq!(u16::from_be_bytes([request[10], request[11]]), 1024);
                let mut response = [0u8; 16];
                response[..8].copy_from_slice(b"SNP-ACK1");
                response[8] = 1;
                response[9] = request[9];
                response[10..12].copy_from_slice(&request[10..12]);
                response[12..].copy_from_slice(&request[12..]);
                tokio::io::AsyncWriteExt::write_all(&mut tls, &response)
                    .await
                    .expect("write SNAP-Shroud handshake response");
                tokio::io::AsyncWriteExt::flush(&mut tls)
                    .await
                    .expect("flush SNAP-Shroud handshake response");

                let (mut tls_reader, mut tls_writer) = tokio::io::split(tls);
                let (mut peer_reader, mut peer_writer) = tokio::io::split(peer);
                let outgoing = async move {
                        let mut payload = vec![0u8; 768];
                        loop {
                            let count = match tokio::io::AsyncReadExt::read(
                                &mut peer_reader,
                                &mut payload,
                            )
                            .await
                            {
                                Ok(count) => count,
                                Err(error)
                                    if matches!(
                                        error.kind(),
                                        std::io::ErrorKind::ConnectionReset
                                            | std::io::ErrorKind::ConnectionAborted
                                            | std::io::ErrorKind::BrokenPipe
                                            | std::io::ErrorKind::UnexpectedEof
                                    ) =>
                                {
                                    let _ = tokio::io::AsyncWriteExt::shutdown(&mut tls_writer)
                                        .await;
                                    return;
                                }
                                Err(error) => panic!("read peer data for SNAP-Shroud: {error}"),
                            };
                            if count == 0 {
                                let _ = tokio::io::AsyncWriteExt::shutdown(&mut tls_writer).await;
                                return;
                        }
                        let mut cell = vec![0u8; 1024];
                        cell[..8].copy_from_slice(b"SNP-CEL1");
                        cell[8] = 1;
                        cell[9] = 1;
                        cell[10..12].copy_from_slice(&(count as u16).to_be_bytes());
                        cell[12..12 + count].copy_from_slice(&payload[..count]);
                        tokio::io::AsyncWriteExt::write_all(&mut tls_writer, &cell)
                            .await
                            .expect("write peer data as SNAP-Shroud cell");
                        tokio::io::AsyncWriteExt::flush(&mut tls_writer)
                            .await
                            .expect("flush SNAP-Shroud cell");
                    }
                };
                let incoming = async move {
                    loop {
                        let mut cell = vec![0u8; 1024];
                        if tokio::io::AsyncReadExt::read_exact(&mut tls_reader, &mut cell)
                            .await
                            .is_err()
                        {
                            return;
                        }
                        assert_eq!(&cell[..8], b"SNP-CEL1");
                        assert_eq!(cell[8], 1);
                        let count = u16::from_be_bytes([cell[10], cell[11]]) as usize;
                        assert!(count <= 768);
                        match cell[9] {
                            1 => tokio::io::AsyncWriteExt::write_all(
                                &mut peer_writer,
                                &cell[12..12 + count],
                            )
                            .await
                            .expect("forward SNAP-Shroud payload to SHPH peer"),
                            2 => assert_eq!(count, 0),
                            other => panic!("unexpected SNAP-Shroud frame type {other}"),
                        }
                    }
                };
                tokio::join!(outgoing, incoming);
            } else {
                let mut tls = tls;
                tokio::io::copy_bidirectional(&mut tls, &mut peer)
                    .await
                    .expect("forward TLS bridge bytes");
            }
        });
    });

    let server = Command::new(env!("CARGO_BIN_EXE_shph"))
        .arg("--config")
        .arg(&server_config)
        .args([
            "recv-once",
            "--bind",
            &endpoint,
            "--timeout-secs",
            if wrong_peer {
                "3"
            } else if reconnect {
                "16"
            } else {
                "8"
            },
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("start SHPH receiver behind TLS bridge");
    let wrong_server = wrong_peer_addr.map(|wrong_peer_addr| {
        let wrong_endpoint = format!("127.0.0.1:{}", wrong_peer_addr.port());
        Command::new(env!("CARGO_BIN_EXE_shph"))
            .arg("--config")
            .arg(&wrong_server_config)
            .args([
                "recv-once",
                "--bind",
                &wrong_endpoint,
                "--timeout-secs",
                "3",
            ])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("start wrong-identity SHPH receiver behind TLS bridge")
    });
    let client = if reconnect {
        bridge_start_tx
            .send(())
            .expect("start delayed TLS bridge listener");
        let mut client = Command::new(env!("CARGO_BIN_EXE_shph"))
            .arg("--config")
            .arg(&client_config)
            .args(["up", "--no-tun", "--snap-profile"])
            .arg(&profile_path)
            .env("RUST_LOG", "info")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start reconnecting TLS bridge SNAP session");
        client
            .stdin
            .take()
            .expect("TLS bridge client stdin")
            .write_all(format!("snap-{adapter}-payload\n").as_bytes())
            .expect("write TLS bridge payload");
        client
            .wait_with_output()
            .expect("wait for reconnecting TLS bridge SNAP session")
    } else {
        thread::sleep(Duration::from_millis(150));
        Command::new(env!("CARGO_BIN_EXE_shph"))
            .arg("--config")
            .arg(&client_config)
            .args(["up", "--no-tun", "--snap-profile"])
            .arg(&profile_path)
            .env("RUST_LOG", "info")
            .output()
            .expect("run TLS bridge SNAP session")
    };
    let receiver = server.wait_with_output().expect("wait for SHPH receiver");
    let wrong_receiver = wrong_server.map(|server| {
        server
            .wait_with_output()
            .expect("wait for wrong-identity SHPH receiver")
    });
    let bridge_result = bridge.join();

    if wrong_peer {
        let client_stdout = normalized_process_output(&client);
        let receiver_stdout = String::from_utf8_lossy(&receiver.stdout);
        assert!(
            !client.status.success(),
            "wrong pinned identity was accepted: {client_stdout}"
        );
        assert!(
            client_stdout.contains("TerminalFailure"),
            "client stdout: {client_stdout}\nclient stderr: {}",
            String::from_utf8_lossy(&client.stderr)
        );
        assert!(
            String::from_utf8_lossy(&client.stderr)
                .contains("peer identity and signing key are not pinned"),
            "expected pinned-identity rejection, got: {}",
            String::from_utf8_lossy(&client.stderr)
        );
        assert!(
            !client_stdout.contains("attempt=2"),
            "wrong-peer authentication must not fall through to the allowed direct candidate: {client_stdout}"
        );
        assert!(
            !receiver_stdout.contains(&format!("must-not-reach-fallback-{adapter}")),
            "the allowed direct fallback received application data: {receiver_stdout}"
        );
        assert!(bridge_result.is_ok(), "TLS bridge thread panicked");
        assert!(wrong_receiver.is_some());
        fs::remove_dir_all(dir).expect("remove test directory");
        return;
    }

    assert!(
        client.status.success(),
        "client stdout: {}\nclient stderr: {}",
        String::from_utf8_lossy(&client.stdout),
        String::from_utf8_lossy(&client.stderr)
    );
    assert!(
        receiver.status.success(),
        "receiver stdout: {}\nreceiver stderr: {}\nclient stdout: {}\nclient stderr: {}",
        String::from_utf8_lossy(&receiver.stdout),
        String::from_utf8_lossy(&receiver.stderr),
        String::from_utf8_lossy(&client.stdout),
        String::from_utf8_lossy(&client.stderr)
    );
    assert!(String::from_utf8_lossy(&receiver.stdout).contains(&format!("snap-{adapter}-payload")));
    let client_stdout = normalized_process_output(&client);
    assert!(client_stdout.contains("Connected"));
    if reconnect {
        assert!(
            client_stdout.contains("Transport loop: closed"),
            "{client_stdout}"
        );
        assert!(
            client_stdout.contains("Reconnect: attempt 1/2 failed"),
            "{client_stdout}"
        );
        assert!(
            client_stdout.contains("RetryableFailure"),
            "{client_stdout}"
        );
    }
    assert!(bridge_result.is_ok(), "TLS bridge thread panicked");
    fs::remove_dir_all(dir).expect("remove test directory");
}

#[test]
fn snap_quic_adapter_exchanges_authenticated_payload_with_pinned_peer() {
    run_snap_quic_adapter_case(false);
}

#[test]
fn snap_quic_adapter_reconnects_after_setup_failure_and_shuts_down() {
    run_snap_quic_adapter_case(true);
}

fn run_snap_quic_adapter_case(reconnect: bool) {
    let dir = test_dir();
    let client_dir = dir.join("client");
    let server_dir = dir.join("server");
    fs::create_dir_all(&client_dir).expect("create client directory");
    fs::create_dir_all(&server_dir).expect("create server directory");
    let client_config = client_dir.join("config.toml");
    let server_config = server_dir.join("config.toml");
    for config in [&client_config, &server_config] {
        let init = run(config, &["init", "--new"]);
        assert!(
            init.status.success(),
            "init stderr: {}",
            String::from_utf8_lossy(&init.stderr)
        );
    }

    let reserved = UdpSocket::bind("127.0.0.1:0").expect("reserve QUIC loopback port");
    let endpoint = reserved.local_addr().expect("QUIC endpoint");
    if reconnect {
        reserved
            .set_nonblocking(true)
            .expect("set initial QUIC sink nonblocking");
    }
    let client_key = output_key(&client_config, "show-public-key");
    let client_signing_key = output_key(&client_config, "show-signing-public-key");
    let server_key = output_key(&server_config, "show-public-key");
    let server_signing_key = output_key(&server_config, "show-signing-public-key");
    assert!(run(
        &client_config,
        &[
            "add-peer",
            "server",
            "127.0.0.1",
            &endpoint.port().to_string(),
            &server_key,
            "--sign-pubkey",
            &server_signing_key,
        ],
    )
    .status
    .success());
    assert!(run(
        &server_config,
        &[
            "add-peer",
            "client",
            "127.0.0.1",
            "55556",
            &client_key,
            "--sign-pubkey",
            &client_signing_key,
        ],
    )
    .status
    .success());

    let profile_path = dir.join("quic.json");
    fs::write(
        &profile_path,
        serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "profile_name": if reconnect { "quic-reconnect" } else { "quic-lab" },
            "peer_alias": "server",
            "mode": "direct-only",
            "connect_timeout_sec": if reconnect { 1.0 } else { 5.0 },
            "retry_policy": {
                "rounds": 1,
                "max_total_attempts": 1,
                "max_elapsed_sec": 4.0,
                "jitter_ratio": 0.0
            },
            "direct_endpoints": [{
                "ip": "127.0.0.1",
                "port": endpoint.port(),
                "adapter": "quic",
                "transport": "quic"
            }]
        }))
        .expect("serialize QUIC profile"),
    )
    .expect("write QUIC profile");
    let profile_config_path = profile_path.to_string_lossy().replace('\\', "/");
    let peer_endpoint = format!("127.0.0.1:{}", endpoint.port());
    let mut client_toml = fs::read_to_string(&client_config).expect("read client config");
    if reconnect {
        client_toml.push_str(&format!(
            "\n[session]\nrole = \"connect\"\npeer = \"{peer_endpoint}\"\nsnap_profile = \"{profile_config_path}\"\ntimeout_secs = 6\n\n[session.reconnect]\nenabled = true\nmax_attempts = 2\ninitial_delay_ms = 3000\nmax_delay_ms = 3000\n"
        ));
    } else {
        client_toml.push_str(&format!(
            "\n[session]\nrole = \"connect\"\npeer = \"{peer_endpoint}\"\nsnap_profile = \"{profile_config_path}\"\ntimeout_secs = 5\nstartup_payload = \"snap-quic-payload\"\n"
        ));
    }
    fs::write(&client_config, client_toml).expect("write client session config");

    let server_config_thread = server_config.clone();
    let peer_endpoint_thread = peer_endpoint.clone();
    let server = thread::spawn(move || {
        if reconnect {
            let deadline = Instant::now() + Duration::from_millis(1800);
            let mut packet = [0u8; 65535];
            while Instant::now() < deadline {
                match reserved.recv_from(&mut packet) {
                    Ok(_) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("read initial QUIC setup datagram: {error}"),
                }
            }
        }
        drop(reserved);
        run(
            &server_config_thread,
            &[
                "recv-once",
                "--bind",
                &peer_endpoint_thread,
                "--timeout-secs",
                "10",
                "--transport",
                "quic",
            ],
        )
    });
    let client = if reconnect {
        let mut client = Command::new(env!("CARGO_BIN_EXE_shph"))
            .arg("--config")
            .arg(&client_config)
            .args(["up", "--no-tun"])
            .env("RUST_LOG", "info")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start reconnecting SNAP QUIC session");
        client
            .stdin
            .take()
            .expect("QUIC client stdin")
            .write_all(b"snap-quic-payload\n")
            .expect("write QUIC payload");
        client
            .wait_with_output()
            .expect("wait for reconnecting SNAP QUIC session")
    } else {
        thread::sleep(Duration::from_millis(200));
        Command::new(env!("CARGO_BIN_EXE_shph"))
            .arg("--config")
            .arg(&client_config)
            .args(["up", "--no-tun"])
            .env("RUST_LOG", "info")
            .output()
            .expect("run SNAP QUIC session")
    };
    let receiver = server.join().expect("join QUIC receiver");
    assert!(
        client.status.success(),
        "client stdout: {}\nclient stderr: {}",
        String::from_utf8_lossy(&client.stdout),
        String::from_utf8_lossy(&client.stderr)
    );
    assert!(
        receiver.status.success(),
        "receiver stdout: {}\nreceiver stderr: {}",
        String::from_utf8_lossy(&receiver.stdout),
        String::from_utf8_lossy(&receiver.stderr)
    );
    assert!(String::from_utf8_lossy(&receiver.stdout).contains("snap-quic-payload"));
    let client_stdout = normalized_process_output(&client);
    assert!(client_stdout.contains("adapter=quic"));
    if reconnect {
        assert!(
            client_stdout.contains("Reconnect: attempt 1/2 failed"),
            "{client_stdout}"
        );
        assert!(
            client_stdout.contains("RetryableFailure"),
            "{client_stdout}"
        );
        assert!(
            client_stdout.contains("Transport loop: closed"),
            "{client_stdout}"
        );
    }

    fs::remove_dir_all(dir).expect("remove test directory");
}

#[test]
fn snap_quic_wrong_peer_is_terminal_before_allowed_fallback() {
    let dir = test_dir();
    let client_dir = dir.join("client");
    let server_dir = dir.join("server");
    let wrong_server_dir = dir.join("wrong-server");
    for path in [&client_dir, &server_dir, &wrong_server_dir] {
        fs::create_dir_all(path).expect("create peer test directory");
    }
    let client_config = client_dir.join("config.toml");
    let server_config = server_dir.join("config.toml");
    let wrong_server_config = wrong_server_dir.join("config.toml");
    for config in [&client_config, &server_config, &wrong_server_config] {
        let init = run(config, &["init", "--new"]);
        assert!(
            init.status.success(),
            "init stderr: {}",
            String::from_utf8_lossy(&init.stderr)
        );
    }

    let pinned_socket = TcpListener::bind("127.0.0.1:0").expect("reserve pinned TCP port");
    let pinned_addr = pinned_socket.local_addr().expect("pinned TCP address");
    drop(pinned_socket);
    let wrong_quic_socket = UdpSocket::bind("127.0.0.1:0").expect("reserve wrong QUIC port");
    let wrong_quic_addr = wrong_quic_socket.local_addr().expect("wrong QUIC address");
    drop(wrong_quic_socket);

    let client_public = output_key(&client_config, "show-public-key");
    let client_signing = output_key(&client_config, "show-signing-public-key");
    assert!(run(
        &client_config,
        &[
            "add-peer",
            "server",
            "127.0.0.1",
            &pinned_addr.port().to_string(),
            &output_key(&server_config, "show-public-key"),
            "--sign-pubkey",
            &output_key(&server_config, "show-signing-public-key"),
        ],
    )
    .status
    .success());
    for config in [&server_config, &wrong_server_config] {
        assert!(run(
            config,
            &[
                "add-peer",
                "client",
                "127.0.0.1",
                "55555",
                &client_public,
                "--sign-pubkey",
                &client_signing,
            ],
        )
        .status
        .success());
    }

    let profile_path = dir.join("wrong-quic-peer.json");
    fs::write(
        &profile_path,
        serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "profile_name": "wrong-quic-peer-terminal",
            "peer_alias": "server",
            "mode": "direct-only",
            "retry_policy": {
                "rounds": 1,
                "max_total_attempts": 2,
                "max_elapsed_sec": 8.0,
                "jitter_ratio": 0.0
            },
            "direct_endpoints": [
                {
                    "ip": "127.0.0.1",
                    "port": wrong_quic_addr.port(),
                    "adapter": "quic",
                    "transport": "quic",
                    "priority": 1,
                    "allowed_fallback": ["direct-tcp"]
                },
                {
                    "ip": "127.0.0.1",
                    "port": pinned_addr.port(),
                    "adapter": "direct-tcp",
                    "transport": "tcp",
                    "priority": 2
                }
            ]
        }))
        .expect("serialize wrong-peer QUIC profile"),
    )
    .expect("write wrong-peer QUIC profile");
    let endpoint = format!("127.0.0.1:{}", pinned_addr.port());
    let profile_for_config = profile_path.to_string_lossy().replace('\\', "/");
    let mut client_toml = fs::read_to_string(&client_config).expect("read client config");
    client_toml.push_str(&format!(
        "\n[session]\nrole = \"connect\"\npeer = \"{endpoint}\"\nsnap_profile = \"{profile_for_config}\"\ntimeout_secs = 6\nstartup_payload = \"must-not-reach-quic-fallback\"\n"
    ));
    fs::write(&client_config, client_toml).expect("configure wrong-peer QUIC client");

    let pinned_server = Command::new(env!("CARGO_BIN_EXE_shph"))
        .arg("--config")
        .arg(&server_config)
        .args(["recv-once", "--bind", &endpoint, "--timeout-secs", "3"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("start pinned direct-TCP fallback server");
    let wrong_quic_endpoint = format!("127.0.0.1:{}", wrong_quic_addr.port());
    let wrong_server = Command::new(env!("CARGO_BIN_EXE_shph"))
        .arg("--config")
        .arg(&wrong_server_config)
        .args([
            "recv-once",
            "--bind",
            &wrong_quic_endpoint,
            "--timeout-secs",
            "3",
            "--transport",
            "quic",
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("start wrong-identity QUIC peer");
    thread::sleep(Duration::from_millis(200));
    let client = Command::new(env!("CARGO_BIN_EXE_shph"))
        .arg("--config")
        .arg(&client_config)
        .args(["up", "--no-tun", "--snap-profile"])
        .arg(&profile_path)
        .env("RUST_LOG", "info")
        .output()
        .expect("run wrong-peer QUIC SNAP session");
    let pinned_receiver = pinned_server
        .wait_with_output()
        .expect("wait for pinned fallback server");
    let _wrong_receiver = wrong_server
        .wait_with_output()
        .expect("wait for wrong-identity QUIC peer");
    let client_stdout = normalized_process_output(&client);
    assert!(
        !client.status.success(),
        "wrong pinned identity was accepted: {client_stdout}"
    );
    assert!(
        client_stdout.contains("TerminalFailure"),
        "client stdout: {client_stdout}\nclient stderr: {}",
        String::from_utf8_lossy(&client.stderr)
    );
    assert!(
        String::from_utf8_lossy(&client.stderr)
            .contains("peer identity and signing key are not pinned"),
        "expected pinned-identity rejection, got: {}",
        String::from_utf8_lossy(&client.stderr)
    );
    assert!(
        !client_stdout.contains("attempt=2"),
        "wrong-peer authentication must not fall through to the allowed direct candidate: {client_stdout}"
    );
    assert!(
        !String::from_utf8_lossy(&pinned_receiver.stdout).contains("must-not-reach-quic-fallback"),
        "the allowed direct fallback received application data: {}",
        String::from_utf8_lossy(&pinned_receiver.stdout)
    );
    fs::remove_dir_all(dir).expect("remove test directory");
}

#[test]
fn snap_standards_quic_wrong_peer_is_terminal_before_allowed_fallback() {
    let dir = test_dir();
    let client_dir = dir.join("client");
    let server_dir = dir.join("server");
    let wrong_server_dir = dir.join("wrong-server");
    for path in [&client_dir, &server_dir, &wrong_server_dir] {
        fs::create_dir_all(path).expect("create peer test directory");
    }
    let client_config = client_dir.join("config.toml");
    let server_config = server_dir.join("config.toml");
    let wrong_server_config = wrong_server_dir.join("config.toml");
    for config in [&client_config, &server_config, &wrong_server_config] {
        let init = run(config, &["init", "--new"]);
        assert!(
            init.status.success(),
            "init stderr: {}",
            String::from_utf8_lossy(&init.stderr)
        );
    }

    let pinned_socket = TcpListener::bind("127.0.0.1:0").expect("reserve pinned TCP port");
    let pinned_addr = pinned_socket.local_addr().expect("pinned TCP address");
    drop(pinned_socket);
    let wrong_quic_socket =
        UdpSocket::bind("127.0.0.1:0").expect("reserve wrong standards-QUIC port");
    let wrong_quic_addr = wrong_quic_socket
        .local_addr()
        .expect("wrong standards-QUIC address");
    drop(wrong_quic_socket);

    let client_public = output_key(&client_config, "show-public-key");
    let client_signing = output_key(&client_config, "show-signing-public-key");
    assert!(run(
        &client_config,
        &[
            "add-peer",
            "server",
            "127.0.0.1",
            &pinned_addr.port().to_string(),
            &output_key(&server_config, "show-public-key"),
            "--sign-pubkey",
            &output_key(&server_config, "show-signing-public-key"),
        ],
    )
    .status
    .success());
    for config in [&server_config, &wrong_server_config] {
        assert!(run(
            config,
            &[
                "add-peer",
                "client",
                "127.0.0.1",
                "55560",
                &client_public,
                "--sign-pubkey",
                &client_signing,
            ],
        )
        .status
        .success());
    }

    let certificate = wrong_server_dir.join("server.der");
    let private_key = wrong_server_dir.join("server.key");
    let wrong_quic_endpoint = format!("127.0.0.1:{}", wrong_quic_addr.port());
    let wrong_server = Command::new(env!("CARGO_BIN_EXE_shph"))
        .arg("--config")
        .arg(&wrong_server_config)
        .args([
            "recv-once",
            "--bind",
            &wrong_quic_endpoint,
            "--timeout-secs",
            "4",
            "--transport",
            "quic-standard",
            "--quic-cert",
        ])
        .arg(&certificate)
        .arg("--quic-key")
        .arg(&private_key)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("start wrong-identity standards-QUIC peer");
    for _ in 0..200 {
        if certificate.exists() && private_key.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    assert!(
        certificate.exists(),
        "wrong peer did not write QUIC certificate"
    );
    assert!(
        private_key.exists(),
        "wrong peer did not write QUIC private key"
    );

    let profile_path = dir.join("wrong-standards-quic-peer.json");
    fs::write(
        &profile_path,
        serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "profile_name": "wrong-standards-quic-peer-terminal",
            "peer_alias": "server",
            "mode": "direct-only",
            "retry_policy": {
                "rounds": 1,
                "max_total_attempts": 2,
                "max_elapsed_sec": 8.0,
                "jitter_ratio": 0.0
            },
            "direct_endpoints": [
                {
                    "ip": "127.0.0.1",
                    "port": wrong_quic_addr.port(),
                    "adapter": "quic-standard",
                    "transport": "quic-standard",
                    "priority": 1,
                    "allowed_fallback": ["direct-tcp"]
                },
                {
                    "ip": "127.0.0.1",
                    "port": pinned_addr.port(),
                    "adapter": "direct-tcp",
                    "transport": "tcp",
                    "priority": 2
                }
            ]
        }))
        .expect("serialize wrong-peer standards-QUIC profile"),
    )
    .expect("write wrong-peer standards-QUIC profile");
    let endpoint = format!("127.0.0.1:{}", pinned_addr.port());
    let profile_for_config = profile_path.to_string_lossy().replace('\\', "/");
    let certificate_for_config = certificate.to_string_lossy().replace('\\', "/");
    let mut client_toml = fs::read_to_string(&client_config).expect("read client config");
    client_toml.push_str(&format!(
        "\n[session]\nrole = \"connect\"\npeer = \"{endpoint}\"\nsnap_profile = \"{profile_for_config}\"\ntimeout_secs = 6\nstartup_payload = \"must-not-reach-standard-quic-fallback\"\nquic_cert = \"{certificate_for_config}\"\n"
    ));
    fs::write(&client_config, client_toml).expect("configure wrong-peer standards-QUIC client");

    let pinned_server = Command::new(env!("CARGO_BIN_EXE_shph"))
        .arg("--config")
        .arg(&server_config)
        .args([
            "recv-once",
            "--bind",
            &endpoint,
            "--timeout-secs",
            "4",
            "--transport",
            "tcp",
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("start pinned direct-TCP fallback server");
    thread::sleep(Duration::from_millis(150));
    let client = Command::new(env!("CARGO_BIN_EXE_shph"))
        .arg("--config")
        .arg(&client_config)
        .args(["up", "--no-tun", "--snap-profile"])
        .arg(&profile_path)
        .env("RUST_LOG", "info")
        .output()
        .expect("run wrong-peer standards-QUIC SNAP session");
    let pinned_receiver = pinned_server
        .wait_with_output()
        .expect("wait for pinned fallback server");
    let _wrong_receiver = wrong_server
        .wait_with_output()
        .expect("wait for wrong-identity standards-QUIC peer");
    let client_stdout = normalized_process_output(&client);
    assert!(
        !client.status.success(),
        "wrong pinned identity was accepted: {client_stdout}"
    );
    assert!(
        client_stdout.contains("TerminalFailure"),
        "client stdout: {client_stdout}\nclient stderr: {}",
        String::from_utf8_lossy(&client.stderr)
    );
    assert!(
        String::from_utf8_lossy(&client.stderr)
            .contains("peer identity and signing key are not pinned"),
        "expected pinned-identity rejection, got: {}",
        String::from_utf8_lossy(&client.stderr)
    );
    assert!(
        !client_stdout.contains("attempt=2"),
        "wrong-peer authentication must not fall through to the allowed direct candidate: {client_stdout}"
    );
    assert!(
        !String::from_utf8_lossy(&pinned_receiver.stdout)
            .contains("must-not-reach-standard-quic-fallback"),
        "the allowed direct fallback received application data: {}",
        String::from_utf8_lossy(&pinned_receiver.stdout)
    );
    fs::remove_dir_all(dir).expect("remove test directory");
}

#[test]
fn snap_mixed_direct_to_standards_quic_fallback_exchanges_authenticated_payload() {
    let dir = test_dir();
    let client_dir = dir.join("client");
    let server_dir = dir.join("server");
    fs::create_dir_all(&client_dir).expect("create client directory");
    fs::create_dir_all(&server_dir).expect("create server directory");
    let client_config = client_dir.join("config.toml");
    let server_config = server_dir.join("config.toml");
    for config in [&client_config, &server_config] {
        let init = run(config, &["init", "--new"]);
        assert!(
            init.status.success(),
            "init stderr: {}",
            String::from_utf8_lossy(&init.stderr)
        );
    }

    let endpoint = UdpSocket::bind("127.0.0.1:0")
        .expect("reserve standards-QUIC endpoint")
        .local_addr()
        .expect("standards-QUIC address");
    let unused_port = UdpSocket::bind("127.0.0.1:0")
        .expect("reserve failed standards-QUIC candidate")
        .local_addr()
        .expect("failed candidate address")
        .port();
    let unused_tcp_port = TcpListener::bind("127.0.0.1:0")
        .expect("reserve failed TCP candidate")
        .local_addr()
        .expect("failed TCP candidate address")
        .port();
    let peer_endpoint = format!("127.0.0.1:{}", endpoint.port());
    assert!(run(
        &client_config,
        &[
            "add-peer",
            "server",
            "127.0.0.1",
            &endpoint.port().to_string(),
            &output_key(&server_config, "show-public-key"),
            "--sign-pubkey",
            &output_key(&server_config, "show-signing-public-key"),
        ],
    )
    .status
    .success());
    assert!(run(
        &server_config,
        &[
            "add-peer",
            "client",
            "127.0.0.1",
            "55557",
            &output_key(&client_config, "show-public-key"),
            "--sign-pubkey",
            &output_key(&client_config, "show-signing-public-key"),
        ],
    )
    .status
    .success());

    let certificate = server_dir.join("server.der");
    let private_key = server_dir.join("server.key");
    let server_config_thread = server_config.clone();
    let certificate_thread = certificate.clone();
    let private_key_thread = private_key.clone();
    let peer_endpoint_thread = peer_endpoint.clone();
    let server = thread::spawn(move || {
        run(
            &server_config_thread,
            &[
                "recv-once",
                "--bind",
                &peer_endpoint_thread,
                "--timeout-secs",
                "12",
                "--transport",
                "quic-standard",
                "--quic-cert",
                certificate_thread.to_str().expect("certificate path"),
                "--quic-key",
                private_key_thread.to_str().expect("private key path"),
            ],
        )
    });
    for _ in 0..200 {
        if certificate.exists() && private_key.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    assert!(certificate.exists(), "receiver did not write certificate");
    assert!(private_key.exists(), "receiver did not write private key");

    let profile_path = dir.join("standard-quic.json");
    fs::write(
        &profile_path,
        format!(
            r#"{{
                "version":1,
                "profile_name":"standard-quic-retry",
                "peer_alias":"server",
                "connect_timeout_sec":3.0,
                "retry_policy":{{"rounds":1,"max_total_attempts":3,"max_elapsed_sec":12.0,"jitter_ratio":0.0}},
                "direct_endpoints":[
                    {{"ip":"127.0.0.1","port":{},"adapter":"direct-tcp","transport":"tcp","priority":1,"allowed_fallback":["quic-standard"]}},
                    {{"ip":"127.0.0.1","port":{},"adapter":"quic-standard","transport":"quic-standard","priority":2}},
                    {{"ip":"127.0.0.1","port":{},"adapter":"quic-standard","transport":"quic-standard","priority":3}}
                ]
            }}"#,
            unused_tcp_port,
            unused_port,
            endpoint.port()
        ),
    )
    .expect("write standards-QUIC SNAP profile");
    let cert_path_config = certificate.to_string_lossy().replace('\\', "/");
    let mut client_toml = fs::read_to_string(&client_config).expect("read client config");
    client_toml.push_str(&format!(
        "\n[session]\nrole = \"connect\"\npeer = \"{peer_endpoint}\"\ntimeout_secs = 5\nstartup_payload = \"snap-standard-quic-payload\"\nquic_cert = \"{cert_path_config}\"\n"
    ));
    fs::write(&client_config, client_toml).expect("configure standards-QUIC session");

    let client = Command::new(env!("CARGO_BIN_EXE_shph"))
        .arg("--config")
        .arg(&client_config)
        .args(["up", "--no-tun", "--snap-profile"])
        .arg(&profile_path)
        .env("RUST_LOG", "info")
        .output()
        .expect("run standards-QUIC SNAP session");
    let receiver = server.join().expect("join standards-QUIC receiver");
    assert!(
        client.status.success(),
        "client stdout: {}\nclient stderr: {}",
        String::from_utf8_lossy(&client.stdout),
        String::from_utf8_lossy(&client.stderr)
    );
    assert!(
        receiver.status.success(),
        "receiver stdout: {}\nreceiver stderr: {}",
        String::from_utf8_lossy(&receiver.stdout),
        String::from_utf8_lossy(&receiver.stderr)
    );
    assert!(String::from_utf8_lossy(&receiver.stdout).contains("snap-standard-quic-payload"));
    let client_output = String::from_utf8_lossy(&client.stdout);
    assert!(
        client_output.contains("RetryableFailure"),
        "{client_output}"
    );
    assert!(client_output.contains("Connected"), "{client_output}");

    fs::remove_dir_all(dir).expect("remove test directory");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn persistent_snap_session_falls_back_to_standards_quic_and_shuts_down() {
    let dir = test_dir();
    fs::create_dir_all(&dir).expect("create test directory");
    let client_config = dir.join("client.toml");
    let init = run(&client_config, &["init", "--new"]);
    assert!(
        init.status.success(),
        "init stderr: {}",
        String::from_utf8_lossy(&init.stderr)
    );

    let server_identity = IdentityKeyPair::generate().expect("server identity");
    let server_public = server_identity.public_key_b64();
    let server_signing = server_identity.signing_public_b64();
    let client_identity = PeerPin::new(
        base64::engine::general_purpose::STANDARD
            .decode(output_key(&client_config, "show-public-key"))
            .expect("decode client identity")
            .try_into()
            .expect("32-byte client identity"),
        base64::engine::general_purpose::STANDARD
            .decode(output_key(&client_config, "show-signing-public-key"))
            .expect("decode client signing key")
            .try_into()
            .expect("32-byte client signing key"),
    );
    let server = server_endpoint(
        "127.0.0.1:0".parse().expect("loopback address"),
        StandardsQuicConfig::default(),
    )
    .expect("standards-QUIC server");
    let server_addr = server.endpoint.local_addr().expect("server address");
    let server_certificate = server.certificate_der.clone();
    let certificate_path = dir.join("server.der");
    fs::write(&certificate_path, server_certificate).expect("write server certificate");
    let server_policy = PeerPolicy::single(client_identity);
    let (first_closed_tx, first_closed_rx) = tokio::sync::oneshot::channel();
    let (reconnected_tx, reconnected_rx) = tokio::sync::oneshot::channel();
    let server_task = tokio::spawn(async move {
        let first_connection = tokio::time::timeout(
            Duration::from_secs(10),
            accept(
                &server,
                &server_identity,
                &server_policy,
                HandshakeProfile::SecureDefault,
                Duration::from_secs(8),
            ),
        )
        .await
        .expect("first persistent SNAP SHPH handshake timeout")
        .expect("first persistent SNAP SHPH handshake");
        first_connection
            .connection
            .close(0u32.into(), b"exercise outer SNAP reconnect");
        let _ = first_closed_tx.send(());
        let connection = tokio::time::timeout(
            Duration::from_secs(10),
            accept(
                &server,
                &server_identity,
                &server_policy,
                HandshakeProfile::SecureDefault,
                Duration::from_secs(8),
            ),
        )
        .await
        .expect("persistent SNAP server accept timeout")
        .expect("persistent SNAP server handshake");
        let _ = reconnected_tx.send(());
        tokio::time::timeout(Duration::from_secs(10), connection.connection.closed())
            .await
            .expect("persistent SNAP client shutdown timeout");
    });

    let add_peer = run(
        &client_config,
        &[
            "add-peer",
            "server",
            "127.0.0.1",
            &server_addr.port().to_string(),
            &server_public,
            "--sign-pubkey",
            &server_signing,
        ],
    );
    assert!(
        add_peer.status.success(),
        "add-peer stderr: {}",
        String::from_utf8_lossy(&add_peer.stderr)
    );

    let unused_tcp_port = TcpListener::bind("127.0.0.1:0")
        .expect("reserve failed direct-TCP candidate")
        .local_addr()
        .expect("failed direct-TCP address")
        .port();
    let profile_path = dir.join("persistent-standard-quic.json");
    fs::write(
        &profile_path,
        format!(
            r#"{{
                "version":1,
                "profile_name":"persistent-standard-quic",
                "peer_alias":"server",
                "connect_timeout_sec":3.0,
                "retry_policy":{{"rounds":1,"max_total_attempts":2,"max_elapsed_sec":10.0,"jitter_ratio":0.0}},
                "direct_endpoints":[
                    {{"ip":"127.0.0.1","port":{unused_tcp_port},"adapter":"direct-tcp","transport":"tcp","priority":1,"allowed_fallback":["quic-standard"]}},
                    {{"ip":"127.0.0.1","port":{},"adapter":"quic-standard","transport":"quic-standard","priority":2}}
                ]
            }}"#,
            server_addr.port()
        ),
    )
    .expect("write persistent SNAP profile");
    let certificate_path = certificate_path.to_string_lossy().replace('\\', "/");
    let peer_endpoint = format!("127.0.0.1:{}", server_addr.port());
    let mut config_text = fs::read_to_string(&client_config).expect("read client config");
    config_text.push_str(&format!(
        "\n[session]\nrole = \"connect\"\npeer = \"{peer_endpoint}\"\ntimeout_secs = 5\nquic_cert = \"{certificate_path}\"\n\n[session.reconnect]\nenabled = true\nmax_attempts = 2\ninitial_delay_ms = 1000\nmax_delay_ms = 1000\n"
    ));
    fs::write(&client_config, config_text).expect("configure persistent connect session");

    let mut client = Command::new(env!("CARGO_BIN_EXE_shph"))
        .arg("--config")
        .arg(&client_config)
        .args(["up", "--no-tun", "--snap-profile"])
        .arg(&profile_path)
        .env("RUST_LOG", "info")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start persistent SNAP session");
    let mut client_stdin = client.stdin.take().expect("persistent SNAP client stdin");
    tokio::time::timeout(Duration::from_secs(10), first_closed_rx)
        .await
        .expect("first persistent SNAP session close timeout")
        .expect("first persistent SNAP session close signal");
    client_stdin
        .write_all(b"probe\nprobe\nprobe\nprobe\n")
        .expect("write persistent SNAP reconnect probes");
    let reconnect_signal = tokio::time::timeout(Duration::from_secs(10), reconnected_rx).await;
    if !matches!(reconnect_signal, Ok(Ok(()))) {
        drop(client_stdin);
        let client = tokio::task::spawn_blocking(move || client.wait_with_output())
            .await
            .expect("join persistent SNAP client process")
            .expect("wait for persistent SNAP client");
        let server_result = server_task.await;
        panic!(
            "persistent SNAP client did not reconnect; client stdout: {}\nclient stderr: {}\nserver result: {server_result:?}",
            String::from_utf8_lossy(&client.stdout),
            String::from_utf8_lossy(&client.stderr)
        );
    }
    drop(client_stdin);
    let client = tokio::task::spawn_blocking(move || client.wait_with_output())
        .await
        .expect("join persistent SNAP client process")
        .expect("wait for persistent SNAP client");
    server_task.await.expect("server worker join");
    assert!(
        client.status.success(),
        "client stdout: {}\nclient stderr: {}",
        String::from_utf8_lossy(&client.stdout),
        String::from_utf8_lossy(&client.stderr)
    );

    let client_output = normalized_process_output(&client);

    assert!(
        client_output.contains("RetryableFailure"),
        "{client_output}"
    );
    assert!(client_output.contains("Connected"), "{client_output}");
    assert!(client_output.contains("connect-loop"), "{client_output}");
    assert!(
        client_output.contains("Reconnect: attempt 1/2 failed"),
        "{client_output}"
    );

    fs::remove_dir_all(dir).expect("remove test directory");
}

#[test]
fn snap_offline_mesh_and_data_mule_exchange_authenticated_payloads() {
    run_snap_file_adapter_roundtrip("offline-mesh");
    run_snap_file_adapter_roundtrip("data-mule");
}

#[test]
fn snap_offline_mesh_rejects_wrong_peer_before_allowed_fallback() {
    run_snap_file_adapter_roundtrip_with_wrong_peer("offline-mesh", true);
}

#[test]
fn snap_data_mule_rejects_wrong_peer_before_allowed_fallback() {
    let dir = test_dir();
    let client_dir = dir.join("client");
    let server_dir = dir.join("server");
    fs::create_dir_all(&client_dir).expect("create client directory");
    fs::create_dir_all(&server_dir).expect("create server directory");
    let client_config = client_dir.join("config.toml");
    let server_config = server_dir.join("config.toml");
    for config in [&client_config, &server_config] {
        let init = run(config, &["init", "--new"]);
        assert!(
            init.status.success(),
            "init stderr: {}",
            String::from_utf8_lossy(&init.stderr)
        );
    }

    let peer_socket = TcpListener::bind("127.0.0.1:0").expect("reserve direct fallback port");
    let peer_addr = peer_socket.local_addr().expect("direct fallback address");
    drop(peer_socket);
    let peer_endpoint = format!("127.0.0.1:{}", peer_addr.port());
    let peer_port = peer_addr.port().to_string();
    let client_public = output_key(&client_config, "show-public-key");
    let server_public = output_key(&server_config, "show-public-key");
    let server_signing = output_key(&server_config, "show-signing-public-key");
    assert!(run(
        &client_config,
        &[
            "add-peer",
            "server",
            "127.0.0.1",
            &peer_port,
            &server_public,
            "--sign-pubkey",
            &server_signing,
        ],
    )
    .status
    .success());

    let to_server = dir.join("to-server");
    let to_client = dir.join("to-client");
    fs::create_dir_all(&to_server).expect("create data-mule server inbox");
    fs::create_dir_all(&to_client).expect("create data-mule client inbox");
    let to_server_text = to_server.to_string_lossy().replace('\\', "/");
    let to_client_text = to_client.to_string_lossy().replace('\\', "/");
    let profile_path = dir.join("data-mule-wrong-peer.json");
    fs::write(
        &profile_path,
        serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "profile_name": "data-mule-wrong-peer",
            "peer_alias": "server",
            "mode": "direct-only",
            "retry_policy": {
                "rounds": 1,
                "max_total_attempts": 2,
                "max_elapsed_sec": 8.0,
                "jitter_ratio": 0.0
            },
            "direct_endpoints": [
                {
                    "ip": "127.0.0.1",
                    "port": peer_addr.port(),
                    "adapter": "data-mule",
                    "transport": "data-mule",
                    "priority": 1,
                    "allowed_fallback": ["direct-tcp"]
                },
                {
                    "ip": "127.0.0.1",
                    "port": peer_addr.port(),
                    "adapter": "direct-tcp",
                    "transport": "tcp",
                    "priority": 2
                }
            ]
        }))
        .expect("serialize data-mule wrong-peer profile"),
    )
    .expect("write data-mule wrong-peer profile");

    let profile_for_config = profile_path.to_string_lossy().replace('\\', "/");
    let mut client_toml = fs::read_to_string(&client_config).expect("read client config");
    client_toml.push_str(&format!(
        "\n[roadmap.transport]\nkind = \"data_mule\"\ninbox_dir = \"{to_client_text}\"\noutbox_dir = \"{to_server_text}\"\npoll_interval_ms = 10\nmax_file_bytes = 32768\nmax_total_bytes = 1048576\nmax_age_ms = 60000\n\n[session]\nrole = \"connect\"\npeer = \"{peer_endpoint}\"\nsnap_profile = \"{profile_for_config}\"\ntimeout_secs = 8\n"
    ));
    fs::write(&client_config, client_toml).expect("configure data-mule client");

    let server_config_thread = server_config.clone();
    let peer_endpoint_thread = peer_endpoint.clone();
    let fallback_receiver = thread::spawn(move || {
        run(
            &server_config_thread,
            &[
                "recv-once",
                "--bind",
                &peer_endpoint_thread,
                "--timeout-secs",
                "4",
                "--transport",
                "tcp",
            ],
        )
    });
    let mut client = Command::new(env!("CARGO_BIN_EXE_shph"))
        .arg("--config")
        .arg(&client_config)
        .args(["up", "--no-tun"])
        .env("RUST_LOG", "info")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start data-mule SNAP client");

    let outbound_root = to_server.join(shph_core::roadmap::safe_path_component(&server_public));
    let deadline = Instant::now() + Duration::from_secs(8);
    let hello_arrived = loop {
        let arrived = fs::read_dir(&outbound_root)
            .ok()
            .and_then(|mut entries| entries.next())
            .is_some();
        if arrived {
            break true;
        }
        if let Some(status) = client.try_wait().expect("poll data-mule client") {
            let output = client
                .wait_with_output()
                .expect("collect exited data-mule client output");
            panic!(
                "data-mule client exited before sending its hello ({status}): stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        assert!(
            Instant::now() < deadline,
            "data-mule client did not publish its handshake hello"
        );
        thread::sleep(Duration::from_millis(20));
    };
    assert!(hello_arrived);

    let wrong_identity = IdentityKeyPair::generate().expect("wrong peer identity");
    let wrong_hello =
        shph_core::build_hello_with_profile(&wrong_identity, HandshakeProfile::SecureDefault)
            .expect("build wrong-peer hello")
            .local_hello;
    let created_at_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_millis() as u64;
    let envelope_id = format!("{created_at_unix_ms}-0");
    let response = shph_core::DataMuleEnvelope {
        envelope_id: envelope_id.clone(),
        created_at_unix_ms,
        from_node: server_public,
        to_node: client_public.clone(),
        ciphertext_b64: base64::engine::general_purpose::STANDARD
            .encode(serde_json::to_vec(&wrong_hello).expect("serialize wrong-peer hello")),
        nonce_b64: base64::engine::general_purpose::STANDARD.encode(0u64.to_le_bytes()),
    };
    let response_path = shph_core::roadmap::data_mule_inbox_path(
        &to_client.to_string_lossy(),
        &client_public,
        &envelope_id,
    );
    fs::create_dir_all(response_path.parent().expect("response parent"))
        .expect("create wrong-peer response inbox");
    fs::write(
        &response_path,
        serde_json::to_vec(&response).expect("serialize data-mule response envelope"),
    )
    .expect("write wrong-peer data-mule response");

    let client_output = client
        .wait_with_output()
        .expect("wait for data-mule client");
    let fallback = fallback_receiver
        .join()
        .expect("join direct fallback receiver");
    let stdout = String::from_utf8_lossy(&client_output.stdout);
    let stderr = String::from_utf8_lossy(&client_output.stderr);
    assert!(
        !client_output.status.success(),
        "wrong peer was accepted: {stdout}"
    );
    assert!(
        stdout.contains("TerminalFailure")
            || stderr.contains("peer identity and signing key are not pinned"),
        "expected terminal wrong-peer rejection, stdout={stdout} stderr={stderr}"
    );
    assert!(
        !stdout.contains("attempt=2"),
        "wrong data-mule peer triggered allowed direct fallback: {stdout}"
    );
    assert!(
        !fallback.status.success(),
        "direct fallback received the wrong-peer attempt: stdout={} stderr={}",
        String::from_utf8_lossy(&fallback.stdout),
        String::from_utf8_lossy(&fallback.stderr)
    );
    fs::remove_dir_all(dir).expect("remove test directory");
}

fn run_snap_file_adapter_roundtrip(adapter: &str) {
    run_snap_file_adapter_roundtrip_with_wrong_peer(adapter, false);
}

fn run_snap_file_adapter_roundtrip_with_wrong_peer(adapter: &str, wrong_peer: bool) {
    assert!(
        !wrong_peer || adapter == "offline-mesh",
        "only offline-mesh models a live wrong-peer response through this CLI fixture"
    );
    let dir = test_dir();
    let client_dir = dir.join("client");
    let server_dir = dir.join("server");
    let wrong_server_dir = dir.join("wrong-server");
    fs::create_dir_all(&client_dir).expect("create client directory");
    fs::create_dir_all(&server_dir).expect("create server directory");
    if wrong_peer {
        fs::create_dir_all(&wrong_server_dir).expect("create wrong peer directory");
    }
    let client_config = client_dir.join("config.toml");
    let server_config = server_dir.join("config.toml");
    let wrong_server_config = wrong_server_dir.join("config.toml");
    for config in std::iter::once(&client_config)
        .chain(std::iter::once(&server_config))
        .chain(wrong_peer.then_some(&wrong_server_config))
    {
        let init = run(config, &["init", "--new"]);
        assert!(
            init.status.success(),
            "init stderr: {}",
            String::from_utf8_lossy(&init.stderr)
        );
    }

    let peer_socket = TcpListener::bind("127.0.0.1:0").expect("reserve direct fallback port");
    let peer_addr = peer_socket.local_addr().expect("direct fallback address");
    drop(peer_socket);
    let peer_endpoint = format!("127.0.0.1:{}", peer_addr.port());
    let peer_port = peer_addr.port().to_string();
    let client_public = output_key(&client_config, "show-public-key");
    let client_signing = output_key(&client_config, "show-signing-public-key");
    let server_public = output_key(&server_config, "show-public-key");
    let server_signing = output_key(&server_config, "show-signing-public-key");
    assert!(run(
        &client_config,
        &[
            "add-peer",
            "server",
            "127.0.0.1",
            &peer_port,
            &server_public,
            "--sign-pubkey",
            &server_signing,
        ],
    )
    .status
    .success());
    if wrong_peer {
        assert!(run(
            &wrong_server_config,
            &[
                "add-peer",
                "client",
                "127.0.0.1",
                "55559",
                &client_public,
                "--sign-pubkey",
                &client_signing,
            ],
        )
        .status
        .success());
    }
    assert!(run(
        &server_config,
        &[
            "add-peer",
            "client",
            "127.0.0.1",
            "55559",
            &client_public,
            "--sign-pubkey",
            &client_signing,
        ],
    )
    .status
    .success());

    let client_roadmap = if adapter == "offline-mesh" {
        let spool = dir.join("mesh-spool");
        let spool = spool.to_string_lossy().replace('\\', "/");
        format!(
            "\n[roadmap.transport]\nkind = \"offline_mesh\"\nnode_id = \"client-node\"\npeer_id = \"server-node\"\nspool_dir = \"{spool}\"\npoll_interval_ms = 10\nmax_idle_entries = 128\n"
        )
    } else {
        let to_server = dir.join("to-server");
        let to_client = dir.join("to-client");
        fs::create_dir_all(&to_server).expect("create data-mule server inbox");
        fs::create_dir_all(&to_client).expect("create data-mule client inbox");
        let to_server = to_server.to_string_lossy().replace('\\', "/");
        let to_client = to_client.to_string_lossy().replace('\\', "/");
        format!(
            "\n[roadmap.transport]\nkind = \"data_mule\"\ninbox_dir = \"{to_client}\"\noutbox_dir = \"{to_server}\"\npoll_interval_ms = 10\nmax_file_bytes = 32768\nmax_total_bytes = 1048576\nmax_age_ms = 60000\n"
        )
    };
    let server_roadmap = if adapter == "offline-mesh" {
        let spool = dir.join("mesh-spool").to_string_lossy().replace('\\', "/");
        format!(
            "\n[roadmap.transport]\nkind = \"offline_mesh\"\nnode_id = \"server-node\"\npeer_id = \"client-node\"\nspool_dir = \"{spool}\"\npoll_interval_ms = 10\nmax_idle_entries = 128\n"
        )
    } else {
        let to_server = dir.join("to-server").to_string_lossy().replace('\\', "/");
        let to_client = dir.join("to-client").to_string_lossy().replace('\\', "/");
        format!(
            "\n[roadmap.transport]\nkind = \"data_mule\"\ninbox_dir = \"{to_server}\"\noutbox_dir = \"{to_client}\"\npoll_interval_ms = 10\nmax_file_bytes = 32768\nmax_total_bytes = 1048576\nmax_age_ms = 60000\n"
        )
    };
    let mut server_toml = fs::read_to_string(&server_config).expect("read server config");
    server_toml.push_str(&server_roadmap);
    fs::write(&server_config, server_toml).expect("configure file-adapter receiver");
    if wrong_peer {
        let mut wrong_server_toml =
            fs::read_to_string(&wrong_server_config).expect("read wrong peer config");
        wrong_server_toml.push_str(&server_roadmap);
        fs::write(&wrong_server_config, wrong_server_toml)
            .expect("configure wrong-identity file-adapter receiver");
    }

    let profile_path = dir.join(format!("{adapter}.json"));
    fs::write(
        &profile_path,
        serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "profile_name": format!("{adapter}-session"),
            "peer_alias": "server",
            "mode": "direct-only",
            "retry_policy": {
                "rounds": 1,
                "max_total_attempts": if wrong_peer { 2 } else { 1 },
                "max_elapsed_sec": 8.0,
                "jitter_ratio": 0.0
            },
            "direct_endpoints": if wrong_peer {
                serde_json::json!([
                    {
                        "ip": "127.0.0.1",
                        "port": peer_addr.port(),
                        "adapter": adapter,
                        "transport": adapter,
                        "priority": 1,
                        "allowed_fallback": ["direct-tcp"]
                    },
                    {
                        "ip": "127.0.0.1",
                        "port": peer_addr.port(),
                        "adapter": "direct-tcp",
                        "transport": "tcp",
                        "priority": 2
                    }
                ])
            } else {
                serde_json::json!([{
                    "ip": "127.0.0.1",
                    "port": peer_addr.port(),
                    "adapter": adapter,
                    "transport": adapter
                }])
            }
        }))
        .expect("serialize file-adapter SNAP profile"),
    )
    .expect("write file-adapter SNAP profile");
    let profile_config_path = profile_path.to_string_lossy().replace('\\', "/");
    let mut client_toml = fs::read_to_string(&client_config).expect("read client config");
    client_toml.push_str(&client_roadmap);
    client_toml.push_str(&format!(
        "\n[session]\nrole = \"connect\"\npeer = \"{peer_endpoint}\"\nsnap_profile = \"{profile_config_path}\"\ntimeout_secs = 12\nstartup_payload = \"{}\"\n",
        if wrong_peer {
            "must-not-reach-file-fallback"
        } else {
            "snap-file-adapter-payload"
        }
    ));
    fs::write(&client_config, client_toml).expect("configure file-adapter sender");

    let server_config_thread = server_config.clone();
    let peer_endpoint_thread = peer_endpoint.to_owned();
    let adapter_arg = adapter.to_owned();
    let server = if wrong_peer {
        thread::spawn(move || {
            run(
                &server_config_thread,
                &[
                    "recv-once",
                    "--bind",
                    &peer_endpoint_thread,
                    "--timeout-secs",
                    "3",
                    "--transport",
                    "tcp",
                ],
            )
        })
    } else {
        thread::spawn(move || {
            run(
                &server_config_thread,
                &[
                    "recv-once",
                    "--bind",
                    &peer_endpoint_thread,
                    "--timeout-secs",
                    "12",
                    "--transport",
                    &adapter_arg,
                ],
            )
        })
    };
    let wrong_server = wrong_peer.then(|| {
        let wrong_server_config = wrong_server_config.clone();
        let peer_endpoint_thread = peer_endpoint.to_owned();
        let adapter_arg = adapter.to_owned();
        thread::spawn(move || {
            run(
                &wrong_server_config,
                &[
                    "recv-once",
                    "--bind",
                    &peer_endpoint_thread,
                    "--timeout-secs",
                    "4",
                    "--transport",
                    &adapter_arg,
                ],
            )
        })
    });
    thread::sleep(Duration::from_millis(100));

    let client = Command::new(env!("CARGO_BIN_EXE_shph"))
        .arg("--config")
        .arg(&client_config)
        .args(["up", "--no-tun"])
        .env("RUST_LOG", "info")
        .output()
        .expect("run file-adapter SNAP session");
    let receiver = server.join().expect("join file-adapter receiver");
    let wrong_receiver =
        wrong_server.map(|server| server.join().expect("join wrong file receiver"));

    if wrong_peer {
        let client_stdout = normalized_process_output(&client);
        let receiver_stdout = String::from_utf8_lossy(&receiver.stdout);
        assert!(
            !client.status.success(),
            "wrong pinned identity was accepted: {client_stdout}"
        );
        assert!(
            client_stdout.contains("TerminalFailure"),
            "client stdout: {client_stdout}\nclient stderr: {}",
            String::from_utf8_lossy(&client.stderr)
        );
        assert!(
            String::from_utf8_lossy(&client.stderr)
                .contains("peer identity and signing key are not pinned"),
            "expected pinned-identity rejection, got: {}",
            String::from_utf8_lossy(&client.stderr)
        );
        assert!(
            !client_stdout.contains("attempt=2"),
            "wrong-peer authentication must not fall through to the allowed direct candidate: {client_stdout}"
        );
        assert!(
            !receiver_stdout.contains("must-not-reach-file-fallback"),
            "the allowed direct fallback received application data: {receiver_stdout}"
        );
        assert!(wrong_receiver.is_some());
        fs::remove_dir_all(dir).expect("remove test directory");
        return;
    }

    assert!(
        client.status.success(),
        "{adapter} client stdout: {}\nclient stderr: {}\nreceiver stdout: {}\nreceiver stderr: {}",
        String::from_utf8_lossy(&client.stdout),
        String::from_utf8_lossy(&client.stderr),
        String::from_utf8_lossy(&receiver.stdout),
        String::from_utf8_lossy(&receiver.stderr)
    );
    assert!(
        receiver.status.success(),
        "{adapter} receiver stdout: {}\nreceiver stderr: {}",
        String::from_utf8_lossy(&receiver.stdout),
        String::from_utf8_lossy(&receiver.stderr)
    );
    assert!(
        String::from_utf8_lossy(&receiver.stdout).contains("snap-file-adapter-payload"),
        "{}",
        String::from_utf8_lossy(&receiver.stdout)
    );
    fs::remove_dir_all(dir).expect("remove test directory");
}

#[test]
fn snap_python_mesh_and_mule_adapters_keep_shph_peer_authentication() {
    run_snap_python_plugin_adapter_roundtrip("mesh-dtn-local", false);
    run_snap_python_plugin_adapter_roundtrip("mule-usb", false);
}

#[test]
fn snap_python_mesh_and_mule_adapters_reject_wrong_peer_before_fallback() {
    run_snap_python_plugin_adapter_case("mesh-dtn-local", false, true);
    run_snap_python_plugin_adapter_case("mule-usb", false, true);
}

#[test]
fn snap_python_mesh_and_mule_adapters_reconnect_after_setup_failure_and_shut_down() {
    run_snap_python_plugin_adapter_roundtrip("mesh-dtn-local", true);
    run_snap_python_plugin_adapter_roundtrip("mule-usb", true);
}

fn run_snap_python_plugin_adapter_roundtrip(adapter: &str, reconnect: bool) {
    run_snap_python_plugin_adapter_case(adapter, reconnect, false);
}

fn run_snap_python_plugin_adapter_case(adapter: &str, reconnect: bool, wrong_peer: bool) {
    let dir = test_dir();
    let client_dir = dir.join("client");
    let server_dir = dir.join("server");
    let wrong_server_dir = dir.join("wrong-server");
    fs::create_dir_all(&client_dir).expect("create client directory");
    fs::create_dir_all(&server_dir).expect("create server directory");
    if wrong_peer {
        fs::create_dir_all(&wrong_server_dir).expect("create wrong peer directory");
    }
    let client_config = client_dir.join("config.toml");
    let server_config = server_dir.join("config.toml");
    let wrong_server_config = wrong_server_dir.join("config.toml");
    for config in std::iter::once(&client_config)
        .chain(std::iter::once(&server_config))
        .chain(wrong_peer.then_some(&wrong_server_config))
    {
        let init = run(config, &["init", "--new"]);
        assert!(
            init.status.success(),
            "init stderr: {}",
            String::from_utf8_lossy(&init.stderr)
        );
    }

    let peer_socket = TcpListener::bind("127.0.0.1:0").expect("reserve peer port");
    let peer_addr = peer_socket.local_addr().expect("peer address");
    drop(peer_socket);
    let stale_socket = TcpListener::bind("127.0.0.1:0").expect("reserve stale peer port");
    let stale_addr = stale_socket.local_addr().expect("stale peer address");
    drop(stale_socket);
    let proxy_listener = if adapter == "mule-usb" {
        Some(TcpListener::bind("127.0.0.1:0").expect("bind mock mule proxy"))
    } else {
        None
    };
    let proxy_addr = proxy_listener
        .as_ref()
        .map(|listener| listener.local_addr().expect("mule proxy address"));
    let pinned_addr = if adapter == "mesh-dtn-local" {
        stale_addr
    } else {
        peer_addr
    };

    let client_public = output_key(&client_config, "show-public-key");
    let client_signing = output_key(&client_config, "show-signing-public-key");
    let server_public = output_key(&server_config, "show-public-key");
    let server_signing = output_key(&server_config, "show-signing-public-key");
    assert!(run(
        &client_config,
        &[
            "add-peer",
            "server",
            "127.0.0.1",
            &pinned_addr.port().to_string(),
            &server_public,
            "--sign-pubkey",
            &server_signing,
        ],
    )
    .status
    .success());
    assert!(run(
        &server_config,
        &[
            "add-peer",
            "client",
            "127.0.0.1",
            "55555",
            &client_public,
            "--sign-pubkey",
            &client_signing,
        ],
    )
    .status
    .success());
    if wrong_peer {
        assert!(run(
            &wrong_server_config,
            &[
                "add-peer",
                "client",
                "127.0.0.1",
                "55555",
                &client_public,
                "--sign-pubkey",
                &client_signing,
            ],
        )
        .status
        .success());
    }

    let key_file = dir.join("plugin.key");
    fs::write(&key_file, "reference-compatible plugin key placeholder\n")
        .expect("write plugin key placeholder");
    let key_file = key_file.to_string_lossy().replace('\\', "/");
    let service_port = proxy_addr.map_or(1, |address| address.port());
    let profile_path = dir.join(format!("{adapter}.json"));
    let mut profile = serde_json::json!({
        "version": 1,
        "profile_name": format!("{adapter}-loopback"),
        "peer_alias": "server",
        "mode": if wrong_peer || adapter == "mesh-dtn-local" { "auto" } else { "bridges-only" },
        "connect_timeout_sec": 4.0,
        "retry_policy": {
            "rounds": 1,
            "max_total_attempts": if wrong_peer || adapter == "mesh-dtn-local" { 2 } else { 1 },
            "max_elapsed_sec": 6.0,
            "jitter_ratio": 0.0
        },
        "bridges": [{
            "label": "python-compatible-plugin",
            "ip": "127.0.0.1",
            "port": service_port,
            "key_file": key_file,
            "adapter": adapter,
            "transport": "onion-tcp"
        }]
    });
    if wrong_peer {
        profile["direct_endpoints"] = serde_json::json!([{
            "ip": "127.0.0.1",
            "port": stale_addr.port(),
            "adapter": "direct-tcp",
            "transport": "tcp",
            "priority": 2
        }]);
        profile["bridges"][0]["priority"] = serde_json::json!(1);
        profile["bridges"][0]["allowed_fallback"] = serde_json::json!(["direct-tcp"]);
    } else if adapter == "mesh-dtn-local" {
        profile["direct_endpoints"] = serde_json::json!([{
            "ip": "127.0.0.1",
            "port": stale_addr.port(),
            "priority": 1,
            "allowed_fallback": ["mesh-dtn-local"]
        }]);
        profile["bridges"][0]["priority"] = serde_json::json!(2);
    }
    fs::write(
        &profile_path,
        serde_json::to_vec(&profile).expect("serialize plugin SNAP profile"),
    )
    .expect("write plugin SNAP profile");

    let mesh_peers_path = dir.join("mesh-peers.json");
    if adapter == "mesh-dtn-local" {
        fs::write(
            &mesh_peers_path,
            serde_json::to_vec(&serde_json::json!({
                "peers": [{
                    "ip": "127.0.0.1",
                    "port": if reconnect { stale_addr.port() } else { peer_addr.port() }
                }]
            }))
            .expect("serialize mesh peer file"),
        )
        .expect("write mesh peer file");
    }

    let profile_for_config = profile_path.to_string_lossy().replace('\\', "/");
    let session_peer = format!("127.0.0.1:{}", pinned_addr.port());
    let mut client_toml = fs::read_to_string(&client_config).expect("read client config");
    if reconnect {
        client_toml.push_str(&format!(
            "\n[session]\nrole = \"connect\"\npeer = \"{session_peer}\"\nsnap_profile = \"{profile_for_config}\"\ntimeout_secs = 8\n\n[session.reconnect]\nenabled = true\nmax_attempts = 2\ninitial_delay_ms = 8000\nmax_delay_ms = 8000\n"
        ));
    } else {
        client_toml.push_str(&format!(
            "\n[session]\nrole = \"connect\"\npeer = \"{session_peer}\"\nsnap_profile = \"{profile_for_config}\"\ntimeout_secs = 6\nstartup_payload = \"snap-{adapter}-payload\"\n"
        ));
    }
    fs::write(&client_config, client_toml).expect("configure plugin SNAP client");

    let proxy = proxy_listener.map(|listener| {
        let expected_peer = peer_addr;
        thread::spawn(move || {
            if reconnect {
                let (first_client, _) = listener.accept().expect("accept first mule proxy client");
                drop(first_client);
            }
            let (mut proxy_client, _) = listener.accept().expect("accept mule proxy client");
            proxy_client
                .set_read_timeout(Some(Duration::from_secs(6)))
                .expect("set mule proxy read timeout");
            let mut request_line = Vec::new();
            loop {
                let mut byte = [0u8; 1];
                if proxy_client.read(&mut byte).expect("read mule request") == 0 {
                    panic!("mule client closed before ready request");
                }
                if byte[0] == b'\n' {
                    break;
                }
                request_line.push(byte[0]);
                assert!(request_line.len() <= 16 * 1024, "mule hello is bounded");
            }
            let request: Value = serde_json::from_slice(&request_line).expect("parse mule hello");
            assert_eq!(request["v"], 1);
            assert_eq!(request["op"], "connect");
            assert_eq!(request["target_ip"], "127.0.0.1");
            assert_eq!(request["target_port"], expected_peer.port());
            let mut peer = TcpStream::connect(expected_peer).expect("connect pinned SHPH peer");
            proxy_client
                .write_all(b"{\"ok\":true}\n")
                .expect("accept mule proxy request");
            let mut proxy_reader = proxy_client.try_clone().expect("clone mule stream");
            let mut peer_writer = peer.try_clone().expect("clone SHPH stream");
            let outbound = thread::spawn(move || {
                let _ = copy(&mut proxy_reader, &mut peer_writer);
                let _ = peer_writer.shutdown(Shutdown::Write);
            });
            let _ = copy(&mut peer, &mut proxy_client);
            let _ = proxy_client.shutdown(Shutdown::Write);
            outbound.join().expect("join mule outbound copy");
        })
    });

    let endpoint = format!("127.0.0.1:{}", peer_addr.port());
    let receiver_config = if wrong_peer {
        &wrong_server_config
    } else {
        &server_config
    };
    let server = Command::new(env!("CARGO_BIN_EXE_shph"))
        .arg("--config")
        .arg(receiver_config)
        .args([
            "recv-once",
            "--bind",
            &endpoint,
            "--timeout-secs",
            if reconnect { "30" } else { "8" },
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("start SHPH receiver for plugin adapter");
    thread::sleep(Duration::from_millis(150));
    let mesh_update = if reconnect && adapter == "mesh-dtn-local" {
        let mesh_peers_path = mesh_peers_path.clone();
        Some(thread::spawn(move || {
            thread::sleep(Duration::from_secs(3));
            fs::write(
                mesh_peers_path,
                serde_json::to_vec(&serde_json::json!({
                    "peers": [{"ip": "127.0.0.1", "port": peer_addr.port()}]
                }))
                .expect("serialize repaired mesh peer file"),
            )
            .expect("repair mesh peer file before reconnect");
        }))
    } else {
        None
    };
    let mut client_command = Command::new(env!("CARGO_BIN_EXE_shph"));
    client_command
        .arg("--config")
        .arg(&client_config)
        .args(["up", "--no-tun", "--snap-profile"])
        .arg(&profile_path)
        .env("RUST_LOG", "info");
    if adapter == "mesh-dtn-local" {
        client_command.env("SIERRANODE_MESH_DTN_PEERS_FILE", &mesh_peers_path);
    } else {
        let proxy_addr = proxy_addr.expect("mule proxy was bound");
        client_command.env(
            "SIERRANODE_MULE_PROXY_ADDR",
            format!("127.0.0.1:{}", proxy_addr.port()),
        );
    }
    let client = if reconnect {
        client_command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut client = client_command
            .spawn()
            .expect("start reconnecting plugin SNAP session");
        client
            .stdin
            .take()
            .expect("plugin client stdin")
            .write_all(format!("snap-{adapter}-payload\n").as_bytes())
            .expect("write plugin payload");
        client
            .wait_with_output()
            .expect("wait for reconnecting plugin SNAP session")
    } else {
        client_command.output().expect("run plugin SNAP session")
    };
    let receiver = server.wait_with_output().expect("wait for plugin receiver");
    if let Some(mesh_update) = mesh_update {
        mesh_update.join().expect("join mesh peer repair");
    }
    if let Some(proxy) = proxy {
        proxy.join().expect("join mule proxy");
    }

    assert!(
        client.status.success() != wrong_peer,
        "{adapter} client stdout: {}\nclient stderr: {}\nreceiver stdout: {}\nreceiver stderr: {}",
        String::from_utf8_lossy(&client.stdout),
        String::from_utf8_lossy(&client.stderr),
        String::from_utf8_lossy(&receiver.stdout),
        String::from_utf8_lossy(&receiver.stderr)
    );
    if wrong_peer {
        let client_stdout = normalized_process_output(&client);
        assert!(
            client_stdout.contains("TerminalFailure"),
            "{adapter} wrong-peer authentication was not terminal: {client_stdout}"
        );
        assert!(
            !client_stdout.contains("attempt=2"),
            "{adapter} attempted its allowed fallback after wrong-peer authentication: {client_stdout}"
        );
        assert!(
            String::from_utf8_lossy(&client.stderr)
                .contains("peer identity and signing key are not pinned"),
            "expected pinned-identity rejection, got: {}",
            String::from_utf8_lossy(&client.stderr)
        );
        assert!(
            !String::from_utf8_lossy(&receiver.stdout).contains(&format!("snap-{adapter}-payload")),
            "wrong peer received application payload: {}",
            String::from_utf8_lossy(&receiver.stdout)
        );
    } else {
        assert!(
            receiver.status.success(),
            "{adapter} receiver stdout: {}\nreceiver stderr: {}",
            String::from_utf8_lossy(&receiver.stdout),
            String::from_utf8_lossy(&receiver.stderr)
        );
        assert!(
            String::from_utf8_lossy(&receiver.stdout).contains(&format!("snap-{adapter}-payload")),
            "{}",
            String::from_utf8_lossy(&receiver.stdout)
        );
    }
    if reconnect {
        let client_stdout = normalized_process_output(&client);
        assert!(
            client_stdout.contains("Reconnect: attempt 1/2 failed"),
            "{client_stdout}"
        );
        assert!(
            client_stdout.contains("RetryableFailure"),
            "{client_stdout}"
        );
        assert!(
            client_stdout.contains("Transport loop: closed"),
            "{client_stdout}"
        );
    }
    fs::remove_dir_all(dir).expect("remove test directory");
}

#[test]
fn snap_direct_candidates_use_socks5_socks5h_and_tor_underlays() {
    run_snap_underlay_roundtrip("socks5");
    run_snap_underlay_roundtrip("socks5h");
    run_snap_underlay_roundtrip("tor");
}

#[test]
fn snap_socks5_socks5h_and_tor_underlays_reject_wrong_peer_before_fallback() {
    run_snap_underlay_wrong_peer("socks5");
    run_snap_underlay_wrong_peer("socks5h");
    run_snap_underlay_wrong_peer("tor");
}

fn run_snap_underlay_roundtrip(kind: &str) {
    run_snap_underlay_case(kind, false, false);
}

fn run_snap_underlay_wrong_peer(kind: &str) {
    run_snap_underlay_case(kind, true, false);
}

#[test]
fn snap_socks5_socks5h_and_tor_underlays_reconnect_after_setup_failure_and_shut_down() {
    run_snap_underlay_case("socks5", false, true);
    run_snap_underlay_case("socks5h", false, true);
    run_snap_underlay_case("tor", false, true);
}

fn run_snap_underlay_case(kind: &str, wrong_peer: bool, reconnect: bool) {
    let dir = test_dir();
    let client_dir = dir.join("client");
    let server_dir = dir.join("server");
    let wrong_server_dir = dir.join("wrong-server");
    fs::create_dir_all(&client_dir).expect("create client directory");
    fs::create_dir_all(&server_dir).expect("create server directory");
    if wrong_peer {
        fs::create_dir_all(&wrong_server_dir).expect("create wrong peer directory");
    }
    let client_config = client_dir.join("config.toml");
    let server_config = server_dir.join("config.toml");
    let wrong_server_config = wrong_server_dir.join("config.toml");
    for config in std::iter::once(&client_config)
        .chain(std::iter::once(&server_config))
        .chain(wrong_peer.then_some(&wrong_server_config))
    {
        let init = run(config, &["init", "--new"]);
        assert!(
            init.status.success(),
            "init stderr: {}",
            String::from_utf8_lossy(&init.stderr)
        );
    }

    let peer_socket = TcpListener::bind("127.0.0.1:0").expect("reserve peer port");
    let peer_addr = peer_socket.local_addr().expect("peer address");
    drop(peer_socket);
    let wrong_peer_addr = if wrong_peer {
        let socket = TcpListener::bind("127.0.0.1:0").expect("reserve wrong peer port");
        let address = socket.local_addr().expect("wrong peer address");
        drop(socket);
        Some(address)
    } else {
        None
    };
    let proxy_listener = TcpListener::bind("127.0.0.1:0").expect("bind SOCKS proxy");
    let proxy_addr = proxy_listener.local_addr().expect("SOCKS proxy address");
    proxy_listener
        .set_nonblocking(true)
        .expect("set mock SOCKS listener nonblocking");

    let client_public = output_key(&client_config, "show-public-key");
    let client_signing = output_key(&client_config, "show-signing-public-key");
    let server_public = output_key(&server_config, "show-public-key");
    let server_signing = output_key(&server_config, "show-signing-public-key");
    assert!(run(
        &client_config,
        &[
            "add-peer",
            "server",
            "127.0.0.1",
            &peer_addr.port().to_string(),
            &server_public,
            "--sign-pubkey",
            &server_signing,
        ],
    )
    .status
    .success());
    assert!(run(
        &server_config,
        &[
            "add-peer",
            "client",
            "127.0.0.1",
            "55555",
            &client_public,
            "--sign-pubkey",
            &client_signing,
        ],
    )
    .status
    .success());
    if wrong_peer {
        assert!(run(
            &wrong_server_config,
            &[
                "add-peer",
                "client",
                "127.0.0.1",
                "55555",
                &client_public,
                "--sign-pubkey",
                &client_signing,
            ],
        )
        .status
        .success());
    }

    let endpoint = format!("127.0.0.1:{}", peer_addr.port());
    let profile_path = dir.join(format!("{kind}.json"));
    fs::write(
        &profile_path,
        serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "profile_name": format!("{kind}-snap-underlay"),
            "peer_alias": "server",
            "mode": "direct-only",
            "retry_policy": {
                "rounds": 1,
                "max_total_attempts": if wrong_peer { 2 } else { 1 },
                "max_elapsed_sec": 6.0,
                "jitter_ratio": 0.0
            },
            "direct_endpoints": if wrong_peer {
                serde_json::json!([
                    {
                        "ip": "127.0.0.1",
                        "port": wrong_peer_addr.expect("wrong peer address").port(),
                        "priority": 1,
                        "adapter": "direct-tcp",
                        "transport": "tcp",
                        "allowed_fallback": ["direct-tcp"]
                    },
                    {
                        "ip": "127.0.0.1",
                        "port": peer_addr.port(),
                        "priority": 2,
                        "adapter": "direct-tcp",
                        "transport": "tcp"
                    }
                ])
            } else {
                serde_json::json!([{
                    "ip": "127.0.0.1",
                    "port": peer_addr.port(),
                    "adapter": "direct-tcp",
                    "transport": "tcp"
                }])
            }
        }))
        .expect("serialize underlay SNAP profile"),
    )
    .expect("write underlay SNAP profile");
    let profile_for_config = profile_path.to_string_lossy().replace('\\', "/");
    let mut client_toml = fs::read_to_string(&client_config).expect("read client config");
    if reconnect {
        client_toml.push_str(&format!(
            "\n[session]\nrole = \"connect\"\npeer = \"{endpoint}\"\nsnap_profile = \"{profile_for_config}\"\ntimeout_secs = 6\n\n[session.reconnect]\nenabled = true\nmax_attempts = 2\ninitial_delay_ms = 1200\nmax_delay_ms = 1200\n"
        ));
    } else {
        client_toml.push_str(&format!(
            "\n[session]\nrole = \"connect\"\npeer = \"{endpoint}\"\nsnap_profile = \"{profile_for_config}\"\ntimeout_secs = 6\nstartup_payload = \"snap-{kind}-underlay-payload\"\n"
        ));
    }
    fs::write(&client_config, client_toml).expect("configure underlay SNAP client");

    let expected_peer = wrong_peer_addr.unwrap_or(peer_addr);
    let tor_mode = kind == "tor";
    let proxy = thread::spawn(move || {
        if reconnect {
            let deadline = Instant::now() + Duration::from_secs(8);
            let (first_client, _) = loop {
                match proxy_listener.accept() {
                    Ok(pair) => break pair,
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("accept first mock SOCKS client: {error}"),
                }
            };
            drop(first_client);
        }
        let deadline = Instant::now() + Duration::from_secs(8);
        let (mut proxy_client, _) = loop {
            match proxy_listener.accept() {
                Ok(pair) => break pair,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("accept mock SOCKS client: {error}"),
            }
        };
        proxy_client
            .set_nonblocking(false)
            .expect("set accepted SOCKS stream blocking");
        proxy_client
            .set_read_timeout(Some(Duration::from_secs(6)))
            .expect("set mock SOCKS read timeout");
        let mut greeting = [0u8; 3];
        proxy_client
            .read_exact(&mut greeting)
            .expect("read SOCKS greeting");
        if tor_mode {
            assert_eq!(greeting, [5, 1, 2]);
            proxy_client
                .write_all(&[5, 2])
                .expect("select Tor username/password method");
            let mut auth_header = [0u8; 2];
            proxy_client
                .read_exact(&mut auth_header)
                .expect("read Tor auth header");
            assert_eq!(auth_header, [1, 16]);
            let mut username = vec![0u8; auth_header[1] as usize];
            proxy_client
                .read_exact(&mut username)
                .expect("read Tor username");
            let mut password_len = [0u8; 1];
            proxy_client
                .read_exact(&mut password_len)
                .expect("read Tor password length");
            assert_eq!(password_len[0], 16);
            let mut password = vec![0u8; password_len[0] as usize];
            proxy_client
                .read_exact(&mut password)
                .expect("read Tor password");
            proxy_client
                .write_all(&[1, 0])
                .expect("accept Tor SOCKS auth");
        } else {
            assert_eq!(greeting, [5, 1, 0]);
            proxy_client
                .write_all(&[5, 0])
                .expect("select SOCKS5 no-auth method");
        }

        let mut request = [0u8; 4];
        proxy_client
            .read_exact(&mut request)
            .expect("read SOCKS CONNECT request");
        assert_eq!(request, [5, 1, 0, 1]);
        let mut target_ip = [0u8; 4];
        proxy_client
            .read_exact(&mut target_ip)
            .expect("read SOCKS target address");
        assert_eq!(
            target_ip,
            expected_peer
                .ip()
                .to_string()
                .parse::<std::net::Ipv4Addr>()
                .unwrap()
                .octets()
        );
        let mut target_port = [0u8; 2];
        proxy_client
            .read_exact(&mut target_port)
            .expect("read SOCKS target port");
        assert_eq!(u16::from_be_bytes(target_port), expected_peer.port());

        let mut peer = TcpStream::connect(expected_peer).expect("connect pinned SHPH peer");
        proxy_client
            .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
            .expect("write SOCKS CONNECT success");
        let mut proxy_reader = proxy_client.try_clone().expect("clone SOCKS stream");
        let mut peer_writer = peer.try_clone().expect("clone SHPH stream");
        let outbound = thread::spawn(move || {
            let _ = copy(&mut proxy_reader, &mut peer_writer);
            let _ = peer_writer.shutdown(Shutdown::Write);
        });
        let _ = copy(&mut peer, &mut proxy_client);
        let _ = proxy_client.shutdown(Shutdown::Write);
        outbound.join().expect("join SOCKS outbound copy");
    });

    let server_config_thread = server_config.clone();
    let endpoint_thread = endpoint.clone();
    let server = thread::spawn(move || {
        run(
            &server_config_thread,
            &[
                "recv-once",
                "--bind",
                &endpoint_thread,
                "--timeout-secs",
                if wrong_peer { "3" } else { "10" },
            ],
        )
    });
    let wrong_server = wrong_peer_addr.map(|wrong_peer_addr| {
        let config = wrong_server_config.clone();
        let endpoint = format!("127.0.0.1:{}", wrong_peer_addr.port());
        thread::spawn(move || {
            run(
                &config,
                &["recv-once", "--bind", &endpoint, "--timeout-secs", "3"],
            )
        })
    });
    thread::sleep(Duration::from_millis(150));
    let underlay = format!("{kind}://127.0.0.1:{}", proxy_addr.port());
    let client = if reconnect {
        let mut client = Command::new(env!("CARGO_BIN_EXE_shph"))
            .arg("--config")
            .arg(&client_config)
            .args(["up", "--no-tun", "--snap-profile"])
            .arg(&profile_path)
            .args(["--underlay", &underlay])
            .env("RUST_LOG", "info")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start reconnecting SNAP underlay session");
        client
            .stdin
            .take()
            .expect("underlay client stdin")
            .write_all(format!("snap-{kind}-underlay-payload\n").as_bytes())
            .expect("write underlay payload");
        client
            .wait_with_output()
            .expect("wait for reconnecting SNAP underlay session")
    } else {
        Command::new(env!("CARGO_BIN_EXE_shph"))
            .arg("--config")
            .arg(&client_config)
            .args(["up", "--no-tun", "--snap-profile"])
            .arg(&profile_path)
            .args(["--underlay", &underlay])
            .env("RUST_LOG", "info")
            .output()
            .expect("run SNAP underlay session")
    };
    let receiver = server.join().expect("join SHPH receiver");
    let wrong_receiver = wrong_server.map(|server| server.join().expect("join wrong peer"));
    proxy.join().expect("join mock SOCKS proxy");

    if wrong_peer {
        let client_stdout = normalized_process_output(&client);
        assert!(
            !client.status.success(),
            "wrong pinned identity was accepted through {kind}: {client_stdout}"
        );
        assert!(
            client_stdout.contains("TerminalFailure"),
            "client stdout: {client_stdout}\nclient stderr: {}",
            String::from_utf8_lossy(&client.stderr)
        );
        assert!(
            String::from_utf8_lossy(&client.stderr)
                .contains("peer identity and signing key are not pinned"),
            "expected pinned-identity rejection, got: {}",
            String::from_utf8_lossy(&client.stderr)
        );
        assert!(
            !client_stdout.contains("attempt=2"),
            "wrong-peer authentication must not fall through to the allowed candidate: {client_stdout}"
        );
        assert!(
            !String::from_utf8_lossy(&receiver.stdout)
                .contains(&format!("snap-{kind}-underlay-payload")),
            "correct-peer fallback received application data: {}",
            String::from_utf8_lossy(&receiver.stdout)
        );
        assert!(wrong_receiver.is_some());
        fs::remove_dir_all(dir).expect("remove test directory");
        return;
    }

    assert!(
        client.status.success(),
        "{kind} client stdout: {}\nclient stderr: {}\nreceiver stdout: {}\nreceiver stderr: {}",
        String::from_utf8_lossy(&client.stdout),
        String::from_utf8_lossy(&client.stderr),
        String::from_utf8_lossy(&receiver.stdout),
        String::from_utf8_lossy(&receiver.stderr)
    );
    assert!(
        receiver.status.success(),
        "{kind} receiver stdout: {}\nreceiver stderr: {}",
        String::from_utf8_lossy(&receiver.stdout),
        String::from_utf8_lossy(&receiver.stderr)
    );
    assert!(
        String::from_utf8_lossy(&receiver.stdout)
            .contains(&format!("snap-{kind}-underlay-payload")),
        "{}",
        String::from_utf8_lossy(&receiver.stdout)
    );
    if reconnect {
        let client_stdout = normalized_process_output(&client);
        assert!(
            client_stdout.contains("Reconnect: attempt 1/2 failed"),
            "{client_stdout}"
        );
        assert!(
            client_stdout.contains("RetryableFailure"),
            "{client_stdout}"
        );
        assert!(
            client_stdout.contains("Transport loop: closed"),
            "{client_stdout}"
        );
    }
    fs::remove_dir_all(dir).expect("remove test directory");
}

#[test]
fn snap_wrong_peer_is_terminal_before_candidate_fallback() {
    let dir = test_dir();
    let client_dir = dir.join("client");
    let pinned_server_dir = dir.join("pinned-server");
    let wrong_server_dir = dir.join("wrong-server");
    for path in [&client_dir, &pinned_server_dir, &wrong_server_dir] {
        fs::create_dir_all(path).expect("create peer test directory");
    }
    let client_config = client_dir.join("config.toml");
    let pinned_server_config = pinned_server_dir.join("config.toml");
    let wrong_server_config = wrong_server_dir.join("config.toml");
    for config in [&client_config, &pinned_server_config, &wrong_server_config] {
        let init = run(config, &["init", "--new"]);
        assert!(
            init.status.success(),
            "init stderr: {}",
            String::from_utf8_lossy(&init.stderr)
        );
    }

    let pinned_socket = TcpListener::bind("127.0.0.1:0").expect("reserve pinned peer port");
    let pinned_addr = pinned_socket.local_addr().expect("pinned peer address");
    drop(pinned_socket);
    let wrong_socket = TcpListener::bind("127.0.0.1:0").expect("reserve wrong peer port");
    let wrong_addr = wrong_socket.local_addr().expect("wrong peer address");
    drop(wrong_socket);

    let client_public = output_key(&client_config, "show-public-key");
    let client_signing = output_key(&client_config, "show-signing-public-key");
    assert!(run(
        &client_config,
        &[
            "add-peer",
            "server",
            "127.0.0.1",
            &pinned_addr.port().to_string(),
            &output_key(&pinned_server_config, "show-public-key"),
            "--sign-pubkey",
            &output_key(&pinned_server_config, "show-signing-public-key"),
        ],
    )
    .status
    .success());
    assert!(run(
        &wrong_server_config,
        &[
            "add-peer",
            "client",
            "127.0.0.1",
            "55555",
            &client_public,
            "--sign-pubkey",
            &client_signing,
        ],
    )
    .status
    .success());

    let profile_path = dir.join("wrong-peer.json");
    fs::write(
        &profile_path,
        serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "profile_name": "wrong-peer-terminal",
            "peer_alias": "server",
            "mode": "direct-only",
            "retry_policy": {
                "rounds": 1,
                "max_total_attempts": 2,
                "max_elapsed_sec": 6.0,
                "jitter_ratio": 0.0
            },
            "direct_endpoints": [
                {"ip": "127.0.0.1", "port": wrong_addr.port(), "priority": 1},
                {"ip": "127.0.0.1", "port": pinned_addr.port(), "priority": 2}
            ]
        }))
        .expect("serialize wrong-peer profile"),
    )
    .expect("write wrong-peer profile");
    let endpoint = format!("127.0.0.1:{}", pinned_addr.port());
    let profile_for_config = profile_path.to_string_lossy().replace('\\', "/");
    let mut client_toml = fs::read_to_string(&client_config).expect("read client config");
    client_toml.push_str(&format!(
        "\n[session]\nrole = \"connect\"\npeer = \"{endpoint}\"\nsnap_profile = \"{profile_for_config}\"\ntimeout_secs = 6\nstartup_payload = \"must-not-reach-wrong-peer\"\n"
    ));
    fs::write(&client_config, client_toml).expect("configure wrong-peer client");

    let wrong_endpoint = format!("127.0.0.1:{}", wrong_addr.port());
    let wrong_server = Command::new(env!("CARGO_BIN_EXE_shph"))
        .arg("--config")
        .arg(&wrong_server_config)
        .args([
            "recv-once",
            "--bind",
            &wrong_endpoint,
            "--timeout-secs",
            "3",
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("start wrong-identity peer");
    thread::sleep(Duration::from_millis(150));
    let client = Command::new(env!("CARGO_BIN_EXE_shph"))
        .arg("--config")
        .arg(&client_config)
        .args(["up", "--no-tun", "--snap-profile"])
        .arg(&profile_path)
        .env("RUST_LOG", "info")
        .output()
        .expect("run wrong-peer SNAP session");
    let wrong_receiver = wrong_server
        .wait_with_output()
        .expect("wait for wrong-identity peer");

    let client_stdout = normalized_process_output(&client);
    assert!(
        !client.status.success(),
        "wrong pinned identity was accepted"
    );
    assert!(
        client_stdout.contains("TerminalFailure"),
        "client stdout: {client_stdout}"
    );
    assert!(
        String::from_utf8_lossy(&client.stderr)
            .contains("peer identity and signing key are not pinned"),
        "expected pinned-identity rejection, got: {}",
        String::from_utf8_lossy(&client.stderr)
    );
    assert!(
        !client_stdout.contains("RetryableFailure") && !client_stdout.contains("attempt=2"),
        "wrong-peer authentication must not fall through: {client_stdout}"
    );
    let _ = wrong_receiver;
    fs::remove_dir_all(dir).expect("remove test directory");
}

#[test]
fn snap_forbidden_adapter_fallback_is_skipped() {
    let dir = test_dir();
    let client_dir = dir.join("client");
    let server_dir = dir.join("server");
    fs::create_dir_all(&client_dir).expect("create client directory");
    fs::create_dir_all(&server_dir).expect("create server directory");
    let client_config = client_dir.join("config.toml");
    let server_config = server_dir.join("config.toml");
    for config in [&client_config, &server_config] {
        let init = run(config, &["init", "--new"]);
        assert!(
            init.status.success(),
            "init stderr: {}",
            String::from_utf8_lossy(&init.stderr)
        );
    }
    let pinned_socket = TcpListener::bind("127.0.0.1:0").expect("reserve pinned endpoint");
    let pinned_addr = pinned_socket.local_addr().expect("pinned endpoint");
    drop(pinned_socket);
    let failed_socket = TcpListener::bind("127.0.0.1:0").expect("reserve failed endpoint");
    let failed_addr = failed_socket.local_addr().expect("failed endpoint");
    drop(failed_socket);

    assert!(run(
        &client_config,
        &[
            "add-peer",
            "server",
            "127.0.0.1",
            &pinned_addr.port().to_string(),
            &output_key(&server_config, "show-public-key"),
            "--sign-pubkey",
            &output_key(&server_config, "show-signing-public-key"),
        ],
    )
    .status
    .success());

    let key_file = dir.join("plugin.key");
    fs::write(&key_file, "placeholder\n").expect("write plugin key placeholder");
    let key_file = key_file.to_string_lossy().replace('\\', "/");
    let profile_path = dir.join("fallback-policy.json");
    fs::write(
        &profile_path,
        serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "profile_name": "fallback-policy",
            "peer_alias": "server",
            "mode": "auto",
            "connect_timeout_sec": 2.0,
            "retry_policy": {
                "rounds": 1,
                "max_total_attempts": 3,
                "max_elapsed_sec": 4.0,
                "jitter_ratio": 0.0
            },
            "direct_endpoints": [{
                "ip": "127.0.0.1",
                "port": failed_addr.port(),
                "priority": 1,
                "allowed_fallback": ["mule-usb"]
            }],
            "bridges": [
                {
                    "label": "must-not-be-used",
                    "ip": "127.0.0.1",
                    "port": 1,
                    "key_file": key_file,
                    "adapter": "mesh-dtn-local",
                    "transport": "onion-tcp",
                    "priority": 2
                },
                {
                    "label": "allowed-but-unconfigured",
                    "ip": "127.0.0.1",
                    "port": 2,
                    "key_file": key_file,
                    "adapter": "mule-usb",
                    "transport": "onion-tcp",
                    "priority": 3
                }
            ]
        }))
        .expect("serialize fallback profile"),
    )
    .expect("write fallback profile");
    let endpoint = format!("127.0.0.1:{}", pinned_addr.port());
    let profile_for_config = profile_path.to_string_lossy().replace('\\', "/");
    let mut client_toml = fs::read_to_string(&client_config).expect("read client config");
    client_toml.push_str(&format!(
        "\n[session]\nrole = \"connect\"\npeer = \"{endpoint}\"\nsnap_profile = \"{profile_for_config}\"\ntimeout_secs = 4\n"
    ));
    fs::write(&client_config, client_toml).expect("configure fallback-policy client");

    let client = Command::new(env!("CARGO_BIN_EXE_shph"))
        .arg("--config")
        .arg(&client_config)
        .args(["up", "--no-tun", "--snap-profile"])
        .arg(&profile_path)
        .env("RUST_LOG", "info")
        .env_remove("SIERRANODE_MULE_PROXY_ADDR")
        .output()
        .expect("run fallback-policy SNAP session");
    let client_stdout = normalized_process_output(&client);
    assert!(
        !client.status.success(),
        "profile without a mule proxy connected"
    );
    let mesh_audit = client_stdout
        .lines()
        .find(|line| line.contains("adapter=mesh-dtn-local"))
        .expect("mesh candidate should have a fallback audit event");
    assert!(
        mesh_audit.contains("FallbackDenied"),
        "forbidden mesh fallback was attempted: {mesh_audit}"
    );
    assert!(
        String::from_utf8_lossy(&client.stderr).contains("SIERRANODE_MULE_PROXY_ADDR"),
        "client stderr: {}",
        String::from_utf8_lossy(&client.stderr)
    );
    fs::remove_dir_all(dir).expect("remove test directory");
}

#[test]
fn snap_external_bridge_setup_failures_use_allowed_direct_fallback() {
    for adapter in [
        "bridge-onion-tcp",
        "bridge-tls",
        "edge-relay",
        "bridge-ws",
        "shroud-tcp",
    ] {
        run_snap_bridge_setup_failure_fallback(adapter);
    }
}

fn run_snap_bridge_setup_failure_fallback(adapter: &str) {
    let dir = test_dir();
    let client_dir = dir.join("client");
    let server_dir = dir.join("server");
    fs::create_dir_all(&client_dir).expect("create client directory");
    fs::create_dir_all(&server_dir).expect("create server directory");
    let client_config = client_dir.join("config.toml");
    let server_config = server_dir.join("config.toml");
    for config in [&client_config, &server_config] {
        let init = run(config, &["init", "--new"]);
        assert!(
            init.status.success(),
            "init stderr: {}",
            String::from_utf8_lossy(&init.stderr)
        );
    }

    let fallback_socket = TcpListener::bind("127.0.0.1:0").expect("reserve fallback port");
    let fallback_addr = fallback_socket.local_addr().expect("fallback address");
    drop(fallback_socket);
    let failed_socket = TcpListener::bind("127.0.0.1:0").expect("reserve failed bridge port");
    let failed_addr = failed_socket.local_addr().expect("failed bridge address");
    drop(failed_socket);

    let client_public = output_key(&client_config, "show-public-key");
    let client_signing = output_key(&client_config, "show-signing-public-key");
    let server_public = output_key(&server_config, "show-public-key");
    let server_signing = output_key(&server_config, "show-signing-public-key");
    assert!(run(
        &client_config,
        &[
            "add-peer",
            "server",
            "127.0.0.1",
            &fallback_addr.port().to_string(),
            &server_public,
            "--sign-pubkey",
            &server_signing,
        ],
    )
    .status
    .success());
    assert!(run(
        &server_config,
        &[
            "add-peer",
            "client",
            "127.0.0.1",
            "55555",
            &client_public,
            "--sign-pubkey",
            &client_signing,
        ],
    )
    .status
    .success());

    fs::write(
        dir.join("bridge.key"),
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n",
    )
    .expect("write bridge key");
    let mut bridge = serde_json::json!({
        "label": format!("{adapter}-failed-setup"),
        "ip": "127.0.0.1",
        "port": failed_addr.port(),
        "key_file": "bridge.key",
        "adapter": adapter,
        "transport": "onion-tcp",
        "priority": 1,
        "timeout_sec": 1.0,
        "allowed_fallback": ["direct-tcp"],
        "operator_service_contract": {
            "owner": "SHPH loopback test",
            "service_id": format!("{adapter}-closed-listener"),
            "authorization_ref": format!("test-fixture:{adapter}-closed-listener")
        }
    });
    let mut edge_profiles = serde_json::json!({});
    if adapter != "bridge-onion-tcp" {
        bridge["tls_enabled"] = serde_json::json!(true);
        bridge["sni"] = serde_json::json!("localhost");
        bridge["edge_label"] = serde_json::json!("edge");
        edge_profiles["edge"] = serde_json::json!({
            "host": "127.0.0.1",
            "port": failed_addr.port(),
            "tls_required": true
        });
    }
    if adapter == "bridge-ws" {
        bridge["ws_path"] = serde_json::json!("/snap-v1");
    }
    if adapter == "shroud-tcp" {
        bridge["shroud_profile"] = serde_json::json!("balanced");
    }

    let profile_path = dir.join(format!("{adapter}.json"));
    fs::write(
        &profile_path,
        serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "profile_name": format!("{adapter}-setup-fallback"),
            "peer_alias": "server",
            "mode": "auto",
            "connect_timeout_sec": 2.0,
            "retry_policy": {
                "rounds": 1,
                "max_total_attempts": 2,
                "max_elapsed_sec": 6.0,
                "jitter_ratio": 0.0
            },
            "direct_endpoints": [{
                "ip": "127.0.0.1",
                "port": fallback_addr.port(),
                "priority": 2
            }],
            "bridges": [bridge],
            "edge_profiles": edge_profiles
        }))
        .expect("serialize bridge fallback profile"),
    )
    .expect("write bridge fallback profile");

    let endpoint = format!("127.0.0.1:{}", fallback_addr.port());
    let profile_config_path = profile_path.to_string_lossy().replace('\\', "/");
    let mut client_toml = fs::read_to_string(&client_config).expect("read client config");
    let payload = format!("snap-{adapter}-fallback-payload");
    client_toml.push_str(&format!(
        "\n[session]\nrole = \"connect\"\npeer = \"{endpoint}\"\nsnap_profile = \"{profile_config_path}\"\ntimeout_secs = 8\nstartup_payload = \"{payload}\"\n"
    ));
    fs::write(&client_config, client_toml).expect("configure SNAP client");

    let server_config_thread = server_config.clone();
    let endpoint_thread = endpoint.clone();
    let receiver = thread::spawn(move || {
        run(
            &server_config_thread,
            &[
                "recv-once",
                "--bind",
                &endpoint_thread,
                "--timeout-secs",
                "10",
            ],
        )
    });
    thread::sleep(Duration::from_millis(150));
    let client = Command::new(env!("CARGO_BIN_EXE_shph"))
        .arg("--config")
        .arg(&client_config)
        .args(["up", "--no-tun", "--snap-profile"])
        .arg(&profile_path)
        .env("RUST_LOG", "info")
        .output()
        .expect("run bridge setup fallback session");
    let receiver = receiver.join().expect("join SHPH receiver");

    let client_stdout = normalized_process_output(&client);
    let receiver_stdout = String::from_utf8_lossy(&receiver.stdout);
    assert!(
        client.status.success(),
        "{adapter} client stdout: {client_stdout}\nclient stderr: {}\nreceiver stdout: {receiver_stdout}\nreceiver stderr: {}",
        String::from_utf8_lossy(&client.stderr),
        String::from_utf8_lossy(&receiver.stderr)
    );
    assert!(
        client_stdout.contains("RetryableFailure") && client_stdout.contains("Connected"),
        "{adapter} did not retry the failed setup before connecting: {client_stdout}"
    );
    assert!(
        receiver.status.success(),
        "receiver stdout: {receiver_stdout}\nreceiver stderr: {}",
        String::from_utf8_lossy(&receiver.stderr)
    );
    assert!(
        receiver_stdout.contains(&payload),
        "{adapter} fallback payload missing: {receiver_stdout}"
    );
    fs::remove_dir_all(dir).expect("remove test directory");
}

#[test]
fn snap_quic_setup_failures_use_allowed_direct_fallback() {
    for adapter in ["quic", "quic-standard"] {
        run_snap_quic_setup_failure_fallback(adapter);
    }
}

#[test]
fn snap_session_reconnects_after_initial_adapter_failure_and_shuts_down() {
    let dir = test_dir();
    let client_dir = dir.join("client");
    let server_dir = dir.join("server");
    fs::create_dir_all(&client_dir).expect("create client directory");
    fs::create_dir_all(&server_dir).expect("create server directory");
    let client_config = client_dir.join("config.toml");
    let server_config = server_dir.join("config.toml");
    for config in [&client_config, &server_config] {
        let init = run(config, &["init", "--new"]);
        assert!(
            init.status.success(),
            "init stderr: {}",
            String::from_utf8_lossy(&init.stderr)
        );
    }

    let peer_socket = TcpListener::bind("127.0.0.1:0").expect("reserve reconnect peer port");
    let peer_addr = peer_socket.local_addr().expect("reconnect peer address");
    drop(peer_socket);
    let peer_endpoint = format!("127.0.0.1:{}", peer_addr.port());
    let peer_port = peer_addr.port().to_string();
    let client_public = output_key(&client_config, "show-public-key");
    let client_signing = output_key(&client_config, "show-signing-public-key");
    let server_public = output_key(&server_config, "show-public-key");
    let server_signing = output_key(&server_config, "show-signing-public-key");
    assert!(run(
        &client_config,
        &[
            "add-peer",
            "server",
            "127.0.0.1",
            &peer_port,
            &server_public,
            "--sign-pubkey",
            &server_signing,
        ],
    )
    .status
    .success());
    assert!(run(
        &server_config,
        &[
            "add-peer",
            "client",
            "127.0.0.1",
            "55559",
            &client_public,
            "--sign-pubkey",
            &client_signing,
        ],
    )
    .status
    .success());

    let profile_path = dir.join("reconnect.json");
    fs::write(
        &profile_path,
        serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "profile_name": "reconnect-direct",
            "peer_alias": "server",
            "mode": "direct-only",
            "connect_timeout_sec": 2.0,
            "retry_policy": {
                "rounds": 1,
                "max_total_attempts": 1,
                "max_elapsed_sec": 4.0,
                "jitter_ratio": 0.0
            },
            "direct_endpoints": [{
                "ip": "127.0.0.1",
                "port": peer_addr.port(),
                "adapter": "direct-tcp",
                "transport": "tcp"
            }]
        }))
        .expect("serialize reconnect SNAP profile"),
    )
    .expect("write reconnect SNAP profile");
    let profile_for_config = profile_path.to_string_lossy().replace('\\', "/");
    let mut client_toml = fs::read_to_string(&client_config).expect("read client config");
    client_toml.push_str(&format!(
        "\n[session]\nrole = \"connect\"\npeer = \"{peer_endpoint}\"\nsnap_profile = \"{profile_for_config}\"\ntimeout_secs = 8\n\n[session.reconnect]\nenabled = true\nmax_attempts = 2\ninitial_delay_ms = 6000\nmax_delay_ms = 6000\n"
    ));
    fs::write(&client_config, client_toml).expect("configure reconnecting SNAP client");

    let server_config_thread = server_config.clone();
    let peer_endpoint_thread = peer_endpoint.clone();
    let server = thread::spawn(move || {
        thread::sleep(Duration::from_secs(3));
        run(
            &server_config_thread,
            &[
                "recv-once",
                "--bind",
                &peer_endpoint_thread,
                "--timeout-secs",
                "8",
                "--transport",
                "tcp",
            ],
        )
    });

    let mut client = Command::new(env!("CARGO_BIN_EXE_shph"))
        .arg("--config")
        .arg(&client_config)
        .args(["up", "--no-tun"])
        .env("RUST_LOG", "info")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run reconnecting SNAP session");
    client
        .stdin
        .take()
        .expect("client stdin pipe")
        .write_all(b"snap-reconnect-payload\n")
        .expect("write reconnect payload");
    let client = client
        .wait_with_output()
        .expect("collect reconnecting SNAP session output");
    let receiver = server.join().expect("join reconnect receiver");
    let client_stdout = normalized_process_output(&client);
    let receiver_stdout = String::from_utf8_lossy(&receiver.stdout);
    assert!(
        client.status.success(),
        "client stdout: {client_stdout}\nclient stderr: {}",
        String::from_utf8_lossy(&client.stderr)
    );
    assert!(
        client_stdout.contains("Reconnect: attempt 1/2 failed")
            && client_stdout.contains("RetryableFailure")
            && client_stdout.contains("Connected")
            && client_stdout.contains("connect-loop")
            && client_stdout.contains("Transport loop: closed"),
        "SNAP session did not reconnect and shut down cleanly: {client_stdout}"
    );
    assert!(
        receiver_stdout.contains("SHPH handshake recv-once ok")
            && receiver_stdout.contains("Payload: snap-reconnect-payload"),
        "retry did not establish the paired authenticated server session: {receiver_stdout}\n{}",
        String::from_utf8_lossy(&receiver.stderr)
    );
    fs::remove_dir_all(dir).expect("remove test directory");
}

fn run_snap_quic_setup_failure_fallback(adapter: &str) {
    let dir = test_dir();
    let client_dir = dir.join("client");
    let server_dir = dir.join("server");
    fs::create_dir_all(&client_dir).expect("create client directory");
    fs::create_dir_all(&server_dir).expect("create server directory");
    let client_config = client_dir.join("config.toml");
    let server_config = server_dir.join("config.toml");
    for config in [&client_config, &server_config] {
        let init = run(config, &["init", "--new"]);
        assert!(
            init.status.success(),
            "init stderr: {}",
            String::from_utf8_lossy(&init.stderr)
        );
    }

    let fallback_socket = TcpListener::bind("127.0.0.1:0").expect("reserve fallback port");
    let fallback_addr = fallback_socket.local_addr().expect("fallback address");
    drop(fallback_socket);
    let failed_socket = UdpSocket::bind("127.0.0.1:0").expect("reserve failed QUIC port");
    let failed_addr = failed_socket.local_addr().expect("failed QUIC address");
    drop(failed_socket);

    let client_public = output_key(&client_config, "show-public-key");
    let client_signing = output_key(&client_config, "show-signing-public-key");
    let server_public = output_key(&server_config, "show-public-key");
    let server_signing = output_key(&server_config, "show-signing-public-key");
    assert!(run(
        &client_config,
        &[
            "add-peer",
            "server",
            "127.0.0.1",
            &fallback_addr.port().to_string(),
            &server_public,
            "--sign-pubkey",
            &server_signing,
        ],
    )
    .status
    .success());
    assert!(run(
        &server_config,
        &[
            "add-peer",
            "client",
            "127.0.0.1",
            "55555",
            &client_public,
            "--sign-pubkey",
            &client_signing,
        ],
    )
    .status
    .success());

    let certificate_path = if adapter == "quic-standard" {
        let material = shph_transport::standards_quic::generate_server_material()
            .expect("generate local QUIC trust certificate");
        let path = dir.join("quic-trust.der");
        fs::write(&path, material.certificate_der()).expect("write QUIC trust certificate");
        Some(path)
    } else {
        None
    };
    let profile_path = dir.join(format!("{adapter}.json"));
    fs::write(
        &profile_path,
        serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "profile_name": format!("{adapter}-setup-fallback"),
            "peer_alias": "server",
            "mode": "direct-only",
            "connect_timeout_sec": 1.0,
            "retry_policy": {
                "rounds": 1,
                "max_total_attempts": 2,
                "max_elapsed_sec": 8.0,
                "jitter_ratio": 0.0
            },
            "direct_endpoints": [
                {
                    "ip": "127.0.0.1",
                    "port": failed_addr.port(),
                    "adapter": adapter,
                    "transport": adapter,
                    "priority": 1,
                    "timeout_sec": 1.0,
                    "allowed_fallback": ["direct-tcp"]
                },
                {
                    "ip": "127.0.0.1",
                    "port": fallback_addr.port(),
                    "adapter": "direct-tcp",
                    "transport": "tcp",
                    "priority": 2
                }
            ]
        }))
        .expect("serialize QUIC fallback profile"),
    )
    .expect("write QUIC fallback profile");

    let endpoint = format!("127.0.0.1:{}", fallback_addr.port());
    let profile_config_path = profile_path.to_string_lossy().replace('\\', "/");
    let mut client_toml = fs::read_to_string(&client_config).expect("read client config");
    let payload = format!("snap-{adapter}-fallback-payload");
    client_toml.push_str(&format!(
        "\n[session]\nrole = \"connect\"\npeer = \"{endpoint}\"\nsnap_profile = \"{profile_config_path}\"\ntimeout_secs = 8\nstartup_payload = \"{payload}\"\n"
    ));
    if let Some(certificate_path) = &certificate_path {
        let path = certificate_path.to_string_lossy().replace('\\', "/");
        client_toml.push_str(&format!("quic_cert = \"{path}\"\n"));
    }
    fs::write(&client_config, client_toml).expect("configure SNAP client");

    let server_config_thread = server_config.clone();
    let endpoint_thread = endpoint.clone();
    let receiver = thread::spawn(move || {
        run(
            &server_config_thread,
            &[
                "recv-once",
                "--bind",
                &endpoint_thread,
                "--timeout-secs",
                "10",
            ],
        )
    });
    thread::sleep(Duration::from_millis(150));
    let client = Command::new(env!("CARGO_BIN_EXE_shph"))
        .arg("--config")
        .arg(&client_config)
        .args(["up", "--no-tun", "--snap-profile"])
        .arg(&profile_path)
        .env("RUST_LOG", "info")
        .output()
        .expect("run QUIC setup fallback session");
    let receiver = receiver.join().expect("join SHPH receiver");

    let client_stdout = normalized_process_output(&client);
    let receiver_stdout = String::from_utf8_lossy(&receiver.stdout);
    assert!(
        client.status.success(),
        "{adapter} client stdout: {client_stdout}\nclient stderr: {}\nreceiver stdout: {receiver_stdout}\nreceiver stderr: {}",
        String::from_utf8_lossy(&client.stderr),
        String::from_utf8_lossy(&receiver.stderr)
    );
    assert!(
        client_stdout.contains(&format!("adapter={adapter}"))
            && client_stdout.contains("RetryableFailure")
            && client_stdout.contains("Connected"),
        "{adapter} did not retry the failed setup before connecting: {client_stdout}"
    );
    assert!(
        receiver.status.success(),
        "receiver stdout: {receiver_stdout}\nreceiver stderr: {}",
        String::from_utf8_lossy(&receiver.stderr)
    );
    assert!(
        receiver_stdout.contains(&payload),
        "{adapter} fallback payload missing: {receiver_stdout}"
    );
    fs::remove_dir_all(dir).expect("remove test directory");
}

#[test]
fn snap_file_adapter_setup_failures_use_allowed_direct_fallback() {
    for adapter in ["offline-mesh", "data-mule"] {
        run_snap_file_adapter_setup_failure_fallback(adapter);
    }
}

fn run_snap_file_adapter_setup_failure_fallback(adapter: &str) {
    let dir = test_dir();
    let client_dir = dir.join("client");
    let server_dir = dir.join("server");
    fs::create_dir_all(&client_dir).expect("create client directory");
    fs::create_dir_all(&server_dir).expect("create server directory");
    let client_config = client_dir.join("config.toml");
    let server_config = server_dir.join("config.toml");
    for config in [&client_config, &server_config] {
        let init = run(config, &["init", "--new"]);
        assert!(
            init.status.success(),
            "init stderr: {}",
            String::from_utf8_lossy(&init.stderr)
        );
    }

    let peer_socket = TcpListener::bind("127.0.0.1:0").expect("reserve direct peer port");
    let peer_addr = peer_socket.local_addr().expect("direct peer address");
    drop(peer_socket);
    let peer_endpoint = format!("127.0.0.1:{}", peer_addr.port());
    let peer_port = peer_addr.port().to_string();
    let client_public = output_key(&client_config, "show-public-key");
    let client_signing = output_key(&client_config, "show-signing-public-key");
    let server_public = output_key(&server_config, "show-public-key");
    let server_signing = output_key(&server_config, "show-signing-public-key");
    assert!(run(
        &client_config,
        &[
            "add-peer",
            "server",
            "127.0.0.1",
            &peer_port,
            &server_public,
            "--sign-pubkey",
            &server_signing,
        ],
    )
    .status
    .success());
    assert!(run(
        &server_config,
        &[
            "add-peer",
            "client",
            "127.0.0.1",
            "55559",
            &client_public,
            "--sign-pubkey",
            &client_signing,
        ],
    )
    .status
    .success());

    let blocker = dir.join("not-a-directory");
    fs::write(&blocker, b"adapter setup must fail with an I/O error")
        .expect("create file-system obstruction");
    let broken_path = blocker
        .join("adapter-data")
        .to_string_lossy()
        .replace('\\', "/");
    let roadmap = if adapter == "offline-mesh" {
        format!(
            "\n[roadmap.transport]\nkind = \"offline_mesh\"\nnode_id = \"client-node\"\npeer_id = \"server-node\"\nspool_dir = \"{broken_path}\"\npoll_interval_ms = 10\nmax_idle_entries = 128\n"
        )
    } else {
        let inbox = dir.join("mule-inbox").to_string_lossy().replace('\\', "/");
        format!(
            "\n[roadmap.transport]\nkind = \"data_mule\"\ninbox_dir = \"{inbox}\"\noutbox_dir = \"{broken_path}\"\npoll_interval_ms = 10\nmax_file_bytes = 32768\nmax_total_bytes = 1048576\nmax_age_ms = 60000\n"
        )
    };

    let profile_path = dir.join(format!("{adapter}-setup-fallback.json"));
    fs::write(
        &profile_path,
        serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "profile_name": format!("{adapter}-setup-fallback"),
            "peer_alias": "server",
            "mode": "direct-only",
            "retry_policy": {
                "rounds": 1,
                "max_total_attempts": 2,
                "max_elapsed_sec": 8.0,
                "jitter_ratio": 0.0
            },
            "direct_endpoints": [
                {
                    "ip": "127.0.0.1",
                    "port": peer_addr.port(),
                    "adapter": adapter,
                    "transport": adapter,
                    "priority": 1,
                    "allowed_fallback": ["direct-tcp"]
                },
                {
                    "ip": "127.0.0.1",
                    "port": peer_addr.port(),
                    "adapter": "direct-tcp",
                    "transport": "tcp",
                    "priority": 2
                }
            ]
        }))
        .expect("serialize file-adapter fallback profile"),
    )
    .expect("write file-adapter fallback profile");
    let profile_for_config = profile_path.to_string_lossy().replace('\\', "/");
    let payload = format!("snap-{adapter}-setup-fallback-payload");
    let mut client_toml = fs::read_to_string(&client_config).expect("read client config");
    client_toml.push_str(&roadmap);
    client_toml.push_str(&format!(
        "\n[session]\nrole = \"connect\"\npeer = \"{peer_endpoint}\"\nsnap_profile = \"{profile_for_config}\"\ntimeout_secs = 8\nstartup_payload = \"{payload}\"\n"
    ));
    fs::write(&client_config, client_toml).expect("configure SNAP client");

    let server_config_thread = server_config.clone();
    let peer_endpoint_thread = peer_endpoint.clone();
    let receiver = thread::spawn(move || {
        run(
            &server_config_thread,
            &[
                "recv-once",
                "--bind",
                &peer_endpoint_thread,
                "--timeout-secs",
                "10",
                "--transport",
                "tcp",
            ],
        )
    });
    thread::sleep(Duration::from_millis(100));

    let client = Command::new(env!("CARGO_BIN_EXE_shph"))
        .arg("--config")
        .arg(&client_config)
        .args(["up", "--no-tun"])
        .env("RUST_LOG", "info")
        .output()
        .expect("run file-adapter setup fallback session");
    let server = receiver.join().expect("join SHPH receiver");
    let client_stdout = normalized_process_output(&client);
    let server_stdout = String::from_utf8_lossy(&server.stdout);
    assert!(
        client.status.success(),
        "{adapter} client stdout: {client_stdout}\nclient stderr: {}\nreceiver stdout: {server_stdout}\nreceiver stderr: {}",
        String::from_utf8_lossy(&client.stderr),
        String::from_utf8_lossy(&server.stderr)
    );
    let saw_failed_adapter = client_stdout.contains(&format!("adapter={adapter}"));
    let saw_retry = client_stdout.contains("RetryableFailure");
    let saw_direct_fallback = client_stdout.contains("adapter=direct-tcp");
    let saw_connection = client_stdout.contains("Connected");
    assert!(
        saw_failed_adapter && saw_retry && saw_direct_fallback && saw_connection,
        "{adapter} retry evidence was incomplete (failed_adapter={saw_failed_adapter}, retry={saw_retry}, direct_fallback={saw_direct_fallback}, connected={saw_connection}): {client_stdout}"
    );
    assert!(
        server.status.success(),
        "receiver stdout: {server_stdout}\nreceiver stderr: {}",
        String::from_utf8_lossy(&server.stderr)
    );
    assert!(
        server_stdout.contains(&payload),
        "{adapter} fallback payload missing: {server_stdout}"
    );
    fs::remove_dir_all(dir).expect("remove test directory");
}

#[test]
fn snap_file_adapters_reconnect_after_setup_failure_and_shut_down() {
    for adapter in ["offline-mesh", "data-mule"] {
        run_snap_file_adapter_reconnect(adapter);
    }
}

fn run_snap_file_adapter_reconnect(adapter: &str) {
    let dir = test_dir();
    let client_dir = dir.join("client");
    let server_dir = dir.join("server");
    fs::create_dir_all(&client_dir).expect("create client directory");
    fs::create_dir_all(&server_dir).expect("create server directory");
    let client_config = client_dir.join("config.toml");
    let server_config = server_dir.join("config.toml");
    for config in [&client_config, &server_config] {
        let init = run(config, &["init", "--new"]);
        assert!(
            init.status.success(),
            "init stderr: {}",
            String::from_utf8_lossy(&init.stderr)
        );
    }

    let peer_socket = TcpListener::bind("127.0.0.1:0").expect("reserve file-adapter peer port");
    let peer_addr = peer_socket.local_addr().expect("file-adapter peer address");
    drop(peer_socket);
    let peer_endpoint = format!("127.0.0.1:{}", peer_addr.port());
    let peer_port = peer_addr.port().to_string();
    let client_public = output_key(&client_config, "show-public-key");
    let client_signing = output_key(&client_config, "show-signing-public-key");
    let server_public = output_key(&server_config, "show-public-key");
    let server_signing = output_key(&server_config, "show-signing-public-key");
    assert!(run(
        &client_config,
        &[
            "add-peer",
            "server",
            "127.0.0.1",
            &peer_port,
            &server_public,
            "--sign-pubkey",
            &server_signing,
        ],
    )
    .status
    .success());
    assert!(run(
        &server_config,
        &[
            "add-peer",
            "client",
            "127.0.0.1",
            "55559",
            &client_public,
            "--sign-pubkey",
            &client_signing,
        ],
    )
    .status
    .success());

    let blocker = dir.join("adapter-storage");
    fs::write(&blocker, b"temporary setup obstruction")
        .expect("create temporary file-adapter obstruction");
    let shared_root = blocker.to_string_lossy().replace('\\', "/");
    let to_client = dir.join("to-client").to_string_lossy().replace('\\', "/");
    let (client_roadmap, server_roadmap, repair_blocker) = if adapter == "offline-mesh" {
        (
            format!(
                "\n[roadmap.transport]\nkind = \"offline_mesh\"\nnode_id = \"client-node\"\npeer_id = \"server-node\"\nspool_dir = \"{shared_root}\"\npoll_interval_ms = 10\nmax_idle_entries = 128\n"
            ),
            format!(
                "\n[roadmap.transport]\nkind = \"offline_mesh\"\nnode_id = \"server-node\"\npeer_id = \"client-node\"\nspool_dir = \"{shared_root}\"\npoll_interval_ms = 10\nmax_idle_entries = 128\n"
            ),
            blocker.clone(),
        )
    } else {
        let outbox = blocker.join("adapter-data").join("to-server");
        let outbox = outbox.to_string_lossy().replace('\\', "/");
        (
            format!(
                "\n[roadmap.transport]\nkind = \"data_mule\"\ninbox_dir = \"{to_client}\"\noutbox_dir = \"{outbox}\"\npoll_interval_ms = 10\nmax_file_bytes = 32768\nmax_total_bytes = 1048576\nmax_age_ms = 60000\n"
            ),
            format!(
                "\n[roadmap.transport]\nkind = \"data_mule\"\ninbox_dir = \"{outbox}\"\noutbox_dir = \"{to_client}\"\npoll_interval_ms = 10\nmax_file_bytes = 32768\nmax_total_bytes = 1048576\nmax_age_ms = 60000\n"
            ),
            blocker.clone(),
        )
    };
    let mut client_toml = fs::read_to_string(&client_config).expect("read client config");
    client_toml.push_str(&client_roadmap);
    let mut server_toml = fs::read_to_string(&server_config).expect("read server config");
    server_toml.push_str(&server_roadmap);
    fs::write(&client_config, client_toml).expect("configure file-adapter client");
    fs::write(&server_config, server_toml).expect("configure file-adapter receiver");

    let profile_path = dir.join(format!("{adapter}-reconnect.json"));
    fs::write(
        &profile_path,
        serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "profile_name": format!("{adapter}-reconnect"),
            "peer_alias": "server",
            "mode": "direct-only",
            "connect_timeout_sec": 3.0,
            "retry_policy": {
                "rounds": 1,
                "max_total_attempts": 1,
                "max_elapsed_sec": 8.0,
                "jitter_ratio": 0.0
            },
            "direct_endpoints": [{
                "ip": "127.0.0.1",
                "port": peer_addr.port(),
                "adapter": adapter,
                "transport": adapter
            }]
        }))
        .expect("serialize file-adapter reconnect profile"),
    )
    .expect("write file-adapter reconnect profile");
    let profile_for_config = profile_path.to_string_lossy().replace('\\', "/");
    let mut client_toml = fs::read_to_string(&client_config).expect("read configured client");
    client_toml.push_str(&format!(
        "\n[session]\nrole = \"connect\"\npeer = \"{peer_endpoint}\"\nsnap_profile = \"{profile_for_config}\"\ntimeout_secs = 12\n\n[session.reconnect]\nenabled = true\nmax_attempts = 2\ninitial_delay_ms = 6000\nmax_delay_ms = 6000\n"
    ));
    fs::write(&client_config, client_toml).expect("configure reconnecting file-adapter client");

    let server_config_thread = server_config.clone();
    let peer_endpoint_thread = peer_endpoint.clone();
    let adapter_thread = adapter.to_owned();
    let repair_blocker_thread = repair_blocker.clone();
    let receiver = thread::spawn(move || {
        thread::sleep(Duration::from_secs(2));
        fs::remove_file(&repair_blocker_thread).expect("remove temporary adapter obstruction");
        if adapter_thread == "offline-mesh" {
            fs::create_dir_all(&repair_blocker_thread).expect("create repaired mesh spool");
        } else {
            fs::create_dir_all(repair_blocker_thread.join("adapter-data").join("to-server"))
                .expect("create repaired data-mule outbox");
            fs::create_dir_all(&to_client).expect("create repaired data-mule inbox");
        }
        run(
            &server_config_thread,
            &[
                "recv-once",
                "--bind",
                &peer_endpoint_thread,
                "--timeout-secs",
                "12",
                "--transport",
                &adapter_thread,
            ],
        )
    });

    let payload = format!("snap-{adapter}-reconnect-payload");
    let mut client = Command::new(env!("CARGO_BIN_EXE_shph"))
        .arg("--config")
        .arg(&client_config)
        .args(["up", "--no-tun"])
        .env("RUST_LOG", "info")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start reconnecting file-adapter client");
    client
        .stdin
        .take()
        .expect("client stdin pipe")
        .write_all(format!("{payload}\n").as_bytes())
        .expect("write reconnect payload");
    let client = client
        .wait_with_output()
        .expect("collect reconnecting file-adapter output");
    let server = receiver.join().expect("join file-adapter receiver");
    let client_stdout = normalized_process_output(&client);
    let server_stdout = String::from_utf8_lossy(&server.stdout);
    assert!(
        client.status.success(),
        "{adapter} reconnect client stdout: {client_stdout}\nclient stderr: {}\nreceiver stdout: {server_stdout}\nreceiver stderr: {}",
        String::from_utf8_lossy(&client.stderr),
        String::from_utf8_lossy(&server.stderr)
    );
    assert!(
        client_stdout.contains("Reconnect: attempt 1/2 failed")
            && client_stdout.contains("RetryableFailure")
            && client_stdout.contains("Connected")
            && client_stdout.contains("Transport loop: closed"),
        "{adapter} did not reconnect and shut down cleanly: {client_stdout}"
    );
    assert!(
        server.status.success() && server_stdout.contains(&payload),
        "{adapter} paired session did not receive its authenticated payload: stdout={server_stdout} stderr={}",
        String::from_utf8_lossy(&server.stderr)
    );
    fs::remove_dir_all(dir).expect("remove test directory");
}

#[test]
fn snap_runtime_enforces_max_total_attempts() {
    let dir = test_dir();
    fs::create_dir_all(&dir).expect("create test directory");
    let client_config = dir.join("client.toml");
    let server_config = dir.join("server.toml");
    for config in [&client_config, &server_config] {
        let init = run(config, &["init", "--new"]);
        assert!(
            init.status.success(),
            "init stderr: {}",
            String::from_utf8_lossy(&init.stderr)
        );
    }

    let ports: Vec<u16> = (0..3)
        .map(|_| {
            let socket = TcpListener::bind("127.0.0.1:0").expect("reserve closed candidate");
            let port = socket
                .local_addr()
                .expect("closed candidate address")
                .port();
            drop(socket);
            port
        })
        .collect();
    let peer_endpoint = format!("127.0.0.1:{}", ports[0]);
    let client_public = output_key(&client_config, "show-public-key");
    let client_signing = output_key(&client_config, "show-signing-public-key");
    let server_public = output_key(&server_config, "show-public-key");
    let server_signing = output_key(&server_config, "show-signing-public-key");
    assert!(run(
        &client_config,
        &[
            "add-peer",
            "server",
            "127.0.0.1",
            &ports[0].to_string(),
            &server_public,
            "--sign-pubkey",
            &server_signing,
        ],
    )
    .status
    .success());
    assert!(run(
        &server_config,
        &[
            "add-peer",
            "client",
            "127.0.0.1",
            "55559",
            &client_public,
            "--sign-pubkey",
            &client_signing,
        ],
    )
    .status
    .success());

    let profile_path = dir.join("attempt-budget.json");
    fs::write(
        &profile_path,
        serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "profile_name": "attempt-budget",
            "peer_alias": "server",
            "mode": "direct-only",
            "retry_policy": {
                "rounds": 4,
                "max_total_attempts": 2,
                "max_elapsed_sec": 10.0,
                "jitter_ratio": 0.0
            },
            "direct_endpoints": ports.iter().enumerate().map(|(index, port)| {
                serde_json::json!({
                    "ip": "127.0.0.1",
                    "port": port,
                    "adapter": "direct-tcp",
                    "transport": "tcp",
                    "priority": index + 1
                })
            }).collect::<Vec<_>>()
        }))
        .expect("serialize attempt-budget profile"),
    )
    .expect("write attempt-budget profile");
    let profile_for_config = profile_path.to_string_lossy().replace('\\', "/");
    let mut client_toml = fs::read_to_string(&client_config).expect("read client config");
    client_toml.push_str(&format!(
        "\n[session]\nrole = \"connect\"\npeer = \"{peer_endpoint}\"\nsnap_profile = \"{profile_for_config}\"\ntimeout_secs = 4\n"
    ));
    fs::write(&client_config, client_toml).expect("configure attempt-budget client");

    let client = Command::new(env!("CARGO_BIN_EXE_shph"))
        .arg("--config")
        .arg(&client_config)
        .args(["up", "--no-tun"])
        .env("RUST_LOG", "info")
        .output()
        .expect("run attempt-budget SNAP session");
    let stdout = normalized_process_output(&client);
    assert!(
        !client.status.success(),
        "closed peers unexpectedly connected"
    );
    assert_eq!(
        stdout
            .lines()
            .filter(|line| line.contains("SNAP path attempt profile_hash="))
            .count(),
        2,
        "SNAP exceeded its configured two-attempt limit: {stdout}"
    );
    assert!(
        stdout.contains("attempt=1") && stdout.contains("attempt=2"),
        "{stdout}"
    );
    assert!(
        !stdout.contains("attempt=3"),
        "SNAP attempted a third candidate: {stdout}"
    );
    fs::remove_dir_all(dir).expect("remove test directory");
}

#[test]
fn snap_runtime_stops_later_candidates_when_elapsed_budget_expires() {
    let dir = test_dir();
    fs::create_dir_all(&dir).expect("create test directory");
    let client_config = dir.join("client.toml");
    let server_config = dir.join("server.toml");
    for config in [&client_config, &server_config] {
        let init = run(config, &["init", "--new"]);
        assert!(
            init.status.success(),
            "init stderr: {}",
            String::from_utf8_lossy(&init.stderr)
        );
    }

    let stalled_listener = TcpListener::bind("127.0.0.1:0").expect("bind stalled peer");
    let stalled_port = stalled_listener
        .local_addr()
        .expect("stalled peer address")
        .port();
    let closed_socket = TcpListener::bind("127.0.0.1:0").expect("reserve later candidate");
    let later_port = closed_socket
        .local_addr()
        .expect("later candidate address")
        .port();
    drop(closed_socket);
    let peer_endpoint = format!("127.0.0.1:{stalled_port}");
    let client_public = output_key(&client_config, "show-public-key");
    let client_signing = output_key(&client_config, "show-signing-public-key");
    let server_public = output_key(&server_config, "show-public-key");
    let server_signing = output_key(&server_config, "show-signing-public-key");
    assert!(run(
        &client_config,
        &[
            "add-peer",
            "server",
            "127.0.0.1",
            &stalled_port.to_string(),
            &server_public,
            "--sign-pubkey",
            &server_signing,
        ],
    )
    .status
    .success());
    assert!(run(
        &server_config,
        &[
            "add-peer",
            "client",
            "127.0.0.1",
            "55559",
            &client_public,
            "--sign-pubkey",
            &client_signing,
        ],
    )
    .status
    .success());

    let stalled_peer = thread::spawn(move || {
        let (mut stream, _) = stalled_listener.accept().expect("accept stalled peer");
        let mut hello = [0u8; 4096];
        let received = stream.read(&mut hello).expect("read first candidate hello");
        assert!(received > 0, "first candidate sent an empty hello");
        thread::sleep(Duration::from_secs(3));
    });

    let profile_path = dir.join("elapsed-budget.json");
    fs::write(
        &profile_path,
        serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "profile_name": "elapsed-budget",
            "peer_alias": "server",
            "mode": "direct-only",
            "connect_timeout_sec": 4.0,
            "retry_policy": {
                "rounds": 1,
                "max_total_attempts": 2,
                "max_elapsed_sec": 2.0,
                "jitter_ratio": 0.0
            },
            "direct_endpoints": [
                {
                    "ip": "127.0.0.1",
                    "port": stalled_port,
                    "adapter": "direct-tcp",
                    "transport": "tcp",
                    "priority": 1,
                    "allowed_fallback": ["direct-tcp"]
                },
                {
                    "ip": "127.0.0.1",
                    "port": later_port,
                    "adapter": "direct-tcp",
                    "transport": "tcp",
                    "priority": 2
                }
            ]
        }))
        .expect("serialize elapsed-budget profile"),
    )
    .expect("write elapsed-budget profile");
    let profile_for_config = profile_path.to_string_lossy().replace('\\', "/");
    let mut client_toml = fs::read_to_string(&client_config).expect("read client config");
    client_toml.push_str(&format!(
        "\n[session]\nrole = \"connect\"\npeer = \"{peer_endpoint}\"\nsnap_profile = \"{profile_for_config}\"\ntimeout_secs = 4\n"
    ));
    fs::write(&client_config, client_toml).expect("configure elapsed-budget client");

    let started = Instant::now();
    let client = Command::new(env!("CARGO_BIN_EXE_shph"))
        .arg("--config")
        .arg(&client_config)
        .args(["up", "--no-tun"])
        .env("RUST_LOG", "info")
        .output()
        .expect("run elapsed-budget SNAP session");
    let elapsed = started.elapsed();
    stalled_peer.join().expect("join stalled peer");
    let stdout = normalized_process_output(&client);
    assert!(
        !client.status.success(),
        "stalled peer unexpectedly connected"
    );
    assert!(
        stdout.contains("RetryableFailure") && stdout.contains("BudgetExceeded"),
        "elapsed budget did not stop after the first timeout: stdout={stdout}; stderr={}",
        String::from_utf8_lossy(&client.stderr)
    );
    assert!(
        !stdout.contains("attempt=2"),
        "SNAP started another candidate after its time budget: {stdout}"
    );
    assert!(
        elapsed < Duration::from_secs(3),
        "SNAP exceeded its two-second elapsed budget by too much ({elapsed:?}): {stdout}"
    );
    fs::remove_dir_all(dir).expect("remove test directory");
}
