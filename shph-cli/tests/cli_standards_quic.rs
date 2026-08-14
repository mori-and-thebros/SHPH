use std::fs;
use std::io::ErrorKind;
use std::net::UdpSocket;
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn skip_when_unpermitted_loopback() -> bool {
    match UdpSocket::bind("127.0.0.1:0") {
        Ok(socket) => {
            drop(socket);
            false
        }
        Err(err) if err.kind() == ErrorKind::PermissionDenied => {
            eprintln!("skipping cli_standards_quic: loopback UDP bind denied ({err})");
            true
        }
        Err(err) => panic!("cli_standards_quic requires loopback UDP; bind failed: {err}"),
    }
}

fn test_dir(name: &str) -> PathBuf {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    std::env::temp_dir().join(format!("shph-{name}-{}-{timestamp}", std::process::id()))
}

fn test_port() -> u16 {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    20_000 + ((timestamp % 40_000) as u16)
}

fn command(config: &PathBuf, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_shph"))
        .arg("--config")
        .arg(config)
        .args(args)
        .output()
        .expect("run shph command")
}

fn public_key(config: &PathBuf, signing: bool) -> String {
    let command_name = if signing {
        "show-signing-public-key"
    } else {
        "show-public-key"
    };
    let output = command(config, &[command_name]);
    assert!(
        output.status.success(),
        "key command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("key output utf8")
        .trim()
        .to_string()
}

fn add_peer(config: &PathBuf, alias: &str, bind: &str, peer_config: &PathBuf) {
    let (host, port) = bind.rsplit_once(':').expect("endpoint");
    let output = command(
        config,
        &[
            "add-peer",
            alias,
            host,
            port,
            &public_key(peer_config, false),
            "--sign-pubkey",
            &public_key(peer_config, true),
        ],
    );
    assert!(
        output.status.success(),
        "add-peer failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn standards_quic_one_shot_cli_transfers_payload_and_receipt_ack() {
    if skip_when_unpermitted_loopback() {
        return;
    }

    let server_dir = test_dir("standards-quic-server");
    let client_dir = test_dir("standards-quic-client");
    fs::create_dir_all(&server_dir).expect("create server dir");
    fs::create_dir_all(&client_dir).expect("create client dir");
    let server_config = server_dir.join("config.toml");
    let client_config = client_dir.join("config.toml");
    assert!(command(&server_config, &["init", "--new"]).status.success());
    assert!(command(&client_config, &["init", "--new"]).status.success());

    let bind = format!("127.0.0.1:{}", test_port());
    add_peer(&server_config, "client", &bind, &client_config);
    add_peer(&client_config, "server", &bind, &server_config);

    let certificate = server_dir.join("server.der");
    let server_config_for_thread = server_config.clone();
    let certificate_for_thread = certificate.clone();
    let server_bind = bind.clone();
    let receiver = thread::spawn(move || {
        command(
            &server_config_for_thread,
            &[
                "recv-once",
                "--bind",
                &server_bind,
                "--timeout-secs",
                "5",
                "--transport",
                "quic-standard",
                "--quic-cert",
                certificate_for_thread.to_str().expect("certificate path"),
            ],
        )
    });

    for _ in 0..50 {
        if certificate.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    assert!(
        certificate.exists(),
        "server did not publish QUIC certificate"
    );

    let sender = command(
        &client_config,
        &[
            "send-once",
            "--peer",
            &bind,
            "--text",
            "hello-over-standards-quic",
            "--timeout-secs",
            "5",
            "--transport",
            "quic-standard",
            "--quic-cert",
            certificate.to_str().expect("certificate path"),
        ],
    );
    let receiver = receiver.join().expect("receiver thread join");
    assert!(
        receiver.status.success(),
        "receiver failed: stdout={} stderr={}",
        String::from_utf8_lossy(&receiver.stdout),
        String::from_utf8_lossy(&receiver.stderr)
    );
    assert!(
        sender.status.success(),
        "sender failed: stdout={} stderr={}",
        String::from_utf8_lossy(&sender.stdout),
        String::from_utf8_lossy(&sender.stderr)
    );
    assert!(String::from_utf8_lossy(&sender.stdout).contains("Sent bytes:"));

    let receiver_stdout = String::from_utf8_lossy(&receiver.stdout);
    assert!(receiver_stdout.contains("Payload: hello-over-standards-quic"));

    fs::remove_dir_all(server_dir).ok();
    fs::remove_dir_all(client_dir).ok();
}
