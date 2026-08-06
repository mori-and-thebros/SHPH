use std::fs;
use std::io::ErrorKind;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn skip_when_unpermitted_loopback() -> bool {
    match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => {
            drop(listener);
            false
        }
        Err(err) if err.kind() == ErrorKind::PermissionDenied => {
            eprintln!(
                "skipping cli_tcp_data_plane: loopback TCP bind denied ({})",
                err
            );
            true
        }
        Err(err) => panic!("cli_tcp_data_plane requires loopback TCP; bind failed: {err}"),
    }
}

fn test_dir(name: &str) -> PathBuf {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let pid = std::process::id();
    std::env::temp_dir().join(format!("shph-{name}-{pid}-{ts}"))
}

fn public_key(config: &PathBuf) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_shph"))
        .arg("--config")
        .arg(config)
        .arg("show-public-key")
        .output()
        .expect("show public key");
    assert!(output.status.success());
    String::from_utf8(output.stdout)
        .expect("public key utf8")
        .trim()
        .to_string()
}

fn signing_public_key(config: &PathBuf) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_shph"))
        .arg("--config")
        .arg(config)
        .arg("show-signing-public-key")
        .output()
        .expect("show signing public key");
    assert!(output.status.success());
    String::from_utf8(output.stdout)
        .expect("signing public key utf8")
        .trim()
        .to_string()
}

fn add_peer(config: &PathBuf, alias: &str, bind: &str, pubkey: &str, sign_pubkey: &str) {
    let (host, port) = bind.rsplit_once(':').expect("endpoint");
    let output = Command::new(env!("CARGO_BIN_EXE_shph"))
        .arg("--config")
        .arg(config)
        .arg("add-peer")
        .arg(alias)
        .arg(host)
        .arg(port)
        .arg(pubkey)
        .arg("--sign-pubkey")
        .arg(sign_pubkey)
        .output()
        .expect("add peer");
    assert!(output.status.success(), "add-peer failed");
}

#[test]
fn send_once_and_recv_once_transfer_encrypted_payload() {
    if skip_when_unpermitted_loopback() {
        return;
    }
    let server_dir = test_dir("server-dp");
    let client_dir = test_dir("client-dp");
    fs::create_dir_all(&server_dir).expect("create server dir");
    fs::create_dir_all(&client_dir).expect("create client dir");

    let server_cfg = server_dir.join("config.toml");
    let client_cfg = client_dir.join("config.toml");

    let init_server = Command::new(env!("CARGO_BIN_EXE_shph"))
        .arg("--config")
        .arg(&server_cfg)
        .arg("init")
        .arg("--new")
        .output()
        .expect("init server");
    assert!(init_server.status.success());

    let init_client = Command::new(env!("CARGO_BIN_EXE_shph"))
        .arg("--config")
        .arg(&client_cfg)
        .arg("init")
        .arg("--new")
        .output()
        .expect("init client");
    assert!(init_client.status.success());
    let bind = "127.0.0.1:7220";
    add_peer(
        &server_cfg,
        "client",
        bind,
        &public_key(&client_cfg),
        &signing_public_key(&client_cfg),
    );
    add_peer(
        &client_cfg,
        "server",
        bind,
        &public_key(&server_cfg),
        &signing_public_key(&server_cfg),
    );

    let server_cfg_for_thread = server_cfg.clone();
    let recv_handle = thread::spawn(move || {
        Command::new(env!("CARGO_BIN_EXE_shph"))
            .arg("--config")
            .arg(server_cfg_for_thread)
            .arg("recv-once")
            .arg("--bind")
            .arg(bind)
            .arg("--timeout-secs")
            .arg("3")
            .output()
            .expect("recv-once output")
    });

    thread::sleep(Duration::from_millis(150));

    let send_out = Command::new(env!("CARGO_BIN_EXE_shph"))
        .arg("--config")
        .arg(&client_cfg)
        .arg("send-once")
        .arg("--peer")
        .arg(bind)
        .arg("--text")
        .arg("hello-over-data-plane")
        .arg("--timeout-secs")
        .arg("3")
        .output()
        .expect("send-once output");
    assert!(
        send_out.status.success(),
        "send stderr: {}",
        String::from_utf8_lossy(&send_out.stderr)
    );
    let send_stdout = String::from_utf8(send_out.stdout).expect("send stdout");
    assert!(send_stdout.contains("handshake send-once ok"));

    let recv_out = recv_handle.join().expect("recv thread join");
    assert!(
        recv_out.status.success(),
        "recv stderr: {}",
        String::from_utf8_lossy(&recv_out.stderr)
    );
    let recv_stdout = String::from_utf8(recv_out.stdout).expect("recv stdout");
    assert!(recv_stdout.contains("handshake recv-once ok"));
    assert!(recv_stdout.contains("Payload: hello-over-data-plane"));
}
