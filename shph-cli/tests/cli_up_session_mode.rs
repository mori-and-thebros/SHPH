use serde_json::Value;
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
                "skipping cli_up_session_mode: loopback TCP bind denied ({})",
                err
            );
            true
        }
        Err(err) => panic!("cli_up_session_mode requires loopback TCP; bind failed: {err}"),
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

fn set_session(config_path: &PathBuf, session_toml: &str) {
    let mut cfg = fs::read_to_string(config_path).expect("read config");
    cfg.push('\n');
    cfg.push_str(session_toml);
    fs::write(config_path, cfg).expect("write config");
}

#[test]
fn up_runs_session_configured_data_plane() {
    if skip_when_unpermitted_loopback() {
        return;
    }
    let server_dir = test_dir("server-up");
    let client_dir = test_dir("client-up");
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

    set_session(
        &server_cfg,
        r#"[session]
role = "listen"
bind = "127.0.0.1:7230"
timeout_secs = 3
startup_payload = "expect"
"#,
    );
    set_session(
        &client_cfg,
        r#"[session]
role = "connect"
peer = "127.0.0.1:7230"
timeout_secs = 3
startup_payload = "vpn-up-path"
"#,
    );

    let server_cfg_for_thread = server_cfg.clone();
    let listen_handle = thread::spawn(move || {
        Command::new(env!("CARGO_BIN_EXE_shph"))
            .arg("--config")
            .arg(server_cfg_for_thread)
            .arg("up")
            .output()
            .expect("server up output")
    });

    thread::sleep(Duration::from_millis(180));

    let client_out = Command::new(env!("CARGO_BIN_EXE_shph"))
        .arg("--config")
        .arg(&client_cfg)
        .arg("up")
        .output()
        .expect("client up output");
    assert!(
        client_out.status.success(),
        "client stderr: {}",
        String::from_utf8_lossy(&client_out.stderr)
    );
    let client_stdout = String::from_utf8(client_out.stdout).expect("client stdout");
    assert!(client_stdout.contains("Session mode: connect"));
    assert!(client_stdout.contains("handshake send-once ok"));
    // Phase A.1: one-shot up path must emit the full session lifecycle trail.
    assert!(client_stdout.contains("Session id: send-once-"));
    assert!(client_stdout.contains("Session start:"));
    assert!(client_stdout.contains("Session end:"));
    assert!(client_stdout.contains("Final metrics: MetricsSnapshot"));
    assert!(client_stdout.contains("Initial metrics: MetricsSnapshot"));

    let server_out = listen_handle.join().expect("listen join");
    assert!(
        server_out.status.success(),
        "server stderr: {}",
        String::from_utf8_lossy(&server_out.stderr)
    );
    let server_stdout = String::from_utf8(server_out.stdout).expect("server stdout");
    assert!(server_stdout.contains("Session mode: listen"));
    assert!(server_stdout.contains("handshake recv-once ok"));
    assert!(server_stdout.contains("Payload: vpn-up-path"));
    // Phase A.1: receiver side lifecycle trail + received-byte accounting.
    assert!(server_stdout.contains("Session id: recv-once-"));
    assert!(server_stdout.contains("Session start:"));
    assert!(server_stdout.contains("Session end:"));
    assert!(server_stdout.contains("Final metrics: MetricsSnapshot"));

    let _ = Value::Null;
}

#[test]
fn up_without_startup_payload_uses_loop_modes() {
    if skip_when_unpermitted_loopback() {
        return;
    }
    let server_dir = test_dir("server-up-loop");
    let client_dir = test_dir("client-up-loop");
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

    set_session(
        &server_cfg,
        r#"[session]
role = "listen"
bind = "127.0.0.1:7231"
timeout_secs = 3
"#,
    );
    set_session(
        &client_cfg,
        r#"[session]
role = "connect"
peer = "127.0.0.1:7231"
timeout_secs = 3
"#,
    );

    let server_cfg_for_thread = server_cfg.clone();
    let listen_handle = thread::spawn(move || {
        Command::new(env!("CARGO_BIN_EXE_shph"))
            .arg("--config")
            .arg(server_cfg_for_thread)
            .arg("up")
            .output()
            .expect("server up output")
    });

    thread::sleep(Duration::from_millis(180));

    let mut client_cmd = Command::new(env!("CARGO_BIN_EXE_shph"));
    client_cmd.arg("--config").arg(&client_cfg).arg("up");
    client_cmd.stdin(std::process::Stdio::piped());
    client_cmd.stdout(std::process::Stdio::piped());
    client_cmd.stderr(std::process::Stdio::piped());
    let mut client = client_cmd.spawn().expect("spawn client up");
    {
        use std::io::Write as _;
        let mut stdin = client.stdin.take().expect("client stdin");
        stdin
            .write_all(b"loop-message\n")
            .expect("write client payload");
    }
    let client_out = client.wait_with_output().expect("client output");

    assert!(
        client_out.status.success(),
        "client stderr: {}",
        String::from_utf8_lossy(&client_out.stderr)
    );
    let client_stdout = String::from_utf8(client_out.stdout).expect("client stdout");
    assert!(client_stdout.contains("Session mode: connect"));
    assert!(client_stdout.contains("handshake connect-loop ok"));
    // Phase A.1: loop-mode up path emits the lifecycle trail and clean close.
    assert!(client_stdout.contains("Session id: connect-"));
    assert!(client_stdout.contains("Session start:"));
    assert!(client_stdout.contains("Session end:"));
    assert!(client_stdout.contains("Final metrics: MetricsSnapshot"));

    let server_out = listen_handle.join().expect("listen join");
    assert!(
        server_out.status.success(),
        "server stderr: {}",
        String::from_utf8_lossy(&server_out.stderr)
    );
    let server_stdout = String::from_utf8(server_out.stdout).expect("server stdout");
    assert!(server_stdout.contains("Session mode: listen"));
    assert!(server_stdout.contains("handshake listen-loop ok"));
    assert!(server_stdout.contains("RX: loop-message"));
    assert!(server_stdout.contains("Transport loop: closed"));
    assert!(server_stdout.contains("Session id: listen-"));
    assert!(server_stdout.contains("Final metrics: MetricsSnapshot"));
}
