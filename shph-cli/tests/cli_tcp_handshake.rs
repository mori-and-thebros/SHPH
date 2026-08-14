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
                "skipping cli_tcp_handshake: loopback TCP bind denied ({})",
                err
            );
            true
        }
        Err(err) => panic!("cli_tcp_handshake requires loopback TCP; bind failed: {err}"),
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

fn test_port() -> u16 {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let pid = std::process::id();
    let hashed = ts.rotate_left(13) ^ u128::from(pid);
    let port = ((hashed % 40_000) as u16) + 20_000; // 20000..59999
    port
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
    let endpoint = bind.rsplit_once(':').expect("endpoint port");
    let output = Command::new(env!("CARGO_BIN_EXE_shph"))
        .arg("--config")
        .arg(config)
        .arg("add-peer")
        .arg(alias)
        .arg(endpoint.0)
        .arg(endpoint.1)
        .arg(pubkey)
        .arg("--sign-pubkey")
        .arg(sign_pubkey)
        .output()
        .expect("add peer");
    assert!(
        output.status.success(),
        "add-peer stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn run_connect(bind: &str, client_cfg: &PathBuf) -> Result<std::process::Output, String> {
    for attempt in 0..8 {
        let connect_out = Command::new(env!("CARGO_BIN_EXE_shph"))
            .arg("--config")
            .arg(client_cfg)
            .arg("connect")
            .arg("--peer")
            .arg(bind)
            .arg("--timeout-secs")
            .arg("3")
            .output()
            .map_err(|err| format!("connect spawn failed: {err}"))?;

        if connect_out.status.success() {
            return Ok(connect_out);
        }

        if attempt < 7 {
            thread::sleep(Duration::from_millis(150));
            continue;
        }
        let stdout = String::from_utf8_lossy(&connect_out.stdout).to_string();
        let stderr = String::from_utf8_lossy(&connect_out.stderr).to_string();
        return Err(format!(
            "connect failed after 8 attempts: status={:?}, stdout={stdout}, stderr={stderr}",
            connect_out.status.code()
        ));
    }

    unreachable!()
}

#[test]
fn listen_and_connect_complete_handshake() {
    if skip_when_unpermitted_loopback() {
        return;
    }
    let server_dir = test_dir("server");
    let client_dir = test_dir("client");
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

    let server_cfg_for_thread = server_cfg.clone();
    let port = test_port();
    let bind = format!("127.0.0.1:{port}");
    add_peer(
        &server_cfg,
        "client",
        &bind,
        &public_key(&client_cfg),
        &signing_public_key(&client_cfg),
    );
    add_peer(
        &client_cfg,
        "server",
        &bind,
        &public_key(&server_cfg),
        &signing_public_key(&server_cfg),
    );

    let listen_handle = thread::spawn(move || {
        Command::new(env!("CARGO_BIN_EXE_shph"))
            .arg("--config")
            .arg(server_cfg_for_thread)
            .arg("listen")
            .arg("--bind")
            .arg(format!("127.0.0.1:{port}"))
            .arg("--timeout-secs")
            .arg("3")
            .output()
            .expect("listen output")
    });

    thread::sleep(Duration::from_millis(150));

    let connect_out =
        run_connect(&bind, &client_cfg).expect("connect command failed after retries");
    assert!(connect_out.status.success());
    let connect_stdout = String::from_utf8(connect_out.stdout).expect("connect stdout");
    assert!(connect_stdout.contains("handshake connect ok"));

    let listen_out = listen_handle.join().expect("listen thread join");
    assert!(listen_out.status.success());
    let listen_stdout = String::from_utf8(listen_out.stdout).expect("listen stdout");
    assert!(listen_stdout.contains("handshake listen ok"));
}
