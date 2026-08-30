use std::fs;
use std::io::ErrorKind;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const RELIABILITY_SESSIONS: usize = 8;
const PROCESS_TIMEOUT: Duration = Duration::from_secs(8);

struct Cleanup(PathBuf);

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn skip_when_unpermitted_loopback() -> bool {
    match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => {
            drop(listener);
            false
        }
        Err(error) if error.kind() == ErrorKind::PermissionDenied => {
            eprintln!("skipping cli_reliability: loopback TCP bind denied ({error})");
            true
        }
        Err(error) => panic!("cli_reliability requires loopback TCP; bind failed: {error}"),
    }
}

fn test_dir() -> PathBuf {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "shph-cli-reliability-{}-{timestamp}",
        std::process::id()
    ))
}

fn test_endpoint() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("allocate loopback port");
    let port = listener.local_addr().expect("loopback address").port();
    drop(listener);
    format!("127.0.0.1:{port}")
}

fn run_successfully(config: &Path, args: &[&str]) -> Output {
    let output = Command::new(env!("CARGO_BIN_EXE_shph"))
        .arg("--config")
        .arg(config)
        .args(args)
        .output()
        .expect("run shph command");
    assert!(
        output.status.success(),
        "command failed: {:?}\nstderr: {}",
        args,
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn public_key(config: &Path) -> String {
    String::from_utf8(run_successfully(config, &["show-public-key"]).stdout)
        .expect("public key utf8")
        .trim()
        .to_owned()
}

fn signing_public_key(config: &Path) -> String {
    String::from_utf8(run_successfully(config, &["show-signing-public-key"]).stdout)
        .expect("signing public key utf8")
        .trim()
        .to_owned()
}

fn add_peer(config: &Path, alias: &str, endpoint: &str, pubkey: &str, sign_pubkey: &str) {
    let (host, port) = endpoint.rsplit_once(':').expect("endpoint port");
    let port = port.parse::<u16>().expect("endpoint port number");
    let output = Command::new(env!("CARGO_BIN_EXE_shph"))
        .arg("--config")
        .arg(config)
        .arg("add-peer")
        .arg(alias)
        .arg(host)
        .arg(port.to_string())
        .arg(pubkey)
        .arg("--sign-pubkey")
        .arg(sign_pubkey)
        .output()
        .expect("add peer");
    assert!(
        output.status.success(),
        "add-peer failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn spawn_session(config: &Path, args: &[&str]) -> Child {
    Command::new(env!("CARGO_BIN_EXE_shph"))
        .arg("--config")
        .arg(config)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn session")
}

fn wait_with_timeout(mut child: Child, label: &str) -> Output {
    let deadline = Instant::now() + PROCESS_TIMEOUT;
    loop {
        match child.try_wait().expect("poll session") {
            Some(_) => return child.wait_with_output().expect("collect session output"),
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let output = child.wait_with_output().expect("collect timed-out output");
                panic!("{label} exceeded {PROCESS_TIMEOUT:?}: {output:?}");
            }
            None => thread::sleep(Duration::from_millis(20)),
        }
    }
}

#[test]
fn repeated_fresh_process_sessions_remain_authenticated() {
    if skip_when_unpermitted_loopback() {
        return;
    }

    let root = test_dir();
    let _cleanup = Cleanup(root.clone());
    let server_dir = root.join("server");
    let client_dir = root.join("client");
    fs::create_dir_all(&server_dir).expect("create server dir");
    fs::create_dir_all(&client_dir).expect("create client dir");
    let server_config = server_dir.join("config.toml");
    let client_config = client_dir.join("config.toml");

    run_successfully(&server_config, &["init", "--new"]);
    run_successfully(&client_config, &["init", "--new"]);

    let server_key = public_key(&server_config);
    let server_signing_key = signing_public_key(&server_config);
    let client_key = public_key(&client_config);
    let client_signing_key = signing_public_key(&client_config);
    let endpoint = test_endpoint();
    add_peer(
        &server_config,
        "client",
        &endpoint,
        &client_key,
        &client_signing_key,
    );
    add_peer(
        &client_config,
        "server",
        &endpoint,
        &server_key,
        &server_signing_key,
    );

    for session in 0..RELIABILITY_SESSIONS {
        let payload = format!("reliability-session-{session}");
        let receiver = spawn_session(
            &server_config,
            &["recv-once", "--bind", &endpoint, "--timeout-secs", "3"],
        );
        thread::sleep(Duration::from_millis(120));
        let sender = spawn_session(
            &client_config,
            &[
                "send-once",
                "--peer",
                &endpoint,
                "--text",
                &payload,
                "--timeout-secs",
                "3",
            ],
        );

        let sender_output = wait_with_timeout(sender, "sender");
        assert!(
            sender_output.status.success(),
            "sender failed for session {session}: {}",
            String::from_utf8_lossy(&sender_output.stderr)
        );
        let receiver_output = wait_with_timeout(receiver, "receiver");
        assert!(
            receiver_output.status.success(),
            "receiver failed for session {session}: {}",
            String::from_utf8_lossy(&receiver_output.stderr)
        );
        let receiver_stdout = String::from_utf8_lossy(&receiver_output.stdout);
        assert!(
            receiver_stdout.contains(&format!("Payload: {payload}")),
            "receiver did not report the expected payload for session {session}: {receiver_stdout}"
        );
    }
}
