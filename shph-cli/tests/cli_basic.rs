use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn test_dir(name: &str) -> PathBuf {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "shph-cli-basic-{name}-{}-{timestamp}",
        std::process::id()
    ))
}

#[test]
fn cli_help_contains_main_commands() {
    let output = Command::new(env!("CARGO_BIN_EXE_shph"))
        .arg("--help")
        .output()
        .expect("run shph --help");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    assert!(stdout.contains("init"));
    assert!(stdout.contains("up"));
    assert!(stdout.contains("apply"));
    assert!(stdout.contains("reconcile"));
    assert!(stdout.contains("undo"));
    assert!(stdout.contains("add-peer"));
    assert!(stdout.contains("handshake-sim"));
    assert!(stdout.contains("listen"));
    assert!(stdout.contains("connect"));
    assert!(stdout.contains("send-once"));
    assert!(stdout.contains("recv-once"));
    assert!(stdout.contains("doctor"));
    assert!(stdout.contains("--json"));

    let join_help = Command::new(env!("CARGO_BIN_EXE_shph"))
        .args(["join", "--help"])
        .output()
        .expect("run join help");
    assert!(join_help.status.success());
    let join_help_stdout = String::from_utf8(join_help.stdout).expect("join help utf8");
    assert!(join_help_stdout.contains("--ticket-file"));
    assert!(join_help_stdout.contains("--transport-peer"));
    assert!(join_help_stdout.contains("--check"));

    let doctor_help = Command::new(env!("CARGO_BIN_EXE_shph"))
        .args(["doctor", "--help"])
        .output()
        .expect("run doctor help");
    assert!(doctor_help.status.success());
    let doctor_help_stdout = String::from_utf8(doctor_help.stdout).expect("doctor help utf8");
    assert!(doctor_help_stdout.contains("--deep"));

    let recv_help = Command::new(env!("CARGO_BIN_EXE_shph"))
        .args(["recv-once", "--help"])
        .output()
        .expect("run recv-once --help");
    assert!(recv_help.status.success());
    let recv_help_stdout = String::from_utf8(recv_help.stdout).expect("recv help utf8");
    assert!(recv_help_stdout.contains("quic-standard"));
    assert!(recv_help_stdout.contains("--quic-cert"));
}

#[test]
fn doctor_and_status_json_are_machine_readable() {
    let workdir = test_dir("json");
    fs::create_dir_all(&workdir).expect("create workdir");
    let config = workdir.join("config.toml");

    let init = Command::new(env!("CARGO_BIN_EXE_shph"))
        .arg("--config")
        .arg(&config)
        .args(["init", "--new"])
        .output()
        .expect("run init");
    assert!(
        init.status.success(),
        "init stderr: {}",
        String::from_utf8_lossy(&init.stderr)
    );

    let doctor = Command::new(env!("CARGO_BIN_EXE_shph"))
        .arg("--config")
        .arg(&config)
        .args(["doctor", "--strict", "--json"])
        .output()
        .expect("run doctor");
    assert!(
        doctor.status.success(),
        "doctor stderr: {}",
        String::from_utf8_lossy(&doctor.stderr)
    );
    let doctor_json: Value = serde_json::from_slice(&doctor.stdout).expect("doctor JSON output");
    assert_eq!(doctor_json["ok"], true);
    assert!(doctor_json["checks"].as_array().is_some());

    let deep_doctor = Command::new(env!("CARGO_BIN_EXE_shph"))
        .arg("--config")
        .arg(&config)
        .args(["doctor", "--deep", "--json"])
        .output()
        .expect("run deep doctor");
    assert!(
        deep_doctor.status.success(),
        "deep doctor stderr: {}",
        String::from_utf8_lossy(&deep_doctor.stderr)
    );
    let deep_doctor_json: Value =
        serde_json::from_slice(&deep_doctor.stdout).expect("deep doctor JSON output");
    assert!(deep_doctor_json["checks"]
        .as_array()
        .expect("deep checks")
        .iter()
        .any(|check| check["name"] == "deep-session"));

    let ticket_file = workdir.join("join.ticket");
    let id = Command::new(env!("CARGO_BIN_EXE_shph"))
        .arg("--config")
        .arg(&config)
        .args(["id", "--ticket-file"])
        .arg(&ticket_file)
        .output()
        .expect("write ticket file");
    assert!(
        id.status.success(),
        "id stderr: {}",
        String::from_utf8_lossy(&id.stderr)
    );
    let ticket = fs::read_to_string(&ticket_file).expect("read ticket file");
    assert!(ticket.starts_with("shph://v1:"));

    let status = Command::new(env!("CARGO_BIN_EXE_shph"))
        .arg("--config")
        .arg(&config)
        .args(["status", "--json"])
        .output()
        .expect("run status");
    assert!(
        status.status.success(),
        "status stderr: {}",
        String::from_utf8_lossy(&status.stderr)
    );
    let status_json: Value = serde_json::from_slice(&status.stdout).expect("status JSON output");
    assert_eq!(status_json["config"]["state"], "ready");
    assert_eq!(status_json["peers"], 0);
    assert!(status_json["transport_peer"].is_null());

    let mut configured = fs::read_to_string(&config).expect("read initialized config");
    configured.push_str(
        r#"

[session]
role = "connect"
peer = "relay.example:443"
transport_peer = "127.0.0.1:8443"
"#,
    );
    fs::write(&config, configured).expect("write session config");

    let status_with_transport_peer = Command::new(env!("CARGO_BIN_EXE_shph"))
        .arg("--config")
        .arg(&config)
        .args(["status", "--json"])
        .output()
        .expect("run configured status");
    assert!(status_with_transport_peer.status.success());
    let configured_status: Value =
        serde_json::from_slice(&status_with_transport_peer.stdout).expect("configured status JSON");
    assert_eq!(configured_status["session"], "connect (relay.example:443)");
    assert_eq!(configured_status["transport_peer"], "127.0.0.1:8443");

    let peers = Command::new(env!("CARGO_BIN_EXE_shph"))
        .arg("--config")
        .arg(&config)
        .args(["peers", "--json"])
        .output()
        .expect("run peers alias");
    assert!(peers.status.success());
    let peers_json: Value = serde_json::from_slice(&peers.stdout).expect("peers JSON output");
    assert_eq!(peers_json, Value::Array(Vec::new()));

    let _ = fs::remove_dir_all(workdir);
}
