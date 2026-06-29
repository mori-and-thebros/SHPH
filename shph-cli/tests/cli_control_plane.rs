use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn test_dir(name: &str) -> PathBuf {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let pid = std::process::id();
    std::env::temp_dir().join(format!("shph-{name}-{pid}-{ts}"))
}

fn append_toml(path: &PathBuf, extra: &str) {
    let mut cfg = fs::read_to_string(path).expect("read config");
    cfg.push('\n');
    cfg.push_str(extra);
    fs::write(path, cfg).expect("write config");
}

fn init_config(path: &PathBuf) {
    let out = Command::new(env!("CARGO_BIN_EXE_shph"))
        .arg("--config")
        .arg(path)
        .arg("init")
        .arg("--new")
        .output()
        .expect("run init");
    assert!(
        out.status.success(),
        "init stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn up_with_control_plane_dry_run_logs_actions() {
    let workdir = test_dir("cp-dry-run");
    fs::create_dir_all(&workdir).expect("create dir");
    let cfg = workdir.join("config.toml");
    init_config(&cfg);

    append_toml(
        &cfg,
        r#"[control_plane]
apply_routes = true
route_cidrs = ["10.44.0.0/16"]
apply_dns = true
dns_servers = ["1.1.1.1"]
dry_run = true
"#,
    );

    let out = Command::new(env!("CARGO_BIN_EXE_shph"))
        .arg("--config")
        .arg(&cfg)
        .arg("up")
        .output()
        .expect("run up");

    assert!(
        out.status.success(),
        "up stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).expect("up stdout");
    assert!(stdout.contains("Control plane: routes=true(1), dns=true(1), dry_run=true"));
    assert!(stdout.contains("[dry-run] route add 10.44.0.0/16"));
    assert!(stdout.contains("[dry-run] dns add 1.1.1.1"));
}

#[test]
fn up_rejects_invalid_control_plane_cidr() {
    let workdir = test_dir("cp-bad-cidr");
    fs::create_dir_all(&workdir).expect("create dir");
    let cfg = workdir.join("config.toml");
    init_config(&cfg);

    append_toml(
        &cfg,
        r#"[control_plane]
apply_routes = true
route_cidrs = ["10.44.0.0/99"]
dry_run = true
"#,
    );

    let out = Command::new(env!("CARGO_BIN_EXE_shph"))
        .arg("--config")
        .arg(&cfg)
        .arg("up")
        .output()
        .expect("run up");

    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr)
        .expect("stderr utf8")
        .to_lowercase();
    assert!(stderr.contains("invalid cidr") || stderr.contains("cidr prefix out of range"));
}

#[test]
fn up_connect_mode_emits_reconnect_attempts() {
    let workdir = test_dir("cp-reconnect");
    fs::create_dir_all(&workdir).expect("create dir");
    let cfg = workdir.join("config.toml");
    init_config(&cfg);

    append_toml(
        &cfg,
        r#"[session]
role = "connect"
peer = "127.0.0.1:6550"
timeout_secs = 1

[session.reconnect]
enabled = true
max_attempts = 2
initial_delay_ms = 1
max_delay_ms = 2
"#,
    );

    let out = Command::new(env!("CARGO_BIN_EXE_shph"))
        .arg("--config")
        .arg(&cfg)
        .arg("up")
        .output()
        .expect("run up");

    assert!(!out.status.success());
    let stdout = String::from_utf8(out.stdout).expect("stdout utf8");
    assert!(stdout.contains("Session mode: connect (127.0.0.1:6550)"));
    assert!(stdout.contains("Reconnect: attempt 1/2 failed"));
}
