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

#[test]
fn control_plane_apply_reconcile_and_undo_are_idempotent_in_dry_run() {
    let workdir = test_dir("cp-commands");
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

    let apply = Command::new(env!("CARGO_BIN_EXE_shph"))
        .arg("--config")
        .arg(&cfg)
        .arg("apply")
        .output()
        .expect("apply");
    assert!(apply.status.success(), "apply failed");
    let apply_stdout = String::from_utf8(apply.stdout).expect("apply stdout");
    assert!(apply_stdout.contains("[dry-run] route add 10.44.0.0/16"));
    assert!(apply_stdout.contains("[dry-run] dns add 1.1.1.1"));

    let reconcile = Command::new(env!("CARGO_BIN_EXE_shph"))
        .arg("--config")
        .arg(&cfg)
        .arg("reconcile")
        .output()
        .expect("reconcile");
    assert!(reconcile.status.success(), "reconcile failed");
    let reconcile_stdout = String::from_utf8(reconcile.stdout).expect("reconcile stdout");
    assert!(reconcile_stdout.contains("[dry-run] route add 10.44.0.0/16"));

    let undo = Command::new(env!("CARGO_BIN_EXE_shph"))
        .arg("--config")
        .arg(&cfg)
        .arg("undo")
        .output()
        .expect("undo");
    assert!(undo.status.success(), "undo failed");
    assert!(String::from_utf8(undo.stdout)
        .expect("undo stdout")
        .contains("no applied state"));
}

#[test]
fn roadmap_cli_validates_shamir_and_exports_empty_audit() {
    let workdir = test_dir("roadmap-cli");
    fs::create_dir_all(&workdir).expect("create dir");
    let cfg = workdir.join("config.toml");
    init_config(&cfg);
    append_toml(
        &cfg,
        r#"[roadmap.shamir]
enabled = true
threshold = 2
shares = 3

[roadmap.ratchet_audit]
journal_path = "audit.jsonl"
max_entries = 4
"#,
    );
    fs::write(workdir.join("secret.txt"), b"roadmap-secret").expect("write secret");

    let validate = Command::new(env!("CARGO_BIN_EXE_shph"))
        .arg("--config")
        .arg(&cfg)
        .arg("validate-roadmap")
        .output()
        .expect("validate roadmap");
    assert!(
        validate.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&validate.stderr)
    );
    assert!(String::from_utf8(validate.stdout)
        .expect("stdout")
        .contains("Roadmap: valid"));

    let split = Command::new(env!("CARGO_BIN_EXE_shph"))
        .arg("--config")
        .arg(&cfg)
        .arg("shamir-split")
        .arg("--secret-file")
        .arg(workdir.join("secret.txt"))
        .arg("--output-dir")
        .arg(workdir.join("shares"))
        .output()
        .expect("shamir split");
    assert!(split.status.success());
    assert!(String::from_utf8_lossy(&split.stdout).contains("Wrote 3 Shamir share files"));

    let mut share_paths = Vec::new();
    for index in 1..=2 {
        let path = workdir
            .join("shares")
            .join(format!("share-{index:03}.json"));
        share_paths.push(path);
    }
    let recovered_path = workdir.join("recovered-secret.txt");
    let recover = Command::new(env!("CARGO_BIN_EXE_shph"))
        .arg("--config")
        .arg(&cfg)
        .arg("shamir-recover")
        .args(&share_paths)
        .arg("--output-file")
        .arg(&recovered_path)
        .output()
        .expect("shamir recover");
    assert!(
        recover.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&recover.stderr)
    );
    assert_eq!(
        fs::read_to_string(recovered_path).expect("recovered secret"),
        "roadmap-secret"
    );

    let export = Command::new(env!("CARGO_BIN_EXE_shph"))
        .arg("--config")
        .arg(&cfg)
        .arg("ratchet-audit-export")
        .output()
        .expect("audit export");
    assert!(export.status.success());
    assert_eq!(
        String::from_utf8(export.stdout)
            .expect("export utf8")
            .trim(),
        "[]"
    );
    fs::remove_dir_all(workdir).ok();
}

#[test]
fn roadmap_cli_rejects_hardware_identity_provider() {
    let workdir = test_dir("roadmap-hardware");
    fs::create_dir_all(&workdir).expect("create dir");
    let cfg = workdir.join("config.toml");
    init_config(&cfg);
    append_toml(
        &cfg,
        r#"[roadmap.identity]
kind = "yubikey_piv"
slot = "9a"
"#,
    );

    let out = Command::new(env!("CARGO_BIN_EXE_shph"))
        .arg("--config")
        .arg(&cfg)
        .arg("validate-roadmap")
        .output()
        .expect("validate roadmap");
    assert!(!out.status.success());
    assert!(String::from_utf8(out.stderr)
        .expect("stderr")
        .contains("backend unavailable"));
    fs::remove_dir_all(workdir).ok();
}
