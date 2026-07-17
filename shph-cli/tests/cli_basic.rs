use std::process::Command;

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
    assert!(stdout.contains("up"));
}
