//! Runs the built binary the way an MCP host and a shell would.

use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::{Value, json};

fn signer(dir: &std::path::Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_tuyo-signer"));
    for name in [
        "TUYO_SIGNER_PROFILE",
        "TUYO_SIGNER_KEY_DIR",
        "TUYO_SIGNER_AUTO_UPDATE",
    ] {
        command.env_remove(name);
    }
    command
        .env("TUYO_SIGNER_DATA_DIR", dir)
        .env("TUYO_SIGNER_KEY_STORAGE", "file")
        .env("TUYO_SIGNER_UPDATE_CHECK", "0");
    command
}

#[test]
fn signs_over_mcp_stdio() {
    let dir = tempfile::tempdir().unwrap();
    let mut child = signer(dir.path())
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let hash = format!("0x{}", "cd".repeat(32));
    let requests = [
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"create_signer","arguments":{"tag":"agent"}}}),
    ];
    let mut stdin = child.stdin.take().unwrap();
    for request in &requests {
        writeln!(stdin, "{request}").unwrap();
    }
    drop(stdin);
    let output = child.wait_with_output().unwrap();
    let lines: Vec<Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 2);
    let created = &lines[1]["result"]["structuredContent"];
    assert_eq!(created["storage"], "file");

    // The command line sees the same profile.
    let output = signer(dir.path())
        .args([
            "sign-hash",
            "--signer",
            created["address"].as_str().unwrap(),
            "--hash",
            &hash,
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let signed: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(signed["tag"], "agent");
    assert_eq!(signed["signature"].as_str().unwrap().len(), 132);
}

#[test]
fn reports_errors_as_json_on_stderr() {
    let dir = tempfile::tempdir().unwrap();
    let output = signer(dir.path())
        .args(["get", "missing"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let error: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["code"], "signer_not_found");
}
