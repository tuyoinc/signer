//! Runs the built binary the way an MCP host and a shell would.

use std::io::Write;
use std::process::{Command, Stdio};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};

fn signer(dir: &std::path::Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_tuyo-signer"));
    for name in [
        "TUYO_SIGNER_PROFILE",
        "TUYO_SIGNER_KEY_DIR",
        "TUYO_SIGNER_AUTO_UPDATE",
        "TUYO_SIGNER_API_ISSUER",
        "TUYO_SIGNER_API_AUDIENCE",
    ] {
        command.env_remove(name);
    }
    command
        .env("TUYO_SIGNER_DATA_DIR", dir)
        .env("TUYO_SIGNER_KEY_STORAGE", "file");
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

fn json_command(dir: &std::path::Path, name: &str, input: &Value) -> std::process::Output {
    let mut child = signer(dir)
        .arg(name)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    serde_json::to_writer(child.stdin.take().unwrap(), input).unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn creates_identity_without_credentials_or_an_api_preparation_call() {
    let dir = tempfile::tempdir().unwrap();
    assert!(
        signer(dir.path())
            .args(["create", "agent"])
            .output()
            .unwrap()
            .status
            .success()
    );
    let output = signer(dir.path())
        .args(["identity", "--signer", "agent"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(stdout.lines().count(), 1);
    assert!(stdout.ends_with('\n'));
    let token = stdout.trim_end();
    let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(token).unwrap()).unwrap();
    assert_eq!(claims["version"], 1);
    assert_eq!(claims["scope"], "all");
    assert_eq!(
        claims["expiresAt"].as_u64().unwrap() - claims["issuedAt"].as_u64().unwrap(),
        300
    );

    let output = signer(dir.path())
        .args(["identity", "--signer", "agent", "--scope", "all", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let identity: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(identity["tag"], "agent");
    assert_eq!(identity["scope"], "all");
    assert_eq!(
        identity["expiresAt"].as_u64().unwrap() - identity["issuedAt"].as_u64().unwrap(),
        300
    );
    let decoded: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(identity["token"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(decoded["signAddress"], identity["signer"]);
    assert_eq!(decoded["scope"], identity["scope"]);
    assert_eq!(
        identity["token"],
        identity["headers"]["Tuyo-Agent-Identity"]
    );
    assert!(!identity.to_string().contains("accessToken"));
    assert!(
        !std::fs::read_to_string(dir.path().join("state.json"))
            .unwrap()
            .contains("Tuyo-Agent-Identity")
    );
}

#[test]
fn signs_arbitrary_scope_strings_without_a_cli_allowlist() {
    let dir = tempfile::tempdir().unwrap();
    assert!(
        signer(dir.path())
            .args(["create", "agent"])
            .output()
            .unwrap()
            .status
            .success()
    );
    let scope = "future:pod/read:🌊";
    let output = signer(dir.path())
        .args(["identity", "--signer", "agent", "--scope", scope])
        .output()
        .unwrap();
    assert!(output.status.success());
    let claims: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(String::from_utf8(output.stdout).unwrap().trim())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(claims["scope"], scope);
}

#[test]
fn signs_an_execution_and_returns_its_submission_request() {
    let dir = tempfile::tempdir().unwrap();
    assert!(
        signer(dir.path())
            .args(["create", "agent"])
            .output()
            .unwrap()
            .status
            .success()
    );
    let expires = (time::OffsetDateTime::now_utc() + time::Duration::seconds(120))
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    let input = json!({
        "signer":"agent", "signing":{
            "version":1, "method":"personal_sign", "encoding":"hex", "data":"0x00ff801234",
            "expiresAt":expires,
            "submission":{"method":"POST","path":"/public/future_operations/finish",
                "headers":{"Content-Type":"application/json"},"body":{"signature":null,"opaqueContext":"retained"}},
        },
    });
    let output = json_command(dir.path(), "sign-execution", &input);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let signed: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        signed["request"]["path"],
        "/public/future_operations/finish"
    );
    assert_eq!(
        signed["request"]["body"]["signature"]
            .as_str()
            .unwrap()
            .len(),
        132
    );
    assert_eq!(signed["request"]["body"]["opaqueContext"], "retained");
    assert_eq!(signed["request"]["body"]["signature"], signed["signature"]);
    assert_eq!(
        signed["request"]["headers"],
        json!({"Content-Type":"application/json"})
    );
}

#[test]
fn reports_invalid_signing_input_without_echoing_the_credential() {
    let dir = tempfile::tempdir().unwrap();
    let output = json_command(
        dir.path(),
        "sign-execution",
        &json!({
            "signer":"agent", "signing":"sensitive-test-bearer",
        }),
    );
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("sensitive-test-bearer"));
    let error: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["code"], "invalid_request");
}

#[test]
fn accepts_the_full_byte_limit_and_returns_only_a_signature_without_submission() {
    let dir = tempfile::tempdir().unwrap();
    assert!(
        signer(dir.path())
            .args(["create", "agent"])
            .output()
            .unwrap()
            .status
            .success()
    );
    let input = json!({"signer":"agent","signing":{
        "version":1,"method":"personal_sign","encoding":"hex","data":format!("0x{}", "ff".repeat(65536)),
    }});
    let output = json_command(dir.path(), "sign-execution", &input);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let signed: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(signed["signature"].as_str().unwrap().len(), 132);
    assert!(signed.get("request").is_none());
    assert!(signed.get("expiresAt").is_none());
}
