//! A minimal MCP server over stdio (newline-delimited JSON-RPC 2.0). The
//! signer has a small fixed tool set and no other capabilities, so the protocol is
//! implemented directly instead of through an SDK.

use std::io::{BufRead, Write};

use serde_json::{Map, Value, json};

use crate::error::SignerError;
use crate::request::{IdentityInput, SignExecutionInput};
use crate::service::Service;
use crate::update::{Updater, VERSION};

const PROTOCOL_VERSIONS: &[&str] = &["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];

const INSTRUCTIONS: &str = "Offline Tuyo signer. Call identity with the original agent signer, then attach headers.Tuyo-Agent-Identity alongside OAuth on every manager request, including preparation, status and submission. Identity lasts five minutes and can be reused or refreshed for each request. For on-chain execution, also call sign_execution with the unchanged backend-provided signing envelope and the same signer; attach identity when sending its returned submission. Neither tool needs an OAuth credential. Identity proves the key, not approval of a transaction. Keys remain local; never request or reveal private keys. No signer tool sends HTTP requests or broadcasts; MCP never checks for updates online.";

struct Tool {
    name: &'static str,
    description: &'static str,
    read_only: bool,
    /// (name, JSON schema, required)
    params: &'static [(&'static str, &'static str, bool)],
}

const TAG: &str = r#"{"type":"string","pattern":"^[a-zA-Z0-9_-]{1,64}$","description":"1 to 64 letters, digits, _ or -, unique within the profile."}"#;
const SIGNER: &str = r#"{"type":"string","pattern":"^(0x[0-9a-fA-F]{40}|[a-zA-Z0-9_-]{1,64})$","description":"The signer's address or tag."}"#;
const HASH: &str = r#"{"type":"string","pattern":"^0x[0-9a-fA-F]{64}$","description":"The 32-byte hash to sign, exactly as the preparing flow supplied it."}"#;
const TOUCH_ID: &str = r#"{"type":"boolean","description":"macOS only. Require Touch ID (or the login password) for every signature with this signer. Set only when the user asked for it; it cannot be changed later."}"#;
const ISSUER: &str = r#"{"type":"string","description":"Optional OAuth issuer override. Defaults to TUYO_SIGNER_API_ISSUER, or https://api.tuyo.com/. No URL is fetched."}"#;
const AUDIENCE: &str = r#"{"type":"string","description":"Optional public API OAuth resource URI override. Defaults to TUYO_SIGNER_API_AUDIENCE, or issuer + public."}"#;
const SCOPE: &str = r#"{"type":"string","default":"all","description":"Opaque scope signed unchanged; the API defines and enforces supported values. Defaults to all, adding no restriction to existing permissions."}"#;
const SIGNING: &str = r#"{"type":"object","additionalProperties":false,"required":["version","method","encoding","data"],"properties":{"version":{"const":1},"method":{"const":"personal_sign"},"encoding":{"const":"hex"},"data":{"type":"string","pattern":"^0x([0-9a-fA-F]{2})*$","maxLength":131074},"expiresAt":{"type":"string","format":"date-time"},"submission":{"type":"object","additionalProperties":false,"required":["method","path","body"],"properties":{"method":{"enum":["POST","PUT","PATCH","DELETE"]},"path":{"type":"string","maxLength":4096,"description":"Origin-relative backend path; no host or fragment."},"headers":{"type":"object","additionalProperties":{"type":"string"}},"body":{"type":"object","required":["signature"],"properties":{"signature":{"type":"null"}},"additionalProperties":true}}}},"description":"Copy the complete signing object supplied by the backend. Signs data as exact bytes; it does not interpret or verify the operation's meaning. Optional submission instructions produce a ready-to-send request with body.signature filled."}"#;

const TOOLS: &[Tool] = &[
    Tool {
        name: "list_signers",
        description: "List every signer in this profile with its tag, public key, onchain address, key storage and creation time, without opening any key.",
        read_only: true,
        params: &[],
    },
    Tool {
        name: "get_signer",
        description: "Read one signer by tag: its public key, onchain address, key storage and creation time, without opening the key.",
        read_only: true,
        params: &[("tag", TAG, true)],
    },
    Tool {
        name: "create_signer",
        description: "Create a signer with a new key under a tag, or return the existing signer with that tag. A new key goes to the OS credential store, or to an owner-only key file on hosts without one. Returns only public metadata, including where the key is stored.",
        read_only: false,
        params: &[("tag", TAG, true), ("requireTouchId", TOUCH_ID, false)],
    },
    Tool {
        name: "identity",
        description: "Prove possession of the original agent key offline. Pass only signer (tag or address); clock, protocol version and five-minute expiry are automatic. Returns an opaque token, scope, expiry and headers.Tuyo-Agent-Identity ready to attach alongside OAuth to every manager request, including preparation, status and submission. Optional scope is any string, signed unchanged and defaulting to all; the API defines and enforces supported values. Reuse until expiresAt or call again for each request. No OAuth credential, HTTP request data or server challenge is needed. This authenticates identity; on-chain execution still needs its separate operation signature from sign_execution. Nothing is sent or persisted. Touch ID keys require approval.",
        read_only: false,
        params: &[
            ("signer", SIGNER, true),
            ("issuer", ISSUER, false),
            ("audience", AUDIENCE, false),
            ("scope", SCOPE, false),
        ],
    },
    Tool {
        name: "sign_execution",
        description: "Sign arbitrary backend-prepared bytes offline with the selected key using personal_sign. Pass signer and the backend's signing envelope unchanged. Returns signature and, when submission is provided, a request with body.signature filled. Does not parse execution IDs, status, chains or calldata and does not verify payload meaning. No OAuth credential is needed. Send the result with the backend's required authentication; manager flows also require identity from the same key. Nothing is sent. Touch ID keys require one approval.",
        read_only: false,
        params: &[("signer", SIGNER, true), ("signing", SIGNING, true)],
    },
    Tool {
        name: "sign_hash",
        description: "Sign a 32-byte hash, such as a UserOperation hash, using personal_sign (EIP-191) with the signer whose address or tag is given. Signers created with requireTouchId wait for the user to approve with Touch ID. Returns only the signer tag and address, the hash and the signature. Sign only a hash supplied by a trusted Tuyo flow for an operation the user requested. Does not authorize permissions, access HTTP APIs or broadcast transactions.",
        read_only: false,
        params: &[("signer", SIGNER, true), ("hash", HASH, true)],
    },
    Tool {
        name: "get_status",
        description: "Read the signer's version, profile, default key storage and whether an update is available or required, without opening any key.",
        read_only: true,
        params: &[],
    },
];

pub struct Server<'a> {
    pub service: &'a Service,
    pub updater: &'a Updater,
    pub profile: String,
    pub storage: &'static str,
}

impl Server<'_> {
    pub fn run(&self, input: impl BufRead, mut output: impl Write) -> std::io::Result<()> {
        for line in input.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            if let Some(response) = self.handle_line(&line) {
                serde_json::to_writer(&mut output, &response)?;
                output.write_all(b"\n")?;
                output.flush()?;
            }
        }
        Ok(())
    }

    pub fn handle_line(&self, line: &str) -> Option<Value> {
        let Ok(message) = serde_json::from_str::<Value>(line) else {
            return Some(error_response(Value::Null, -32700, "Parse error"));
        };
        let Some(object) = message.as_object() else {
            return Some(error_response(Value::Null, -32600, "Invalid request"));
        };
        let method = object.get("method").and_then(Value::as_str);
        let id = object.get("id").cloned();
        let (Some(method), Some(id)) = (method, id) else {
            // Notifications and responses need no answer.
            return None;
        };
        let params = object.get("params").cloned().unwrap_or(Value::Null);
        Some(match self.dispatch(method, &params) {
            Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
            Err((code, message)) => error_response(id, code, &message),
        })
    }

    fn dispatch(&self, method: &str, params: &Value) -> Result<Value, (i64, String)> {
        match method {
            "initialize" => {
                let requested = params.get("protocolVersion").and_then(Value::as_str);
                let version = requested
                    .filter(|v| PROTOCOL_VERSIONS.contains(v))
                    .unwrap_or(PROTOCOL_VERSIONS[0]);
                Ok(json!({
                    "protocolVersion": version,
                    "capabilities": {"tools": {"listChanged": false}},
                    "serverInfo": {"name": "com.tuyo.signer", "title": "Tuyo signer", "version": VERSION},
                    "instructions": INSTRUCTIONS,
                }))
            }
            "ping" => Ok(json!({})),
            "tools/list" => Ok(json!({"tools": TOOLS.iter().map(tool_json).collect::<Vec<_>>()})),
            "tools/call" => {
                let name = params
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let empty = Map::new();
                let arguments = match params.get("arguments") {
                    None | Some(Value::Null) => &empty,
                    Some(Value::Object(map)) => map,
                    Some(_) => return Err((-32602, "arguments must be an object".into())),
                };
                let tool = TOOLS
                    .iter()
                    .find(|t| t.name == name)
                    .ok_or_else(|| (-32602, format!("Unknown tool: {name}")))?;
                Ok(tool_result(self.call(tool, arguments)))
            }
            _ => Err((-32601, format!("Method not found: {method}"))),
        }
    }

    fn call(&self, tool: &Tool, args: &Map<String, Value>) -> Result<Value, SignerError> {
        for key in args.keys() {
            if !tool.params.iter().any(|(name, _, _)| name == key) {
                return Err(invalid(&format!("Unexpected argument {key}.")));
            }
        }
        let string = |name: &str| -> Result<&str, SignerError> {
            args.get(name)
                .and_then(Value::as_str)
                .ok_or_else(|| invalid(&format!("{name} must be a string.")))
        };
        let value = match tool.name {
            "list_signers" => to_value(self.service.list_signers()?),
            "get_signer" => to_value(self.service.get_signer(string("tag")?)?),
            "create_signer" => {
                let touch_id = match args.get("requireTouchId") {
                    None => false,
                    Some(Value::Bool(b)) => *b,
                    Some(_) => return Err(invalid("requireTouchId must be a boolean.")),
                };
                to_value(self.service.create_signer(string("tag")?, touch_id)?)
            }
            "sign_hash" => to_value(self.service.sign_hash(string("signer")?, string("hash")?)?),
            "identity" => {
                let input: IdentityInput = serde_json::from_value(Value::Object(args.clone()))
                    .map_err(|_| invalid("Check the identity arguments and their types."))?;
                to_value(self.service.identity(&input)?)
            }
            "sign_execution" => {
                let input: SignExecutionInput = serde_json::from_value(Value::Object(args.clone()))
                    .map_err(|_| invalid("Check the sign_execution arguments and their types."))?;
                to_value(self.service.sign_execution(&input)?)
            }
            "get_status" => {
                let mut status = to_value(self.updater.status());
                status["profile"] = json!(self.profile);
                status["keyStorage"] = json!(self.storage);
                status
            }
            _ => unreachable!("tool list is fixed"),
        };
        Ok(value)
    }
}

fn tool_json(tool: &Tool) -> Value {
    let mut properties = Map::new();
    let mut required = Vec::new();
    for (name, schema, is_required) in tool.params {
        properties.insert(
            (*name).into(),
            serde_json::from_str(schema).expect("valid schema"),
        );
        if *is_required {
            required.push(*name);
        }
    }
    json!({
        "name": tool.name,
        "description": tool.description,
        "inputSchema": {
            "type": "object",
            "properties": properties,
            "required": required,
            "additionalProperties": false,
        },
        "annotations": {
            "readOnlyHint": tool.read_only,
            "destructiveHint": !tool.read_only,
            "idempotentHint": tool.name != "identity",
            "openWorldHint": false,
        },
    })
}

fn tool_result(result: Result<Value, SignerError>) -> Value {
    match result {
        Ok(value) => json!({
            "content": [{"type": "text", "text": value.to_string()}],
            "structuredContent": value,
        }),
        Err(error) => json!({
            "isError": true,
            "content": [{"type": "text", "text": json!({"code": error.code, "message": error.message}).to_string()}],
        }),
    }
}

fn to_value(value: impl serde::Serialize) -> Value {
    serde_json::to_value(value).expect("serializable")
}

fn invalid(message: &str) -> SignerError {
    SignerError::new("invalid_request", message)
}

fn error_response(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backends::StorageSetting;
    use crate::service::tests::fixture;

    fn call(server: &Server, id: u64, method: &str, params: Value) -> Value {
        let line =
            json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}).to_string();
        server.handle_line(&line).unwrap()
    }

    #[test]
    fn speaks_mcp() {
        let dir = tempfile::tempdir().unwrap();
        let f = fixture(dir.path(), StorageSetting::Auto, false, true);
        let updater = Updater {
            url: String::new(),
            cache_dir: None,
            public_key: None,
        };
        let server = Server {
            service: &f.service,
            updater: &updater,
            profile: "default".into(),
            storage: "auto",
        };

        let init = call(
            &server,
            1,
            "initialize",
            json!({"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}),
        );
        assert_eq!(init["result"]["protocolVersion"], "2025-06-18");
        assert_eq!(init["result"]["serverInfo"]["name"], "com.tuyo.signer");
        assert!(
            server
                .handle_line(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#)
                .is_none()
        );

        let tools = call(&server, 2, "tools/list", json!({}));
        let names: Vec<_> = tools["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert_eq!(
            names,
            [
                "list_signers",
                "get_signer",
                "create_signer",
                "identity",
                "sign_execution",
                "sign_hash",
                "get_status"
            ]
        );

        let created = call(
            &server,
            3,
            "tools/call",
            json!({"name": "create_signer", "arguments": {"tag": "agent"}}),
        );
        let signer = &created["result"]["structuredContent"];
        assert_eq!(signer["storage"], "file");
        assert_eq!(signer["tag"], "agent");

        let hash = format!("0x{}", "ab".repeat(32));
        let signed = call(
            &server,
            4,
            "tools/call",
            json!({"name": "sign_hash", "arguments": {"signer": signer["address"], "hash": hash}}),
        );
        assert_eq!(signed["result"]["structuredContent"]["hash"], hash);

        let request = call(
            &server,
            8,
            "tools/call",
            json!({
                "name":"identity", "arguments":{
                    "signer":"agent",
                },
            }),
        );
        assert!(
            request["result"]["structuredContent"]["headers"]["Tuyo-Agent-Identity"].is_string()
        );
        assert!(!request.to_string().contains("mcp-test-bearer"));
        let identity = &request["result"]["structuredContent"];
        assert_eq!(identity["scope"], "all");
        assert_eq!(
            identity["token"],
            identity["headers"]["Tuyo-Agent-Identity"]
        );
        let scoped = call(
            &server,
            10,
            "tools/call",
            json!({
                "name":"identity", "arguments":{"signer":"agent", "scope":"future:pod/read"}
            }),
        );
        assert_eq!(
            scoped["result"]["structuredContent"]["scope"],
            "future:pod/read"
        );

        let expires = (time::OffsetDateTime::now_utc() + time::Duration::seconds(120))
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();
        let submission = call(
            &server,
            9,
            "tools/call",
            json!({
                "name":"sign_execution", "arguments":{
                    "signer":"agent", "signing":{
                        "version":1,"method":"personal_sign","encoding":"hex","data":"0x00ff", "expiresAt":expires,
                        "submission":{"method":"PUT","path":"/public/future_submission", "body":{"signature":null}},
                    },
                },
            }),
        );
        assert!(
            submission["result"]["structuredContent"]["request"]["body"]["signature"].is_string()
        );
        assert!(!submission.to_string().contains("mcp-test-bearer"));

        let extra = call(
            &server,
            5,
            "tools/call",
            json!({"name": "get_signer", "arguments": {"tag": "agent", "x": 1}}),
        );
        assert_eq!(extra["result"]["isError"], true);
        assert!(
            extra["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("invalid_request")
        );

        let status = call(&server, 6, "tools/call", json!({"name": "get_status"}));
        assert_eq!(status["result"]["structuredContent"]["version"], VERSION);

        assert_eq!(call(&server, 7, "nope", json!({}))["error"]["code"], -32601);
        assert_eq!(server.handle_line("{").unwrap()["error"]["code"], -32700);
    }
}
