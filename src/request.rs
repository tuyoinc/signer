//! Stateless agent identity and operation signing. No transport or OAuth credentials.
use crate::error::{Result, SignerError};
use crate::service::{MessageSignature, Signature};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

const LIFETIME_SECONDS: u64 = 300;
const DEFAULT_ISSUER: &str = "https://api.tuyo.com/";

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct IdentityInput {
    pub signer: String,
    #[serde(default)]
    pub issuer: Option<String>,
    #[serde(default)]
    pub audience: Option<String>,
    #[serde(default = "default_identity_scope")]
    pub scope: String,
}

fn default_identity_scope() -> String {
    "all".into()
}

#[derive(Debug)]
pub struct PreparedIdentity {
    pub digest: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub scope: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedIdentity {
    pub tag: String,
    pub signer: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub scope: String,
    pub token: String,
    pub headers: BTreeMap<String, String>,
    pub next_step: &'static str,
}

impl IdentityInput {
    pub fn prepare(&self, sign_address: &str, now: u64) -> Result<PreparedIdentity> {
        let (issuer, audience) = domain(self.issuer.as_deref(), self.audience.as_deref())?;
        let expires_at = now
            .checked_add(LIFETIME_SECONDS)
            .filter(|_| now > 0)
            .ok_or_else(|| invalid("The system clock must be set correctly before signing."))?;
        let canonical = serde_json_canonicalizer::to_vec(&json!({
            "domain":"tuyo-agent-identity", "version":1, "issuer":issuer, "audience":audience,
            "signAddress":sign_address, "issuedAt":now, "expiresAt":expires_at,
            "scope":self.scope,
        }))
        .map_err(|_| invalid("The identity cannot be encoded."))?;
        Ok(PreparedIdentity {
            digest: format!("0x{}", hex::encode(Sha256::digest(canonical))),
            issued_at: now,
            expires_at,
            scope: self.scope.clone(),
        })
    }
}

impl PreparedIdentity {
    pub fn signed(self, signature: Signature, now: u64) -> Result<SignedIdentity> {
        if self.expires_at.saturating_sub(now) <= 10 || now < self.issued_at {
            return Err(SignerError::new(
                "identity_expired",
                "Run identity again; too little time remains after key approval or the clock changed.",
            ));
        }
        let token = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!({
                "version":1,
                "signAddress":signature.signer,
                "issuedAt":self.issued_at,
                "expiresAt":self.expires_at,
                "scope":self.scope,
                "signature":signature.signature,
            }))
            .map_err(|_| invalid("The identity cannot be encoded."))?,
        );
        Ok(SignedIdentity {
            tag: signature.tag,
            signer: signature.signer,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            scope: self.scope,
            token: token.clone(),
            headers: BTreeMap::from([("Tuyo-Agent-Identity".into(), token)]),
            next_step: "Attach headers to manager requests alongside OAuth. Reusable until expiresAt; run identity again to refresh. On-chain submission also requires sign_execution with this signer. No HTTP request was sent.",
        })
    }
}

/// A stable signing envelope; it carries no execution-specific model or identifiers.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SignExecutionInput {
    pub signer: String,
    pub signing: SigningEnvelope,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SigningEnvelope {
    pub version: u8,
    pub method: String,
    pub encoding: String,
    pub data: String,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub submission: Option<SubmissionTemplate>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmissionTemplate {
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    pub body: serde_json::Map<String, Value>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedExecution {
    #[serde(flatten)]
    pub signed: MessageSignature,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<HttpRequest>,
    pub next_step: &'static str,
}

#[derive(Debug, Serialize)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub headers: BTreeMap<String, String>,
    pub body: Value,
}

pub const MAX_SIGNING_BYTES: usize = 64 * 1024;

pub struct PreparedSigning {
    pub message: Vec<u8>,
    pub expires_at: Option<u64>,
}

impl SigningEnvelope {
    pub fn prepare(&self, now: u64) -> Result<PreparedSigning> {
        if self.version != 1 || self.method != "personal_sign" || self.encoding != "hex" {
            return Err(invalid(
                "Supported signing format: version 1, method personal_sign, encoding hex.",
            ));
        }
        let hex = self
            .data
            .strip_prefix("0x")
            .filter(|v| v.len() <= MAX_SIGNING_BYTES * 2)
            .ok_or_else(|| {
                invalid("signing.data must be 0x-prefixed hex, at most 64 KiB of bytes.")
            })?;
        let message = hex::decode(hex)
            .map_err(|_| invalid("signing.data must encode whole bytes as hexadecimal."))?;
        let expires_at = self.expires_at.as_deref().map(parse_expiry).transpose()?;
        let prepared = PreparedSigning {
            message,
            expires_at,
        };
        prepared.check_expiry(now)?;
        if let Some(template) = &self.submission {
            template.validate()?;
        }
        Ok(prepared)
    }

    pub fn signed(
        &self,
        signed: MessageSignature,
        prepared: PreparedSigning,
        now: u64,
    ) -> Result<SignedExecution> {
        // Key approval can take time. The API also checks its own operation deadline.
        prepared.check_expiry(now)?;
        let request = self
            .submission
            .as_ref()
            .map(|template| template.fill(&signed.signature));
        Ok(SignedExecution {
            signed,
            expires_at: prepared.expires_at,
            request,
            next_step: "Send the returned request, or submit signature as instructed by the backend, with its required authentication. Payload meaning was not checked. No HTTP request was sent.",
        })
    }
}

impl PreparedSigning {
    fn check_expiry(&self, now: u64) -> Result<()> {
        if self.expires_at.is_some_and(|expiry| expiry <= now) {
            return Err(SignerError::new(
                "execution_expired",
                "The signing envelope expired. Ask the backend for current signing instructions.",
            ));
        }
        Ok(())
    }
}

impl SubmissionTemplate {
    fn validate(&self) -> Result<()> {
        if !matches!(self.method.as_str(), "POST" | "PUT" | "PATCH" | "DELETE")
            || !self.path.starts_with('/')
            || self.path.starts_with("//")
            || self.path.len() > 4096
            || self
                .path
                .chars()
                .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '#' | '\\'))
            || self.body.get("signature") != Some(&Value::Null)
        {
            return Err(invalid(
                "submission requires a write method, an origin-relative path, and body.signature set to null.",
            ));
        }
        if self
            .headers
            .iter()
            .any(|(name, value)| !valid_header_name(name) || value.chars().any(char::is_control))
        {
            return Err(invalid("submission headers contain invalid characters."));
        }
        Ok(())
    }

    fn fill(&self, signature: &str) -> HttpRequest {
        let mut body = self.body.clone();
        body.insert("signature".into(), Value::String(signature.into()));
        let mut headers = self.headers.clone();
        if !headers
            .keys()
            .any(|key| key.eq_ignore_ascii_case("content-type"))
        {
            headers.insert("Content-Type".into(), "application/json".into());
        }
        HttpRequest {
            method: self.method.clone(),
            path: self.path.clone(),
            headers,
            body: Value::Object(body),
        }
    }
}

fn parse_expiry(value: &str) -> Result<u64> {
    OffsetDateTime::parse(value, &Rfc3339)
        .ok()
        .and_then(|date| u64::try_from(date.unix_timestamp()).ok())
        .ok_or_else(|| invalid("signing.expiresAt must be an RFC 3339 timestamp."))
}

fn valid_header_name(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

pub fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|time| time.as_secs())
        .map_err(|_| invalid("The system clock must be set correctly before signing."))
}

fn domain(issuer: Option<&str>, audience: Option<&str>) -> Result<(String, String)> {
    let issuer = issuer
        .map(str::to_owned)
        .or_else(|| std::env::var("TUYO_SIGNER_API_ISSUER").ok())
        .unwrap_or_else(|| DEFAULT_ISSUER.into());
    let authority = issuer
        .strip_prefix("https://")
        .or_else(|| issuer.strip_prefix("http://"))
        .and_then(|value| value.split('/').next())
        .unwrap_or_default();
    if authority.is_empty()
        || issuer.contains(['?', '#', '@'])
        || issuer.chars().any(char::is_whitespace)
    {
        return Err(invalid(
            "issuer must be an absolute HTTP(S) URL without credentials, query or fragment.",
        ));
    }
    let issuer = format!("{}/", issuer.trim_end_matches('/'));
    let audience = audience
        .map(str::to_owned)
        .or_else(|| std::env::var("TUYO_SIGNER_API_AUDIENCE").ok())
        .unwrap_or_else(|| format!("{issuer}public"));
    if audience.is_empty() || audience.chars().any(char::is_whitespace) {
        return Err(invalid(
            "audience must be the public API OAuth resource URI.",
        ));
    }
    Ok((issuer, audience))
}

fn invalid(message: &str) -> SignerError {
    SignerError::new("invalid_request", message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{self, SigningKey};

    #[test]
    fn matches_the_api_identity_digest_and_viem_signature() {
        let vectors: Vec<Value> =
            serde_json::from_str(include_str!("../tests/fixtures/agent-identities.json")).unwrap();
        for vector in vectors {
            let input: IdentityInput = serde_json::from_value(vector["input"].clone()).unwrap();
            let now = vector["now"].as_u64().unwrap();
            let prepared = input
                .prepare(vector["signAddress"].as_str().unwrap(), now)
                .unwrap();
            assert_eq!(prepared.digest, vector["digest"]);
            assert_eq!(prepared.expires_at, vector["expiresAt"]);
            let key = SigningKey::from_hex(vector["privateKey"].as_str().unwrap()).unwrap();
            let signature = key
                .sign_digest(&keys::personal_message_digest(
                    &keys::parse_hash(&prepared.digest).unwrap(),
                ))
                .unwrap();
            assert_eq!(signature, vector["signature"]);
            let signed = prepared
                .signed(
                    Signature {
                        tag: "agent".into(),
                        signer: key.address(),
                        hash: vector["digest"].as_str().unwrap().into(),
                        signature,
                    },
                    now,
                )
                .unwrap();
            assert_eq!(signed.headers["Tuyo-Agent-Identity"], vector["header"]);
        }
    }

    #[test]
    fn rejects_expired_identity_after_key_approval() {
        let input: IdentityInput = serde_json::from_value(json!({"signer":"agent"})).unwrap();
        let key = SigningKey::generate();
        let now = 2000000000;
        let prepared = input.prepare(&key.address(), now).unwrap();
        let signature = key
            .sign_digest(&keys::personal_message_digest(
                &keys::parse_hash(&prepared.digest).unwrap(),
            ))
            .unwrap();
        assert_eq!(
            prepared
                .signed(
                    Signature {
                        tag: "agent".into(),
                        signer: key.address(),
                        hash: String::new(),
                        signature
                    },
                    now + 300
                )
                .unwrap_err()
                .code,
            "identity_expired"
        );
    }

    #[test]
    fn signs_scope_strings_without_interpreting_them() {
        let address = SigningKey::generate().address();
        let now = 2000000000;
        let default: IdentityInput = serde_json::from_value(json!({"signer":"agent"})).unwrap();
        let explicit: IdentityInput =
            serde_json::from_value(json!({"signer":"agent", "scope":"all"})).unwrap();
        let scoped: IdentityInput =
            serde_json::from_value(json!({"signer":"agent", "scope":"future:pod/read:🌊"}))
                .unwrap();
        let default = default.prepare(&address, now).unwrap();
        assert_eq!(default.scope, "all");
        assert_eq!(
            default.digest,
            explicit.prepare(&address, now).unwrap().digest
        );
        let scoped = scoped.prepare(&address, now).unwrap();
        assert_eq!(scoped.scope, "future:pod/read:🌊");
        assert_ne!(default.digest, scoped.digest);
    }

    #[test]
    fn rejects_identity_overrides_for_clock_version_or_credentials() {
        for field in [
            "issuedAt",
            "expiresAt",
            "version",
            "accessToken",
            "method",
            "path",
        ] {
            let mut value = json!({"signer":"agent"});
            value[field] = json!("unexpected");
            assert!(serde_json::from_value::<IdentityInput>(value).is_err());
        }
        let input: IdentityInput =
            serde_json::from_value(json!({"signer":"agent", "issuer":"invalid"})).unwrap();
        assert!(
            input
                .prepare(&SigningKey::generate().address(), 2000000000)
                .is_err()
        );
    }

    #[test]
    fn rejects_unsupported_formats_malformed_bytes_and_expired_envelopes() {
        let valid = json!({"version":1,"method":"personal_sign","encoding":"hex","data":"0x1234"});
        for patch in [
            json!({"version":2}),
            json!({"method":"eth_sign"}),
            json!({"encoding":"utf8"}),
            json!({"data":"1234"}),
            json!({"data":"0x1"}),
            json!({"data":"0xgg"}),
            json!({"data":format!("0x{}", "ab".repeat(MAX_SIGNING_BYTES+1))}),
            json!({"expiresAt":"invalid"}),
            json!({"expiresAt":"2033-05-18T03:33:20Z"}),
        ] {
            let mut input = valid.clone();
            input
                .as_object_mut()
                .unwrap()
                .extend(patch.as_object().unwrap().clone());
            let envelope: SigningEnvelope = serde_json::from_value(input).unwrap();
            assert!(envelope.prepare(2000000000).is_err());
        }
    }

    #[test]
    fn checks_expiry_again_after_approval_without_an_operation_specific_margin() {
        let envelope: SigningEnvelope = serde_json::from_value(json!({
            "version":1,"method":"personal_sign","encoding":"hex","data":"0x00",
            "expiresAt":"2033-05-18T03:33:21Z",
        }))
        .unwrap();
        let prepared = envelope.prepare(2000000000).unwrap();
        let signed = MessageSignature {
            tag: "agent".into(),
            signer: String::new(),
            signature: String::new(),
        };
        assert_eq!(
            envelope
                .signed(signed, prepared, 2000000001)
                .unwrap_err()
                .code,
            "execution_expired"
        );
    }

    #[test]
    fn rejects_ambiguous_submission_templates_before_signing() {
        let valid =
            json!({"method":"POST", "path":"/future?request=opaque", "body":{"signature":null}});
        for patch in [
            json!({"method":"GET"}),
            json!({"path":"https://example.com/submit"}),
            json!({"path":"//example.com/submit"}),
            json!({"path":"/submit#fragment"}),
            json!({"path":"/submit with space"}),
            json!({"body":{}}),
            json!({"body":{"signature":"already filled"}}),
            json!({"headers":{"Invalid Name":"value"}}),
            json!({"headers":{"X-Test":"value\r\nInjected: value"}}),
        ] {
            let mut input = valid.clone();
            input
                .as_object_mut()
                .unwrap()
                .extend(patch.as_object().unwrap().clone());
            let template: SubmissionTemplate = serde_json::from_value(input).unwrap();
            assert!(template.validate().is_err());
        }
    }
}
