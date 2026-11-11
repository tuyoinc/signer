# tuyo-signer

An offline signer for Tuyo agents. It keeps secp256k1 keys in the operating system keychain, or in an owner-only file on hosts without one, and signs agent identity assertions and arbitrary backend-prepared bytes with `personal_sign` (EIP-191). It runs as an MCP server over stdio and as a command line tool.

It is a single static binary of about 3.5 MB with no runtime to install. It never prepares operations, calls HTTP APIs or chain RPC, or broadcasts transactions. Signing and MCP make no network requests, including update checks. Only the explicit `status --check` and `update` commands access the internet.

## Install

```sh
curl -fsSL https://github.com/tuyoinc/signer/releases/latest/download/install.sh | sh
```

This installs to `~/.tuyo/bin/tuyo-signer` without root, verifying the download against the release's `SHA256SUMS`. Set `TUYO_SIGNER_VERSION=v0.1.0` for a specific release and `TUYO_SIGNER_INSTALL_DIR` for another directory. Builds exist for Linux (x86_64 and ARM64, static, any distribution including Alpine), macOS (one universal binary) and Windows (x86_64, download the `.exe` from the release).

With Node available, `npx -y @tuyo/signer mcp` runs the same binary from npm.

### MCP configuration

```json
{
  "mcpServers": {
    "tuyo-signer": {
      "command": "tuyo-signer",
      "args": ["mcp"],
      "env": { "TUYO_SIGNER_PROFILE": "plugin" }
    }
  }
}
```

Use the absolute path (`~/.tuyo/bin/tuyo-signer`) if the MCP host doesn't inherit your `PATH`, or `"command": "npx", "args": ["-y", "@tuyo/signer", "mcp"]`.

## Tools

A profile holds any number of signers, each created under a tag. No tool returns or accepts a private key.

| Tool | Input | Returns |
| --- | --- | --- |
| `list_signers` | none | `{signers: [...]}` |
| `get_signer` | `{tag}` | the signer, or `signer_not_found` |
| `create_signer` | `{tag, requireTouchId?}` | the new signer, or the existing one with that tag after checking its key is still there |
| `identity` | `{signer, issuer?, audience?, scope?}` | Opaque five-minute token, headers and expiry; scope is a string defaulting to `all` |
| `sign_execution` | `{signer, signing}` | A signature over backend-prepared bytes, plus a ready-to-send request when a submission template is supplied |
| `sign_hash` | `{signer, hash}`, where `signer` is an address or a tag | `{tag, signer, hash, signature}` |
| `get_status` | none | version, profile, key storage and update status |

A signer is `{tag, algorithm: "secp256k1", publicKey, address, storage, createdAt, requireTouchId?}`. `address` is what you register as the onchain signer. `storage` is `keychain` or `file`.

Failed calls return `isError` with `{code, message}`. Codes include `signer_not_found`, `key_missing`, `wrong_key`, `storage_mismatch`, `keychain_unavailable`, `touch_id_denied`, `profile_busy`, `execution_expired`, `identity_expired` and `update_required`.

## Command line

The same operations print JSON on stdout. Errors print `{code, message}` on stderr and exit with status 1.

```sh
tuyo-signer create agent                  # create or show a signer
tuyo-signer create mac --require-touch-id # macOS: Touch ID for every signature
tuyo-signer list
tuyo-signer get agent
tuyo-signer identity --signer agent       # opaque five-minute token only
tuyo-signer identity --signer agent --json # structured metadata and headers
tuyo-signer identity --signer agent --scope all # optional string; API defines its meaning
tuyo-signer sign-execution < signing-input.json
tuyo-signer sign-hash --signer agent --hash 0x…  # low-level hash signing
tuyo-signer status --check                # version, storage, update status
tuyo-signer update                        # install the latest release
tuyo-signer mcp                           # MCP server on stdio
```

## Manager identity and execution

```sh
tuyo-signer identity --signer agent
```

Or call the MCP tool `identity({ signer: "agent" })`. No OAuth token, timestamp, protocol version,
HTTP request data or API challenge is needed. The signer fills those protocol fields locally and
prints only an opaque token and a newline. Attach it as `Tuyo-Agent-Identity` alongside OAuth;
callers do not need to decode or construct it. CLI `--json` and MCP return the original signing
address, `issuedAt`, `expiresAt`, `scope`, `token`, and
`headers: { "Tuyo-Agent-Identity": "<opaque token>" }`.
Copy those headers into the HTTP tool alongside OAuth. Identity lasts five minutes; reuse it across
requests or request a fresh assertion each time. After expiry, call `identity` again. The signer
stores no assertion or identity session and the API does not consume a nonce.

Optional `--scope` / MCP `scope` is an arbitrary string, signed unchanged and defaulting to
`"all"`. The signer has no scope allowlist, so future scopes need only API changes. The API
currently accepts only `"all"` and rejects other values. `"all"` adds no identity-token restriction;
it does not grant permissions or bypass OAuth, owner consent, manager grants or operation
signatures. The scope is always present in the token, even when the option is omitted.

All manager proposal and execution requests require identity. Ordinary API reads and purchase
intents retain their existing authentication for now. Future purchase and nickname/logo flows can
use this identity once they associate each resource with its original agent key.

A send or swap works as follows:

1. Obtain identity with the command above.
2. Prepare with `POST /public/agent_executions`, OAuth, the identity header and a UUID
   `Idempotency-Key`. The body is `{ "podId": "<pod UUID>", "intent": <send or convert intent> }`.
   The API derives the manager from identity; OAuth alone cannot prepare an operation.
3. Call `sign_execution({ signer: "agent", signing: preparedResponse.signing })`, or pass that
   JSON on stdin to `tuyo-signer sign-execution`. The backend supplies the complete signing
   envelope, including any submission instructions. The CLI signs the bytes once and returns
   `signature`, plus a ready-to-send `request` when submission instructions are present.
4. Send that request with OAuth and an unexpired identity header **from the same signer**.
   Identity proves the caller's key; the separate operation signature authorizes the saved operation.
5. Read `GET /public/agent_executions/<id>` with OAuth and identity until completion.

Both signing tools are fully offline. Touch ID keys need approval for each identity signature
and each operation signature. The signing envelope's expiry is separate from identity expiry.

Preserve the idempotency key and original intent after ambiguous preparation responses. Retry the
same submitted execution or read status after an ambiguous submission. Refreshing identity does
not create a new execution. There is no automatic owner-proposal fallback.

Identity signs a domain-separated SHA-256 digest of canonical JSON containing `domain:
"tuyo-agent-identity"`, `version: 1`, API issuer/audience, checksummed `signAddress`, `issuedAt`,
`expiresAt` and `scope`. It uses EIP-191 over 32 bytes. The token is unpadded base64url of UTF-8
JSON containing `version`, `signAddress`, `issuedAt`, `expiresAt`, `scope` and `signature`.
Encoding is not encryption. The API requires scope on the wire and verifies the recovered
address against the signed address, then matches the resource's
original key. Maximum lifetime is 300 seconds, with 60 seconds of future-clock tolerance and no
expiry grace. An assertion is reusable and deliberately independent of request contents and OAuth;
treat its header as a temporary credential. It cannot replace OAuth or an operation signature.

Configure another environment with `--issuer` / `--audience`, MCP overrides, or the corresponding
environment variables below. The earlier unshipped `sign-request` tool is replaced by `identity`,
and the unshipped colon-delimited identity header is replaced by the opaque token.

## Generic byte signing protocol

Pass the backend's signing envelope without reconstructing it:

```json
{
  "signer": "agent",
  "signing": {
    "version": 1,
    "method": "personal_sign",
    "encoding": "hex",
    "data": "0x00ff1234",
    "expiresAt": "<optional RFC 3339 deadline>",
    "submission": {
      "method": "POST",
      "path": "/public/<backend-chosen-submit-path>",
      "headers": { "Content-Type": "application/json" },
      "body": { "signature": null, "context": "<backend-provided value>" }
    }
  }
}
```

Only `version`, `method`, `encoding` and `data` are required inside `signing`. Version 1 signs the
exact decoded bytes using EIP-191, including the actual decimal byte length in its prefix.
`0x` signs an empty message. Data can be up to 65,536 bytes; CLI JSON input is limited to 256 KiB.
Unknown versions, methods, encodings and fields are rejected. Preserve version 1 for future
operations that use these same rules; new payload contents and endpoints need no CLI update.

This is blind signing. The CLI validates formatting, size and optional expiry, opens the selected
key, obtains Touch ID approval when required, and signs. It does not check operation status,
execution IDs, UserOperation fields, network, recipients, amounts or the meaning of any bytes.
The backend remains responsible for constructing the correct bytes and verifying the signature
against its authoritative operation, permissions, deadlines and replay protection.

`expiresAt`, when supplied, must still be in the future both before signing and after key approval.
There is no operation-specific minimum time margin in this generic protocol. A backend may enforce
its own stricter submission deadline, as manager execution does.

`submission` is optional and never triggers networking. It accepts POST, PUT, PATCH or DELETE,
an origin-relative path (queries allowed; no host or fragment), optional headers, and a JSON body
whose top-level `signature` is null. The CLI fills that field and preserves all other fields,
adding JSON content type if absent. It returns the signature separately in all cases. With no
submission, no `request` is returned. If expiry was supplied, the output includes `expiresAt`
as Unix seconds. Attach the authentication required by the backend before sending the request.

Envelope expiry and submission metadata are not included in the signature automatically. Any
signed constraints must be encoded by the backend in `data` under the verifying protocol.
Existing manager operations still supply the same 32-byte digest as before, so their signatures
remain compatible. `sign_hash` stays available for callers that explicitly want a 32-byte input;
identity keeps its existing versioned protocol.

The shared `tests/fixtures/execution-signing.json` vectors match the API's viem implementation
for empty, binary and UTF-8 byte sequences, including decimal message-length boundaries.

## Key storage

| Backend | Where the key lives | Who can read it |
| --- | --- | --- |
| `keychain` | macOS login keychain, Windows Credential Manager or Linux Secret Service, under service `com.tuyo.signer` with the signer's address as the account. Keys that earlier versions stored under a hashed account name are found and moved to their address. | macOS: only this binary without a prompt; the item's access list trusts the binary that created it, and release builds are signed with Tuyo's Developer ID so updates keep access. Windows and Linux: any process of the same user. Encrypted at rest. |
| `file` | `<tag>.key` in the profile's `keys/` directory, or `TUYO_SIGNER_KEY_DIR`, mode `0600` in a `0700` directory | Any process running as the same user, and anyone who can read the disk or its backups. Refused if it is a symlink, not owned by this user or readable by others. |

`TUYO_SIGNER_KEY_STORAGE` picks the backend for new signers:

- `auto` (default): the credential store if it answers within a few seconds, otherwise a key file. On Linux the credential store is only tried when a D-Bus session exists, so servers, containers and agent VMs go straight to a file with no setup. The result reports which one was used.
- `keychain`: always the credential store; fails with `keychain_unavailable` when there isn't one.
- `file`: always a key file.

An existing signer is only ever read from the backend recorded for it in `state.json`. If `TUYO_SIGNER_KEY_STORAGE` names a different one, operations on it fail with `storage_mismatch` instead of looking elsewhere. A missing key is never replaced: `create_signer` and `sign_hash` fail with `key_missing`.

Neither backend stops a process running as the same user from asking the signer to sign. The onchain policy and Tuyo's cosigner are what limit what a signature can do.

### Touch ID (macOS)

A signer created with `--require-touch-id` (or `requireTouchId: true`) asks for Touch ID before every signature, falling back to the login password when the sensor can't be used. The setting is stored with the key in the keychain, not only in `state.json`, so editing the profile can't turn it off, and it can't be changed after creation. Creating one needs a Mac with Touch ID set up. Signing needs someone at the Mac: over SSH, or with nobody logged in, it fails with `touch_id_denied` or `touch_id_timeout` after two minutes.

### Remote agents

On agent machines, the defaults need nothing set: no Node, no root, no D-Bus, no TPM. Keys go to owner-only files in `~/.local/share/tuyo/signer/<profile>/keys/`. To keep keys away from the agent itself, run the signer as a separate system user that owns the profile directory, and keep the directory out of images and backups.

The profile lock is an OS file lock, released even if a process crashes. A second process waits up to 30 seconds for it, then fails with `profile_busy`.

## Configuration

| Variable | Default | |
| --- | --- | --- |
| `TUYO_SIGNER_PROFILE` | `default` | Profile name: letters, digits, `_`, `-` |
| `TUYO_SIGNER_DATA_DIR` | `~/.local/share/tuyo/signer/<profile>` | Holds `state.json` (public metadata only) |
| `TUYO_SIGNER_KEY_DIR` | `<data dir>/keys` | Key files |
| `TUYO_SIGNER_KEY_STORAGE` | `auto` | `auto`, `keychain` or `file` |
| `TUYO_SIGNER_API_ISSUER` | `https://api.tuyo.com/` | Issuer used to bind offline identity assertions |
| `TUYO_SIGNER_API_AUDIENCE` | `<issuer>public` | Public API resource URI used to bind identity assertions |
| `TUYO_SIGNER_CACHE_DIR` | platform cache directory | Where the last verified release manifest is kept |
| `HTTPS_PROXY`, `NO_PROXY` | | Used for update downloads; the system's CA certificates are trusted |

`--profile`, `--data-dir` and `--storage` override the first, second and fourth.

## Updates

Signing and MCP never check for updates or install them. `get_status` reads cached release information only. Run `tuyo-signer status --check` to explicitly check for a release, or `tuyo-signer update` to check and install it. The old `TUYO_SIGNER_UPDATE_CHECK` and `TUYO_SIGNER_AUTO_UPDATE` settings no longer trigger networking from MCP. An update is installed only if:

1. The release's `manifest.json` verifies against the Ed25519 key compiled into the binary.
2. The download matches the SHA-256 in that manifest.
3. On macOS, it is signed by Tuyo's Apple team with the identifier `com.tuyo.signer`.
4. It runs and reports the version the manifest names.

The binary is then replaced in one step; a running MCP session keeps the old version until it restarts. A manifest can set `minimumVersion`, below which the signer refuses to sign until updated. Copies installed with npm or Homebrew tell you to update through those instead. Builds without an update key, such as local builds, never update themselves.

## Development

```sh
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
```

Tests use temporary profiles with in-memory or file key storage and never touch real keychain entries. Releases are described in [RELEASING.md](RELEASING.md).

## Security

Report vulnerabilities privately to support@tuyo.com rather than opening a public issue.

## License

MIT or Apache-2.0, at your option.
