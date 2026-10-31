# tuyo-signer

An offline signer for Tuyo agents. It keeps secp256k1 keys in the operating system keychain, or in an owner-only file on hosts without one, and signs 32-byte hashes, such as UserOperation hashes, with `personal_sign` (EIP-191). It runs as an MCP server over stdio and as a command line tool.

It is a single static binary of about 3.5 MB with no runtime to install. It never prepares operations, calls HTTP APIs or chain RPC, or broadcasts transactions. The only network access is the optional update check.

It replaces the Node signer in `tuyoinc/mcp/signer` and reads its profiles, key files and keychain entries as they are.

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
| `sign_hash` | `{signer, hash}`, where `signer` is an address or a tag | `{tag, signer, hash, signature}` |
| `get_status` | none | version, profile, key storage and update status |

A signer is `{tag, algorithm: "secp256k1", publicKey, address, storage, createdAt, requireTouchId?}`. `address` is what you register as the onchain signer. `storage` is `keychain` or `file`.

Failed calls return `isError` with `{code, message}`. Codes include `signer_not_found`, `key_missing`, `wrong_key`, `storage_mismatch`, `keychain_unavailable`, `touch_id_denied`, `profile_busy` and `update_required`.

## Command line

The same operations print JSON on stdout. Errors print `{code, message}` on stderr and exit with status 1.

```sh
tuyo-signer create agent                  # create or show a signer
tuyo-signer create mac --require-touch-id # macOS: Touch ID for every signature
tuyo-signer list
tuyo-signer get agent
tuyo-signer sign-hash --signer agent --hash 0x…  # tag or address
tuyo-signer status --check                # version, storage, update status
tuyo-signer update                        # install the latest release
tuyo-signer mcp                           # MCP server on stdio
```

## Key storage

| Backend | Where the key lives | Who can read it |
| --- | --- | --- |
| `keychain` | macOS login keychain, Windows Credential Manager or Linux Secret Service, under service `com.tuyo.signer` and an account derived from the data directory and tag | macOS: only this binary without a prompt; the item's access list trusts the binary that created it, and release builds are signed with Tuyo's Developer ID so updates keep access. Windows and Linux: any process of the same user. Encrypted at rest. |
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
| `TUYO_SIGNER_UPDATE_CHECK` | on | `0` disables the daily update check in `mcp` |
| `TUYO_SIGNER_AUTO_UPDATE` | off | `1` installs new releases automatically from `mcp`, for machines you run |
| `TUYO_SIGNER_CACHE_DIR` | platform cache directory | Where the last verified release manifest is kept |
| `HTTPS_PROXY`, `NO_PROXY` | | Used for update downloads; the system's CA certificates are trusted |

`--profile`, `--data-dir` and `--storage` override the first, second and fourth.

## Updates

Release builds check for a new release at most once a day while `mcp` runs, and `get_status` reports it. `tuyo-signer update` installs it. An update is installed only if:

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
