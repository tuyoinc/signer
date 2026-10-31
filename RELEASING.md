# Releasing

Push a tag matching the version in `Cargo.toml` on `main`:

```sh
git tag v0.1.0 && git push origin v0.1.0
```

`.github/workflows/release.yml` then builds every target, signs what it has credentials for, and publishes a GitHub Release with the binaries, `SHA256SUMS`, `manifest.json` (+ `.sig`), `install.sh` and build provenance attestations. A tag with a suffix, such as `v0.2.0-rc.1`, becomes a prerelease and is not published to npm or picked up by `releases/latest`.

| Asset | Built on |
| --- | --- |
| `tuyo-signer-x86_64-unknown-linux-musl` | `ubuntu-24.04` |
| `tuyo-signer-aarch64-unknown-linux-musl` | `ubuntu-24.04-arm` |
| `tuyo-signer-universal-apple-darwin` | `macos-15`, both architectures merged with `lipo` |
| `tuyo-signer-x86_64-pc-windows-msvc.exe` | `windows-2025` |

Everything below is optional: without it, releases still build and publish, with the gaps noted as warnings on the run.

## macOS signing and notarization

Uses the same Developer ID Application certificate and notarization login as pulgar. No App ID or provisioning profile is needed: the signer uses the regular login keychain and LocalAuthentication, which need no entitlements.

Create a `macos-signing` environment on this repository with:

| Name | Kind | Value |
| --- | --- | --- |
| `MACOS_SIGNING_CERTIFICATE_P12_BASE64` | secret | The Developer ID Application certificate and private key, exported from Keychain Access as `.p12`, then `base64 -i cert.p12` |
| `MACOS_SIGNING_CERTIFICATE_PASSWORD` | secret | The `.p12` export password |
| `APPLE_NOTARY_APP_PASSWORD` | secret | An app-specific password for the notarization Apple Account |
| `APPLE_TEAM_ID` | variable | The 10-character Team ID |
| `APPLE_NOTARY_APPLE_ID` | variable | The notarization Apple Account email |

With these set, the job imports the certificate into a temporary keychain, signs with hardened runtime, a secure timestamp and the identifier `com.tuyo.signer`, submits to `notarytool` and waits, and deletes the keychain afterwards. It also compiles the Team ID into the binary, so its self-update only accepts binaries from the same team. A bare binary can't be stapled; Gatekeeper checks the ticket online on first launch from a browser download, and installs through `curl` or `npx` aren't quarantined.

Without them, the binary is ad-hoc signed with the same identifier. It runs, but macOS ties keychain access to that exact build, so each new version prompts once for the keychain, and browser downloads are blocked by Gatekeeper.

Keep the identifier `com.tuyo.signer` and the team unchanged: the keychain's trust in existing keys depends on them.

## Update signing key

Self-update trusts only manifests signed with this key. Generate it once, offline:

```sh
openssl genpkey -algorithm ed25519 -out tuyo-signer-update.pem
openssl pkey -in tuyo-signer-update.pem -pubout -outform DER | tail -c 32 | od -An -tx1 | tr -d ' \n'; echo
```

- Repository variable `UPDATE_PUBLIC_KEY`: the 64 hex characters printed by the second command. It is compiled into every build.
- Repository secret `UPDATE_SIGNING_KEY`: the full contents of `tuyo-signer-update.pem`.

Keep an offline backup of the `.pem`. Builds made before the variable was set can't update themselves; reinstall them once. Rotating the key means shipping one release signed with the old key whose binary embeds the new one.

To stop old versions from signing after a security fix, set the repository variable `MINIMUM_VERSION` (for example `0.3.1`) before tagging. Installed signers enforce it the next time they check for updates.

## npm

Stable releases are also published as `@tuyo/signer` plus one package per platform (`@tuyo/signer-darwin`, `-linux-x64`, `-linux-arm64`, `-win32-x64`) when an `npm` environment has an `NPM_TOKEN` secret with publish rights to the `@tuyo` scope.

## Windows

Windows builds are not Authenticode signed yet, so SmartScreen may warn on download. Azure Trusted Signing is the cheapest way to add it.
