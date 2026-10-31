//! Self-update from signed GitHub Releases.
//!
//! Every release publishes `manifest.json`, signed with an offline Ed25519 key
//! whose public half is compiled into the binary (`TUYO_SIGNER_UPDATE_PUBLIC_KEY`
//! at build time). An update is installed only if the manifest verifies, the
//! download matches its SHA-256, the new binary runs and reports the expected
//! version and, on macOS release builds, it is signed by the same Apple team.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{Result, SignerError};
use crate::fsutil;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const TARGET: &str = env!("TUYO_SIGNER_TARGET");
const PUBLIC_KEY: Option<&str> = option_env!("TUYO_SIGNER_UPDATE_PUBLIC_KEY");
const APPLE_TEAM_ID: Option<&str> = option_env!("TUYO_SIGNER_APPLE_TEAM_ID");
const DEFAULT_URL: &str = "https://github.com/tuyoinc/signer/releases/latest/download/";
const CHECK_EVERY: Duration = Duration::from_secs(24 * 60 * 60);
const MAX_DOWNLOAD: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Manifest {
    pub name: String,
    pub version: String,
    /// Older versions refuse to sign until updated.
    #[serde(default)]
    pub minimum_version: Option<String>,
    /// Keyed by Rust target triple.
    pub assets: std::collections::BTreeMap<String, Asset>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Asset {
    pub url: String,
    pub sha256: String,
}

/// A verified manifest as cached on disk, kept with its signature so it is
/// verified again whenever it is read.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Cache {
    checked_at: u64,
    manifest: String,
    signature: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub version: &'static str,
    pub target: &'static str,
    /// False for builds without an update key, such as local builds.
    pub updates_enabled: bool,
    pub latest_version: Option<String>,
    pub update_available: bool,
    pub update_required: bool,
    pub install_method: &'static str,
}

pub struct Updater {
    pub url: String,
    pub cache_dir: Option<PathBuf>,
    pub public_key: Option<VerifyingKey>,
}

impl Updater {
    pub fn from_env() -> Self {
        Self {
            url: std::env::var("TUYO_SIGNER_UPDATE_URL")
                .ok()
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| DEFAULT_URL.into()),
            cache_dir: cache_dir(),
            public_key: PUBLIC_KEY.and_then(parse_public_key),
        }
    }

    pub fn enabled(&self) -> bool {
        self.public_key.is_some()
    }

    fn verify(&self, manifest: &[u8], signature: &[u8]) -> Result<Manifest> {
        let key = self.public_key.as_ref().ok_or_else(disabled)?;
        let signature = Signature::from_slice(signature).map_err(|_| bad_manifest())?;
        key.verify(manifest, &signature)
            .map_err(|_| bad_manifest())?;
        let manifest: Manifest = serde_json::from_slice(manifest).map_err(|_| bad_manifest())?;
        if manifest.name != "tuyo-signer" || Version::parse(&manifest.version).is_err() {
            return Err(bad_manifest());
        }
        Ok(manifest)
    }

    fn cache_path(&self) -> Option<PathBuf> {
        self.cache_dir.as_ref().map(|dir| dir.join("update.json"))
    }

    /// The last verified manifest, however old.
    fn cached(&self) -> Option<(u64, Manifest)> {
        let cache: Cache = serde_json::from_slice(&fs::read(self.cache_path()?).ok()?).ok()?;
        let manifest = self
            .verify(
                cache.manifest.as_bytes(),
                &hex::decode(&cache.signature).ok()?,
            )
            .ok()?;
        Some((cache.checked_at, manifest))
    }

    /// Fetches the latest manifest unless one was checked within a day.
    pub fn check(&self, force: bool) -> Result<Manifest> {
        if !self.enabled() {
            return Err(disabled());
        }
        if !force
            && let Some((checked_at, manifest)) = self.cached()
            && now().saturating_sub(checked_at) < CHECK_EVERY.as_secs()
        {
            return Ok(manifest);
        }
        let text = download(&format!("{}manifest.json", self.url))?;
        let signature = download(&format!("{}manifest.json.sig", self.url))?;
        let manifest = self.verify(&text, &signature)?;
        if let Some(path) = self.cache_path() {
            let cache = Cache {
                checked_at: now(),
                manifest: String::from_utf8(text).map_err(|_| bad_manifest())?,
                signature: hex::encode(signature),
            };
            let _ = write_atomic(&path, &serde_json::to_vec(&cache).expect("serializable"));
        }
        Ok(manifest)
    }

    pub fn status(&self) -> Status {
        let latest = self.cached().map(|(_, m)| m);
        Status {
            version: VERSION,
            target: TARGET,
            updates_enabled: self.enabled(),
            update_available: latest.as_ref().is_some_and(|m| newer(&m.version)),
            update_required: latest.as_ref().is_some_and(required),
            latest_version: latest.map(|m| m.version),
            install_method: install_method(),
        }
    }

    /// Fails with `update_required` when the last verified manifest says this
    /// version must not sign anymore.
    pub fn gate(&self) -> Result<()> {
        match self.cached() {
            Some((_, manifest)) if required(&manifest) => Err(SignerError::new(
                "update_required",
                format!(
                    "This signer version ({VERSION}) is no longer supported. Run `tuyo-signer update` to install {}.",
                    manifest.version
                ),
            )),
            _ => Ok(()),
        }
    }

    /// Downloads, verifies and installs the latest release over this binary.
    /// The running process keeps the old code; the next start uses the new one.
    pub fn apply(&self) -> Result<Option<String>> {
        match install_method() {
            "npm" => {
                return Err(SignerError::new(
                    "managed_install",
                    "This copy was installed with npm. Update it with `npx -y @tuyo/signer@latest`.",
                ));
            }
            "homebrew" => {
                return Err(SignerError::new(
                    "managed_install",
                    "This copy was installed with Homebrew. Update it with `brew upgrade tuyo-signer`.",
                ));
            }
            _ => {}
        }
        let manifest = self.check(true)?;
        if !newer(&manifest.version) {
            return Ok(None);
        }
        let asset = manifest.assets.get(TARGET).ok_or_else(|| {
            SignerError::new(
                "update_unavailable",
                format!("The latest release has no build for {TARGET}."),
            )
        })?;
        let bytes = download(&asset.url)?;
        if !hex::encode(Sha256::digest(&bytes)).eq_ignore_ascii_case(&asset.sha256) {
            return Err(SignerError::new(
                "update_corrupt",
                "The download does not match the signed manifest.",
            ));
        }

        let current = std::env::current_exe().map_err(|_| unwritable())?;
        let directory = current.parent().ok_or_else(unwritable)?;
        let staged = directory.join(format!(".tuyo-signer-update-{}", fsutil::random_suffix()));
        let result = (|| {
            write_executable(&staged, &bytes).map_err(|_| unwritable())?;
            check_new_binary(&staged, &manifest.version)?;
            self_replace::self_replace(&staged).map_err(|_| unwritable())
        })();
        let _ = fs::remove_file(&staged);
        result.map(|()| Some(manifest.version))
    }
}

/// Used by the signing path; never touches the network.
pub fn gate() -> Result<()> {
    Updater::from_env().gate()
}

fn required(manifest: &Manifest) -> bool {
    let current = Version::parse(VERSION).expect("crate version");
    manifest
        .minimum_version
        .as_deref()
        .and_then(|v| Version::parse(v).ok())
        .is_some_and(|minimum| current < minimum)
}

fn newer(version: &str) -> bool {
    let current = Version::parse(VERSION).expect("crate version");
    Version::parse(version).is_ok_and(|v| v > current)
}

/// Runs the new binary once and checks it is the version the manifest names,
/// and on macOS release builds that it is signed by our Apple team.
fn check_new_binary(path: &Path, version: &str) -> Result<()> {
    if let (true, Some(team)) = (cfg!(target_os = "macos"), APPLE_TEAM_ID) {
        let requirement = format!(
            "anchor apple generic and identifier \"com.tuyo.signer\" and certificate leaf[subject.OU] = \"{team}\""
        );
        let ok = Command::new("/usr/bin/codesign")
            .args(["--verify", "--strict", "-R"])
            .arg(requirement)
            .arg(path)
            .output()
            .is_ok_and(|o| o.status.success());
        if !ok {
            return Err(SignerError::new(
                "update_untrusted",
                "The new binary is not signed by Tuyo's Apple Developer ID.",
            ));
        }
    }
    let output = Command::new(path).arg("--version").output().map_err(|_| {
        SignerError::new(
            "update_broken",
            "The new binary does not run on this machine.",
        )
    })?;
    let printed = String::from_utf8_lossy(&output.stdout);
    if !output.status.success() || printed.trim() != format!("tuyo-signer {version}") {
        return Err(SignerError::new(
            "update_broken",
            "The new binary does not report the expected version.",
        ));
    }
    Ok(())
}

pub fn install_method() -> &'static str {
    let Ok(path) = std::env::current_exe() else {
        return "unknown";
    };
    let path = path.to_string_lossy().replace('\\', "/");
    if path.contains("/node_modules/") {
        "npm"
    } else if path.contains("/Cellar/")
        || path.contains("/homebrew/")
        || path.contains("/linuxbrew/")
    {
        "homebrew"
    } else {
        "standalone"
    }
}

fn download(url: &str) -> Result<Vec<u8>> {
    use ureq::tls::{RootCerts, TlsConfig};
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(120)))
        .proxy(ureq::Proxy::try_from_env())
        .tls_config(
            TlsConfig::builder()
                .root_certs(RootCerts::PlatformVerifier)
                .build(),
        )
        .user_agent(format!("tuyo-signer/{VERSION}"))
        .build()
        .into();
    agent
        .get(url)
        .call()
        .and_then(|mut response| {
            response
                .body_mut()
                .with_config()
                .limit(MAX_DOWNLOAD)
                .read_to_vec()
        })
        .map_err(|_| {
            SignerError::new(
                "update_unreachable",
                "Cannot reach the release server. Check the network and any HTTPS_PROXY setting.",
            )
        })
}

fn write_executable(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut file = fsutil::create_private_file(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))?;
    }
    Ok(())
}

fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let directory = path.parent().expect("cache file has a directory");
    fsutil::create_private_dir(directory)?;
    let temporary = directory.join(format!(".update-{}", fsutil::random_suffix()));
    let result = (|| {
        fsutil::create_private_file(&temporary)?.write_all(bytes)?;
        fs::rename(&temporary, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn cache_dir() -> Option<PathBuf> {
    let var = |name: &str| {
        std::env::var_os(name)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    };
    if let Some(dir) = var("TUYO_SIGNER_CACHE_DIR") {
        return Some(dir);
    }
    if cfg!(target_os = "macos") {
        return std::env::home_dir().map(|h| h.join("Library/Caches/com.tuyo.signer"));
    }
    if cfg!(windows) {
        return var("LOCALAPPDATA").map(|d| d.join("tuyo-signer"));
    }
    var("XDG_CACHE_HOME")
        .or_else(|| std::env::home_dir().map(|h| h.join(".cache")))
        .map(|d| d.join("tuyo-signer"))
}

pub fn parse_public_key(text: &str) -> Option<VerifyingKey> {
    let bytes: [u8; 32] = hex::decode(text.trim()).ok()?.try_into().ok()?;
    VerifyingKey::from_bytes(&bytes).ok()
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn disabled() -> SignerError {
    SignerError::new(
        "updates_disabled",
        "This build has no update key, so it cannot update itself. Install a release build.",
    )
}

fn bad_manifest() -> SignerError {
    SignerError::new(
        "update_untrusted",
        "The release manifest is not signed by Tuyo.",
    )
}

fn unwritable() -> SignerError {
    SignerError::new(
        "update_unwritable",
        "Cannot replace the installed binary. Check that its directory is writable.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn updater(dir: &Path) -> (Updater, SigningKey) {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let updater = Updater {
            url: "http://127.0.0.1:9/".into(),
            cache_dir: Some(dir.to_path_buf()),
            public_key: Some(key.verifying_key()),
        };
        (updater, key)
    }

    fn manifest(version: &str, minimum: Option<&str>) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "name": "tuyo-signer",
            "version": version,
            "minimumVersion": minimum,
            "assets": { TARGET: { "url": "http://127.0.0.1:9/x", "sha256": "00" } }
        }))
        .unwrap()
    }

    fn cache(updater: &Updater, key: &SigningKey, text: &[u8]) {
        let cache = Cache {
            checked_at: now(),
            manifest: String::from_utf8(text.to_vec()).unwrap(),
            signature: hex::encode(key.sign(text).to_bytes()),
        };
        fs::write(
            updater.cache_path().unwrap(),
            serde_json::to_vec(&cache).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn accepts_only_signed_manifests() {
        let dir = tempfile::tempdir().unwrap();
        let (updater, key) = updater(dir.path());
        let text = manifest("9.0.0", None);
        assert!(updater.verify(&text, &key.sign(&text).to_bytes()).is_ok());
        let other = SigningKey::from_bytes(&[8u8; 32]);
        assert_eq!(
            updater
                .verify(&text, &other.sign(&text).to_bytes())
                .unwrap_err()
                .code,
            "update_untrusted"
        );
        let mut tampered = text.clone();
        tampered[20] ^= 1;
        assert!(
            updater
                .verify(&tampered, &key.sign(&text).to_bytes())
                .is_err()
        );
    }

    #[test]
    fn reports_updates_and_enforces_the_minimum_version() {
        let dir = tempfile::tempdir().unwrap();
        let (updater, key) = updater(dir.path());
        assert!(!updater.status().update_available);
        assert!(updater.gate().is_ok());

        cache(&updater, &key, &manifest("9.0.0", Some(VERSION)));
        let status = updater.status();
        assert!(status.update_available && !status.update_required);
        assert_eq!(status.latest_version.as_deref(), Some("9.0.0"));
        assert!(updater.gate().is_ok());
        // A fresh cache is used without touching the network.
        assert_eq!(updater.check(false).unwrap().version, "9.0.0");

        cache(&updater, &key, &manifest("9.0.0", Some("9.0.0")));
        assert_eq!(updater.gate().unwrap_err().code, "update_required");

        // A cache that doesn't verify is ignored.
        let forged = manifest("9.0.0", Some("9.0.0"));
        let bad = Cache {
            checked_at: now(),
            manifest: String::from_utf8(forged).unwrap(),
            signature: "00".repeat(64),
        };
        fs::write(
            updater.cache_path().unwrap(),
            serde_json::to_vec(&bad).unwrap(),
        )
        .unwrap();
        assert!(updater.gate().is_ok());
    }

    #[test]
    fn builds_without_a_key_cannot_update() {
        let updater = Updater {
            url: DEFAULT_URL.into(),
            cache_dir: None,
            public_key: None,
        };
        assert_eq!(updater.check(true).unwrap_err().code, "updates_disabled");
        assert!(!updater.status().updates_enabled);
    }
}
