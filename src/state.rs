//! The profile's public metadata (`state.json`) and its cross-process lock.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::error::{Result, SignerError};
use crate::fsutil;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StorageName {
    Keychain,
    File,
}

impl StorageName {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Keychain => "keychain",
            Self::File => "file",
        }
    }
}

/// Public metadata only; the key itself stays in its backend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Signer {
    pub tag: String,
    pub algorithm: String,
    /// Uncompressed SEC1 public key.
    pub public_key: String,
    /// The onchain signer address derived from the public key.
    pub address: String,
    pub storage: StorageName,
    pub created_at: String,
    /// Shown to callers; the binding copy of this setting is stored with the key.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub require_touch_id: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct State {
    pub version: u8,
    pub signers: Vec<Signer>,
    /// Fields written by other versions are kept as they are.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            version: 2,
            signers: Vec::new(),
            extra: BTreeMap::new(),
        }
    }
}

pub struct StateStore {
    pub directory: PathBuf,
}

/// How long to wait for another process (for example one waiting on Touch ID)
/// before failing with `profile_busy`.
const LOCK_WAIT: Duration = Duration::from_secs(30);

impl StateStore {
    pub fn new(directory: PathBuf) -> Self {
        Self { directory }
    }

    fn path(&self) -> PathBuf {
        self.directory.join("state.json")
    }

    pub fn read(&self) -> Result<State> {
        let text = match fs::read_to_string(self.path()) {
            Ok(text) => text,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(State::default()),
            Err(_) => return Err(invalid_state()),
        };
        let state: State = serde_json::from_str(&text).map_err(|_| invalid_state())?;
        if state.version != 2 || !state.signers.iter().all(valid_signer) {
            return Err(invalid_state());
        }
        Ok(state)
    }

    pub fn write(&self, state: &State) -> Result<()> {
        fsutil::create_private_dir(&self.directory).map_err(|_| unwritable())?;
        let mut text = serde_json::to_string_pretty(state).expect("serializable");
        text.push('\n');
        let temporary = self
            .directory
            .join(format!(".state-{}.json", fsutil::random_suffix()));
        let result = (|| -> std::io::Result<()> {
            let mut file = fsutil::create_private_file(&temporary)?;
            file.write_all(text.as_bytes())?;
            file.sync_all()?;
            fs::rename(&temporary, self.path())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
            return Err(unwritable());
        }
        Ok(())
    }

    /// Runs `work` while holding the profile lock. The lock is an OS file lock,
    /// so it is released even if the process crashes.
    pub fn exclusive<T>(&self, work: impl FnOnce() -> Result<T>) -> Result<T> {
        fsutil::create_private_dir(&self.directory).map_err(|_| unwritable())?;
        let path = self.directory.join("process.lock");
        let mut options = OpenOptions::new();
        options.create(true).truncate(false).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(&path).map_err(|_| unwritable())?;
        acquire(&file)?;
        let result = work();
        let _ = file.unlock();
        result
    }
}

fn acquire(file: &File) -> Result<()> {
    let started = Instant::now();
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(()),
            Err(fs::TryLockError::WouldBlock) if started.elapsed() < LOCK_WAIT => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(fs::TryLockError::WouldBlock) => {
                return Err(SignerError::new(
                    "profile_busy",
                    "Another process is using this profile. Retry after it completes.",
                ));
            }
            Err(fs::TryLockError::Error(_)) => return Err(unwritable()),
        }
    }
}

pub fn valid_tag(tag: &str) -> bool {
    (1..=64).contains(&tag.len())
        && tag
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn valid_signer(signer: &Signer) -> bool {
    valid_tag(&signer.tag)
        && signer.algorithm == crate::keys::ALGORITHM
        && crate::keys::parse_hex(&signer.public_key, 65).is_some_and(|b| b[0] == 4)
        && crate::keys::normalize_address(&signer.address).as_deref() == Some(&signer.address)
}

fn invalid_state() -> SignerError {
    SignerError::new(
        "invalid_local_state",
        "Cannot read local state. Restore this profile before using its key.",
    )
}

fn unwritable() -> SignerError {
    SignerError::new(
        "profile_unwritable",
        "Cannot write to the profile directory. Check TUYO_SIGNER_DATA_DIR and its permissions.",
    )
}

/// The current time as JavaScript's `toISOString()` prints it.
pub fn now_iso() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    iso_from_unix_millis(now.as_millis() as i64)
}

pub fn iso_from_unix_millis(millis: i64) -> String {
    let secs = millis.div_euclid(1000);
    let ms = millis.rem_euclid(1000);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{ms:03}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_like_to_iso_string() {
        assert_eq!(iso_from_unix_millis(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(
            iso_from_unix_millis(1_793_401_988_123),
            "2026-10-30T23:13:08.123Z"
        );
        assert_eq!(
            iso_from_unix_millis(951_782_400_000),
            "2000-02-29T00:00:00.000Z"
        );
    }

    #[test]
    fn reads_and_writes_existing_profiles() {
        let dir = tempfile::tempdir().unwrap();
        let store = StateStore::new(dir.path().join("p"));
        assert!(store.read().unwrap().signers.is_empty());
        let ts = r#"{
  "version": 2,
  "signers": [{"tag":"a","algorithm":"secp256k1","publicKey":"0x044e3b81af9c2234cad09d679ce6035ed1392347ce64ce405f5dcd36228a25de6e47fd35c4215d1edf53e6f83de344615ce719bdb0fd878f6ed76f06dd277956de","address":"0x2c7536E3605D9C16a7a3D7b1898e529396a65c23","storage":"file","createdAt":"2026-10-30T23:13:08.123Z"}],
  "note": "kept"
}"#;
        fs::create_dir_all(&store.directory).unwrap();
        fs::write(store.directory.join("state.json"), ts).unwrap();
        let state = store.read().unwrap();
        assert_eq!(state.signers[0].storage, StorageName::File);
        store.write(&state).unwrap();
        let again = fs::read_to_string(store.directory.join("state.json")).unwrap();
        assert!(again.contains("\"note\": \"kept\""));
        assert!(!again.contains("requireTouchId"));
    }

    #[test]
    fn rejects_corrupt_state() {
        let dir = tempfile::tempdir().unwrap();
        let store = StateStore::new(dir.path().to_path_buf());
        fs::write(
            dir.path().join("state.json"),
            r#"{"version":2,"signers":[{"tag":"a b"}]}"#,
        )
        .unwrap();
        assert_eq!(store.read().unwrap_err().code, "invalid_local_state");
    }
}
