//! macOS login keychain, Windows Credential Manager or Linux Secret Service.
//!
//! On macOS the item's access list trusts the binary that created it, so a
//! signed `tuyo-signer` reads its key silently and any other program prompts.

use std::path::Path;
use std::sync::mpsc;
use std::time::Duration;

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::{KeyBackend, keychain_unavailable};
use crate::error::Result;
use crate::keys::{self, SigningKey, StoredKey};
use crate::state::StorageName;

/// Same service as the TypeScript signer, so its keychain entries are found.
pub const SERVICE: &str = "com.tuyo.signer";

pub struct KeychainBackend {
    data_dir: String,
}

impl KeychainBackend {
    pub fn new(data_dir: &Path) -> Self {
        Self {
            data_dir: data_dir.to_string_lossy().into_owned(),
        }
    }

    /// sha256(data directory || NUL || tag), as the TypeScript signer computes it.
    pub fn account(&self, tag: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.data_dir.as_bytes());
        hasher.update(b"\0");
        hasher.update(tag.as_bytes());
        hex::encode(hasher.finalize())
    }

    fn entry(&self, tag: &str) -> Result<keyring::Entry> {
        keyring::Entry::new(SERVICE, &self.account(tag)).map_err(|_| keychain_unavailable())
    }
}

impl KeyBackend for KeychainBackend {
    fn name(&self) -> StorageName {
        StorageName::Keychain
    }

    fn load(&self, tag: &str) -> Result<Option<StoredKey>> {
        match self.entry(tag)?.get_password() {
            Ok(secret) => keys::decode_secret(&Zeroizing::new(secret)).map(Some),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(_) => Err(keychain_unavailable()),
        }
    }

    fn create(&self, tag: &str, require_touch_id: bool) -> Result<StoredKey> {
        let key = SigningKey::generate();
        let secret = keys::encode_secret(&key, require_touch_id);
        self.entry(tag)?
            .set_password(&secret)
            .map_err(|_| keychain_unavailable())?;
        Ok(StoredKey {
            key,
            require_touch_id,
        })
    }
}

/// Whether the credential store answers a read. A host without one (no Secret
/// Service on a server or container, a locked keychain over SSH) returns false
/// within a few seconds instead of hanging.
pub fn keychain_usable() -> bool {
    #[cfg(all(unix, not(target_os = "macos")))]
    if std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_none() {
        return false;
    }
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let answered = keyring::Entry::new(SERVICE, "tuyo-signer-probe")
            .map(|entry| matches!(entry.get_password(), Ok(_) | Err(keyring::Error::NoEntry)))
            .unwrap_or(false);
        let _ = sender.send(answered);
    });
    receiver
        .recv_timeout(Duration::from_secs(5))
        .unwrap_or(false)
}
