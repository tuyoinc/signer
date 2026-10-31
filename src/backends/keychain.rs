//! macOS login keychain, Windows Credential Manager or Linux Secret Service.
//!
//! Each key is an item under service `com.tuyo.signer` whose account is the
//! signer's address. On macOS the item's access list trusts the binary that
//! created it, so a signed `tuyo-signer` reads its key silently and any other
//! program prompts.

use std::path::Path;
use std::sync::mpsc;
use std::time::Duration;

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::{KeyBackend, keychain_unavailable};
use crate::error::Result;
use crate::keys::{self, SigningKey, StoredKey};
use crate::state::StorageName;

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

    /// The account the Node signer used: sha256(data directory || NUL || tag).
    /// Only read, to pick up keys it created.
    pub fn legacy_account(&self, tag: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.data_dir.as_bytes());
        hasher.update(b"\0");
        hasher.update(tag.as_bytes());
        hex::encode(hasher.finalize())
    }

    fn entry(account: &str) -> Result<keyring::Entry> {
        keyring::Entry::new(SERVICE, account).map_err(|_| keychain_unavailable())
    }

    fn read(account: &str) -> Result<Option<StoredKey>> {
        match Self::entry(account)?.get_password() {
            Ok(secret) => keys::decode_secret(&Zeroizing::new(secret)).map(Some),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(_) => Err(keychain_unavailable()),
        }
    }

    fn write(account: &str, stored: &StoredKey) -> Result<()> {
        let secret = keys::encode_secret(&stored.key, stored.require_touch_id);
        Self::entry(account)?
            .set_password(&secret)
            .map_err(|_| keychain_unavailable())
    }
}

impl KeyBackend for KeychainBackend {
    fn name(&self) -> StorageName {
        StorageName::Keychain
    }

    fn load(&self, tag: &str, address: Option<&str>) -> Result<Option<StoredKey>> {
        if let Some(address) = address
            && let Some(stored) = Self::read(address)?
        {
            return Ok(Some(stored));
        }
        // A key the Node signer stored for this tag. Move it under its address
        // so it shows up as such; the old item is left if it can't be removed.
        let legacy = self.legacy_account(tag);
        let Some(stored) = Self::read(&legacy)? else {
            return Ok(None);
        };
        let own = stored.key.address();
        if address.is_none_or(|a| a == own)
            && Self::write(&own, &stored).is_ok()
            && let Ok(entry) = Self::entry(&legacy)
        {
            let _ = entry.delete_credential();
        }
        Ok(Some(stored))
    }

    fn create(&self, _tag: &str, require_touch_id: bool) -> Result<StoredKey> {
        let stored = StoredKey {
            key: SigningKey::generate(),
            require_touch_id,
        };
        Self::write(&stored.key.address(), &stored)?;
        Ok(stored)
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
