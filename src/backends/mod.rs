//! Where signing keys live. Each signer records its backend in state.json and
//! is only ever read from it.

mod file;
mod keychain;

pub use file::FileBackend;
pub use keychain::{KeychainBackend, keychain_usable};

use crate::error::{Result, SignerError};
use crate::keys::StoredKey;
use crate::state::StorageName;

pub trait KeyBackend {
    fn name(&self) -> StorageName;
    /// Keys are addressed by the signer's tag, unique within a profile.
    fn load(&self, tag: &str) -> Result<Option<StoredKey>>;
    fn create(&self, tag: &str, require_touch_id: bool) -> Result<StoredKey>;
}

/// The `TUYO_SIGNER_KEY_STORAGE` setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageSetting {
    /// The OS credential store when it works, otherwise an owner-only file.
    Auto,
    Only(StorageName),
}

impl StorageSetting {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "auto" => Some(Self::Auto),
            "keychain" => Some(Self::Only(StorageName::Keychain)),
            "file" => Some(Self::Only(StorageName::File)),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Only(name) => name.as_str(),
        }
    }
}

pub struct KeyStorage {
    pub keychain: Box<dyn KeyBackend>,
    pub file: Box<dyn KeyBackend>,
    pub setting: StorageSetting,
    /// Whether the credential store answers. Only consulted in auto mode.
    pub keychain_usable: Box<dyn Fn() -> bool>,
}

impl KeyStorage {
    fn backend(&self, name: StorageName) -> &dyn KeyBackend {
        match name {
            StorageName::Keychain => self.keychain.as_ref(),
            StorageName::File => self.file.as_ref(),
        }
    }

    /// An existing signer always stays in the backend that created it.
    pub fn for_signer(&self, recorded: StorageName) -> Result<&dyn KeyBackend> {
        match self.setting {
            StorageSetting::Only(selected) if selected != recorded => Err(SignerError::new(
                "storage_mismatch",
                format!(
                    "This signer's key is in {} storage. Set TUYO_SIGNER_KEY_STORAGE to {} or auto.",
                    recorded.as_str(),
                    recorded.as_str()
                ),
            )),
            _ => Ok(self.backend(recorded)),
        }
    }

    pub fn for_new_signer(&self, require_touch_id: bool) -> Result<&dyn KeyBackend> {
        let name = match self.setting {
            StorageSetting::Only(StorageName::File) if require_touch_id => {
                return Err(SignerError::new(
                    "touch_id_requires_keychain",
                    "Touch ID signers keep their key in the macOS keychain. Unset TUYO_SIGNER_KEY_STORAGE or set it to keychain or auto.",
                ));
            }
            StorageSetting::Only(name) => name,
            StorageSetting::Auto if require_touch_id => StorageName::Keychain,
            StorageSetting::Auto if (self.keychain_usable)() => StorageName::Keychain,
            StorageSetting::Auto => StorageName::File,
        };
        Ok(self.backend(name))
    }
}

pub fn keychain_unavailable() -> SignerError {
    SignerError::new(
        "keychain_unavailable",
        "Cannot use the operating system credential store. On a host without one, set TUYO_SIGNER_KEY_STORAGE=file or auto.",
    )
}
