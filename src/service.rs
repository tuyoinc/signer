//! The signer's operations, shared by the MCP server and the command line.

use serde::Serialize;

use crate::backends::KeyStorage;
use crate::error::{Result, SignerError};
use crate::keys::{self, StoredKey};
use crate::state::{self, Signer, StateStore};

type Check = Box<dyn Fn() -> Result<()>>;
type Approve = Box<dyn Fn(&str) -> Result<()>>;

/// Platform hooks, replaceable in tests.
pub struct Hooks {
    /// Fails when this machine can't do Touch ID.
    pub touch_id_available: Check,
    /// Asks the user to approve one signature.
    pub approve: Approve,
    /// Fails when a signed release manifest says this version must update.
    pub update_gate: Check,
}

impl Hooks {
    pub fn system() -> Self {
        Self {
            touch_id_available: Box::new(crate::touchid::available),
            approve: Box::new(crate::touchid::approve),
            update_gate: Box::new(crate::update::gate),
        }
    }
}

pub struct Service {
    pub store: StateStore,
    pub storage: KeyStorage,
    pub hooks: Hooks,
}

#[derive(Serialize)]
pub struct SignerList {
    pub signers: Vec<Signer>,
}

#[derive(Debug, Serialize)]
pub struct Signature {
    pub tag: String,
    pub signer: String,
    pub hash: String,
    pub signature: String,
}

impl Service {
    pub fn list_signers(&self) -> Result<SignerList> {
        Ok(SignerList {
            signers: self.store.read()?.signers,
        })
    }

    pub fn get_signer(&self, tag: &str) -> Result<Signer> {
        check_tag(tag)?;
        self.store
            .read()?
            .signers
            .into_iter()
            .find(|s| s.tag == tag)
            .ok_or_else(|| {
                SignerError::new("signer_not_found", format!("No signer is tagged {tag}."))
            })
    }

    /// Creates a signer under `tag`, or returns the existing one after checking
    /// its key is still there.
    pub fn create_signer(&self, tag: &str, require_touch_id: bool) -> Result<Signer> {
        check_tag(tag)?;
        self.store.exclusive(|| {
            let mut state = self.store.read()?;
            if let Some(existing) = state.signers.iter().find(|s| s.tag == tag) {
                self.load_key(existing)?;
                return Ok(existing.clone());
            }
            if require_touch_id {
                (self.hooks.touch_id_available)()?;
            }
            let backend = self.storage.for_new_signer(require_touch_id)?;
            // Reuse a key left by a creation that stopped before saving the profile.
            let stored = match backend.load(tag)? {
                Some(stored) => stored,
                None => backend.create(tag, require_touch_id)?,
            };
            let signer = Signer {
                tag: tag.to_owned(),
                algorithm: keys::ALGORITHM.to_owned(),
                public_key: stored.key.public_key(),
                address: stored.key.address(),
                storage: backend.name(),
                created_at: state::now_iso(),
                require_touch_id: stored.require_touch_id,
            };
            state.signers.push(signer.clone());
            self.store.write(&state)?;
            Ok(signer)
        })
    }

    /// personal_sign (EIP-191) over the raw 32-byte hash.
    pub fn sign_hash(&self, signer: &str, hash: &str) -> Result<Signature> {
        let address = keys::normalize_address(signer).ok_or_else(|| {
            SignerError::new("invalid_request", "signer must be a 20-byte hex address.")
        })?;
        let digest = keys::parse_hash(hash).ok_or_else(|| {
            SignerError::new(
                "invalid_request",
                "hash must be 32 bytes of 0x-prefixed hex.",
            )
        })?;
        (self.hooks.update_gate)()?;
        self.store.exclusive(|| {
            let signer = self
                .store
                .read()?
                .signers
                .into_iter()
                .find(|s| s.address == address)
                .ok_or_else(|| {
                    SignerError::new(
                        "signer_not_found",
                        "The requested signer is not in this profile.",
                    )
                })?;
            let stored = self.load_key(&signer)?;
            // Either copy of the setting is enough to require approval.
            if stored.require_touch_id || signer.require_touch_id {
                (self.hooks.approve)(&format!(
                    "sign a Tuyo operation with signer “{}”",
                    signer.tag
                ))?;
            }
            Ok(Signature {
                tag: signer.tag.clone(),
                signer: signer.address.clone(),
                hash: hash.to_ascii_lowercase(),
                signature: stored
                    .key
                    .sign_digest(&keys::personal_message_digest(&digest))?,
            })
        })
    }

    /// A missing or different key is never replaced.
    fn load_key(&self, signer: &Signer) -> Result<StoredKey> {
        let stored = self
            .storage
            .for_signer(signer.storage)?
            .load(&signer.tag)?
            .ok_or_else(|| {
                SignerError::new(
                    "key_missing",
                    format!(
                        "Restore the signing credential for {}; it will not be replaced.",
                        signer.tag
                    ),
                )
            })?;
        if !stored
            .key
            .public_key()
            .eq_ignore_ascii_case(&signer.public_key)
        {
            return Err(SignerError::new(
                "wrong_key",
                format!(
                    "The credential for {} does not match this profile.",
                    signer.tag
                ),
            ));
        }
        Ok(stored)
    }
}

fn check_tag(tag: &str) -> Result<()> {
    if state::valid_tag(tag) {
        Ok(())
    } else {
        Err(SignerError::new(
            "invalid_request",
            "tag must be 1 to 64 letters, digits, _ or -.",
        ))
    }
}

#[cfg(test)]
pub mod tests {
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::path::Path;
    use std::rc::Rc;

    use super::*;
    use crate::backends::{FileBackend, KeyBackend, StorageSetting};
    use crate::keys::SigningKey;
    use crate::state::StorageName;

    /// An in-memory credential store.
    #[derive(Clone, Default)]
    pub struct MemoryKeychain(Rc<RefCell<HashMap<String, String>>>);

    impl KeyBackend for MemoryKeychain {
        fn name(&self) -> StorageName {
            StorageName::Keychain
        }
        fn load(&self, tag: &str) -> Result<Option<StoredKey>> {
            self.0
                .borrow()
                .get(tag)
                .map(|s| keys::decode_secret(s))
                .transpose()
        }
        fn create(&self, tag: &str, require_touch_id: bool) -> Result<StoredKey> {
            let key = SigningKey::generate();
            self.0.borrow_mut().insert(
                tag.into(),
                keys::encode_secret(&key, require_touch_id).to_string(),
            );
            Ok(StoredKey {
                key,
                require_touch_id,
            })
        }
    }

    pub struct Fixture {
        pub service: Service,
        pub keychain: MemoryKeychain,
        pub approvals: Rc<RefCell<Vec<String>>>,
    }

    pub fn fixture(
        dir: &Path,
        setting: StorageSetting,
        keychain_usable: bool,
        approve: bool,
    ) -> Fixture {
        let keychain = MemoryKeychain::default();
        let approvals = Rc::new(RefCell::new(Vec::new()));
        let log = approvals.clone();
        let service = Service {
            store: StateStore::new(dir.to_path_buf()),
            storage: KeyStorage {
                keychain: Box::new(keychain.clone()),
                file: Box::new(FileBackend::new(dir.join("keys"))),
                setting,
                keychain_usable: Box::new(move || keychain_usable),
            },
            hooks: Hooks {
                touch_id_available: Box::new(|| Ok(())),
                approve: Box::new(move |reason| {
                    log.borrow_mut().push(reason.to_owned());
                    if approve {
                        Ok(())
                    } else {
                        Err(SignerError::new("touch_id_denied", "denied"))
                    }
                }),
                update_gate: Box::new(|| Ok(())),
            },
        };
        Fixture {
            service,
            keychain,
            approvals,
        }
    }

    #[test]
    fn creates_lists_and_signs() {
        let dir = tempfile::tempdir().unwrap();
        let f = fixture(dir.path(), StorageSetting::Auto, true, true);
        let signer = f.service.create_signer("ops", false).unwrap();
        assert_eq!(signer.storage, StorageName::Keychain);
        assert_eq!(f.service.create_signer("ops", false).unwrap(), signer);
        assert_eq!(
            f.service.list_signers().unwrap().signers,
            vec![signer.clone()]
        );
        assert_eq!(f.service.get_signer("ops").unwrap(), signer);
        assert_eq!(
            f.service.get_signer("nope").unwrap_err().code,
            "signer_not_found"
        );

        let hash = format!("0x{}", "AB".repeat(32));
        let signed = f
            .service
            .sign_hash(&signer.address.to_lowercase(), &hash)
            .unwrap();
        assert_eq!(signed.signer, signer.address);
        assert_eq!(signed.hash, hash.to_lowercase());
        assert_eq!(signed.signature.len(), 132);
        assert!(f.approvals.borrow().is_empty());
    }

    #[test]
    fn falls_back_to_a_file_only_in_auto_mode() {
        let dir = tempfile::tempdir().unwrap();
        let auto = fixture(dir.path(), StorageSetting::Auto, false, true);
        assert_eq!(
            auto.service.create_signer("a", false).unwrap().storage,
            StorageName::File
        );
        assert!(dir.path().join("keys/a.key").exists());

        let dir = tempfile::tempdir().unwrap();
        let keychain = fixture(
            dir.path(),
            StorageSetting::Only(StorageName::Keychain),
            false,
            true,
        );
        assert_eq!(
            keychain.service.create_signer("a", false).unwrap().storage,
            StorageName::Keychain
        );
    }

    #[test]
    fn keeps_each_signer_in_its_backend() {
        let dir = tempfile::tempdir().unwrap();
        let f = fixture(
            dir.path(),
            StorageSetting::Only(StorageName::File),
            true,
            true,
        );
        let signer = f.service.create_signer("a", false).unwrap();
        let g = fixture(
            dir.path(),
            StorageSetting::Only(StorageName::Keychain),
            true,
            true,
        );
        let hash = format!("0x{}", "00".repeat(32));
        assert_eq!(
            g.service
                .sign_hash(&signer.address, &hash)
                .unwrap_err()
                .code,
            "storage_mismatch"
        );
        let auto = fixture(dir.path(), StorageSetting::Auto, true, true);
        assert!(auto.service.sign_hash(&signer.address, &hash).is_ok());
    }

    #[test]
    fn never_replaces_a_missing_or_different_key() {
        let dir = tempfile::tempdir().unwrap();
        let f = fixture(dir.path(), StorageSetting::Auto, true, true);
        let signer = f.service.create_signer("a", false).unwrap();
        let hash = format!("0x{}", "00".repeat(32));

        let other = SigningKey::generate();
        f.keychain
            .0
            .borrow_mut()
            .insert("a".into(), keys::encode_secret(&other, false).to_string());
        assert_eq!(
            f.service
                .sign_hash(&signer.address, &hash)
                .unwrap_err()
                .code,
            "wrong_key"
        );

        f.keychain.0.borrow_mut().clear();
        assert_eq!(
            f.service
                .sign_hash(&signer.address, &hash)
                .unwrap_err()
                .code,
            "key_missing"
        );
        assert_eq!(
            f.service.create_signer("a", false).unwrap_err().code,
            "key_missing"
        );
    }

    #[test]
    fn asks_for_touch_id_on_every_signature() {
        let dir = tempfile::tempdir().unwrap();
        let f = fixture(dir.path(), StorageSetting::Auto, false, true);
        let signer = f.service.create_signer("mac", true).unwrap();
        assert!(signer.require_touch_id);
        assert_eq!(signer.storage, StorageName::Keychain);
        let hash = format!("0x{}", "11".repeat(32));
        f.service.sign_hash(&signer.address, &hash).unwrap();
        f.service.sign_hash(&signer.address, &hash).unwrap();
        assert_eq!(f.approvals.borrow().len(), 2);
        assert!(f.approvals.borrow()[0].contains("mac"));

        // Editing state.json does not turn the check off: the key carries it.
        let mut state = f.service.store.read().unwrap();
        state.signers[0].require_touch_id = false;
        f.service.store.write(&state).unwrap();
        f.service.sign_hash(&signer.address, &hash).unwrap();
        assert_eq!(f.approvals.borrow().len(), 3);

        let denied = fixture(dir.path(), StorageSetting::Auto, false, false);
        denied
            .keychain
            .0
            .borrow_mut()
            .extend(f.keychain.0.borrow().clone());
        assert_eq!(
            denied
                .service
                .sign_hash(&signer.address, &hash)
                .unwrap_err()
                .code,
            "touch_id_denied"
        );
    }

    #[test]
    fn touch_id_needs_the_keychain() {
        let dir = tempfile::tempdir().unwrap();
        let f = fixture(
            dir.path(),
            StorageSetting::Only(StorageName::File),
            true,
            true,
        );
        assert_eq!(
            f.service.create_signer("a", true).unwrap_err().code,
            "touch_id_requires_keychain"
        );
    }

    #[test]
    fn validates_requests() {
        let dir = tempfile::tempdir().unwrap();
        let f = fixture(dir.path(), StorageSetting::Auto, true, true);
        assert_eq!(
            f.service.create_signer("a b", false).unwrap_err().code,
            "invalid_request"
        );
        assert_eq!(
            f.service.sign_hash("0x12", "0x00").unwrap_err().code,
            "invalid_request"
        );
        let zero = format!("0x{}", "00".repeat(20));
        assert_eq!(
            f.service.sign_hash(&zero, "0x00").unwrap_err().code,
            "invalid_request"
        );
        let hash = format!("0x{}", "00".repeat(32));
        assert_eq!(
            f.service.sign_hash(&zero, &hash).unwrap_err().code,
            "signer_not_found"
        );
    }
}
