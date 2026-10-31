//! Key files readable only by their owner, for hosts without a credential store.

use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::path::PathBuf;

use zeroize::Zeroizing;

use super::KeyBackend;
use crate::error::{Result, SignerError};
use crate::fsutil;
use crate::keys::{self, SigningKey, StoredKey};
use crate::state::StorageName;

pub struct FileBackend {
    pub directory: PathBuf,
}

impl FileBackend {
    pub fn new(directory: PathBuf) -> Self {
        Self { directory }
    }

    pub fn path(&self, tag: &str) -> PathBuf {
        self.directory.join(format!("{tag}.key"))
    }
}

impl KeyBackend for FileBackend {
    fn name(&self) -> StorageName {
        StorageName::File
    }

    fn load(&self, tag: &str, _address: Option<&str>) -> Result<Option<StoredKey>> {
        // Refuse symlinks so the key cannot be redirected to a shared location.
        let mut file = match fsutil::open_no_follow(&self.path(tag)) {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(unreadable()),
        };
        if !fsutil::is_private_file(&file).map_err(|_| unreadable())? {
            return Err(SignerError::new(
                "insecure_key_file",
                "The signing key file must be a regular file owned by this user with mode 0600.",
            ));
        }
        let mut text = Zeroizing::new(String::new());
        file.read_to_string(&mut text).map_err(|_| unreadable())?;
        keys::decode_secret(&text).map(Some)
    }

    fn create(&self, tag: &str, require_touch_id: bool) -> Result<StoredKey> {
        let key = SigningKey::generate();
        let secret = keys::encode_secret(&key, require_touch_id);
        fsutil::create_private_dir(&self.directory).map_err(|_| unwritable())?;
        let temporary = self
            .directory
            .join(format!(".key-{}", fsutil::random_suffix()));
        let result = (|| -> std::io::Result<()> {
            let mut file = fsutil::create_private_file(&temporary)?;
            file.write_all(secret.as_bytes())?;
            file.write_all(b"\n")?;
            file.sync_all()?;
            // hard_link never replaces an existing key, unlike rename.
            fs::hard_link(&temporary, self.path(tag))
        })();
        let _ = fs::remove_file(&temporary);
        match result {
            Ok(()) => Ok(StoredKey {
                key,
                require_touch_id,
            }),
            Err(error) if error.kind() == ErrorKind::AlreadyExists => Err(SignerError::new(
                "key_exists",
                "A signing key file already exists at this path and will not be replaced.",
            )),
            Err(_) => Err(unwritable()),
        }
    }
}

fn unreadable() -> SignerError {
    SignerError::new("key_file_unreadable", "Cannot read the signing key file.")
}

fn unwritable() -> SignerError {
    SignerError::new(
        "key_file_unwritable",
        "Cannot write the signing key file. Check TUYO_SIGNER_KEY_DIR and its permissions.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_owner_only_keys_and_never_replaces_them() {
        let dir = tempfile::tempdir().unwrap();
        let backend = FileBackend::new(dir.path().join("keys"));
        assert!(backend.load("a", None).unwrap().is_none());
        let created = backend.create("a", false).unwrap();
        let loaded = backend.load("a", None).unwrap().unwrap();
        assert_eq!(loaded.key.address(), created.key.address());
        assert_eq!(backend.create("a", false).unwrap_err().code, "key_exists");
        assert_eq!(
            backend.load("a", None).unwrap().unwrap().key.address(),
            created.key.address()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(backend.path("a"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
            let dir_mode = fs::metadata(&backend.directory)
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(dir_mode & 0o777, 0o700);
        }
    }

    #[cfg(unix)]
    #[test]
    fn refuses_readable_files_and_symlinks() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let backend = FileBackend::new(dir.path().to_path_buf());
        backend.create("a", false).unwrap();
        fs::set_permissions(backend.path("a"), fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            backend.load("a", None).unwrap_err().code,
            "insecure_key_file"
        );

        std::os::unix::fs::symlink(backend.path("a"), backend.path("b")).unwrap();
        assert_eq!(
            backend.load("b", None).unwrap_err().code,
            "key_file_unreadable"
        );
    }

    #[test]
    fn reads_typescript_key_files() {
        let dir = tempfile::tempdir().unwrap();
        let backend = FileBackend::new(dir.path().to_path_buf());
        let path = backend.path("ts");
        let mut file = fsutil::create_private_file(&path).unwrap();
        file.write_all(br#"{"version":1,"algorithm":"secp256k1","privateKey":"0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"}
"#).unwrap();
        let loaded = backend.load("ts", None).unwrap().unwrap();
        assert_eq!(
            loaded.key.address(),
            "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23"
        );
        assert!(!loaded.require_touch_id);
    }
}
