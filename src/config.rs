//! Profile, directories and key storage from flags and environment.

use std::path::{Component, Path, PathBuf};

use crate::backends::StorageSetting;
use crate::error::{Result, SignerError};
use crate::state::valid_tag;

pub struct Config {
    pub profile: String,
    pub data_dir: PathBuf,
    pub key_dir: PathBuf,
    pub storage: StorageSetting,
}

#[derive(Default)]
pub struct Overrides {
    pub profile: Option<String>,
    pub data_dir: Option<PathBuf>,
    pub storage: Option<String>,
}

impl Config {
    pub fn load(overrides: Overrides) -> Result<Self> {
        Self::from(
            overrides,
            |name| std::env::var(name).ok().filter(|v| !v.is_empty()),
            std::env::home_dir(),
        )
    }

    pub fn from(
        overrides: Overrides,
        env: impl Fn(&str) -> Option<String>,
        home: Option<PathBuf>,
    ) -> Result<Self> {
        let profile = overrides
            .profile
            .or_else(|| env("TUYO_SIGNER_PROFILE"))
            .unwrap_or_else(|| "default".into());
        if !valid_tag(&profile) {
            return Err(invalid(
                "TUYO_SIGNER_PROFILE must be 1 to 64 letters, digits, _ or -.",
            ));
        }
        let data_dir = match overrides
            .data_dir
            .or_else(|| env("TUYO_SIGNER_DATA_DIR").map(PathBuf::from))
        {
            Some(dir) => dir,
            None => home
                .ok_or_else(|| {
                    invalid("Cannot find the home directory. Set TUYO_SIGNER_DATA_DIR.")
                })?
                .join(".local/share/tuyo/signer")
                .join(&profile),
        };
        let data_dir = resolve(&data_dir)?;
        let key_dir = match env("TUYO_SIGNER_KEY_DIR") {
            Some(dir) => resolve(Path::new(&dir))?,
            None => data_dir.join("keys"),
        };
        let storage = overrides
            .storage
            .or_else(|| env("TUYO_SIGNER_KEY_STORAGE"))
            .unwrap_or_else(|| "auto".into());
        let storage = StorageSetting::parse(&storage)
            .ok_or_else(|| invalid("TUYO_SIGNER_KEY_STORAGE must be auto, keychain or file."))?;
        Ok(Self {
            profile,
            data_dir,
            key_dir,
            storage,
        })
    }
}

/// An absolute, lexically normalized path, like Node's `path.resolve`. Keys
/// stored by earlier versions are found by a hash of it, so it must stay stable.
pub fn resolve(path: &Path) -> Result<PathBuf> {
    let absolute = std::path::absolute(path).map_err(|_| invalid("Invalid data directory."))?;
    let mut out = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other),
        }
    }
    Ok(out)
}

fn invalid(message: &str) -> SignerError {
    SignerError::new("invalid_configuration", message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::StorageName;

    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |name| {
            pairs
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| v.to_string())
        }
    }

    #[test]
    fn uses_default_directories() {
        let home = resolve(Path::new("/home/agent")).unwrap();
        let config = Config::from(Overrides::default(), env(&[]), Some(home.clone())).unwrap();
        assert_eq!(config.profile, "default");
        assert_eq!(
            config.data_dir,
            home.join(".local/share/tuyo/signer/default")
        );
        assert_eq!(config.key_dir, config.data_dir.join("keys"));
        assert_eq!(config.storage, StorageSetting::Auto);
    }

    #[test]
    fn reads_environment_and_flags() {
        let vars = [
            ("TUYO_SIGNER_PROFILE", "plugin"),
            ("TUYO_SIGNER_DATA_DIR", "/srv/a/../signer/./p"),
            ("TUYO_SIGNER_KEY_STORAGE", "file"),
            ("TUYO_SIGNER_KEY_DIR", "/secrets/keys"),
        ];
        let config = Config::from(Overrides::default(), env(&vars), None).unwrap();
        assert_eq!(config.profile, "plugin");
        assert_eq!(
            config.data_dir,
            resolve(Path::new("/srv/signer/p")).unwrap()
        );
        assert_eq!(config.key_dir, resolve(Path::new("/secrets/keys")).unwrap());
        assert_eq!(config.storage, StorageSetting::Only(StorageName::File));

        let flags = Overrides {
            storage: Some("keychain".into()),
            ..Default::default()
        };
        let config = Config::from(flags, env(&vars), None).unwrap();
        assert_eq!(config.storage, StorageSetting::Only(StorageName::Keychain));

        assert!(
            Config::from(
                Overrides::default(),
                env(&[("TUYO_SIGNER_KEY_STORAGE", "tpm")]),
                Some("/h".into())
            )
            .is_err()
        );
        assert!(
            Config::from(
                Overrides::default(),
                env(&[("TUYO_SIGNER_PROFILE", "../x")]),
                Some("/h".into())
            )
            .is_err()
        );
    }
}
