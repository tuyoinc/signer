//! Owner-only files and directories.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::Path;

pub fn create_private_dir(path: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)
}

/// Creates a new file readable only by its owner. Fails if it exists.
pub fn create_private_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

/// Opens a file for reading without following a symlink at its final component.
pub fn open_no_follow(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(not(unix))]
    {
        if path.symlink_metadata()?.file_type().is_symlink() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "symlink"));
        }
    }
    options.open(path)
}

/// True when the file is a regular file owned by this user with no group or
/// other permissions. Windows relies on the default ACLs of the profile.
pub fn is_private_file(file: &File) -> io::Result<bool> {
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Ok(false);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid has no preconditions.
        let uid = unsafe { libc::geteuid() };
        Ok(metadata.mode() & 0o077 == 0 && metadata.uid() == uid)
    }
    #[cfg(not(unix))]
    Ok(true)
}

pub fn random_suffix() -> String {
    use rand_core::RngCore;
    let mut bytes = [0u8; 8];
    rand_core::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}
