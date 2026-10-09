use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

// This writer is deliberately a copy of the state adapter's. The two adapters hold keys
// and state respectively and are not allowed to depend on each other, and moving the
// helper into the core crate would give the pure core filesystem access it must not have.

/// The mode a secret file carries: only its owner may read or write it.
pub const SECRET_FILE_MODE: u32 = 0o600;

/// The mode the directory that holds secrets carries.
pub const SECRET_DIR_MODE: u32 = 0o700;

/// The permission bits of a path, without the file type bits.
pub fn mode_of(path: &Path) -> io::Result<u32> {
    Ok(fs::metadata(path)?.permissions().mode() & 0o7777)
}

/// Create a directory with an exact mode, whatever the process umask says.
pub fn ensure_dir(dir: &Path, mode: u32) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    fs::set_permissions(dir, fs::Permissions::from_mode(mode))
}

/// Create a directory only when it is absent, leaving an existing one's mode alone.
pub fn ensure_dir_if_absent(dir: &Path, mode: u32) -> io::Result<()> {
    if dir.as_os_str().is_empty() || dir.exists() {
        return Ok(());
    }
    ensure_dir(dir, mode)
}

/// The temporary file an atomic write goes through, in the same directory as the target.
pub fn temporary_path(path: &Path) -> io::Result<PathBuf> {
    let Some(name) = path.file_name() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the path has no file name",
        ));
    };
    let mut temporary = std::ffi::OsString::from(".");
    temporary.push(name);
    temporary.push(".tmp");
    Ok(path.with_file_name(temporary))
}

/// Write a secret atomically, with its mode fixed at creation and its rename last.
///
/// The key exists at a readable path only once it is complete: a reader either sees the
/// previous document or the whole new one, and never a partially written key.
pub fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    let directory = directory_of(path);
    fs::create_dir_all(directory)?;
    let temporary = temporary_path(path)?;
    let _ = fs::remove_file(&temporary);
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(mode)
        .open(&temporary)?;
    file.set_permissions(fs::Permissions::from_mode(mode))?;
    if let Err(error) = write_and_flush(&mut file, bytes) {
        drop(file);
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    drop(file);
    fs::rename(&temporary, path)?;
    sync_directory(directory)
}

fn directory_of(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

fn write_and_flush(file: &mut File, bytes: &[u8]) -> io::Result<()> {
    file.write_all(bytes)?;
    file.sync_all()
}

fn sync_directory(directory: &Path) -> io::Result<()> {
    File::open(directory)?.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_secret_is_written_with_its_mode_and_leaves_nothing_behind() {
        let directory = match tempfile::TempDir::new() {
            Ok(directory) => directory,
            Err(error) => panic!("temporary directory: {error}"),
        };
        let path = directory.path().join("wg.key");
        if let Err(error) = write_atomic(&path, b"key", SECRET_FILE_MODE) {
            panic!("writing: {error}");
        }
        match mode_of(&path) {
            Ok(mode) => assert_eq!(mode, SECRET_FILE_MODE),
            Err(error) => panic!("stat: {error}"),
        }
        let temporary = match temporary_path(&path) {
            Ok(temporary) => temporary,
            Err(error) => panic!("temporary path: {error}"),
        };
        assert!(!temporary.exists());
    }

    #[test]
    fn a_secret_directory_is_created_private_and_an_existing_one_is_left_alone() {
        let directory = match tempfile::TempDir::new() {
            Ok(directory) => directory,
            Err(error) => panic!("temporary directory: {error}"),
        };
        let secrets = directory.path().join("secrets");
        if let Err(error) = ensure_dir_if_absent(&secrets, SECRET_DIR_MODE) {
            panic!("creating: {error}");
        }
        match mode_of(&secrets) {
            Ok(mode) => assert_eq!(mode, SECRET_DIR_MODE),
            Err(error) => panic!("stat: {error}"),
        }
        if let Err(error) = ensure_dir_if_absent(directory.path(), SECRET_DIR_MODE) {
            panic!("ensuring: {error}");
        }
        match mode_of(directory.path()) {
            Ok(mode) => assert_ne!(mode & 0o077, 0, "the caller's directory was re-moded"),
            Err(error) => panic!("stat: {error}"),
        }
    }
}
