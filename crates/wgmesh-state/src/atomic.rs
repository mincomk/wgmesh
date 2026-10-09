use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// The mode a state file carries: the daemon writes it, its group may read it.
pub const STATE_FILE_MODE: u32 = 0o640;

/// The mode the directory that holds state carries.
pub const STATE_DIR_MODE: u32 = 0o750;

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

/// Write a file atomically, with its mode fixed at creation and its rename last.
///
/// A reader sees either the whole previous document or the whole new one. A process
/// killed anywhere inside this call leaves the previous document in place and at most a
/// stale temporary file behind, which the next write removes before it starts.
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
    use std::process::Command;

    use super::*;

    fn tempdir() -> tempfile::TempDir {
        match tempfile::TempDir::new() {
            Ok(directory) => directory,
            Err(error) => panic!("temporary directory: {error}"),
        }
    }

    #[test]
    fn an_atomic_write_lands_whole_and_leaves_no_temporary_behind() {
        let directory = tempdir();
        let path = directory.path().join("state.json");
        if let Err(error) = write_atomic(&path, b"first", STATE_FILE_MODE) {
            panic!("writing: {error}");
        }
        if let Err(error) = write_atomic(&path, b"second", STATE_FILE_MODE) {
            panic!("writing again: {error}");
        }
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) => panic!("reading: {error}"),
        };
        assert_eq!(bytes, b"second");
        let temporary = match temporary_path(&path) {
            Ok(temporary) => temporary,
            Err(error) => panic!("temporary path: {error}"),
        };
        assert!(!temporary.exists(), "a temporary file survived the write");
    }

    #[test]
    fn a_stale_temporary_from_a_killed_writer_does_not_block_the_next_write() {
        let directory = tempdir();
        let path = directory.path().join("state.json");
        if let Err(error) = write_atomic(&path, b"first", STATE_FILE_MODE) {
            panic!("writing: {error}");
        }
        let temporary = match temporary_path(&path) {
            Ok(temporary) => temporary,
            Err(error) => panic!("temporary path: {error}"),
        };
        if let Err(error) = std::fs::write(&temporary, b"hal") {
            panic!("writing the corpse: {error}");
        }
        if let Err(error) = write_atomic(&path, b"second", STATE_FILE_MODE) {
            panic!("writing over a stale temporary: {error}");
        }
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) => panic!("reading: {error}"),
        };
        assert_eq!(bytes, b"second");
    }

    #[test]
    fn the_mode_of_a_written_file_is_exactly_the_one_asked_for() {
        let directory = tempdir();
        let path = directory.path().join("state.json");
        if let Err(error) = write_atomic(&path, b"{}", STATE_FILE_MODE) {
            panic!("writing: {error}");
        }
        match mode_of(&path) {
            Ok(mode) => assert_eq!(mode, STATE_FILE_MODE),
            Err(error) => panic!("stat: {error}"),
        }
    }

    #[test]
    fn an_existing_directory_is_not_re_moded() {
        let directory = tempdir();
        if let Err(error) = ensure_dir_if_absent(directory.path(), 0o700) {
            panic!("ensuring: {error}");
        }
        match mode_of(directory.path()) {
            Ok(mode) => assert_ne!(
                mode & 0o700,
                0,
                "the caller's directory was re-moded to {mode:o}"
            ),
            Err(error) => panic!("stat: {error}"),
        }
    }

    #[test]
    #[ignore = "spawned by the umask test"]
    fn write_under_the_callers_umask() {
        let Some(directory) = std::env::var_os("WGMESH_TEST_MODE_DIR") else {
            return;
        };
        let path = Path::new(&directory).join("state.json");
        if let Err(error) = write_atomic(&path, b"{}", STATE_FILE_MODE) {
            eprintln!("the write failed: {error}");
            std::process::exit(2);
        }
        match mode_of(&path) {
            Ok(mode) if mode == STATE_FILE_MODE => {}
            Ok(mode) => {
                eprintln!("the mode is {mode:o}, not {STATE_FILE_MODE:o}");
                std::process::exit(3);
            }
            Err(error) => {
                eprintln!("stat failed: {error}");
                std::process::exit(4);
            }
        }
    }

    #[test]
    fn the_mode_is_exact_even_under_a_umask_that_would_strip_it() {
        let directory = tempdir();
        let executable = match std::env::current_exe() {
            Ok(path) => path,
            Err(error) => panic!("current executable: {error}"),
        };
        let command = format!(
            "umask 077; exec '{}' --ignored 'write_under_the_callers_umask' --nocapture",
            executable.display()
        );
        let status = Command::new("sh")
            .arg("-c")
            .arg(command)
            .env("WGMESH_TEST_MODE_DIR", directory.path())
            .status();
        match status {
            Ok(status) => assert!(
                status.success(),
                "a file written under umask 077 did not end up with {STATE_FILE_MODE:o}: {status}"
            ),
            Err(error) => panic!("spawning sh: {error}"),
        }
    }
}
