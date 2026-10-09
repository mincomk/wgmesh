use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::atomic::{
    STATE_DIR_MODE, STATE_FILE_MODE, ensure_dir_if_absent, temporary_path, write_atomic,
};
use crate::{PersistedState, STATE_SCHEMA, assert_no_secrets};

/// The file name a state store uses inside its directory.
pub const STATE_FILE_NAME: &str = "state.json";

/// Everything that can go wrong while reading or writing state.
#[derive(Debug)]
pub enum StateError {
    /// The file could not be read or written.
    Io { path: PathBuf, source: io::Error },
    /// The state could not be rendered as a document.
    Serialize { source: serde_json::Error },
    /// The document is not the state this build writes.
    Deserialize { source: serde_json::Error },
    /// The document carries a key that looks like a secret, which state never holds.
    SecretField { key: String },
}

impl fmt::Display for StateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StateError::Io { path, source } => {
                write!(formatter, "cannot use {}: {source}", path.display())
            }
            StateError::Serialize { source } => {
                write!(formatter, "cannot render the state: {source}")
            }
            StateError::Deserialize { source } => {
                write!(formatter, "cannot read the state: {source}")
            }
            StateError::SecretField { key } => write!(
                formatter,
                "the state carries a secret-looking key ({key}); state must never hold secrets"
            ),
        }
    }
}

impl std::error::Error for StateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            StateError::Io { source, .. } => Some(source),
            StateError::Serialize { source } | StateError::Deserialize { source } => Some(source),
            StateError::SecretField { .. } => None,
        }
    }
}

/// Why a previous state file was moved aside instead of read.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ResetReason {
    /// The file was written by a schema version this build does not know.
    UnknownSchema(u32),
    /// The file is not a state document at all.
    Corrupt(String),
}

/// What a load found.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum StateLoad {
    /// There is no state file yet: this is a first start.
    Empty,
    /// The state file is current and was read.
    Present(Box<PersistedState>),
    /// The previous file was unusable; it was moved to `backup` and the store starts over.
    Reset {
        reason: ResetReason,
        backup: PathBuf,
    },
}

impl StateLoad {
    /// The state this load produced, when it produced one.
    pub fn state(&self) -> Option<&PersistedState> {
        match self {
            StateLoad::Present(state) => Some(state),
            StateLoad::Empty | StateLoad::Reset { .. } => None,
        }
    }

    /// Whether this load started the store over from nothing.
    pub fn is_reset(&self) -> bool {
        matches!(self, StateLoad::Reset { .. })
    }
}

/// A state store backed by one JSON file, written atomically.
#[derive(Clone, Debug)]
pub struct FileStateStore {
    path: PathBuf,
    mode: u32,
}

impl FileStateStore {
    /// A store whose file is `state.json` inside `dir`.
    pub fn new(dir: impl AsRef<Path>) -> Self {
        Self::at(dir.as_ref().join(STATE_FILE_NAME))
    }

    /// A store at an exact path.
    pub fn at(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            mode: STATE_FILE_MODE,
        }
    }

    /// Write the file with a different mode than the default 0640.
    pub fn with_mode(mut self, mode: u32) -> Self {
        self.mode = mode;
        self
    }

    /// The file this store reads and writes.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The mode this store gives the file it writes.
    pub fn mode(&self) -> u32 {
        self.mode
    }

    /// Read the state, moving an unusable file aside rather than failing on it.
    ///
    /// State is disposable, so a file this build cannot read is backed up and the store
    /// reports a reset instead of an error. A document that carries a secret-looking key
    /// is a bug rather than a file to move aside, and is reported as an error.
    pub fn load(&self) -> Result<StateLoad, StateError> {
        let bytes = match fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(StateLoad::Empty),
            Err(source) => {
                return Err(StateError::Io {
                    path: self.path.clone(),
                    source,
                });
            }
        };
        match serde_json::from_slice::<PersistedState>(&bytes) {
            Ok(state) if state.schema == STATE_SCHEMA => {
                let value: serde_json::Value = serde_json::from_slice(&bytes)
                    .map_err(|source| StateError::Deserialize { source })?;
                assert_no_secrets(&value)?;
                Ok(StateLoad::Present(Box::new(state)))
            }
            Ok(state) => self.reset(ResetReason::UnknownSchema(state.schema)),
            Err(_) => self.reset(self.corruption_reason(&bytes)),
        }
    }

    /// Write the state: a temporary file in the same directory, then a rename.
    pub fn save(&self, state: &PersistedState) -> Result<(), StateError> {
        let value =
            serde_json::to_value(state).map_err(|source| StateError::Serialize { source })?;
        assert_no_secrets(&value)?;
        let mut document = serde_json::to_string_pretty(state)
            .map_err(|source| StateError::Serialize { source })?;
        document.push('\n');
        if let Some(directory) = self.path.parent() {
            ensure_dir_if_absent(directory, STATE_DIR_MODE).map_err(|source| StateError::Io {
                path: directory.to_path_buf(),
                source,
            })?;
        }
        write_atomic(&self.path, document.as_bytes(), self.mode).map_err(|source| StateError::Io {
            path: self.path.clone(),
            source,
        })
    }

    /// Remove the state file, and any temporary a killed writer left behind.
    pub fn clear(&self) -> Result<(), StateError> {
        remove_ignoring_absence(&self.path)?;
        if let Ok(temporary) = temporary_path(&self.path) {
            remove_ignoring_absence(&temporary)?;
        }
        Ok(())
    }

    /// Whether a state file is present at all.
    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    fn reset(&self, reason: ResetReason) -> Result<StateLoad, StateError> {
        let backup = self.next_backup_path(&reason);
        fs::rename(&self.path, &backup).map_err(|source| StateError::Io {
            path: self.path.clone(),
            source,
        })?;
        Ok(StateLoad::Reset { reason, backup })
    }

    fn next_backup_path(&self, reason: &ResetReason) -> PathBuf {
        let label = match reason {
            ResetReason::UnknownSchema(version) => format!("schema-{version}"),
            ResetReason::Corrupt(_) => "corrupt".to_string(),
        };
        let directory = match self.path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        };
        let mut candidate = directory.join(format!("{STATE_FILE_NAME}.{label}.bak"));
        let mut attempt = 1;
        while candidate.exists() {
            candidate = directory.join(format!("{STATE_FILE_NAME}.{label}.bak.{attempt}"));
            attempt += 1;
        }
        candidate
    }

    fn corruption_reason(&self, bytes: &[u8]) -> ResetReason {
        match serde_json::from_slice::<serde_json::Value>(bytes) {
            Ok(value) => match value.get("schema").and_then(|schema| schema.as_u64()) {
                Some(version) if version != u64::from(STATE_SCHEMA) => {
                    ResetReason::UnknownSchema(u32::try_from(version).unwrap_or(u32::MAX))
                }
                Some(_) => ResetReason::Corrupt(
                    "the file claims this schema version but is not a state document".to_string(),
                ),
                None => ResetReason::Corrupt("the file carries no schema version".to_string()),
            },
            Err(error) => ResetReason::Corrupt(error.to_string()),
        }
    }
}

fn remove_ignoring_absence(path: &Path) -> Result<(), StateError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(StateError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

#[cfg(test)]
mod tests {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    use super::*;
    use crate::atomic::mode_of;

    const CRASH_PAYLOAD: usize = 32 * 1024 * 1024;

    fn tempdir() -> tempfile::TempDir {
        match tempfile::TempDir::new() {
            Ok(directory) => directory,
            Err(error) => panic!("temporary directory: {error}"),
        }
    }

    fn sample(device: &str) -> PersistedState {
        let mut state = PersistedState::new(device, "prod");
        state.tunnel_ip = "10.77.0.7/16".to_string();
        state
    }

    fn load_present(store: &FileStateStore) -> PersistedState {
        match store.load() {
            Ok(StateLoad::Present(state)) => *state,
            other => panic!("expected a present state, got {other:?}"),
        }
    }

    fn read(path: &Path) -> Vec<u8> {
        match fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) => panic!("reading {}: {error}", path.display()),
        }
    }

    #[test]
    fn a_saved_state_comes_back_unchanged() {
        let directory = tempdir();
        let store = FileStateStore::new(directory.path());
        let state = sample("d_7Hq2Vx9");
        if let Err(error) = store.save(&state) {
            panic!("saving: {error}");
        }
        assert_eq!(load_present(&store), state);
    }

    #[test]
    fn a_first_start_reports_empty_rather_than_an_error() {
        let directory = tempdir();
        let store = FileStateStore::new(directory.path());
        match store.load() {
            Ok(StateLoad::Empty) => {}
            other => panic!("expected an empty store, got {other:?}"),
        }
    }

    #[test]
    fn the_state_file_mode_is_0640() {
        let directory = tempdir();
        let store = FileStateStore::new(directory.path());
        if let Err(error) = store.save(&sample("d_mode")) {
            panic!("saving: {error}");
        }
        match mode_of(store.path()) {
            Ok(mode) => assert_eq!(mode, 0o640, "the state file is {mode:o}"),
            Err(error) => panic!("stat: {error}"),
        }
    }

    #[test]
    fn the_file_name_is_the_one_the_blueprint_names() {
        let directory = tempdir();
        let store = FileStateStore::new(directory.path());
        assert_eq!(store.path(), directory.path().join(STATE_FILE_NAME));
    }

    #[test]
    fn an_unknown_schema_is_backed_up_and_the_store_starts_over() {
        let directory = tempdir();
        let store = FileStateStore::new(directory.path());
        let mut foreign = sample("d_from_the_future");
        foreign.schema = 99;
        let document = match serde_json::to_string_pretty(&foreign) {
            Ok(document) => document,
            Err(error) => panic!("rendering: {error}"),
        };
        if let Err(error) = fs::write(store.path(), document) {
            panic!("writing the foreign state: {error}");
        }

        let load = match store.load() {
            Ok(load) => load,
            Err(error) => panic!("loading a foreign state: {error}"),
        };
        let backup = match load {
            StateLoad::Reset {
                reason: ResetReason::UnknownSchema(99),
                backup,
            } => backup,
            other => panic!("expected a reset from schema 99, got {other:?}"),
        };
        assert!(backup.exists(), "no backup was written");
        assert!(
            !store.path().exists(),
            "the foreign state is still in the way of a fresh start"
        );
        let backed_up: PersistedState = match serde_json::from_slice(&read(&backup)) {
            Ok(state) => state,
            Err(error) => panic!("the backup is not the file that was moved: {error}"),
        };
        assert_eq!(backed_up.schema, 99);
        assert_eq!(backed_up.device_id, "d_from_the_future");

        if let Err(error) = store.save(&sample("d_fresh")) {
            panic!("saving after a reset: {error}");
        }
        assert_eq!(load_present(&store).device_id, "d_fresh");
    }

    #[test]
    fn a_corrupt_state_file_is_backed_up_too() {
        let directory = tempdir();
        let store = FileStateStore::new(directory.path());
        if let Err(error) = fs::write(store.path(), "{ this is not a state document") {
            panic!("writing: {error}");
        }
        let load = match store.load() {
            Ok(load) => load,
            Err(error) => panic!("loading a corrupt state: {error}"),
        };
        match load {
            StateLoad::Reset {
                reason: ResetReason::Corrupt(_),
                backup,
            } => assert!(backup.exists(), "no backup was written"),
            other => panic!("expected a reset, got {other:?}"),
        }
        if let Err(error) = store.save(&sample("d_fresh")) {
            panic!("saving after a reset: {error}");
        }
        assert_eq!(load_present(&store).device_id, "d_fresh");
    }

    #[test]
    fn a_file_without_a_schema_version_is_backed_up_too() {
        let directory = tempdir();
        let store = FileStateStore::new(directory.path());
        if let Err(error) = fs::write(store.path(), "{\"device_id\": \"d_old\"}") {
            panic!("writing: {error}");
        }
        match store.load() {
            Ok(StateLoad::Reset {
                reason: ResetReason::UnknownSchema(0),
                ..
            }) => {}
            other => panic!("expected a reset from an unversioned file, got {other:?}"),
        }
    }

    #[test]
    fn a_second_reset_does_not_overwrite_the_first_backup() {
        let directory = tempdir();
        let store = FileStateStore::new(directory.path());
        for _ in 0..2 {
            if let Err(error) = fs::write(store.path(), "{ not a state document") {
                panic!("writing: {error}");
            }
            if let Err(error) = store.load() {
                panic!("loading: {error}");
            }
        }
        let backups: Vec<_> = match fs::read_dir(directory.path()) {
            Ok(entries) => entries
                .filter_map(|entry| entry.ok())
                .map(|entry| entry.file_name().to_string_lossy().to_string())
                .filter(|name| name.contains(".bak"))
                .collect(),
            Err(error) => panic!("listing: {error}"),
        };
        assert_eq!(backups.len(), 2, "expected two backups, saw {backups:?}");
    }

    #[test]
    fn a_leftover_temporary_never_becomes_the_state_file() {
        let directory = tempdir();
        let store = FileStateStore::new(directory.path());
        let first = sample("d_first");
        if let Err(error) = store.save(&first) {
            panic!("saving: {error}");
        }
        let temporary = match temporary_path(store.path()) {
            Ok(temporary) => temporary,
            Err(error) => panic!("temporary path: {error}"),
        };
        if let Err(error) = fs::write(&temporary, b"{\"schema\": 1, \"device_id\": \"d_hal") {
            panic!("writing the corpse: {error}");
        }
        assert_eq!(
            load_present(&store),
            first,
            "a half written temporary replaced the state"
        );

        if let Err(error) = store.save(&sample("d_second")) {
            panic!("saving over a leftover: {error}");
        }
        assert!(!temporary.exists(), "the leftover survived the next write");
        assert_eq!(load_present(&store).device_id, "d_second");
    }

    #[test]
    fn clear_removes_the_state_and_its_temporary() {
        let directory = tempdir();
        let store = FileStateStore::new(directory.path());
        if let Err(error) = store.save(&sample("d_clear")) {
            panic!("saving: {error}");
        }
        let temporary = match temporary_path(store.path()) {
            Ok(temporary) => temporary,
            Err(error) => panic!("temporary path: {error}"),
        };
        if let Err(error) = fs::write(&temporary, b"corpse") {
            panic!("writing the corpse: {error}");
        }
        if let Err(error) = store.clear() {
            panic!("clearing: {error}");
        }
        assert!(!store.exists());
        assert!(!temporary.exists());
        match store.load() {
            Ok(StateLoad::Empty) => {}
            other => panic!("expected an empty store after clear, got {other:?}"),
        }
        if let Err(error) = store.clear() {
            panic!("clearing twice: {error}");
        }
    }

    #[test]
    fn the_store_refuses_a_document_that_carries_a_secret() {
        let directory = tempdir();
        let store = FileStateStore::new(directory.path());
        let document = "{\"schema\": 1, \"device_id\": \"d\", \"private_key\": \"AAAA\"}";
        if let Err(error) = fs::write(store.path(), document) {
            panic!("writing: {error}");
        }
        match store.load() {
            Err(StateError::SecretField { key }) => assert_eq!(key, "private_key"),
            other => panic!("expected the secret to be refused, got {other:?}"),
        }
        assert!(
            store.path().exists(),
            "a secret is a bug, not a file to move aside"
        );
    }

    #[test]
    #[ignore = "spawned by the interrupted write test"]
    fn crash_writer() {
        let Some(path) = std::env::var_os("WGMESH_CRASH_WRITE_PATH") else {
            return;
        };
        let payload = vec![b'x'; CRASH_PAYLOAD];
        let _ = write_atomic(Path::new(&path), &payload, STATE_FILE_MODE);
    }

    #[test]
    fn a_writer_killed_mid_write_leaves_the_previous_document_in_place() {
        let directory = tempdir();
        let store = FileStateStore::new(directory.path());
        let first = sample("d_first");
        if let Err(error) = store.save(&first) {
            panic!("saving: {error}");
        }
        let document = read(store.path());

        let executable = match std::env::current_exe() {
            Ok(path) => path,
            Err(error) => panic!("current executable: {error}"),
        };
        let mut child = match Command::new(executable)
            .args(["--ignored", "crash_writer", "--nocapture"])
            .env("WGMESH_CRASH_WRITE_PATH", store.path())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(child) => child,
            Err(error) => panic!("spawning the writer: {error}"),
        };

        let temporary = match temporary_path(store.path()) {
            Ok(temporary) => temporary,
            Err(error) => panic!("temporary path: {error}"),
        };
        let deadline = Instant::now() + Duration::from_secs(30);
        while !temporary.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(temporary.exists(), "the writer never started writing");
        if let Err(error) = child.kill() {
            panic!("killing the writer: {error}");
        }
        if let Err(error) = child.wait() {
            panic!("reaping the writer: {error}");
        }

        let bytes = read(store.path());
        assert!(
            bytes == document || bytes.len() == CRASH_PAYLOAD,
            "the state file holds {} bytes: neither the previous document ({}) nor a whole write ({CRASH_PAYLOAD})",
            bytes.len(),
            document.len()
        );

        if let Err(error) = store.save(&sample("d_second")) {
            panic!("saving after a kill: {error}");
        }
        assert_eq!(load_present(&store).device_id, "d_second");
        assert!(!temporary.exists(), "the temporary survived the recovery");
    }
}
