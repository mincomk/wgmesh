use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::SecretError;
use crate::atomic::{SECRET_DIR_MODE, SECRET_FILE_MODE, ensure_dir_if_absent, write_atomic};
use crate::generate::{self, SIGNATURE_LEN};
use crate::parse::{KEY_LEN, KeyFormat, encode_key, parse_key};

/// The file the tunnel key lives in, relative to the secret directory.
pub const WIREGUARD_KEY_NAME: &str = "wg.key";

/// The file the device signing key lives in, relative to the secret directory.
pub const API_KEY_NAME: &str = "api.key";

/// The file a relay's signing key lives in, relative to the secret directory.
pub const RELAY_KEY_NAME: &str = "relay.key";

/// Whether a store may create a key that is missing.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SecretSource {
    /// Generate the key the first time it is needed. For a directory we own.
    LoadOrGenerate,
    /// Fail when the key is absent. For a path something else provisions.
    RequireExisting,
}

/// Which curve a stored key belongs to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KeyKind {
    /// A WireGuard tunnel key (X25519).
    X25519,
    /// A signing key (Ed25519).
    Ed25519,
}

/// A secret store backed by one file per key.
///
/// The key itself never leaves as bytes unless a caller asks for it by name: a display
/// command and the WireGuard interface adapter are the only callers that do. Everything
/// else signs or derives a public key through this type.
#[derive(Clone, Debug)]
pub struct FileSecretStore {
    path: PathBuf,
    kind: KeyKind,
    source: SecretSource,
    file_mode: u32,
    dir_mode: u32,
}

impl FileSecretStore {
    /// The tunnel key inside a secret directory.
    pub fn wireguard(dir: impl AsRef<Path>, source: SecretSource) -> Self {
        Self::at(
            dir.as_ref().join(WIREGUARD_KEY_NAME),
            KeyKind::X25519,
            source,
        )
    }

    /// The device signing key inside a secret directory.
    pub fn api(dir: impl AsRef<Path>, source: SecretSource) -> Self {
        Self::at(dir.as_ref().join(API_KEY_NAME), KeyKind::Ed25519, source)
    }

    /// A relay's signing key inside a secret directory.
    pub fn relay(dir: impl AsRef<Path>, source: SecretSource) -> Self {
        Self::at(dir.as_ref().join(RELAY_KEY_NAME), KeyKind::Ed25519, source)
    }

    /// A store at an exact path, for a key somewhere else in the filesystem.
    pub fn at(path: impl Into<PathBuf>, kind: KeyKind, source: SecretSource) -> Self {
        Self {
            path: path.into(),
            kind,
            source,
            file_mode: SECRET_FILE_MODE,
            dir_mode: SECRET_DIR_MODE,
        }
    }

    /// Use different modes than the default 0600 file and 0700 directory.
    pub fn with_modes(mut self, file_mode: u32, dir_mode: u32) -> Self {
        self.file_mode = file_mode;
        self.dir_mode = dir_mode;
        self
    }

    /// The file this store reads and, when it may, writes.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Which curve the key belongs to.
    pub fn kind(&self) -> KeyKind {
        self.kind
    }

    /// Whether this store may create the key.
    pub fn source(&self) -> SecretSource {
        self.source
    }

    /// Whether the key is present right now.
    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    /// The key material, generating and persisting it when the store is allowed to.
    ///
    /// The bytes are wrapped in `Zeroizing` so they are wiped when the caller drops them.
    pub fn reveal(&self) -> Result<Zeroizing<[u8; KEY_LEN]>, SecretError> {
        match self.read()? {
            Some((key, _)) => Ok(Zeroizing::new(key)),
            None => match self.source {
                SecretSource::RequireExisting => Err(SecretError::Missing {
                    path: self.path.clone(),
                }),
                SecretSource::LoadOrGenerate => Ok(Zeroizing::new(self.generate()?)),
            },
        }
    }

    /// The public half of the stored key, the only half that ever leaves the daemon.
    pub fn public_key(&self) -> Result<[u8; KEY_LEN], SecretError> {
        let key = self.reveal()?;
        Ok(match self.kind {
            KeyKind::X25519 => generate::x25519_public_key(&key),
            KeyKind::Ed25519 => generate::ed25519_public_key(&key),
        })
    }

    /// Sign a message with the stored key.
    pub fn sign(&self, message: &[u8]) -> Result<[u8; SIGNATURE_LEN], SecretError> {
        match self.kind {
            KeyKind::Ed25519 => {
                let key = self.reveal()?;
                generate::sign(&key, message)
            }
            KeyKind::X25519 => Err(SecretError::WrongKind {
                path: self.path.clone(),
                actual: KeyKind::X25519,
                wanted: KeyKind::Ed25519,
            }),
        }
    }

    /// How the key file is written, once it exists.
    pub fn format(&self) -> Result<KeyFormat, SecretError> {
        match self.read()? {
            Some((_, format)) => Ok(format),
            None => Err(SecretError::Missing {
                path: self.path.clone(),
            }),
        }
    }

    fn read(&self) -> Result<Option<([u8; KEY_LEN], KeyFormat)>, SecretError> {
        let bytes = match fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(SecretError::Io {
                    path: self.path.clone(),
                    source,
                });
            }
        };
        let (key, format) =
            parse_key(&bytes).map_err(|error| error.in_file(self.path.as_path()))?;
        Ok(Some((key, format)))
    }

    fn generate(&self) -> Result<[u8; KEY_LEN], SecretError> {
        let key = generate::random_key()?;
        if let Some(directory) = self.path.parent() {
            ensure_dir_if_absent(directory, self.dir_mode).map_err(|source| SecretError::Io {
                path: directory.to_path_buf(),
                source,
            })?;
        }
        write_atomic(&self.path, encode_key(&key).as_bytes(), self.file_mode).map_err(
            |source| SecretError::Io {
                path: self.path.clone(),
                source,
            },
        )?;
        // Two daemons racing to enrol the same device must converge on one key, so the
        // value that is returned is the value the file ended up holding, not ours.
        match self.read()? {
            Some((persisted, _)) => Ok(persisted),
            None => Err(SecretError::Missing {
                path: self.path.clone(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;
    use crate::atomic::mode_of;
    use crate::generate;

    fn tempdir() -> tempfile::TempDir {
        match tempfile::TempDir::new() {
            Ok(directory) => directory,
            Err(error) => panic!("temporary directory: {error}"),
        }
    }

    fn mode(path: &Path) -> u32 {
        match mode_of(path) {
            Ok(mode) => mode,
            Err(error) => panic!("stat {}: {error}", path.display()),
        }
    }

    fn contents(path: &Path) -> Vec<u8> {
        match fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) => panic!("reading {}: {error}", path.display()),
        }
    }

    fn secrets_dir(directory: &tempfile::TempDir) -> PathBuf {
        directory.path().join("secrets")
    }

    fn format_of(store: &FileSecretStore) -> KeyFormat {
        match store.format() {
            Ok(format) => format,
            Err(error) => panic!("format of {}: {error}", store.path().display()),
        }
    }

    #[test]
    fn a_generated_key_lands_in_a_0700_directory_as_a_0600_file() {
        let directory = tempdir();
        let secrets = secrets_dir(&directory);
        let store = FileSecretStore::wireguard(&secrets, SecretSource::LoadOrGenerate);
        let key = match store.reveal() {
            Ok(key) => key,
            Err(error) => panic!("generating: {error}"),
        };
        assert_eq!(key.len(), KEY_LEN);
        assert_eq!(mode(&secrets), 0o700, "the secret directory is not 0700");
        assert_eq!(mode(store.path()), 0o600, "the key file is not 0600");
        assert_eq!(format_of(&store), KeyFormat::Base64);
    }

    #[test]
    fn a_key_is_generated_once_and_then_read() {
        let directory = tempdir();
        let secrets = secrets_dir(&directory);
        let store = FileSecretStore::wireguard(&secrets, SecretSource::LoadOrGenerate);
        let first = match store.reveal() {
            Ok(key) => *key,
            Err(error) => panic!("first: {error}"),
        };
        let document = contents(store.path());
        let second = match store.reveal() {
            Ok(key) => *key,
            Err(error) => panic!("second: {error}"),
        };
        assert_eq!(first, second, "the key changed between reads");
        assert_eq!(document, contents(store.path()), "the file was rewritten");
    }

    #[test]
    fn require_existing_never_writes_anything() {
        let directory = tempdir();
        let secrets = secrets_dir(&directory);
        let store = FileSecretStore::wireguard(&secrets, SecretSource::RequireExisting);
        match store.reveal() {
            Err(SecretError::Missing { path }) => assert_eq!(path, store.path()),
            other => panic!("expected a missing key error, got {other:?}"),
        }
        assert!(
            !store.path().exists(),
            "a key was written by a read only store"
        );
        assert!(
            !secrets.exists(),
            "a directory was created by a read only store"
        );
    }

    #[test]
    fn require_existing_reads_a_provisioned_file_and_leaves_it_alone() {
        let directory = tempdir();
        let secrets = secrets_dir(&directory);
        if let Err(error) = fs::create_dir_all(&secrets) {
            panic!("creating the directory: {error}");
        }
        let path = secrets.join(WIREGUARD_KEY_NAME);
        let provisioned = [7u8; KEY_LEN];
        if let Err(error) = fs::write(&path, provisioned) {
            panic!("provisioning: {error}");
        }
        if let Err(error) = fs::set_permissions(&path, fs::Permissions::from_mode(0o400)) {
            panic!("making the file read only: {error}");
        }
        let before = contents(&path);

        let store = FileSecretStore::wireguard(&secrets, SecretSource::RequireExisting);
        match store.reveal() {
            Ok(key) => assert_eq!(*key, provisioned),
            Err(error) => panic!("reading a provisioned key: {error}"),
        }
        assert_eq!(contents(&path), before, "the provisioned key was rewritten");
        assert_eq!(mode(&path), 0o400, "the provisioned mode was changed");
        assert_eq!(format_of(&store), KeyFormat::Raw);
    }

    #[test]
    fn an_existing_key_is_kept_rather_than_replaced() {
        let directory = tempdir();
        let secrets = secrets_dir(&directory);
        let store = FileSecretStore::wireguard(&secrets, SecretSource::LoadOrGenerate);
        let first = match store.reveal() {
            Ok(key) => *key,
            Err(error) => panic!("generating: {error}"),
        };
        // A second store over the same directory must find the key, not make a new one.
        let again = FileSecretStore::wireguard(&secrets, SecretSource::LoadOrGenerate);
        match again.reveal() {
            Ok(key) => assert_eq!(*key, first),
            Err(error) => panic!("reading an existing key: {error}"),
        }
    }

    #[test]
    fn a_raw_key_and_a_base64_key_load_to_the_same_secret() {
        let key = [0x2au8; KEY_LEN];
        let raw_directory = tempdir();
        let raw_secrets = secrets_dir(&raw_directory);
        if let Err(error) = fs::create_dir_all(&raw_secrets) {
            panic!("creating: {error}");
        }
        let raw_path = raw_secrets.join(WIREGUARD_KEY_NAME);
        if let Err(error) = fs::write(&raw_path, key) {
            panic!("writing raw: {error}");
        }
        let text_directory = tempdir();
        let text_secrets = secrets_dir(&text_directory);
        if let Err(error) = fs::create_dir_all(&text_secrets) {
            panic!("creating: {error}");
        }
        let text_path = text_secrets.join(WIREGUARD_KEY_NAME);
        if let Err(error) = fs::write(&text_path, encode_key(&key)) {
            panic!("writing base64: {error}");
        }

        let raw = FileSecretStore::wireguard(&raw_secrets, SecretSource::RequireExisting);
        let text = FileSecretStore::wireguard(&text_secrets, SecretSource::RequireExisting);
        let raw_key = match raw.reveal() {
            Ok(key) => *key,
            Err(error) => panic!("raw: {error}"),
        };
        let text_key = match text.reveal() {
            Ok(key) => *key,
            Err(error) => panic!("base64: {error}"),
        };
        assert_eq!(raw_key, text_key);
        assert_eq!(format_of(&raw), KeyFormat::Raw);
        assert_eq!(format_of(&text), KeyFormat::Base64);
        match (raw.public_key(), text.public_key()) {
            (Ok(left), Ok(right)) => {
                assert_eq!(left, right, "the two spellings do not name the same key")
            }
            other => panic!("public keys: {other:?}"),
        }
    }

    #[test]
    fn a_generated_x25519_key_has_a_stable_public_half() {
        let directory = tempdir();
        let secrets = secrets_dir(&directory);
        let store = FileSecretStore::wireguard(&secrets, SecretSource::LoadOrGenerate);
        let first = match store.public_key() {
            Ok(key) => key,
            Err(error) => panic!("public key: {error}"),
        };
        let again = FileSecretStore::wireguard(&secrets, SecretSource::LoadOrGenerate);
        match again.public_key() {
            Ok(key) => assert_eq!(key, first),
            Err(error) => panic!("public key again: {error}"),
        }
        let secret = match store.reveal() {
            Ok(key) => *key,
            Err(error) => panic!("reveal: {error}"),
        };
        assert_eq!(generate::x25519_public_key(&secret), first);
    }

    #[test]
    fn an_ed25519_key_signs_and_its_signature_verifies() {
        let directory = tempdir();
        let secrets = secrets_dir(&directory);
        let store = FileSecretStore::api(&secrets, SecretSource::LoadOrGenerate);
        let public = match store.public_key() {
            Ok(key) => key,
            Err(error) => panic!("public key: {error}"),
        };
        let signature = match store.sign(b"wgmesh") {
            Ok(signature) => signature,
            Err(error) => panic!("signing: {error}"),
        };
        assert!(generate::verify(&public, b"wgmesh", &signature));
        assert!(!generate::verify(&public, b"wgmeshes", &signature));
    }

    #[test]
    fn signing_with_a_tunnel_key_is_refused_rather_than_silently_wrong() {
        let directory = tempdir();
        let secrets = secrets_dir(&directory);
        let store = FileSecretStore::wireguard(&secrets, SecretSource::LoadOrGenerate);
        match store.sign(b"wgmesh") {
            Err(SecretError::WrongKind { actual, wanted, .. }) => {
                assert_eq!(actual, KeyKind::X25519);
                assert_eq!(wanted, KeyKind::Ed25519);
            }
            other => panic!("expected a wrong kind error, got {other:?}"),
        }
    }

    #[test]
    fn the_key_file_names_are_the_ones_the_blueprint_names() {
        let directory = tempdir();
        let secrets = secrets_dir(&directory);
        assert_eq!(
            FileSecretStore::wireguard(&secrets, SecretSource::RequireExisting).path(),
            secrets.join("wg.key")
        );
        assert_eq!(
            FileSecretStore::api(&secrets, SecretSource::RequireExisting).path(),
            secrets.join("api.key")
        );
        assert_eq!(
            FileSecretStore::relay(&secrets, SecretSource::RequireExisting).path(),
            secrets.join("relay.key")
        );
    }

    #[test]
    fn a_key_file_that_is_not_a_key_is_reported_with_its_path() {
        let directory = tempdir();
        let secrets = secrets_dir(&directory);
        if let Err(error) = fs::create_dir_all(&secrets) {
            panic!("creating: {error}");
        }
        let path = secrets.join(WIREGUARD_KEY_NAME);
        if let Err(error) = fs::write(&path, b"not a key at all, but long enough\n") {
            panic!("writing: {error}");
        }
        let store = FileSecretStore::wireguard(&secrets, SecretSource::RequireExisting);
        match store.reveal() {
            Err(SecretError::KeyFile { path: reported, .. }) => assert_eq!(reported, path),
            other => panic!("expected the path to be reported, got {other:?}"),
        }
    }

    #[test]
    fn the_modes_can_be_relaxed_for_a_caller_that_needs_it() {
        let directory = tempdir();
        let secrets = secrets_dir(&directory);
        let store = FileSecretStore::wireguard(&secrets, SecretSource::LoadOrGenerate)
            .with_modes(0o644, 0o755);
        if let Err(error) = store.reveal() {
            panic!("generating: {error}");
        }
        assert_eq!(mode(store.path()), 0o644);
        assert_eq!(mode(&secrets), 0o755);
    }
}
