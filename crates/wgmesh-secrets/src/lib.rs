pub mod atomic;
pub mod file;
pub mod generate;
pub mod parse;

use std::fmt;
use std::path::PathBuf;

pub use atomic::{SECRET_DIR_MODE, SECRET_FILE_MODE, mode_of, temporary_path, write_atomic};
pub use file::{
    API_KEY_NAME, FileSecretStore, KeyKind, RELAY_KEY_NAME, SecretSource, WIREGUARD_KEY_NAME,
};
pub use generate::SIGNATURE_LEN;
pub use parse::{BASE64_KEY_LEN, KEY_LEN, KeyFormat, encode_key, parse_key};

/// Everything that can go wrong while reading, generating or using a secret.
#[derive(Debug)]
pub enum SecretError {
    /// A key file could not be read or written.
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    /// A key was required and is not there.
    Missing { path: PathBuf },
    /// The file holds neither thirty two raw bytes nor one base64 line.
    NotAKey { len: usize, reason: &'static str },
    /// The file is not text, so it cannot be a base64 key.
    NotUtf8 { len: usize },
    /// The single line is not base64.
    Base64 { message: String },
    /// The base64 decoded to a length that is not a key.
    WrongLength { decoded: usize },
    /// The operating system would not give us randomness.
    Randomness { source: getrandom::Error },
    /// Signing failed. For Ed25519 this should not happen.
    Signing { reason: String },
    /// A signing operation was asked of a key that cannot sign.
    WrongKind {
        path: PathBuf,
        actual: KeyKind,
        wanted: KeyKind,
    },
    /// A key file that could not be parsed, named by its path.
    KeyFile {
        path: PathBuf,
        cause: Box<SecretError>,
    },
}

impl SecretError {
    /// Name the file an error came from, when the error is about the file's contents.
    pub fn in_file(self, path: &std::path::Path) -> Self {
        match self {
            SecretError::NotAKey { .. }
            | SecretError::NotUtf8 { .. }
            | SecretError::Base64 { .. }
            | SecretError::WrongLength { .. } => SecretError::KeyFile {
                path: path.to_path_buf(),
                cause: Box::new(self),
            },
            other => other,
        }
    }
}

impl fmt::Display for SecretError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecretError::Io { path, source } => {
                write!(formatter, "cannot use {}: {source}", path.display())
            }
            SecretError::Missing { path } => write!(
                formatter,
                "{} does not exist, and this path is provisioned elsewhere so it is never created here",
                path.display()
            ),
            SecretError::NotAKey { len, reason } => {
                write!(formatter, "{len} bytes are not a key: {reason}")
            }
            SecretError::NotUtf8 { len } => write!(
                formatter,
                "{len} bytes are not text, so they cannot be a base64 key"
            ),
            SecretError::Base64 { message } => {
                write!(formatter, "the key is not base64: {message}")
            }
            SecretError::WrongLength { decoded } => write!(
                formatter,
                "the base64 line decodes to {decoded} bytes, and a key is {KEY_LEN}"
            ),
            SecretError::Randomness { source } => {
                write!(
                    formatter,
                    "the operating system gave no randomness: {source}"
                )
            }
            SecretError::Signing { reason } => write!(formatter, "signing failed: {reason}"),
            SecretError::WrongKind {
                path,
                actual,
                wanted,
            } => write!(
                formatter,
                "{} holds a {actual:?} key, and {wanted:?} is required here",
                path.display()
            ),
            SecretError::KeyFile { path, cause } => {
                write!(formatter, "{}: {cause}", path.display())
            }
        }
    }
}

impl std::error::Error for SecretError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SecretError::Io { source, .. } => Some(source),
            SecretError::Randomness { source } => Some(source),
            SecretError::KeyFile { cause, .. } => Some(cause.as_ref()),
            SecretError::Missing { .. }
            | SecretError::NotAKey { .. }
            | SecretError::NotUtf8 { .. }
            | SecretError::Base64 { .. }
            | SecretError::WrongLength { .. }
            | SecretError::Signing { .. }
            | SecretError::WrongKind { .. } => None,
        }
    }
}

/// Check an Ed25519 signature against a public key the store already holds.
///
/// This is the one operation that has to be right: a private key never leaves
/// the machine it was generated on, and everything else about authentication is
/// bookkeeping around this call.
pub fn verify(public_key: &wgmesh_core::PublicKey, message: &[u8], signature: &[u8]) -> bool {
    let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(public_key.as_bytes()) else {
        return false;
    };
    let Ok(signature) = ed25519_dalek::Signature::from_slice(signature) else {
        return false;
    };
    key.verify_strict(message, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_parse_error_is_named_by_the_file_it_came_from() {
        let error = SecretError::NotAKey {
            len: 3,
            reason: "too short",
        }
        .in_file(std::path::Path::new("/var/lib/wgmesh/secrets/wg.key"));
        match &error {
            SecretError::KeyFile { path, .. } => {
                assert_eq!(path, std::path::Path::new("/var/lib/wgmesh/secrets/wg.key"))
            }
            other => panic!("expected the path to be attached, got {other:?}"),
        }
        assert!(error.to_string().contains("wg.key"));
    }

    #[test]
    fn an_error_that_already_names_a_file_is_left_alone() {
        let error = SecretError::Missing {
            path: PathBuf::from("/run/secrets/wg.key"),
        }
        .in_file(std::path::Path::new("/somewhere/else"));
        match error {
            SecretError::Missing { path } => assert_eq!(path, PathBuf::from("/run/secrets/wg.key")),
            other => panic!("expected the original error, got {other:?}"),
        }
    }
}
