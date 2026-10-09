use std::fs;
use std::path::{Path, PathBuf};

use crate::pin;

pub const PIN_KEY: &str = "coordinator_spki_sha256";

#[derive(Debug)]
pub enum TrustError {
    Io(String),
    NoPin(String),
    NotACertificate,
    // The one that matters: the coordinator answered with a key that is not the
    // pinned one, so the request is not made at all.
    PinChanged { pinned: String, observed: String },
}

impl core::fmt::Display for TrustError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(message) => write!(f, "{message}"),
            Self::NoPin(path) => write!(
                f,
                "{path} carries no {PIN_KEY}; run `wgmesh trust --rotate` once"
            ),
            Self::NotACertificate => f.write_str("the pinned material is not a certificate"),
            Self::PinChanged { pinned, observed } => write!(
                f,
                "the coordinator presented {observed}, which is not the pinned {pinned}; \
                 the connection is refused until `wgmesh trust --rotate` accepts the new key"
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rotation {
    pub previous: Option<String>,
    pub current: String,
}

pub struct TrustStore {
    path: PathBuf,
}

fn value_of(line: &str) -> Option<String> {
    let trimmed = line.trim();
    let (key, rest) = trimmed.split_once('=')?;
    if key.trim() != PIN_KEY {
        return None;
    }
    let rest = rest.trim();
    let value = rest.trim_matches('"').trim_matches('\'').trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_owned())
    }
}

impl TrustStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn read(&self) -> Result<String, TrustError> {
        fs::read_to_string(&self.path).map_err(|error| {
            TrustError::Io(format!("cannot read {}: {error}", self.path.display()))
        })
    }

    pub fn pinned(&self) -> Option<String> {
        let text = self.read().ok()?;
        text.lines().find_map(value_of)
    }

    pub fn show(&self) -> Result<String, TrustError> {
        self.pinned()
            .ok_or_else(|| TrustError::NoPin(self.path.display().to_string()))
    }

    pub fn pin_of(&self, certificate_der: &[u8]) -> Result<String, TrustError> {
        pin::spki_sha256(certificate_der).ok_or(TrustError::NotACertificate)
    }

    // The only way a pin moves. Everything else compares against what is stored,
    // which is why a rotated certificate is refused until this has run.
    pub fn rotate(&self, certificate_der: &[u8]) -> Result<Rotation, TrustError> {
        let observed = self.pin_of(certificate_der)?;
        let text = self.read().unwrap_or_default();
        let previous = text.lines().find_map(value_of);
        let mut lines: Vec<String> = Vec::new();
        let mut replaced = false;
        for line in text.lines() {
            if value_of(line).is_some() {
                lines.push(format!("{PIN_KEY} = \"{observed}\""));
                replaced = true;
            } else {
                lines.push(line.to_owned());
            }
        }
        if !replaced {
            lines.push(format!("{PIN_KEY} = \"{observed}\""));
        }
        let mut rendered = lines.join("\n");
        rendered.push('\n');
        fs::write(&self.path, rendered).map_err(|error| {
            TrustError::Io(format!("cannot write {}: {error}", self.path.display()))
        })?;
        Ok(Rotation {
            previous,
            current: observed,
        })
    }

    // What a client does before every request.
    pub fn ensure(&self, certificate_der: &[u8]) -> Result<(), TrustError> {
        let pinned = self.show()?;
        let observed = self.pin_of(certificate_der)?;
        if observed == pin::normalize(&pinned) {
            Ok(())
        } else {
            Err(TrustError::PinChanged { pinned, observed })
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    const CERT_A: &[u8] = include_bytes!("../tests/fixtures/coordinator-a.der");
    const CERT_B: &[u8] = include_bytes!("../tests/fixtures/coordinator-b.der");
    const PIN_A: &str = "eef4fe3c04c8f4fb8a918abab36cd3fc76f6274aee0efaeb942e595ac03f3a1c";
    const PIN_B: &str = "126305e03335353e8ced874514512ee646fa380247802e061c539b2c7a8a00d5";

    fn config(text: &str) -> (tempfile::TempDir, TrustStore) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.toml");
        fs::write(&path, text).unwrap();
        (dir, TrustStore::new(path))
    }

    #[test]
    fn rotate_records_the_pin_and_leaves_the_rest_of_the_file_alone() {
        let (_dir, store) =
            config("network = \"prod\"\ncoordinator = \"https://wgmesh.example.com\"\n");
        let rotation = store.rotate(CERT_A).unwrap();
        assert_eq!(rotation.previous, None);
        assert_eq!(rotation.current, PIN_A);
        assert_eq!(store.show().unwrap(), PIN_A);

        let text = fs::read_to_string(store.path()).unwrap();
        assert!(text.contains("network = \"prod\""));
        assert!(text.contains("coordinator = \"https://wgmesh.example.com\""));
        assert!(text.contains(&format!("{PIN_KEY} = \"{PIN_A}\"")));
    }

    #[test]
    fn the_old_pin_refuses_the_new_certificate() {
        let (_dir, store) = config("network = \"prod\"\n");
        store.rotate(CERT_A).unwrap();
        store.ensure(CERT_A).unwrap();

        match store.ensure(CERT_B) {
            Err(TrustError::PinChanged { pinned, observed }) => {
                assert_eq!(pinned, PIN_A);
                assert_eq!(observed, PIN_B);
            }
            other => panic!("the old pin must refuse the new certificate, got {other:?}"),
        }
    }

    #[test]
    fn rotating_to_the_new_certificate_makes_it_accepted_and_the_old_one_refused() {
        let (_dir, store) = config(&format!("{PIN_KEY} = \"{PIN_A}\"\n"));
        let rotation = store.rotate(CERT_B).unwrap();
        assert_eq!(rotation.previous, Some(String::from(PIN_A)));
        assert_eq!(rotation.current, PIN_B);
        store.ensure(CERT_B).unwrap();
        assert!(matches!(
            store.ensure(CERT_A),
            Err(TrustError::PinChanged { .. })
        ));

        let text = fs::read_to_string(store.path()).unwrap();
        assert_eq!(
            text.matches(PIN_KEY).count(),
            1,
            "the pin line is replaced, not duplicated"
        );
    }

    #[test]
    fn a_configuration_without_a_pin_says_so_instead_of_accepting_everything() {
        let (_dir, store) = config("network = \"prod\"\n");
        assert!(store.pinned().is_none());
        match store.show() {
            Err(TrustError::NoPin(path)) => assert!(path.ends_with("agent.toml")),
            other => panic!("an absent pin must not be treated as a match, got {other:?}"),
        }
        assert!(store.ensure(CERT_A).is_err());
    }

    #[test]
    fn a_pin_line_that_is_not_a_certificate_is_never_rotated_into() {
        let (_dir, store) = config("network = \"prod\"\n");
        assert!(matches!(
            store.rotate(b"not a certificate"),
            Err(TrustError::NotACertificate)
        ));
        assert!(store.pinned().is_none());
    }

    #[test]
    fn an_acceptably_formatted_pin_value_is_read() {
        let (_dir, store) = config(&format!("{PIN_KEY}=\"{}\"\n", PIN_A.to_uppercase()));
        assert_eq!(store.show().unwrap(), PIN_A.to_uppercase());
        assert!(store.pinned().is_some());
    }
}
