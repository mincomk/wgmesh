// The forwarding toggle of the blueprint, section 6.6, as file I/O over a
// configurable sysctl root so it is testable without a kernel.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// The sysctl tree on a normal Linux host.
pub const PROC_SYS: &str = "/proc/sys";

/// The keys `[forwarding] enabled = true` turns on.
pub const FORWARDING_KEYS: [&str; 2] = ["net/ipv4/ip_forward", "net/ipv6/conf/all/forwarding"];

/// One key that was written, and what it held before.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SysctlChange {
    /// The key, relative to the sysctl root, e.g. `net/ipv4/ip_forward`.
    pub key: String,
    /// The value the key held before the write, `None` when it did not exist.
    pub previous: Option<String>,
    /// The value that was written.
    pub requested: String,
}

impl SysctlChange {
    /// The file this key lives in under `root`.
    pub fn path(&self, root: &Path) -> PathBuf {
        root.join(&self.key)
    }
}

/// Write every key in `keys` to `value`, remembering what was there.
///
/// The root is a parameter rather than a constant so the whole thing is
/// testable without touching a live kernel: point it at a directory of your own
/// and the reads, writes and restores are ordinary file I/O.
///
/// # Errors
///
/// Fails on the first key that can not be read or written, after the keys before
/// it have already been changed. The caller gets no list back on failure, so a
/// partial write has to be recovered from what the caller knows it asked for.
pub fn write_all(root: &Path, keys: &[&str], value: &str) -> io::Result<Vec<SysctlChange>> {
    let mut changes = Vec::with_capacity(keys.len());
    for key in keys {
        let path = root.join(key);
        let previous = match fs::read_to_string(&path) {
            Ok(contents) => Some(contents.trim().to_string()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        fs::write(&path, value)?;
        changes.push(SysctlChange {
            key: (*key).to_string(),
            previous,
            requested: value.to_string(),
        });
    }
    Ok(changes)
}

/// Put every key back the way [`write_all`] found it.
///
/// A key that did not exist before is left alone rather than removed: a sysctl
/// entry is a kernel object, and creating one is not something this helper does.
///
/// # Errors
///
/// Fails on the first key that can not be written back.
pub fn restore_all(root: &Path, changes: &[SysctlChange]) -> io::Result<()> {
    for change in changes {
        let Some(previous) = change.previous.as_deref() else {
            continue;
        };
        fs::write(change.path(root), previous)?;
    }
    Ok(())
}

/// Forwarding as a value that knows how to put itself back.
#[derive(Debug)]
pub struct Forwarding {
    root: PathBuf,
    changes: Vec<SysctlChange>,
}

impl Forwarding {
    /// What was changed, and what it held before.
    pub fn changes(&self) -> &[SysctlChange] {
        &self.changes
    }

    /// Put every key back the way it was.
    ///
    /// # Errors
    ///
    /// Fails on the first key that can not be written back.
    pub fn restore(self) -> io::Result<()> {
        restore_all(&self.root, &self.changes)
    }
}

/// Turn IPv4 and IPv6 forwarding on, handing back what to restore.
///
/// # Errors
///
/// Fails when a key can not be read or written — on a host where the caller may
/// not change `net.ipv4.ip_forward`, this is where that shows up, and the caller
/// has to decide whether to run anyway.
pub fn enable_forwarding(root: &Path) -> io::Result<Forwarding> {
    let changes = write_all(root, &FORWARDING_KEYS, "1")?;
    Ok(Forwarding {
        root: root.to_path_buf(),
        changes,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("wgmesh-sysctl-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        for key in FORWARDING_KEYS {
            let path = root.join(key);
            let parent = path.parent().expect("a key has a parent");
            fs::create_dir_all(parent).expect("the scratch tree is writable");
            fs::write(path, "0\n").expect("the scratch key is writable");
        }
        root
    }

    #[test]
    fn enabling_reports_the_previous_value_and_restores_it() {
        let root = scratch("restore");
        let forwarding = enable_forwarding(&root).expect("forwarding can be turned on");

        assert_eq!(forwarding.changes().len(), 2);
        for change in forwarding.changes() {
            assert_eq!(change.previous.as_deref(), Some("0"));
            assert_eq!(change.requested, "1");
            let now = fs::read_to_string(change.path(&root)).expect("the key is readable");
            assert_eq!(now.trim(), "1");
        }

        forwarding.restore().expect("forwarding can be put back");
        for key in FORWARDING_KEYS {
            let now = fs::read_to_string(root.join(key)).expect("the key is readable");
            assert_eq!(now.trim(), "0");
        }
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_key_that_was_already_on_is_still_remembered() {
        let root = scratch("already-on");
        for key in FORWARDING_KEYS {
            fs::write(root.join(key), "1").expect("the scratch key is writable");
        }

        let forwarding = enable_forwarding(&root).expect("forwarding can be turned on");
        assert_eq!(forwarding.changes()[0].previous.as_deref(), Some("1"));
        assert_eq!(forwarding.changes()[0].requested, "1");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_key_that_does_not_exist_is_skipped_on_restore() {
        let root =
            std::env::temp_dir().join(format!("wgmesh-sysctl-{}-missing", std::process::id()));
        let _ = fs::remove_dir_all(&root);

        let changes = vec![SysctlChange {
            key: "net/ipv4/ip_forward".to_string(),
            previous: None,
            requested: "1".to_string(),
        }];
        restore_all(&root, &changes).expect("an absent key is not an error");
        assert!(!root.join("net/ipv4/ip_forward").exists());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_missing_key_reports_no_previous_value() {
        let root =
            std::env::temp_dir().join(format!("wgmesh-sysctl-{}-absent", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("net/ipv4")).expect("the scratch tree is writable");

        let changes = write_all(&root, &["net/ipv4/ip_forward"], "1").expect("the key is written");
        assert_eq!(changes[0].previous, None);
        let written =
            fs::read_to_string(root.join("net/ipv4/ip_forward")).expect("the key is readable");
        assert_eq!(written, "1");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_write_that_can_not_happen_is_an_error() {
        let root =
            std::env::temp_dir().join(format!("wgmesh-sysctl-{}-denied", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("the scratch tree is writable");

        // `net` is a file here, so the key's directory is not a directory and
        // the write fails.
        fs::write(root.join("net"), "not a directory").expect("the scratch file is writable");
        assert!(write_all(&root, &["net/ipv4/ip_forward"], "1").is_err());
        let _ = fs::remove_dir_all(&root);
    }
}
