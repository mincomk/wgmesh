use std::fs;
use std::path::PathBuf;

use wgmesh_ports::{RouteError, Sysctl};

/// `net.ipv4.ip_forward`, the tunable that turns a host into an IPv4 router.
pub const IPV4_FORWARD: &str = "net.ipv4.ip_forward";

/// `net.ipv6.conf.all.forwarding`, the IPv6 half of the same decision.
pub const IPV6_FORWARD: &str = "net.ipv6.conf.all.forwarding";

/// `net.ipv4.conf.all.rp_filter`. WireGuard paths are asymmetric, so a strict reverse-path
/// filter drops packets that are perfectly legitimate; `2` (loose) is what this wants.
pub const ALL_RP_FILTER: &str = "net.ipv4.conf.all.rp_filter";

/// The kernel tunables, named the way `sysctl` names them.
///
/// Going through `/proc/sys` instead of the `sysctl` binary keeps the read side honest — the
/// value that comes back is the one the kernel holds, not one a tool remembered — and it is
/// what lets `wgmesh doctor` read these on a machine where nothing may be written.
pub struct ProcSysctl {
    root: PathBuf,
}

impl Default for ProcSysctl {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcSysctl {
    pub fn new() -> Self {
        Self {
            root: PathBuf::from("/proc/sys"),
        }
    }

    /// The same adapter in front of another root, which is how the write path is tested
    /// without privileges.
    pub fn rooted(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn path_of(&self, key: &str) -> Result<PathBuf, RouteError> {
        if key.is_empty()
            || !key.chars().all(|character| {
                character.is_ascii_alphanumeric()
                    || character == '.'
                    || character == '_'
                    || character == '-'
            })
        {
            return Err(RouteError::fatal(format!("`{key}` is not a sysctl name")));
        }
        Ok(self.root.join(key.replace('.', "/")))
    }
}

impl Sysctl for ProcSysctl {
    fn read(&self, key: &str) -> Result<String, RouteError> {
        let path = self.path_of(key)?;
        fs::read_to_string(&path)
            .map(|text| text.trim().to_owned())
            .map_err(|error| RouteError::fatal(format!("{key}: {error}")))
    }

    fn write(&self, key: &str, value: &str) -> Result<(), RouteError> {
        let path = self.path_of(key)?;
        if value.contains('\n') {
            return Err(RouteError::fatal(format!(
                "`{key}` was handed a multi-line value"
            )));
        }
        fs::write(&path, value).map_err(|error| RouteError::fatal(format!("{key}: {error}")))
    }
}

/// `1` is on, `0` is off, and anything else (a mode, like `rp_filter = 2`) is neither.
pub fn as_flag(value: &str) -> Option<bool> {
    match value.trim() {
        "1" => Some(true),
        "0" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_proc_root_is_named_the_way_sysctl_names_it() {
        let sysctl = ProcSysctl::new();
        assert_eq!(
            sysctl.path_of(IPV4_FORWARD).unwrap(),
            PathBuf::from("/proc/sys/net/ipv4/ip_forward")
        );
        assert!(sysctl.path_of("net/ipv4").is_err());
        assert!(sysctl.path_of("").is_err());
    }

    #[test]
    fn reading_the_real_kernel_tunables_needs_no_privileges() {
        let sysctl = ProcSysctl::new();
        for key in [IPV4_FORWARD, IPV6_FORWARD, ALL_RP_FILTER] {
            let Ok(value) = sysctl.read(key) else {
                // A container with no `/proc/sys` has no tunables to read; that is an
                // environment, not a regression.
                return;
            };
            assert!(
                !value.is_empty() && !value.contains('\n'),
                "`{key}` answered `{value}`"
            );
        }
        assert!(as_flag(&sysctl.read(IPV4_FORWARD).unwrap()).is_some());
    }

    #[test]
    fn the_write_path_round_trips_against_a_root_we_own() {
        let dir = std::env::temp_dir().join(format!("wgmesh-sysctl-{}", std::process::id()));
        let nested = dir.join("net/ipv4");
        fs::create_dir_all(&nested).expect("create");
        fs::write(nested.join("ip_forward"), "0\n").expect("seed");

        let sysctl = ProcSysctl::rooted(&dir);
        assert_eq!(sysctl.read(IPV4_FORWARD).unwrap(), "0");
        sysctl.write(IPV4_FORWARD, "1").expect("write");
        assert_eq!(sysctl.read(IPV4_FORWARD).unwrap(), "1");
        sysctl.write(IPV4_FORWARD, "0").expect("restore");
        assert_eq!(sysctl.read(IPV4_FORWARD).unwrap(), "0");
        assert!(sysctl.write(IPV4_FORWARD, "1\n2").is_err());

        fs::remove_dir_all(&dir).expect("clean");
    }

    #[test]
    fn a_tunable_that_is_not_there_is_an_error_rather_than_a_default() {
        let sysctl = ProcSysctl::rooted("/nonexistent-wgmesh-root");
        assert!(sysctl.read(IPV4_FORWARD).is_err());
        assert!(sysctl.write(IPV4_FORWARD, "1").is_err());
    }
}
