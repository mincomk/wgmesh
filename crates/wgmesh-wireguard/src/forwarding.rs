use std::collections::BTreeMap;
use std::sync::Mutex;

use wgmesh_ports::{Firewall, ForwardingPolicy, RouteError, Sysctl};

use crate::sysctl::{IPV4_FORWARD, IPV6_FORWARD};

/// What `[forwarding] enabled = true` means, in one place.
///
/// Two rules decide everything this type does. Nothing is touched unless `enabled` is true,
/// and nothing is touched that was not asked for: `sysctl = false` means no tunable is read
/// or written, and `firewall = "off"` means no rule is created. Whatever it does touch it
/// remembers, so [`deactivate`](ForwardingManager::deactivate) puts the host back the way it
/// was — including a value the host had set to something other than the kernel default.
pub struct ForwardingManager<S: Sysctl, F: Firewall> {
    policy: ForwardingPolicy,
    sysctl: S,
    firewall: F,
    previous: Mutex<BTreeMap<String, String>>,
}

/// The tunables forwarding needs, in the order they are set.
pub const FORWARD_KEYS: [&str; 2] = [IPV4_FORWARD, IPV6_FORWARD];

/// What [`ForwardingManager::activate`] did.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct ForwardingReport {
    /// The tunables this call changed, with the value each held before.
    pub sysctl_changed: Vec<(String, String)>,
    /// Whether this call created or refreshed the nftables table.
    pub firewall_managed: bool,
}

impl ForwardingReport {
    pub fn touched_nothing(&self) -> bool {
        self.sysctl_changed.is_empty() && !self.firewall_managed
    }
}

impl<S: Sysctl, F: Firewall> ForwardingManager<S, F> {
    pub fn new(policy: ForwardingPolicy, sysctl: S, firewall: F) -> Self {
        Self {
            policy,
            sysctl,
            firewall,
            previous: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn policy(&self) -> ForwardingPolicy {
        self.policy
    }

    /// The values the host held before this process changed anything, for the state file.
    pub fn previous(&self) -> BTreeMap<String, String> {
        match self.previous.lock() {
            Ok(previous) => previous.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    pub fn activate(&self) -> Result<ForwardingReport, RouteError> {
        let mut report = ForwardingReport::default();
        if !self.policy.enabled {
            return Ok(report);
        }

        if self.policy.sysctl {
            for key in FORWARD_KEYS {
                let held = self.sysctl.read(key)?;
                if held.trim() == "1" {
                    // Already on: not ours to undo, so it is not recorded as ours either.
                    continue;
                }
                match self.previous.lock() {
                    Ok(mut previous) => {
                        previous.insert(key.to_owned(), held.clone());
                    }
                    Err(poisoned) => {
                        poisoned.into_inner().insert(key.to_owned(), held.clone());
                    }
                }
                self.sysctl.write(key, "1")?;
                report.sysctl_changed.push((key.to_owned(), held));
            }
        }

        if self.policy.manage_firewall {
            self.firewall.ensure()?;
            report.firewall_managed = true;
        }

        Ok(report)
    }

    /// Put back every tunable this process changed and delete our own table. Safe to call
    /// without [`activate`](ForwardingManager::activate), and safe to call twice.
    pub fn deactivate(&self) -> Result<(), RouteError> {
        let held = match self.previous.lock() {
            Ok(mut previous) => std::mem::take(&mut *previous),
            Err(poisoned) => std::mem::take(&mut *poisoned.into_inner()),
        };
        for (key, value) in &held {
            self.sysctl.write(key, value)?;
        }
        if self.policy.enabled && self.policy.manage_firewall {
            self.firewall.remove()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall::NftFirewall;
    use crate::testing::{RecordingRunner, RecordingSysctl};
    use std::sync::Arc;

    fn managed(runner: Arc<RecordingRunner>) -> NftFirewall<Arc<RecordingRunner>> {
        NftFirewall::new(runner, vec![String::from("wg0")])
    }

    fn policy(enabled: bool, sysctl: bool, manage_firewall: bool) -> ForwardingPolicy {
        ForwardingPolicy {
            enabled,
            sysctl,
            manage_firewall,
        }
    }

    #[test]
    fn forwarding_that_is_off_touches_neither_sysctl_nor_the_firewall() {
        let sysctl = Arc::new(RecordingSysctl::new());
        let runner = Arc::new(RecordingRunner::new());
        let manager = ForwardingManager::new(
            policy(false, true, true),
            sysctl.clone(),
            managed(runner.clone()),
        );
        let report = manager.activate().expect("nothing can fail");
        assert!(report.touched_nothing());
        manager.deactivate().expect("nothing to undo");
        assert!(sysctl.reads().is_empty());
        assert!(sysctl.writes().is_empty());
        assert!(runner.lines().is_empty());
    }

    #[test]
    fn sysctl_false_leaves_the_tunables_alone() {
        let sysctl = Arc::new(RecordingSysctl::new());
        sysctl.seed(IPV4_FORWARD, "0");
        sysctl.seed(IPV6_FORWARD, "0");
        let runner = Arc::new(RecordingRunner::new());
        let manager = ForwardingManager::new(
            policy(true, false, false),
            sysctl.clone(),
            managed(runner.clone()),
        );

        manager.activate().expect("forwarding on");
        assert!(
            sysctl.reads().is_empty(),
            "`sysctl = false` must not even read"
        );
        assert!(sysctl.writes().is_empty());
        assert_eq!(sysctl.value(IPV4_FORWARD).as_deref(), Some("0"));
        assert!(
            runner.lines().is_empty(),
            "`firewall = \"off\"` creates no rule"
        );
        assert!(manager.previous().is_empty());

        manager.deactivate().expect("deactivate");
        assert!(sysctl.writes().is_empty());
    }

    #[test]
    fn the_sysctl_we_change_is_remembered_and_restored() {
        let sysctl = Arc::new(RecordingSysctl::new());
        sysctl.seed(IPV4_FORWARD, "0");
        sysctl.seed(IPV6_FORWARD, "1");
        let runner = Arc::new(RecordingRunner::new());
        let manager =
            ForwardingManager::new(policy(true, true, false), sysctl.clone(), managed(runner));

        let report = manager.activate().expect("forwarding on");
        assert_eq!(
            report.sysctl_changed,
            vec![(String::from(IPV4_FORWARD), String::from("0"))],
            "the one already at 1 is left alone and not claimed"
        );
        assert_eq!(sysctl.value(IPV4_FORWARD).as_deref(), Some("1"));
        assert_eq!(sysctl.value(IPV6_FORWARD).as_deref(), Some("1"));

        manager.deactivate().expect("deactivate");
        assert_eq!(
            sysctl.value(IPV4_FORWARD).as_deref(),
            Some("0"),
            "the value the host had is put back"
        );
        assert_eq!(sysctl.value(IPV6_FORWARD).as_deref(), Some("1"));
        assert!(
            manager.previous().is_empty(),
            "a restored value is no longer ours"
        );
    }

    #[test]
    fn managing_the_firewall_creates_our_table_and_deleting_it_undoes_everything() {
        let sysctl = Arc::new(RecordingSysctl::new());
        sysctl.seed(IPV4_FORWARD, "1");
        sysctl.seed(IPV6_FORWARD, "1");
        let runner = Arc::new(RecordingRunner::new());
        let manager = ForwardingManager::new(
            policy(true, true, true),
            sysctl.clone(),
            managed(runner.clone()),
        );

        let report = manager.activate().expect("forwarding on");
        assert!(report.firewall_managed);
        assert!(report.sysctl_changed.is_empty(), "both were already 1");

        let lines = runner.lines();
        assert_eq!(lines[0], "nft add table inet wgmesh");
        assert!(lines.iter().all(|line| line.contains("inet wgmesh")));
        assert_eq!(runner.programs(), vec!["nft"]);

        runner.clear();
        manager.deactivate().expect("deactivate");
        assert_eq!(runner.lines(), vec!["nft delete table inet wgmesh"]);
    }

    #[test]
    fn a_second_round_trip_leaves_the_host_exactly_as_it_was() {
        let sysctl = Arc::new(RecordingSysctl::new());
        sysctl.seed(IPV4_FORWARD, "0");
        sysctl.seed(IPV6_FORWARD, "0");
        let runner = Arc::new(RecordingRunner::new());
        let manager = ForwardingManager::new(
            policy(true, true, true),
            sysctl.clone(),
            managed(runner.clone()),
        );

        for _ in 0..2 {
            manager.activate().expect("on");
            manager.deactivate().expect("off");
        }
        assert_eq!(sysctl.value(IPV4_FORWARD).as_deref(), Some("0"));
        assert_eq!(sysctl.value(IPV6_FORWARD).as_deref(), Some("0"));
        assert_eq!(
            runner
                .lines()
                .iter()
                .filter(|line| line.starts_with("nft delete table"))
                .count(),
            2
        );
    }
}
