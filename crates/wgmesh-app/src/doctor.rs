use wgmesh_ports::ForwardingPolicy;

/// What `wgmesh doctor` says about one thing it looked at.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CheckState {
    Ok,
    Warn,
    Fail,
}

impl CheckState {
    pub fn as_str(self) -> &'static str {
        match self {
            CheckState::Ok => "ok",
            CheckState::Warn => "warn",
            CheckState::Fail => "fail",
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Check {
    pub name: &'static str,
    pub state: CheckState,
    pub detail: String,
    /// The point of `wgmesh doctor` is this line: what to do next. It is never empty.
    pub remedy: String,
}

impl Check {
    fn ok(name: &'static str, detail: String, remedy: impl Into<String>) -> Self {
        Self {
            name,
            state: CheckState::Ok,
            detail,
            remedy: remedy.into(),
        }
    }

    fn warn(name: &'static str, detail: String, remedy: impl Into<String>) -> Self {
        Self {
            name,
            state: CheckState::Warn,
            detail,
            remedy: remedy.into(),
        }
    }

    fn fail(name: &'static str, detail: String, remedy: impl Into<String>) -> Self {
        Self {
            name,
            state: CheckState::Fail,
            detail,
            remedy: remedy.into(),
        }
    }

    pub fn line(&self) -> String {
        format!(
            "{state:<4} {name:<22} {detail}\n     -> {remedy}",
            state = self.state.as_str(),
            name = self.name,
            detail = self.detail,
            remedy = self.remedy,
        )
    }
}

/// What the host says about forwarding right now. `None` means it could not be read, which is
/// a different thing from "off".
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct ForwardingObservation {
    pub ipv4_forward: Option<bool>,
    pub ipv6_forward: Option<bool>,
}

fn describe(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "1 (on)",
        Some(false) => "0 (off)",
        None => "unreadable",
    }
}

/// The forwarding half of `wgmesh doctor`.
///
/// Every branch ends in a sentence the operator can act on, because the answer to "forwarding
/// is not working" depends on who owns each piece: with `sysctl = true` and
/// `firewall = "manage"` this package does the work; with either off, somebody else must.
pub fn forwarding_checks(policy: ForwardingPolicy, observed: ForwardingObservation) -> Vec<Check> {
    let mut checks = Vec::new();

    if !policy.enabled {
        checks.push(Check::ok(
            "forwarding",
            String::from("disabled: this device is an endpoint, not a gateway"),
            "set `[forwarding] enabled = true` if traffic must cross between the tunnel and \
             another interface",
        ));
        return checks;
    }

    let tunables = format!(
        "net.ipv4.ip_forward is {}, net.ipv6.conf.all.forwarding is {}",
        describe(observed.ipv4_forward),
        describe(observed.ipv6_forward)
    );
    if policy.sysctl {
        checks.push(Check::ok(
            "forwarding.sysctl",
            format!(
                "{tunables}; wgmesh sets both on start and restores the previous values on stop"
            ),
            "nothing: `sysctl = true` is what makes this wgmesh's job",
        ));
    } else if observed.ipv4_forward == Some(false) || observed.ipv6_forward == Some(false) {
        checks.push(Check::fail(
            "forwarding.sysctl",
            format!("{tunables}, and `sysctl = false` tells wgmesh not to touch them"),
            "set them from outside (`sysctl -w net.ipv4.ip_forward=1`, NixOS: \
             `boot.kernel.sysctl`), or set `[forwarding] sysctl = true`",
        ));
    } else {
        checks.push(Check::warn(
            "forwarding.sysctl",
            format!("{tunables}; wgmesh will not touch them because `sysctl = false`"),
            "keep both at 1 from outside wgmesh (NixOS: `boot.kernel.sysctl`)",
        ));
    }

    if policy.manage_firewall {
        checks.push(Check::ok(
            "forwarding.firewall",
            String::from(
                "wgmesh owns `inet wgmesh` and nothing else; `nft delete table inet wgmesh` \
                 removes every trace",
            ),
            "a host chain that drops forwarded traffic still wins - a verdict in one base \
             chain does not exempt a packet from the next, so allow forwarding there too if \
             the host filters it",
        ));
    } else {
        checks.push(Check::warn(
            "forwarding.firewall",
            String::from("wgmesh does not touch the firewall (`firewall = \"off\"`)"),
            "allow forwarding between the tunnel and the trusted interfaces yourself, keep \
             `net.ipv4.conf.all.rp_filter = 2` for WireGuard's asymmetric paths, or set \
             `firewall = \"manage\"` and let wgmesh own `inet wgmesh`",
        ));
    }

    checks
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn every_state_ends_in_something_to_do() {
        let off = ForwardingPolicy::default();
        let checks = forwarding_checks(off, ForwardingObservation::default());
        assert_eq!(checks.len(), 1);
        assert!(checks.iter().all(|check| !check.remedy.is_empty()));

        let manual = ForwardingPolicy {
            enabled: true,
            sysctl: false,
            manage_firewall: false,
        };
        let checks = forwarding_checks(
            manual,
            ForwardingObservation {
                ipv4_forward: Some(false),
                ipv6_forward: Some(false),
            },
        );
        assert!(checks.iter().all(|check| !check.remedy.is_empty()));
        let sysctl = checks
            .iter()
            .find(|check| check.name == "forwarding.sysctl")
            .expect("the sysctl check is there");
        assert_eq!(sysctl.state, CheckState::Fail);
        assert!(sysctl.remedy.contains("net.ipv4.ip_forward=1"));

        let managed = ForwardingPolicy {
            enabled: true,
            sysctl: true,
            manage_firewall: true,
        };
        let checks = forwarding_checks(
            managed,
            ForwardingObservation {
                ipv4_forward: Some(true),
                ipv6_forward: Some(true),
            },
        );
        assert!(checks.iter().all(|check| check.state == CheckState::Ok));
        assert!(
            checks
                .iter()
                .any(|check| check.detail.contains("inet wgmesh"))
        );
        assert!(checks.iter().any(|check| check.line().contains("->")));
    }
}
