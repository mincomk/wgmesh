use serde::{Deserialize, Serialize};

use crate::agent::LogFormat;
use crate::validate::{Problem, check_absolute_dir, parse_allowed};

/// The band a coordinator's network is carved from, and the name both sides
/// call it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Network {
    pub name: String,
    pub cidr: String,
    pub mtu: u16,
    /// First address handed to a device; the rest of the block is the pool.
    pub first_host: u8,
}

impl Default for Network {
    fn default() -> Self {
        Self {
            name: "prod".to_owned(),
            cidr: "10.77.0.0/16".to_owned(),
            mtu: 1420,
            first_host: 1,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Api {
    pub listen: String,
    /// What nodes reach this coordinator by. Printed in enroll output.
    pub public_url: String,
}

impl Default for Api {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:8080".to_owned(),
            public_url: String::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Policy {
    /// A device that joins without `auto_approve` waits here. A leaked token
    /// costs nothing until an operator says yes.
    pub default_auto_approve: bool,
    pub max_devices_per_network: usize,
    /// The allowance `/v1/join` and `/v1/relay/enroll` share, per client
    /// address, per minute.
    pub join_rate_limit_per_minute: u32,
    /// How many client addresses the limiter tracks before it starts dropping
    /// the ones that have gone quiet.
    pub rate_limit_tracked_ips: usize,
    /// How far a request's timestamp may be from the server's clock.
    pub signature_skew_secs: i64,
    /// How long a nonce is remembered, so a captured request cannot be
    /// replayed inside the skew window.
    pub nonce_ttl_secs: u64,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            default_auto_approve: false,
            max_devices_per_network: 256,
            join_rate_limit_per_minute: 30,
            rate_limit_tracked_ips: 4096,
            signature_skew_secs: 60,
            nonce_ttl_secs: 120,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RelayPolicy {
    pub heartbeat_timeout_secs: u64,
    /// How many heartbeats in a row may go missing before a relay's pairs are
    /// re-homed.
    pub reassign_after_misses: u32,
    pub keyset_ttl_secs: u64,
    /// The last port a slot may be drawn from. Slots are drawn from the whole
    /// range at random, so guessing one is not a matter of counting upward.
    pub slot_port_range: [u16; 2],
}

impl Default for RelayPolicy {
    fn default() -> Self {
        Self {
            heartbeat_timeout_secs: 15,
            reassign_after_misses: 3,
            keyset_ttl_secs: 300,
            slot_port_range: [51_820, 51_999],
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct State {
    pub dir: String,
    /// Snapshot of the store, written atomically beside the state directory.
    pub file: String,
}

impl Default for State {
    fn default() -> Self {
        Self {
            dir: "/var/lib/wgmesh".to_owned(),
            file: "coordinator.json".to_owned(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Log {
    pub level: String,
    pub format: LogFormat,
}

impl Default for Log {
    fn default() -> Self {
        Self {
            level: "info".to_owned(),
            format: LogFormat::Json,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub api: Api,
    pub network: Network,
    pub policy: Policy,
    pub relay: RelayPolicy,
    pub state: State,
    pub log: Log,
}

impl Settings {
    pub fn state_path(&self) -> String {
        format!("{}/{}", self.state.dir, self.state.file)
    }

    pub fn network_prefix(&self) -> Result<wgmesh_core::Allowed, Problem> {
        parse_allowed(&self.network.cidr).ok_or_else(|| {
            Problem::new(
                "network.cidr",
                format!("\"{}\" is not a CIDR", self.network.cidr),
            )
        })
    }

    pub fn validate(&self) -> Vec<Problem> {
        let mut problems = Vec::new();
        check_absolute_dir(&self.state.dir, "state.dir", &mut problems);
        if self.network_prefix().is_err() {
            problems.push(Problem::new(
                "network.cidr",
                format!("\"{}\" is not a CIDR", self.network.cidr),
            ));
        }
        if self.api.listen.is_empty() {
            problems.push(Problem::new("api.listen", "is required"));
        }
        if self.policy.max_devices_per_network == 0 {
            problems.push(Problem::new(
                "policy.max_devices_per_network",
                "must be at least 1",
            ));
        }
        if self.policy.join_rate_limit_per_minute == 0 {
            problems.push(Problem::new(
                "policy.join_rate_limit_per_minute",
                "must be at least 1 — zero would refuse every join, including the first",
            ));
        }
        let [low, high] = self.relay.slot_port_range;
        if low == 0 || low >= high {
            problems.push(Problem::new(
                "relay.slot_port_range",
                "must be a non-empty range of unprivileged ports",
            ));
        }
        if self.relay.keyset_ttl_secs == 0 {
            problems.push(Problem::new(
                "relay.keyset_ttl_secs",
                "must be greater than zero — a relay with no keyset serves nobody",
            ));
        }
        problems
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn an_empty_coordinator_file_is_a_working_configuration() {
        let settings: Settings = crate::parse("").unwrap();
        assert_eq!(settings.api.listen, "127.0.0.1:8080");
        assert_eq!(settings.network.cidr, "10.77.0.0/16");
        assert_eq!(settings.policy.join_rate_limit_per_minute, 30);
        assert!(!settings.policy.default_auto_approve);
        assert!(settings.validate().is_empty());
    }

    #[test]
    fn the_rate_limit_may_be_tuned_and_zero_is_refused() {
        let mut settings = Settings::default();
        settings.policy.join_rate_limit_per_minute = 0;
        assert!(!settings.validate().is_empty());
        settings.policy.join_rate_limit_per_minute = 5;
        assert!(settings.validate().is_empty());
    }

    #[test]
    fn a_network_cidr_that_is_not_one_is_refused() {
        let mut settings = Settings::default();
        settings.network.cidr = "10.77.0.0".to_owned();
        assert!(!settings.validate().is_empty());
    }

    #[test]
    fn the_slot_range_must_make_sense() {
        let mut settings = Settings::default();
        settings.relay.slot_port_range = [51_999, 51_820];
        assert!(!settings.validate().is_empty());
    }

    #[test]
    fn the_state_file_sits_under_the_state_directory() {
        assert_eq!(
            Settings::default().state_path(),
            "/var/lib/wgmesh/coordinator.json"
        );
    }
}
