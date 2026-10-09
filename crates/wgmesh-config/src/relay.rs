use serde::{Deserialize, Serialize};

use crate::agent::LogFormat;
use crate::validate::{Problem, check_absolute_dir, check_coordinator_url, check_spki};

/// What one relay slot may carry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    /// Packets per second, per slot.
    pub pps_per_slot: u32,
    /// Megabits per second, per slot. Bandwidth is the cost of a relay, so
    /// this is the number the bill is written against.
    pub mbit_per_slot: u32,
    /// A single packet larger than this is refused outright rather than
    /// counted against the bucket, so one huge datagram cannot empty a slot.
    pub max_packet_bytes: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            pps_per_slot: 5_000,
            mbit_per_slot: 100,
            max_packet_bytes: 65_535,
        }
    }
}

impl Limits {
    /// Bytes per second a slot may carry.
    pub fn bytes_per_second(&self) -> f64 {
        f64::from(self.mbit_per_slot) * 1_000_000.0 / 8.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RelaySection {
    pub listen: String,
    pub port_range: [u16; 2],
    /// How long the relay keeps serving with the keyset it already has after
    /// the coordinator goes away. Past this it refuses new forwarding, so a
    /// revoked device cannot be served forever by a stale relay.
    pub keyset_ttl_secs: u64,
}

impl Default for RelaySection {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0".to_owned(),
            port_range: [51_820, 51_999],
            keyset_ttl_secs: 300,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CoordinatorSection {
    pub url: String,
    pub spki_sha256: String,
    pub heartbeat_secs: u64,
}

impl Default for CoordinatorSection {
    fn default() -> Self {
        Self {
            url: String::new(),
            spki_sha256: String::new(),
            heartbeat_secs: 5,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Enrollment {
    pub token_file: String,
}

// Not derivable: `wait_for_approval` defaults to `true`, and a derived
// `Default` would quietly wait for nothing.
#[allow(clippy::derivable_impls)]
impl Default for Enrollment {
    fn default() -> Self {
        Self {
            token_file: String::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct State {
    pub dir: String,
}

impl Default for State {
    fn default() -> Self {
        Self {
            dir: "/var/lib/wgmesh".to_owned(),
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
            format: LogFormat::Text,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub relay: RelaySection,
    pub limits: Limits,
    pub coordinator: CoordinatorSection,
    pub enrollment: Enrollment,
    pub state: State,
    pub log: Log,
}

impl Settings {
    pub fn api_key_path(&self) -> String {
        format!("{}/secrets/relay.key", self.state.dir)
    }

    pub fn validate(&self) -> Vec<Problem> {
        let mut problems = Vec::new();
        check_coordinator_url(&self.coordinator.url, "coordinator.url", &mut problems);
        check_spki(
            &self.coordinator.spki_sha256,
            "coordinator.spki_sha256",
            &mut problems,
        );
        check_absolute_dir(&self.state.dir, "state.dir", &mut problems);
        let [low, high] = self.relay.port_range;
        if low == 0 || low >= high {
            problems.push(Problem::new(
                "relay.port_range",
                "must be a non-empty range of unprivileged ports",
            ));
        }
        if self.limits.pps_per_slot == 0 {
            problems.push(Problem::new(
                "limits.pps_per_slot",
                "must be at least 1 — a slot with no packet allowance forwards nothing",
            ));
        }
        if self.limits.mbit_per_slot == 0 {
            problems.push(Problem::new(
                "limits.mbit_per_slot",
                "must be at least 1 — bandwidth is the cost of a relay, so it needs a ceiling",
            ));
        }
        if self.limits.max_packet_bytes < 32 {
            problems.push(Problem::new(
                "limits.max_packet_bytes",
                "must be at least 32 — that is the smallest WireGuard packet",
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
    fn an_empty_relay_file_is_a_working_configuration() {
        let settings: Settings = crate::parse("").unwrap();
        assert_eq!(settings.limits.pps_per_slot, 5_000);
        assert_eq!(settings.limits.mbit_per_slot, 100);
        assert_eq!(settings.relay.port_range, [51_820, 51_999]);
        assert_eq!(settings.relay.keyset_ttl_secs, 300);
        // What is missing from an empty file is the coordinator, and only the
        // coordinator: everything else has a safe default.
        let problems = settings.validate();
        assert_eq!(problems.len(), 2, "{problems:?}");
        assert!(
            problems
                .iter()
                .all(|problem| problem.field.starts_with("coordinator.")),
            "{problems:?}"
        );
    }

    #[test]
    fn the_byte_ceiling_follows_from_the_megabit_ceiling() {
        let limits = Limits {
            mbit_per_slot: 8,
            ..Limits::default()
        };
        assert_eq!(limits.bytes_per_second(), 1_000_000.0);
    }

    #[test]
    fn a_slot_limit_of_zero_is_refused_in_either_unit() {
        let mut settings = Settings::default();
        settings.limits.pps_per_slot = 0;
        assert!(!settings.validate().is_empty());
        let mut settings = Settings::default();
        settings.limits.mbit_per_slot = 0;
        assert!(!settings.validate().is_empty());
    }

    #[test]
    fn a_coordinator_url_without_https_is_refused() {
        let mut settings = Settings::default();
        settings.coordinator.url = "http://coord.example.com".to_owned();
        settings.coordinator.spki_sha256 = "a".repeat(64);
        assert_eq!(settings.validate().len(), 1);
    }

    #[test]
    fn the_relay_key_defaults_under_the_state_directory() {
        assert_eq!(
            Settings::default().api_key_path(),
            "/var/lib/wgmesh/secrets/relay.key"
        );
    }
}
