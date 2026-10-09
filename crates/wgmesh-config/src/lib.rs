#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use wgmesh_core::{DiscoveryPolicy, TraversalConfig};

/// Traversal settings, 1:1 with the `[traversal]` table of `agent.toml`.
///
/// Every field has a default, so a configuration file only has to state what it
/// changes. The three switches this milestone is about are `lan_candidates`,
/// `ipv6` and `upnp`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TraversalSettings {
    /// How long the relay path is left alone before the first direct attempt.
    pub punch_delay_secs: u64,
    /// How long a direct attempt is given. Must stay shorter than a NAT mapping
    /// lifetime, because the peer endpoint is the only one WireGuard has: while
    /// the attempt runs, the relay path is broken.
    pub punch_window_secs: u64,
    /// Growth of the interval between direct attempts. Repeated failure is
    /// expected on a symmetric NAT, so this is what keeps the flapping bounded.
    pub backoff_secs: Vec<u64>,
    /// `persistent-keepalive` on every peer: keeps the NAT mapping alive, times
    /// the simultaneous send, and doubles as the liveness probe for a direct
    /// path.
    pub keepalive_secs: u64,
    /// How often a fresh relay observation is pulled.
    pub sync_interval_secs: u64,
    /// Same-LAN private addresses. Off means those candidates are never made.
    pub lan_candidates: bool,
    /// Global IPv6 addresses. Off means those candidates are never made.
    pub ipv6: bool,
    /// NAT-PMP / UPnP-IGD port mapping. Off (the default) means the agent does
    /// not talk to the router at all.
    pub upnp: bool,
}

impl Default for TraversalSettings {
    fn default() -> Self {
        Self {
            punch_delay_secs: 2,
            punch_window_secs: 5,
            backoff_secs: vec![30, 120, 600],
            keepalive_secs: 25,
            sync_interval_secs: 30,
            lan_candidates: true,
            ipv6: true,
            upnp: false,
        }
    }
}

impl TraversalSettings {
    pub fn traversal_config(&self) -> TraversalConfig {
        TraversalConfig {
            punch_delay: Duration::from_secs(self.punch_delay_secs),
            punch_window: Duration::from_secs(self.punch_window_secs),
            backoff: self
                .backoff_secs
                .iter()
                .map(|secs| Duration::from_secs(*secs))
                .collect(),
        }
    }

    pub fn discovery_policy(&self) -> DiscoveryPolicy {
        DiscoveryPolicy {
            lan_candidates: self.lan_candidates,
            ipv6: self.ipv6,
        }
    }

    pub fn keepalive(&self) -> Duration {
        Duration::from_secs(self.keepalive_secs)
    }

    pub fn sync_interval(&self) -> Duration {
        Duration::from_secs(self.sync_interval_secs)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub traversal: TraversalSettings,
}

impl Settings {
    pub fn from_toml(text: &str) -> Result<Self, SettingsError> {
        toml::from_str(text).map_err(|err| SettingsError::Parse(err.to_string()))
    }

    /// Collect every problem instead of stopping at the first one, so a human
    /// fixes one file rather than one field per run.
    pub fn validate(&self) -> Vec<ValidationError> {
        let traversal = &self.traversal;
        let mut problems = Vec::new();
        if traversal.keepalive_secs == 0 {
            problems.push(ValidationError::ZeroKeepalive);
        }
        if traversal.punch_window_secs == 0 {
            problems.push(ValidationError::ZeroPunchWindow);
        }
        if traversal.punch_window_secs >= traversal.keepalive_secs && traversal.keepalive_secs != 0
        {
            problems.push(ValidationError::PunchWindowTooLong {
                window_secs: traversal.punch_window_secs,
                keepalive_secs: traversal.keepalive_secs,
            });
        }
        if traversal.sync_interval_secs == 0 {
            problems.push(ValidationError::ZeroSyncInterval);
        }
        if traversal.backoff_secs.is_empty() {
            problems.push(ValidationError::EmptyBackoff);
        }
        if traversal
            .backoff_secs
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        {
            problems.push(ValidationError::BackoffNotIncreasing(
                traversal.backoff_secs.clone(),
            ));
        }
        problems
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum SettingsError {
    Parse(String),
}

impl fmt::Display for SettingsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(detail) => write!(f, "could not parse the settings file: {detail}"),
        }
    }
}

impl std::error::Error for SettingsError {}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ValidationError {
    ZeroKeepalive,
    ZeroPunchWindow,
    PunchWindowTooLong {
        window_secs: u64,
        keepalive_secs: u64,
    },
    ZeroSyncInterval,
    EmptyBackoff,
    BackoffNotIncreasing(Vec<u64>),
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroKeepalive => write!(f, "traversal.keepalive_secs must not be zero"),
            Self::ZeroPunchWindow => write!(f, "traversal.punch_window_secs must not be zero"),
            Self::PunchWindowTooLong {
                window_secs,
                keepalive_secs,
            } => write!(
                f,
                "traversal.punch_window_secs ({window_secs}) must be shorter than \
                 traversal.keepalive_secs ({keepalive_secs}) so a failed attempt cannot outlive \
                 the relay mapping it broke"
            ),
            Self::ZeroSyncInterval => write!(f, "traversal.sync_interval_secs must not be zero"),
            Self::EmptyBackoff => write!(
                f,
                "traversal.backoff_secs must list at least one interval; a symmetric NAT fails \
                 repeatedly and needs a retreat"
            ),
            Self::BackoffNotIncreasing(list) => {
                write!(f, "traversal.backoff_secs {list:?} must strictly increase")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_defaults_are_the_documented_ones() {
        let defaults = TraversalSettings::default();
        assert_eq!(defaults.punch_delay_secs, 2);
        assert_eq!(defaults.punch_window_secs, 5);
        assert_eq!(defaults.backoff_secs, vec![30, 120, 600]);
        assert_eq!(defaults.keepalive_secs, 25);
        assert_eq!(defaults.sync_interval_secs, 30);
        assert!(defaults.lan_candidates);
        assert!(defaults.ipv6);
    }

    #[test]
    fn upnp_is_off_unless_it_is_asked_for() {
        assert!(!TraversalSettings::default().upnp);
        assert!(!Settings::default().traversal.upnp);

        let parsed = Settings::from_toml("[traversal]\n").unwrap();
        assert!(!parsed.traversal.upnp);

        let on = Settings::from_toml("[traversal]\nupnp = true\n").unwrap();
        assert!(on.traversal.upnp);
        assert!(on.validate().is_empty());
    }

    #[test]
    fn an_empty_file_is_the_default_configuration() {
        let parsed = Settings::from_toml("").unwrap();
        assert_eq!(parsed, Settings::default());
        assert_eq!(parsed.validate(), Vec::new());
    }

    #[test]
    fn the_switches_reach_the_core_types() {
        let parsed = Settings::from_toml(
            "[traversal]\nlan_candidates = false\nipv6 = false\npunch_window_secs = 4\n",
        )
        .unwrap();
        let policy = parsed.traversal.discovery_policy();
        assert!(!policy.lan_candidates);
        assert!(!policy.ipv6);
        assert_eq!(
            parsed.traversal.traversal_config().punch_window,
            Duration::from_secs(4)
        );
        assert_eq!(
            parsed.traversal.traversal_config().backoff,
            vec![
                Duration::from_secs(30),
                Duration::from_secs(120),
                Duration::from_secs(600)
            ]
        );
    }

    #[test]
    fn a_punch_window_that_outlives_the_keepalive_is_rejected() {
        let parsed = Settings::from_toml("[traversal]\npunch_window_secs = 25\n").unwrap();
        assert_eq!(
            parsed.validate(),
            vec![ValidationError::PunchWindowTooLong {
                window_secs: 25,
                keepalive_secs: 25
            }]
        );
    }

    #[test]
    fn backoff_must_be_non_empty_and_increasing() {
        let empty = Settings::from_toml("[traversal]\nbackoff_secs = []\n").unwrap();
        assert_eq!(empty.validate(), vec![ValidationError::EmptyBackoff]);

        let flat = Settings::from_toml("[traversal]\nbackoff_secs = [30, 30, 600]\n").unwrap();
        assert_eq!(
            flat.validate(),
            vec![ValidationError::BackoffNotIncreasing(vec![30, 30, 600])]
        );

        let descending =
            Settings::from_toml("[traversal]\nbackoff_secs = [600, 120, 30]\n").unwrap();
        assert_eq!(
            descending.validate(),
            vec![ValidationError::BackoffNotIncreasing(vec![600, 120, 30])]
        );
    }

    #[test]
    fn every_problem_is_reported_at_once() {
        let parsed = Settings::from_toml(
            "[traversal]\nkeepalive_secs = 3\npunch_window_secs = 9\nsync_interval_secs = 0\n\
             backoff_secs = [60, 30]\n",
        )
        .unwrap();
        let problems = parsed.validate();
        assert!(problems.contains(&ValidationError::ZeroSyncInterval));
        assert!(problems.contains(&ValidationError::PunchWindowTooLong {
            window_secs: 9,
            keepalive_secs: 3
        }));
        assert!(problems.contains(&ValidationError::BackoffNotIncreasing(vec![60, 30])));
    }

    #[test]
    fn a_zero_keepalive_is_reported_on_its_own() {
        let parsed = Settings::from_toml("[traversal]\nkeepalive_secs = 0\n").unwrap();
        assert_eq!(parsed.validate(), vec![ValidationError::ZeroKeepalive]);
    }

    #[test]
    fn an_unknown_key_is_refused_rather_than_ignored() {
        assert!(Settings::from_toml("[traversal]\nupnp_typo = true\n").is_err());
    }
}
