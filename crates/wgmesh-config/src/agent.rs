use serde::{Deserialize, Serialize};

use std::time::Duration;

use wgmesh_core::{DiscoveryPolicy, TraversalConfig};

use crate::route::{AllowedIpsSetting, FirewallSetting, RelayPoolSetting, RouteSection};
use crate::{Layers, LogSection, StateSection};

/// The agent configuration, as the blueprint's §5 defines it.
///
/// Every field has a default, so a file only carries what it changes.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
#[derive(Default)]
pub struct Settings {
    pub interface: InterfaceSection,
    pub coordinator: CoordinatorSection,
    pub enrollment: EnrollmentSection,
    pub peers: PeersSection,
    pub route: RouteSection,
    pub forwarding: ForwardingSection,
    pub traversal: TraversalSection,
    pub relay: RelaySection,
    pub sync: SyncSection,
    pub state: StateSection,
    pub log: LogSection,
}

impl Settings {
    /// Resolve the effective settings from the four layers.
    pub fn load(layers: &Layers) -> Result<Self, crate::ConfigError> {
        crate::resolve(layers)
    }

    /// Every problem this configuration has, not just the first.
    pub fn validate(&self) -> Vec<crate::Problem> {
        crate::validate::validate(self)
    }
}

/// The `[interface]` table.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct InterfaceSection {
    pub name: String,
    pub mtu: u32,
    pub listen_port: u16,
    pub private_key_file: String,
    pub api_key_file: String,
}

impl Default for InterfaceSection {
    fn default() -> Self {
        Self {
            name: "wg0".to_string(),
            mtu: 1420,
            listen_port: 0,
            private_key_file: String::new(),
            api_key_file: String::new(),
        }
    }
}

/// The `[coordinator]` table.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CoordinatorSection {
    pub url: String,
    pub spki_sha256: String,
    pub network: String,
}

impl Default for CoordinatorSection {
    fn default() -> Self {
        Self {
            url: String::new(),
            spki_sha256: String::new(),
            network: "default".to_string(),
        }
    }
}

/// The `[enrollment]` table.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EnrollmentSection {
    pub token_file: String,
    pub wait_for_approval: bool,
}

impl Default for EnrollmentSection {
    fn default() -> Self {
        Self {
            token_file: String::new(),
            wait_for_approval: true,
        }
    }
}

/// The `[peers]` table: who gets which AllowedIPs entries.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PeersSection {
    pub allowed_ips: AllowedIpsSetting,
    pub exit_peer: String,
}

impl Default for PeersSection {
    fn default() -> Self {
        Self {
            allowed_ips: AllowedIpsSetting::Peer,
            exit_peer: String::new(),
        }
    }
}

/// The `[forwarding]` table.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ForwardingSection {
    pub enabled: bool,
    pub sysctl: bool,
    pub firewall: FirewallSetting,
}

impl Default for ForwardingSection {
    fn default() -> Self {
        Self {
            enabled: false,
            sysctl: true,
            firewall: FirewallSetting::Off,
        }
    }
}

/// The `[traversal]` table: how the agent tries to leave the relay behind.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TraversalSection {
    pub punch_delay_secs: u64,
    pub punch_window_secs: u64,
    pub backoff_secs: Vec<u64>,
    pub keepalive_secs: u64,
    pub lan_candidates: bool,
    pub ipv6: bool,
    pub upnp: bool,
}

impl Default for TraversalSection {
    fn default() -> Self {
        Self {
            punch_delay_secs: 2,
            punch_window_secs: 5,
            backoff_secs: vec![30, 120, 600],
            keepalive_secs: 25,
            lan_candidates: true,
            ipv6: true,
            upnp: false,
        }
    }
}

/// How long a NAT-PMP or UPnP mapping is asked to live.
///
/// Long enough that it outlives the keepalives refreshing it - 120 of them - and
/// no longer than the hour that gateways in the field most commonly honour.
fn mapping_lifetime(keepalive_secs: u64) -> Duration {
    Duration::from_secs(keepalive_secs.max(1).saturating_mul(120).min(3600))
}

impl TraversalSection {
    /// The timings as `wgmesh-core`'s state machine wants them.
    ///
    /// The core owns the shape of the retreat - a bounded list of waits - and the
    /// file owns the numbers, so this is a translation and not a second decision.
    /// A file with an empty `backoff_secs` fails validation rather than reaching
    /// here; `wgmesh_core`'s own default is what a caller gets when the list runs
    /// out.
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

    /// Which candidate classes this node may derive for itself.
    ///
    /// `lan_candidates` and `ipv6` switch off the two classes a node produces
    /// from its own interfaces. They do not switch off the relay-observed address
    /// or the relay itself: those are the path both sides agree on and the
    /// fallback, and the core has no policy field for either.
    pub fn discovery_policy(&self) -> DiscoveryPolicy {
        DiscoveryPolicy {
            lan_candidates: self.lan_candidates,
            ipv6: self.ipv6,
        }
    }

    /// Whether NAT-PMP and UPnP-IGD may be spoken to at all.
    ///
    /// Off by default and off means off: the agent does not call the port mapper,
    /// so no request is made to the router. A mapping is an opportunistic extra
    /// candidate, never a prerequisite for the traversal.
    pub fn upnp_enabled(&self) -> bool {
        self.upnp
    }

    /// How long a mapping is asked to live, when one is asked for.
    pub fn mapping_lifetime(&self) -> Duration {
        mapping_lifetime(self.keepalive_secs)
    }

    /// The persistent keepalive every peer of this mesh is given.
    pub fn keepalive(&self) -> Duration {
        Duration::from_secs(self.keepalive_secs)
    }
}

/// The `[relay]` table of the agent: which relays it accepts.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RelaySection {
    pub pool: RelayPoolSetting,
    pub pin: String,
}

impl Default for RelaySection {
    fn default() -> Self {
        Self {
            pool: RelayPoolSetting::Any,
            pin: String::new(),
        }
    }
}

/// The `[sync]` table.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SyncSection {
    pub interval_secs: u64,
    pub sse: bool,
}

impl Default for SyncSection {
    fn default() -> Self {
        Self {
            interval_secs: 30,
            sse: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_section_defaults_are_the_ones_the_blueprint_ships() {
        let settings = Settings::default();
        assert_eq!(settings.interface, InterfaceSection::default());
        assert_eq!(settings.coordinator.network, "default");
        assert!(settings.enrollment.wait_for_approval);
        assert_eq!(settings.peers.allowed_ips, AllowedIpsSetting::Peer);
        assert_eq!(settings.peers.exit_peer, "");
        assert_eq!(settings.route, RouteSection::default());
        assert!(!settings.forwarding.enabled);
        assert_eq!(settings.traversal.punch_delay_secs, 2);
        assert_eq!(settings.traversal.punch_window_secs, 5);
        assert_eq!(settings.traversal.backoff_secs, vec![30, 120, 600]);
        assert_eq!(settings.traversal.keepalive_secs, 25);
        assert_eq!(settings.relay.pool, RelayPoolSetting::Any);
        assert_eq!(settings.sync.interval_secs, 30);
        assert_eq!(settings.state.dir.to_string_lossy(), "/var/lib/wgmesh");
        assert_eq!(settings.log.level, crate::LogLevel::Info);
        assert_eq!(settings.log.format, crate::LogFormat::Text);
    }

    /// The file is the only place these three are decided. The agent's own
    /// defaults have to agree with the file's, or a device that never wrote a
    /// config would behave differently from one that did.
    #[test]
    fn the_candidate_switches_default_to_upnp_off_and_both_local_classes_on() {
        let traversal = TraversalSection::default();
        assert!(
            !traversal.upnp_enabled(),
            "off means the router is never spoken to, so off has to be the default"
        );
        assert_eq!(
            traversal.discovery_policy(),
            DiscoveryPolicy {
                lan_candidates: true,
                ipv6: true
            }
        );
    }

    #[test]
    fn the_traversal_timings_carry_into_the_cores_own_shape() {
        let config = TraversalSection::default().traversal_config();
        assert_eq!(config, TraversalConfig::default());
        assert_eq!(config.punch_window, Duration::from_secs(5));
        assert_eq!(
            config.backoff,
            vec![
                Duration::from_secs(30),
                Duration::from_secs(120),
                Duration::from_secs(600)
            ],
            "30 seconds, then 2 minutes, then 10 minutes"
        );
        assert_eq!(
            TraversalSection::default().keepalive(),
            Duration::from_secs(25)
        );
    }

    #[test]
    fn a_file_that_switches_a_class_off_carries_that_decision_to_the_policy() {
        let traversal = TraversalSection {
            lan_candidates: false,
            upnp: true,
            ..TraversalSection::default()
        };
        let policy = traversal.discovery_policy();
        assert!(!policy.lan_candidates);
        assert!(policy.ipv6, "one switch does not move the other");
        assert!(traversal.upnp_enabled());
    }

    #[test]
    fn a_mapping_outlives_the_keepalives_that_refresh_it_without_exceeding_an_hour() {
        assert_eq!(
            TraversalSection::default().mapping_lifetime(),
            Duration::from_secs(3000),
            "120 keepalives at the default 25s"
        );
        assert_eq!(
            TraversalSection {
                keepalive_secs: 300,
                ..TraversalSection::default()
            }
            .mapping_lifetime(),
            Duration::from_secs(3600),
            "and a slow keepalive does not ask for more than gateways honour"
        );
    }
}
