use serde::{Deserialize, Serialize};

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
}
