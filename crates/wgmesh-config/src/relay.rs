use serde::{Deserialize, Serialize};

use crate::{CoordinatorEndpoint, Layers, StateSection};

/// The relay configuration, as the blueprint's §5 defines it.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
#[derive(Default)]
pub struct RelaySettings {
    pub relay: RelayDaemonSection,
    pub limits: LimitsSection,
    pub coordinator: CoordinatorEndpoint,
    pub enrollment: RelayEnrollmentSection,
    pub state: StateSection,
}

impl RelaySettings {
    /// Resolve the effective settings from the four layers.
    pub fn load(layers: &Layers) -> Result<Self, crate::ConfigError> {
        crate::resolve_relay(layers)
    }

    /// Every problem this configuration has, not just the first.
    pub fn validate(&self) -> Vec<crate::Problem> {
        crate::validate::validate_relay(self)
    }
}

/// The `[relay]` table of the relay daemon itself.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RelayDaemonSection {
    pub listen: String,
    pub port_range: [u16; 2],
    pub keyset_ttl_secs: u64,
}

impl Default for RelayDaemonSection {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0".to_string(),
            port_range: [51820, 51999],
            keyset_ttl_secs: 300,
        }
    }
}

/// The `[limits]` table: what one slot may consume.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LimitsSection {
    pub pps_per_slot: u64,
    pub mbit_per_slot: u64,
}

impl Default for LimitsSection {
    fn default() -> Self {
        Self {
            pps_per_slot: 5_000,
            mbit_per_slot: 100,
        }
    }
}

/// The `[enrollment]` table of the relay.
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RelayEnrollmentSection {
    pub token_file: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_relay_defaults_are_the_ones_the_blueprint_ships() {
        let settings = RelaySettings::default();
        assert_eq!(settings.relay.listen, "0.0.0.0");
        assert_eq!(settings.relay.port_range, [51820, 51999]);
        assert_eq!(settings.relay.keyset_ttl_secs, 300);
        assert_eq!(settings.limits.pps_per_slot, 5_000);
        assert_eq!(settings.limits.mbit_per_slot, 100);
        assert_eq!(settings.coordinator.url, "");
        assert_eq!(settings.state.dir.to_string_lossy(), "/var/lib/wgmesh");
    }

    #[test]
    fn a_relay_file_only_carries_what_it_changes() {
        let file = match tempfile::NamedTempFile::new() {
            Ok(file) => file,
            Err(error) => panic!("temporary file: {error}"),
        };
        if let Err(error) = std::fs::write(
            file.path(),
            "[relay]\nport_range = [51820, 51829]\n\n[coordinator]\nurl = \"https://wgmesh.example.com\"\n",
        ) {
            panic!("writing the file: {error}");
        }
        let settings = match RelaySettings::load(&Layers::new().file(file.path())) {
            Ok(settings) => settings,
            Err(error) => panic!("loading the relay file: {error}"),
        };
        assert_eq!(settings.relay.port_range, [51820, 51829]);
        assert_eq!(settings.relay.listen, "0.0.0.0");
        assert_eq!(settings.coordinator.url, "https://wgmesh.example.com");
        assert_eq!(settings.limits.pps_per_slot, 5_000);
    }
}
