use serde::{Deserialize, Serialize};

use crate::{Layers, LogFormat, LogLevel};

/// The coordinator configuration, as the blueprint's §5 defines it.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
#[derive(Default)]
pub struct CoordinatorSettings {
    pub api: ApiSection,
    pub database: DatabaseSection,
    pub policy: PolicySection,
    pub relay: RelayAssignmentSection,
    pub log: CoordinatorLogSection,
}

impl CoordinatorSettings {
    /// Resolve the effective settings from the four layers.
    pub fn load(layers: &Layers) -> Result<Self, crate::ConfigError> {
        crate::resolve_coordinator(layers)
    }

    /// Every problem this configuration has, not just the first.
    pub fn validate(&self) -> Vec<crate::Problem> {
        crate::validate::validate_coordinator(self)
    }
}

/// The `[api]` table: where the coordinator listens and what it tells the world it is.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ApiSection {
    pub listen: String,
    pub public_url: String,
}

impl Default for ApiSection {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:8080".to_string(),
            public_url: String::new(),
        }
    }
}

/// The `[database]` table.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DatabaseSection {
    pub url: String,
    pub max_connections: u32,
}

impl Default for DatabaseSection {
    fn default() -> Self {
        Self {
            url: "sqlite:///var/lib/wgmesh/coordinator.db?mode=rwc".to_string(),
            max_connections: 4,
        }
    }
}

/// The `[policy]` table: who joins without a human, and how many of them.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PolicySection {
    pub default_auto_approve: bool,
    pub max_devices_per_network: u32,
    pub join_rate_limit_per_minute: u32,
}

impl Default for PolicySection {
    fn default() -> Self {
        Self {
            default_auto_approve: false,
            max_devices_per_network: 256,
            join_rate_limit_per_minute: 30,
        }
    }
}

/// The `[relay]` table of the coordinator: when a relay is considered gone.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RelayAssignmentSection {
    pub heartbeat_timeout_secs: u64,
    pub reassign_after_misses: u32,
    pub keyset_ttl_secs: u64,
}

impl Default for RelayAssignmentSection {
    fn default() -> Self {
        Self {
            heartbeat_timeout_secs: 15,
            reassign_after_misses: 3,
            keyset_ttl_secs: 300,
        }
    }
}

/// The `[log]` table of the coordinator, whose records are JSON by default.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CoordinatorLogSection {
    pub level: LogLevel,
    pub format: LogFormat,
}

impl Default for CoordinatorLogSection {
    fn default() -> Self {
        Self {
            level: LogLevel::Info,
            format: LogFormat::Json,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_coordinator_defaults_are_the_ones_the_blueprint_ships() {
        let settings = CoordinatorSettings::default();
        assert_eq!(settings.api.listen, "127.0.0.1:8080");
        assert_eq!(settings.api.public_url, "");
        assert_eq!(
            settings.database.url,
            "sqlite:///var/lib/wgmesh/coordinator.db?mode=rwc"
        );
        assert_eq!(settings.database.max_connections, 4);
        assert!(!settings.policy.default_auto_approve);
        assert_eq!(settings.policy.max_devices_per_network, 256);
        assert_eq!(settings.policy.join_rate_limit_per_minute, 30);
        assert_eq!(settings.relay.heartbeat_timeout_secs, 15);
        assert_eq!(settings.relay.reassign_after_misses, 3);
        assert_eq!(settings.relay.keyset_ttl_secs, 300);
        assert_eq!(settings.log.level, LogLevel::Info);
        assert_eq!(settings.log.format, LogFormat::Json);
    }

    #[test]
    fn a_coordinator_file_only_carries_what_it_changes() {
        let file = match tempfile::NamedTempFile::new() {
            Ok(file) => file,
            Err(error) => panic!("temporary file: {error}"),
        };
        if let Err(error) = std::fs::write(file.path(), "[policy]\ndefault_auto_approve = true\n") {
            panic!("writing the file: {error}");
        }
        let settings = match CoordinatorSettings::load(&Layers::new().file(file.path())) {
            Ok(settings) => settings,
            Err(error) => panic!("loading the coordinator file: {error}"),
        };
        assert!(settings.policy.default_auto_approve);
        assert_eq!(settings.policy.max_devices_per_network, 256);
        assert_eq!(settings.database.max_connections, 4);
        assert_eq!(settings.log.format, LogFormat::Json);
    }
}
