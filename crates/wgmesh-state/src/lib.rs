pub mod atomic;
pub mod file;

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub use atomic::{
    STATE_DIR_MODE, STATE_FILE_MODE, ensure_dir, ensure_dir_if_absent, mode_of, temporary_path,
    write_atomic,
};
pub use file::{FileStateStore, ResetReason, STATE_FILE_NAME, StateError, StateLoad};

/// The schema version this build writes and reads.
pub const STATE_SCHEMA: u32 = 1;

/// The version marker of a state document that carries none.
pub const SCHEMA_UNKNOWN: u32 = 0;

/// What the coordinator told this device, and what the device did about it.
///
/// State is disposable: the daemon writes it to remember what it converged to, and a
/// file it cannot read is backed up and started over rather than repaired. It never
/// holds a private key, a token or any other secret, which `assert_no_secrets` enforces
/// on the way in and on the way out.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct PersistedState {
    pub schema: u32,
    pub device_id: String,
    pub network: String,
    pub tunnel_ip: String,
    pub coordinator: CoordinatorState,
    pub relay: RelayState,
    pub peers: Vec<PeerState>,
    pub observations: BTreeMap<String, Observation>,
    pub routes: Vec<RouteRecord>,
    pub sysctl: BTreeMap<String, String>,
}

impl Default for PersistedState {
    fn default() -> Self {
        Self {
            schema: SCHEMA_UNKNOWN,
            device_id: String::new(),
            network: String::new(),
            tunnel_ip: String::new(),
            coordinator: CoordinatorState::default(),
            relay: RelayState::default(),
            peers: Vec::new(),
            observations: BTreeMap::new(),
            routes: Vec::new(),
            sysctl: BTreeMap::new(),
        }
    }
}

impl PersistedState {
    /// An empty state for a device that has just enrolled.
    pub fn new(device_id: impl Into<String>, network: impl Into<String>) -> Self {
        Self {
            schema: STATE_SCHEMA,
            device_id: device_id.into(),
            network: network.into(),
            ..Self::default()
        }
    }

    /// Whether this state was written by the schema version this build understands.
    pub fn is_current(&self) -> bool {
        self.schema == STATE_SCHEMA
    }
}

/// What the device knows about the coordinator it is pinned to.
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct CoordinatorState {
    pub spki_sha256: String,
    pub last_sync_unix: u64,
    pub etag: String,
}

/// Which relay the device was assigned to, and which slots it knows about.
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RelayState {
    pub assigned: String,
    pub slot_port: u16,
    pub slots: BTreeMap<String, u16>,
}

/// One peer, as the last synchronization described it.
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PeerState {
    pub id: String,
    pub name: String,
    pub wg_pubkey: String,
    pub tunnel_ip: String,
    pub endpoint: Option<String>,
    pub path: PeerPath,
    pub last_handshake_unix: u64,
}

/// Which path traffic to a peer is taking.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum PeerPath {
    #[default]
    Unknown,
    Relayed,
    Direct,
}

/// What a relay saw this device's endpoint as.
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Observation {
    pub ip: String,
    pub port: u16,
    pub seen_unix: u64,
}

/// One route this device installed, remembered so it can be taken back out again.
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RouteRecord {
    pub prefix: String,
    pub table: String,
    pub metric: Option<u32>,
}

/// The substrings that mean a key in a state document is carrying a secret.
const SECRET_KEY_MARKERS: [&str; 6] = [
    "private",
    "secret",
    "token",
    "password",
    "passphrase",
    "psk",
];

/// Tables whose keys are data rather than schema, and so are not read as field names.
const DATA_TABLES: [&str; 2] = ["sysctl", "observations"];

/// Refuse a state document that carries anything that looks like a secret.
///
/// This runs on every read and every write, because "state holds no secrets" is a
/// property of the file 3 split rather than a habit. A developer who adds a
/// `private_key` field to the state gets an error the first time it is saved.
pub fn assert_no_secrets(value: &serde_json::Value) -> Result<(), StateError> {
    match value {
        serde_json::Value::Object(table) => {
            for (key, child) in table {
                let lowered = key.to_ascii_lowercase();
                if SECRET_KEY_MARKERS
                    .iter()
                    .any(|marker| lowered.contains(marker))
                {
                    return Err(StateError::SecretField { key: key.clone() });
                }
                if DATA_TABLES.contains(&lowered.as_str()) {
                    continue;
                }
                assert_no_secrets(child)?;
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                assert_no_secrets(item)?;
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_state_carries_the_current_schema_and_nothing_else() {
        let state = PersistedState::new("d_7Hq2Vx9", "prod");
        assert_eq!(state.schema, STATE_SCHEMA);
        assert!(state.is_current());
        assert_eq!(state.device_id, "d_7Hq2Vx9");
        assert_eq!(state.network, "prod");
        assert_eq!(state.tunnel_ip, "");
        assert!(state.peers.is_empty());
        assert!(state.routes.is_empty());
        assert!(state.sysctl.is_empty());
    }

    #[test]
    fn a_state_that_is_not_marked_with_the_schema_is_not_current() {
        assert!(!PersistedState::default().is_current());
        let mut future = PersistedState::new("d", "prod");
        future.schema = STATE_SCHEMA + 1;
        assert!(!future.is_current());
    }

    #[test]
    fn the_whole_document_survives_a_round_trip_through_json() {
        let mut state = PersistedState::new("d_K3n8", "prod");
        state.tunnel_ip = "10.77.0.7/16".to_string();
        state.coordinator.spki_sha256 = "9f2c".to_string();
        state.coordinator.last_sync_unix = 1_760_000_000;
        state.coordinator.etag = "cfg-42".to_string();
        state.relay.assigned = "relay-2".to_string();
        state.relay.slot_port = 51_903;
        state.relay.slots.insert("relay-1".to_string(), 51_901);
        state.relay.slots.insert("relay-2".to_string(), 51_903);
        state.peers.push(PeerState {
            id: "d_K3n8".to_string(),
            name: "B".to_string(),
            wg_pubkey: "AAAA".to_string(),
            tunnel_ip: "10.77.0.8/32".to_string(),
            endpoint: Some("203.0.113.9:41287".to_string()),
            path: PeerPath::Direct,
            last_handshake_unix: 1_760_000_042,
        });
        state.observations.insert(
            "relay-2".to_string(),
            Observation {
                ip: "203.0.113.7".to_string(),
                port: 41_287,
                seen_unix: 1_760_000_039,
            },
        );
        state.routes.push(RouteRecord {
            prefix: "10.77.0.0/16".to_string(),
            table: "main".to_string(),
            metric: None,
        });
        state
            .sysctl
            .insert("net.ipv4.ip_forward".to_string(), "0".to_string());

        let document = match serde_json::to_string_pretty(&state) {
            Ok(document) => document,
            Err(error) => panic!("rendering: {error}"),
        };
        let read: PersistedState = match serde_json::from_str(&document) {
            Ok(state) => state,
            Err(error) => panic!("reading: {error}"),
        };
        assert_eq!(read, state);
        assert!(document.contains("\"path\": \"direct\""));
        assert!(document.contains("\"schema\": 1"));
    }

    #[test]
    fn a_secret_looking_key_is_refused() {
        for key in [
            "private_key",
            "wg_private",
            "api_secret",
            "enrollment_token",
            "password",
            "psk",
        ] {
            let document = serde_json::json!({ "schema": 1, "peers": [{ key: "x" }] });
            match assert_no_secrets(&document) {
                Err(StateError::SecretField { key: reported }) => assert_eq!(&reported, key),
                other => panic!("{key} was not refused: {other:?}"),
            }
        }
    }

    #[test]
    fn the_data_tables_are_not_read_as_field_names() {
        let document = serde_json::json!({
            "schema": 1,
            "device_id": "d_K3n8",
            "observations": { "relay-2": { "ip": "203.0.113.7", "port": 41287 } },
            "sysctl": { "net.ipv4.ip_forward": "0" },
        });
        assert!(
            assert_no_secrets(&document).is_ok(),
            "a clean state was refused"
        );
    }

    #[test]
    fn an_ordinary_state_has_nothing_a_secret_guard_objects_to() {
        let mut state = PersistedState::new("d_K3n8", "prod");
        state.peers.push(PeerState {
            wg_pubkey: "hiTa5uRvTGVPpFcmYuqUwAAJbmD0Z73eMkP0WnfxTAM=".to_string(),
            ..PeerState::default()
        });
        state
            .sysctl
            .insert("net.ipv4.ip_forward".to_string(), "1".to_string());
        let document = match serde_json::to_value(&state) {
            Ok(document) => document,
            Err(error) => panic!("rendering: {error}"),
        };
        assert!(
            assert_no_secrets(&document).is_ok(),
            "a clean state was refused"
        );
    }
}
