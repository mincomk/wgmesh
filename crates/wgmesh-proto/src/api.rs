use serde::{Deserialize, Serialize};

/// The API generation both sides speak. A mismatch is refused at the edge
/// rather than half-handled.
pub const PROTOCOL_VERSION: u32 = 1;

/// Device lifecycle, shared by nodes and relays.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum PeerState {
    Pending,
    Active,
    Revoked,
}

impl PeerState {
    pub const fn as_str(self) -> &'static str {
        match self {
            PeerState::Pending => "pending",
            PeerState::Active => "active",
            PeerState::Revoked => "revoked",
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum RelayState {
    Pending,
    Active,
    Retired,
    Draining,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct JoinRequest {
    pub token: String,
    pub wg_pubkey: String,
    pub api_pubkey: String,
    pub name: String,
    #[serde(default)]
    pub os: String,
    #[serde(default)]
    pub agent_version: String,
    #[serde(default)]
    pub advertised: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct NetworkView {
    pub name: String,
    pub cidr: String,
    pub mtu: u16,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct PeerView {
    pub device_id: String,
    pub name: String,
    pub wg_pubkey: String,
    pub tunnel_ip: String,
    pub state: PeerState,
    #[serde(default)]
    pub advertised: Vec<String>,
    /// Where this peer was last seen, as reported by the relay the pair uses.
    /// It is a hint for the punch, never a fact the node must trust.
    #[serde(default)]
    pub endpoint: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct RelayView {
    pub relay_id: String,
    pub name: String,
    pub endpoint_host: String,
    #[serde(default)]
    pub region: Option<String>,
    pub state: RelayState,
}

/// One relay–device slot: the UDP port a node sends its WireGuard packets to,
/// and therefore the port the relay reads that node's identity from.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct SlotView {
    pub relay_id: String,
    pub udp_port: u16,
}

/// The relay a pair of devices is assigned to. Both ends get the same value:
/// one end on a different relay than the other simply does not work.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct AssignmentView {
    pub peer_id: String,
    pub relay_id: String,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct ConfigSnapshot {
    /// Opaque version string. A node that presents it back unchanged gets a
    /// `304` instead of a body.
    pub etag: String,
    /// Bumped on every change, so a pushed event and a polled body can be
    /// ordered against each other.
    pub generation: u64,
    pub network: NetworkView,
    pub device: PeerView,
    pub peers: Vec<PeerView>,
    /// This device's slot on every relay in the pool, so a reassignment is
    /// immediately usable.
    pub slots: Vec<SlotView>,
    pub assignments: Vec<AssignmentView>,
    pub relays: Vec<RelayView>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct JoinResponse {
    pub device_id: String,
    pub state: PeerState,
    pub snapshot: ConfigSnapshot,
}

/// What a relay reports about the source address it saw a device come from.
/// The relay itself is known from the signature, so it is not named here.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct Observation {
    pub device_id: String,
    pub ip: String,
    pub port: u16,
    pub seen_at: u64,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct ObservationBatch {
    pub observations: Vec<Observation>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct RelayEnrollRequest {
    pub token: String,
    pub api_pubkey: String,
    pub name: String,
    pub endpoint_host: String,
    pub port_range: [u16; 2],
    #[serde(default)]
    pub region: Option<String>,
    #[serde(default)]
    pub provider: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct RelayEnrollResponse {
    pub relay_id: String,
    pub state: RelayState,
    pub networks: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct SlotEntry {
    pub device_id: String,
    pub udp_port: u16,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct PairEntry {
    pub a: String,
    pub b: String,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct KeysetPeer {
    pub device_id: String,
    pub wg_pubkey: String,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct KeysetNetwork {
    pub network: String,
    pub peers: Vec<KeysetPeer>,
}

/// Everything one relay needs and nothing more: its slots, the pairs it may
/// forward, and the public keys that let it read a handshake's destination.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct RelayAssignment {
    pub relay_id: String,
    pub slots: Vec<SlotEntry>,
    pub pairs: Vec<PairEntry>,
    pub networks: Vec<KeysetNetwork>,
    /// Seconds this assignment stays usable after the coordinator goes away.
    pub keyset_ttl_secs: u64,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct RelayHeartbeat {
    pub forwarded_packets: u64,
    pub forwarded_bytes: u64,
    pub throttled_packets: u64,
    pub dropped_packets: u64,
    #[serde(default)]
    pub pairs_active: u64,
    pub at: u64,
}

/// The event a node receives over the config stream.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct ConfigEvent {
    /// `snapshot`, `revoked`, `reassigned`, `approved`.
    pub kind: String,
    pub generation: u64,
    pub etag: String,
    #[serde(default)]
    pub peer_id: Option<String>,
    #[serde(default)]
    pub relay_id: Option<String>,
    /// Ready to print in an operator's log.
    pub message: String,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn a_config_snapshot_round_trips_through_json() {
        let snapshot = ConfigSnapshot {
            etag: "cfg-42".to_owned(),
            generation: 42,
            network: NetworkView {
                name: "prod".to_owned(),
                cidr: "10.77.0.0/16".to_owned(),
                mtu: 1420,
            },
            device: PeerView {
                device_id: "d_1".to_owned(),
                name: "A".to_owned(),
                wg_pubkey: "AAAA".to_owned(),
                tunnel_ip: "10.77.0.7/16".to_owned(),
                state: PeerState::Active,
                advertised: vec![],
                endpoint: Some("203.0.113.9:41287".to_owned()),
            },
            peers: vec![],
            slots: vec![SlotView {
                relay_id: "relay_1".to_owned(),
                udp_port: 51_901,
            }],
            assignments: vec![AssignmentView {
                peer_id: "d_2".to_owned(),
                relay_id: "relay_1".to_owned(),
            }],
            relays: vec![RelayView {
                relay_id: "relay_1".to_owned(),
                name: "relay-1".to_owned(),
                endpoint_host: "203.0.113.5".to_owned(),
                region: Some("ap-northeast-2".to_owned()),
                state: RelayState::Active,
            }],
        };
        let text = serde_json::to_string(&snapshot).unwrap();
        assert!(text.contains("\"generation\":42"));
        assert_eq!(
            serde_json::from_str::<ConfigSnapshot>(&text).unwrap(),
            snapshot
        );
    }

    #[test]
    fn a_join_request_tolerates_a_client_that_omits_the_optional_fields() {
        let request: JoinRequest =
            serde_json::from_str(r#"{"token":"t","wg_pubkey":"a","api_pubkey":"b","name":"n"}"#)
                .unwrap();
        assert!(request.os.is_empty());
        assert!(request.advertised.is_empty());
    }

    #[test]
    fn a_config_event_names_the_thing_that_changed() {
        let event = ConfigEvent {
            kind: "reassigned".to_owned(),
            generation: 7,
            etag: "cfg-7".to_owned(),
            peer_id: Some("d_2".to_owned()),
            relay_id: Some("relay_2".to_owned()),
            message: "peer d_2 moved to relay-2".to_owned(),
        };
        let text = serde_json::to_string(&event).unwrap();
        assert!(text.contains("\"kind\":\"reassigned\""));
        assert_eq!(serde_json::from_str::<ConfigEvent>(&text).unwrap(), event);
    }

    #[test]
    fn peer_state_is_spelled_the_way_the_api_documents_it() {
        assert_eq!(
            serde_json::to_string(&PeerState::Pending).unwrap(),
            "\"pending\""
        );
        assert_eq!(PeerState::Revoked.as_str(), "revoked");
    }
}
