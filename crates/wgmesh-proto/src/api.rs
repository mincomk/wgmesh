use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize)]
pub struct ErrorDetail {
    pub code: String,
    pub message: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct ErrorBody {
    pub error: ErrorDetail,
}

impl ErrorBody {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            error: ErrorDetail {
                code: code.into(),
                message: message.into(),
            },
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct JoinBody {
    pub token: String,
    pub name: String,
    pub wg_pubkey: String,
    pub api_pubkey: String,
    #[serde(default)]
    pub os: Option<String>,
    #[serde(default)]
    pub agent_version: Option<String>,
    #[serde(default)]
    pub advertised: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct NetworkBody {
    pub id: u32,
    pub name: String,
    pub cidr: String,
    pub mtu: u32,
    pub relay_policy: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct PeerBody {
    pub device_id: String,
    pub name: String,
    pub wg_pubkey: String,
    pub tunnel_ip: String,
    pub advertised: Vec<String>,
    pub relay: Option<String>,
    pub endpoint: Option<String>,
    pub state: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct RelayBody {
    pub relay_id: String,
    pub name: String,
    pub endpoint_host: String,
    pub port_range: String,
    pub region: Option<String>,
    pub state: String,
    pub slot_port: Option<u16>,
}

#[derive(Clone, Debug, Serialize)]
pub struct JoinResponse {
    pub device_id: String,
    pub state: String,
    pub network: NetworkBody,
    pub tunnel_ip: String,
    pub peers: Vec<PeerBody>,
    pub relay_pool: Vec<RelayBody>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SelfObservationBody {
    pub endpoint: String,
    pub seen_at_ms: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct MeBody {
    pub device_id: String,
    pub tunnel_ip: String,
    pub state: String,
    pub slot_port: Option<u16>,
    pub observed: Option<SelfObservationBody>,
}

#[derive(Clone, Debug, Serialize)]
pub struct RelayViewBody {
    pub assigned: Option<String>,
    pub slots: Vec<RelayBody>,
}

/// The whole of `GET /v1/config`. `etag` is filled from the body's own digest,
/// so it is empty on the value the digest is taken over.
#[derive(Clone, Debug, Serialize)]
pub struct ConfigResponse {
    pub etag: String,
    pub network: NetworkBody,
    pub me: MeBody,
    pub relay: RelayViewBody,
    pub peers: Vec<PeerBody>,
    pub keepalive_secs: u32,
}

#[derive(Clone, Debug, Deserialize)]
pub struct EndpointBody {
    #[serde(default)]
    pub observed: Option<ObservedIn>,
    /// Bands this device routes for others, if it is a subnet router.
    #[serde(default)]
    pub advertised: Option<Vec<String>>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ObservedIn {
    pub ip: String,
    pub port: u16,
    #[serde(default)]
    pub seen_at_ms: Option<u64>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct PunchBody {
    pub peer: String,
    pub outcome: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct RotateBody {
    pub wg_pubkey: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct RelayEnrollBody {
    pub token: String,
    pub name: String,
    pub api_pubkey: String,
    pub endpoint_host: String,
    pub port_range: String,
    #[serde(default)]
    pub region: Option<String>,
    #[serde(default)]
    pub provider: Option<String>,
    #[serde(default)]
    pub operator: Option<String>,
    /// Networks this relay offers to serve. Empty means every network.
    #[serde(default)]
    pub networks: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct RelayEnrollResponse {
    pub relay_id: String,
    pub name: String,
    pub endpoint_host: String,
    pub port_range: String,
    pub state: String,
    pub networks: Vec<NetworkBody>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ObservationsBody {
    pub observations: Vec<ObservationIn>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ObservationIn {
    pub device_id: String,
    pub ip: String,
    pub port: u16,
    #[serde(default)]
    pub seen_at_ms: Option<u64>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct HeartbeatBody {
    #[serde(default)]
    pub agent_version: Option<String>,
    #[serde(default)]
    pub traffic: Vec<TrafficIn>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct TrafficIn {
    pub device_id: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    #[serde(default)]
    pub period_start_ms: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SlotBody {
    pub device_id: String,
    pub udp_port: u16,
}

#[derive(Clone, Debug, Serialize)]
pub struct PairBody {
    pub a: String,
    pub b: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct KeysetPeer {
    pub device_id: String,
    pub wg_pubkey: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct KeysetNetwork {
    pub id: u32,
    pub name: String,
    pub peers: Vec<KeysetPeer>,
}

/// What a relay needs to rebuild itself after a restart: its slot table, the
/// pairs assigned to it, and the keyset of every network it serves.
#[derive(Clone, Debug, Serialize)]
pub struct AssignmentResponse {
    pub relay_id: String,
    pub endpoint_host: String,
    pub slots: Vec<SlotBody>,
    pub pairs: Vec<PairBody>,
    pub networks: Vec<KeysetNetwork>,
}

#[derive(Clone, Debug, Serialize)]
pub struct KeysetResponse {
    pub fetched_at_ms: u64,
    pub keyset_ttl_secs: u64,
    pub networks: Vec<KeysetNetwork>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Ack {
    pub ok: bool,
}

impl Ack {
    pub const fn new() -> Self {
        Self { ok: true }
    }
}

impl Default for Ack {
    fn default() -> Self {
        Self::new()
    }
}
