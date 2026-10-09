// Control-plane wire types, shared by the coordinator, the relays and the
// agents. These are the *control* messages; the WireGuard-shaped packets that
// the relays forward are defined in `wgmesh-core`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// A relay's UDP slot for one device, as it reports it to the coordinator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotReport {
    pub device: u32,
    pub port: u16,
}

/// The source address a relay last saw a device send from, on that device's slot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observation {
    pub device: u32,
    pub addr: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayStats {
    pub forwarded: u64,
    pub dropped: u64,
}

/// relayd -> coordinator, every heartbeat interval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayHeartbeat {
    pub id: String,
    pub slots: Vec<SlotReport>,
    pub observations: Vec<Observation>,
    #[serde(default)]
    pub stats: RelayStats,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceKey {
    pub device: u32,
    pub public_key: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pair {
    pub a: u32,
    pub b: u32,
}

/// coordinator -> relayd, the answer to a heartbeat: what this relay is
/// responsible for right now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayDirective {
    pub generation: u64,
    pub devices: Vec<DeviceKey>,
    pub pairs: Vec<Pair>,
}

/// agent -> coordinator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceSync {
    pub device: u32,
    pub public_key: String,
    /// The device this one is configured to talk to.
    pub peer: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayView {
    pub id: String,
    pub healthy: bool,
}

/// The pair's current home and what the agent needs to punch at.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Assigned {
    pub relay_id: String,
    /// This device's slot address on the assigned relay, once known.
    pub slot_addr: Option<String>,
    pub peer_device: u32,
    pub peer_public_key: Option<String>,
    /// Where the assigned relay saw the peer send from.
    pub peer_observed: Option<String>,
    /// Both ends observed at the assigned relay: punch now.
    pub punch: bool,
}

/// coordinator -> agent, the answer to a sync.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceSyncResponse {
    pub device: u32,
    pub peer: u32,
    pub generation: u64,
    pub relays: Vec<RelayView>,
    /// Every relay that has reported a slot for this device, so the agent can
    /// tell a relayed arrival from a direct one.
    pub slot_addrs: BTreeMap<String, String>,
    pub assigned: Option<Assigned>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayStateView {
    pub id: String,
    pub healthy: bool,
    pub slots: BTreeMap<u32, u16>,
    pub observations: BTreeMap<u32, String>,
    pub stats: RelayStats,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceView {
    pub device: u32,
    pub public_key: String,
    pub peer: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairView {
    pub a: u32,
    pub b: u32,
    pub relay_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateView {
    pub generation: u64,
    pub relays: Vec<RelayStateView>,
    pub devices: Vec<DeviceView>,
    pub pairs: Vec<PairView>,
}
