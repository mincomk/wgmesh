use std::net::IpAddr;
use std::time::Duration;

use crate::engine::Counters;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Observation {
    pub device_id: u32,
    pub ip: IpAddr,
    pub port: u16,
    pub seen_at: u64,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TrafficSample {
    pub device_id: u32,
    pub period_start: u64,
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub tx_packets: u64,
    pub tx_bytes: u64,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Heartbeat {
    pub relay_id: String,
    pub at: u64,
    pub uptime_ms: u64,
    pub slots: usize,
    pub pairs: usize,
    pub draining: bool,
    pub keyset_age_ms: Option<u64>,
    pub keyset_devices: usize,
    pub counters: Counters,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Report {
    Heartbeat(Heartbeat),
    Observations(Vec<Observation>),
    Traffic(Vec<TrafficSample>),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SlotStatus {
    pub device_id: u32,
    pub port: u16,
    pub observed: Option<u64>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RelayStatus {
    pub relay_id: String,
    pub at: u64,
    pub uptime_ms: u64,
    pub draining: bool,
    pub keyset_devices: usize,
    pub keyset_age: Option<Duration>,
    pub slots: Vec<SlotStatus>,
    pub pairs: Vec<(u32, u32)>,
    pub counters: Counters,
}
