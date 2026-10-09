use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

// The relay's own knobs. These mirror `/etc/wgmesh/relay.toml`; `wgmesh-config`
// owns the file format, and this struct is what that crate will fill in.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RelayConfig {
    pub relay_id: String,
    pub coordinator: Option<String>,
    pub listen: IpAddr,
    pub port_range: (u16, u16),
    pub keyset_ttl: Duration,
    pub pps_per_slot: u32,
    pub mbit_per_slot: u32,
    pub report_interval: Duration,
    pub poll_budget: Duration,
    // The expanded layout: one UDP socket per node rather than a port per pair. The relay
    // then reads the destination out of the packet -- `mac1` for a handshake,
    // `receiver_index` for everything else -- and the ingress port only says who sent it.
    pub one_port: bool,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            relay_id: String::new(),
            coordinator: None,
            listen: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            port_range: (51_820, 51_999),
            keyset_ttl: Duration::from_secs(300),
            pps_per_slot: 5_000,
            mbit_per_slot: 100,
            report_interval: Duration::from_secs(2),
            poll_budget: Duration::from_millis(20),
            one_port: false,
        }
    }
}
