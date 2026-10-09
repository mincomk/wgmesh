use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

/// What a relay does with the sessions it is already carrying when the keyset
/// reaches `keyset_ttl` without a refresh from the coordinator.
///
/// The keyset is the isolation boundary, so a destination the *frozen* keyset
/// does not name is refused either way: a device that joined, or was revoked,
/// after the link went down is never served on a stale keyset. This knob decides
/// only what happens to the pairs the frozen keyset still knew about.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum EstablishedSessions {
    /// Fail closed: an expired keyset carries nothing at all. This is the
    /// default, because the safe reading of "the control plane is gone" is to
    /// stop.
    #[default]
    Refuse,
    /// Availability first: keep carrying the pairs the frozen keyset names, and
    /// still refuse every destination outside it. The design prefers this for an
    /// operator-owned relay, where a control-plane outage should not cut a
    /// working session.
    Serve,
}

// The relay's own knobs. These mirror `/etc/wgmesh/relay.toml`; `wgmesh-config`
// owns the file format, and this struct is what that crate will fill in.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RelayConfig {
    pub relay_id: String,
    pub coordinator: Option<String>,
    pub listen: IpAddr,
    pub port_range: (u16, u16),
    pub keyset_ttl: Duration,
    pub established_sessions: EstablishedSessions,
    pub pps_per_slot: u32,
    pub mbit_per_slot: u32,
    pub report_interval: Duration,
    pub poll_budget: Duration,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            relay_id: String::new(),
            coordinator: None,
            listen: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            port_range: (51_820, 51_999),
            keyset_ttl: Duration::from_secs(300),
            established_sessions: EstablishedSessions::Refuse,
            pps_per_slot: 5_000,
            mbit_per_slot: 100,
            report_interval: Duration::from_secs(2),
            poll_budget: Duration::from_millis(20),
        }
    }
}
