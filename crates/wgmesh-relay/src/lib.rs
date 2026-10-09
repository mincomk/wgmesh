pub mod assignment;
pub mod config;
pub mod engine;
pub mod error;
pub mod limits;
pub mod report;
pub mod sockets;

// The domain types (`DeviceId`, `Millis`, `PublicKey`) live in `wgmesh-core`. Callers of
// this crate reach them through here rather than having to name the dependency twice.
pub use wgmesh_core;

pub use assignment::{
    Assignment, Keyset, KeysetNetwork, KeysetPeer, PairAssignment, SlotAssignment,
};
pub use config::{EstablishedSessions, RelayConfig};
pub use engine::{
    Counters, Drop, DropCounters, Outcome, RelayEngine, Shutdown, ShutdownHandle, UNPAIRED,
    shutdown,
};
pub use error::RelayError;
pub use limits::SlotLimit;
pub use report::{Heartbeat, Observation, RelayStatus, Report, SlotStatus, TrafficSample};
pub use sockets::{Datagram, SlotSockets, UdpSlotSockets};
