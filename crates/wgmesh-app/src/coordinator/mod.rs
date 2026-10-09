/// The ports the coordinator's use cases depend on, re-exported so the crate
/// that wires them needs no direct dependency on `wgmesh-ports`.
pub mod ports {
    pub use wgmesh_ports::coordinator::*;
}

pub use wgmesh_ports::{Class, Clock, PortError};

/// The coordinator's usecases. Each one knows the ports and nothing else: no
/// SQLite, no HTTP, no clock of its own.
pub mod approve;
pub mod config;
pub mod join;
pub mod net;
pub mod placement;
pub mod reports;
pub mod select_relay;
pub mod types;

pub use approve::ApproveDevice;
pub use config::BuildConfig;
pub use join::JoinDevice;
pub use placement::AssignPair;
pub use reports::{IngestHeartbeat, RecordObservations};
pub use select_relay::{RelayCandidate, SelectRelay, select_relay};
pub use types::{
    ApproveError, ConfigError, ConfigSnapshot, Heartbeat, JoinError, JoinOutcome, JoinPolicy,
    JoinRequest, MeView, Observation, PeerView, PlaceError, PlacePolicy, PunchOutcome, PunchReport,
    RehomeReport, RelayPoolEntry, RelayView, ReportError, SelfObservation, TrafficSample,
};
