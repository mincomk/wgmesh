#![allow(clippy::expect_used)]
pub mod clock;
pub mod coordinator;
pub mod discovery;
pub mod executor;
pub mod nat;
pub mod wireguard;

pub use clock::VirtualClock;
pub use coordinator::FakeCoordinator;
pub use discovery::{FakeInventory, RecordingPortMapper};
pub use executor::block_on;
pub use nat::{NatProfile, NatSim};
pub use wireguard::FakeWireGuard;
