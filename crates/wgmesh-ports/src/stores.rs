// State, secrets and time: the three things the agent keeps between runs, and the one thing it
// reads that it does not own.

use std::collections::BTreeMap;
use std::fmt;

use wgmesh_core::{Allowed, DeviceId, Endpoint, Millis, Path, PublicKey, RelayId, RouteSpec};

use crate::coordinator::Observation;
use crate::{SecretError, StateError};

/// The version of the state schema this build writes.
///
/// A state file carrying a different number is not read: state is disposable, and the file is
/// backed up and started over rather than migrated in place.
pub const STATE_SCHEMA: u32 = 1;

/// A pin on the coordination plane's public key.
///
/// The device remembers, from the moment it first enrolled, which key the coordinator presented.
/// Every later conversation is checked against it, and a change is refused: someone who can
/// answer on the coordinator's address should not become the coordinator just because the device
/// is willing to listen. Rotating the pin is a deliberate act (`wgmesh trust --rotate`) and never
/// the consequence of a failed connection.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Spki([u8; 32]);

impl Spki {
    /// The length of a pin in bytes.
    pub const LEN: usize = 32;

    /// A pin from its raw bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The raw bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for Spki {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Spki {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Spki({self})")
    }
}

/// What the device remembers about its relationship with the coordinator.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CoordinatorLink {
    /// The key the coordinator presented when this device enrolled.
    pub spki: Spki,
    /// When the configuration was last converged.
    pub last_sync: Millis,
    /// The configuration version last converged.
    pub etag: Option<String>,
}

/// What the device remembers about its relay.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct RelayState {
    /// The relay currently assigned.
    pub assigned: Option<RelayId>,
    /// The UDP port this device's traffic arrives on.
    pub slot_port: Option<u16>,
    /// Every slot this device has been given, by relay.
    pub slots: BTreeMap<RelayId, u16>,
}

/// What the device remembers about one peer.
///
/// This is the *device's* memory of a peer, not the kernel's: it is what makes a status line
/// useful after a restart, and it is not the authority on anything. The kernel is asked what it
/// holds whenever a diff is computed.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PeerRecord {
    /// The device.
    pub device: DeviceId,
    /// The name it is known by, when the coordinator gives one.
    pub name: Option<String>,
    /// Its WireGuard public key.
    pub public_key: PublicKey,
    /// Its address inside the tunnel, when its AllowedIPs name one.
    pub tunnel_ip: Option<Allowed>,
    /// The endpoint last used.
    pub endpoint: Option<Endpoint>,
    /// Which way traffic last went.
    pub path: Path,
    /// When a handshake last completed.
    pub last_handshake: Option<Millis>,
}

/// Everything the device remembers between runs.
///
/// Note what is not here: no private key, no token, no plaintext secret. If one appears in a
/// state file, that is a bug.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PersistedState {
    /// The schema version.
    pub schema: u32,
    /// The device id the coordinator assigned.
    pub device: DeviceId,
    /// Which network this device joined.
    pub network: String,
    /// The address this device holds inside the tunnel.
    pub tunnel_ip: Allowed,
    /// The coordinator relationship.
    pub coordinator: CoordinatorLink,
    /// The relay assignment.
    pub relay: RelayState,
    /// The peers, as last seen.
    pub peers: Vec<PeerRecord>,
    /// Where this device was observed from, by relay.
    pub observations: BTreeMap<RelayId, Observation>,
    /// The routes last installed — a memory for undoing, not the truth about the kernel.
    pub routes: Vec<RouteSpec>,
    /// System settings this device changed, and what they were before.
    pub sysctl: BTreeMap<String, String>,
}

impl PersistedState {
    /// A state for a device that has just enrolled.
    pub fn enrolled(
        device: DeviceId,
        network: impl Into<String>,
        tunnel_ip: Allowed,
        spki: Spki,
        at: Millis,
    ) -> Self {
        Self {
            schema: STATE_SCHEMA,
            device,
            network: network.into(),
            tunnel_ip,
            coordinator: CoordinatorLink {
                spki,
                last_sync: at,
                etag: None,
            },
            relay: RelayState::default(),
            peers: Vec::new(),
            observations: BTreeMap::new(),
            routes: Vec::new(),
            sysctl: BTreeMap::new(),
        }
    }
}

/// Where the device keeps its state.
///
/// Deleting the state file is a supported operation — it is how a person makes a device forget
/// where it is — and it must not touch key material. The two live in different stores on
/// purpose: `clear` forgets the identity the coordinator assigned, and the device enrolls again
/// with the key it always had.
pub trait StateStore: Send + Sync {
    /// The state, if there is one.
    fn load(&self) -> Result<Option<PersistedState>, StateError>;

    /// Write the state.
    fn save(&self, state: &PersistedState) -> Result<(), StateError>;

    /// Forget the state. Keys are not this store's to touch.
    fn clear(&self) -> Result<(), StateError>;
}

/// An Ed25519 signature, 64 bytes.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Signature([u8; 64]);

impl Signature {
    /// The length of a signature in bytes.
    pub const LEN: usize = 64;

    /// A signature from its raw bytes.
    pub const fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// The raw bytes.
    pub const fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0[..4] {
            write!(f, "{byte:02x}")?;
        }
        write!(f, "..")
    }
}

/// Key material, and the only thing allowed to touch it.
///
/// There is deliberately no accessor for a private key. The two things anyone needs one for —
/// signing a request, and configuring the kernel interface — are operations performed *by* the
/// store and its adapter, not material handed across a boundary. Everything else in the agent
/// can ask only for a public half.
pub trait SecretStore: Send + Sync {
    /// The WireGuard public key, minting the key pair if the store holds none.
    ///
    /// Called once at startup, and the answer is what a state that is being built for the first
    /// time records.
    fn wireguard_public_key(&self) -> Result<PublicKey, SecretError>;

    /// The API public key: the identity this device signs requests with.
    fn public_key(&self) -> Result<PublicKey, SecretError>;

    /// Sign a message with the API key.
    ///
    /// This is how a request proves where it came from. The private key never leaves the store;
    /// the signature does.
    fn sign(&self, message: &[u8]) -> Result<Signature, SecretError>;
}

/// The clock.
///
/// Nothing else in the agent reads the time. The traversal state machine takes `at` on every
/// event and compares it against times it was given, so a test can run a whole backoff schedule
/// in microseconds and a daemon can run it in hours, on the same code.
pub trait Clock: Send + Sync {
    /// The current time, in milliseconds since the Unix epoch.
    fn now(&self) -> Millis;
}
