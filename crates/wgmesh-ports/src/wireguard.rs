// The kernel WireGuard interface.

use std::time::Duration;

use wgmesh_core::{Allowed, Change, DeviceId, Endpoint, Millis, PublicKey};

use crate::WireGuardError;

/// Everything the adapter needs to create or verify an interface, minus the key.
///
/// There is deliberately no private key here. `SecretStore` does not hand one out, and an
/// interface spec is an `InterfaceSpec` in a log line away from being a key on disk; how the
/// key reaches the kernel is the adapter's business, arranged where the adapter is constructed.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct InterfaceSpec {
    /// The interface name, as the kernel knows it.
    pub name: String,
    /// The MTU to use, when it is not the kernel's default for WireGuard.
    pub mtu: Option<u32>,
    /// The UDP port to listen on, when it is pinned by configuration.
    pub listen_port: Option<u16>,
    /// The firewall mark to set on outgoing packets.
    pub fwmark: Option<u32>,
}

/// What the kernel reports about one peer.
///
/// This is the left-hand side of `wgmesh_core::diff`: the kernel is the authority on what it
/// holds, and the difference between this and the desired set is the only thing that reaches
/// `apply`. `last_handshake` is the one place a time enters the state machine.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PeerStatus {
    /// The device this peer is.
    pub device: DeviceId,
    /// Its WireGuard public key.
    pub public_key: PublicKey,
    /// The endpoint the kernel currently sends to.
    pub endpoint: Option<Endpoint>,
    /// The prefixes this peer may claim.
    pub allowed: Vec<Allowed>,
    /// The persistent keepalive, if any.
    pub keepalive: Option<Duration>,
    /// When a handshake last completed.
    pub last_handshake: Option<Millis>,
    /// Bytes received from this peer.
    pub rx_bytes: u64,
    /// Bytes sent to this peer.
    pub tx_bytes: u64,
}

/// The WireGuard interface, as the agent needs it.
///
/// Note what is missing: a way to work out what the interface *should* look like. The writable
/// surface is `apply`, whose unit is a `Change` list — and that list is produced by
/// `wgmesh_core::diff`, never here.
pub trait WireGuard: Send + Sync {
    /// Bring the interface up, idempotently.
    ///
    /// An interface that already exists with this name and these settings is left as it is.
    fn ensure_interface(&self, spec: &InterfaceSpec) -> Result<(), WireGuardError>;

    /// Write a change list to the interface.
    ///
    /// Add, update and remove only — the adapter does not decide, it writes.
    fn apply(&self, changes: &[Change]) -> Result<(), WireGuardError>;

    /// What the interface currently holds.
    ///
    /// An empty `peers` means every peer the interface holds, not none: that is how a caller
    /// sees a peer it should remove, and a diff against a set that omits it would never produce
    /// the removal.
    fn status(&self, peers: &[DeviceId]) -> Result<Vec<PeerStatus>, WireGuardError>;

    /// The UDP port the interface is listening on.
    fn listen_port(&self) -> Result<u16, WireGuardError>;
}
