// The coordination plane: the calls a device makes, and the vocabulary it speaks.
//
// The request and response types here are the port's own vocabulary, not a wire format. The
// encoding, the signing header and the TLS pinning all belong to the adapter; this crate stays
// free of any serializer, and a use case can be reasoned about without one.

use std::fmt;

use async_trait::async_trait;
use wgmesh_core::{
    Allowed, CandidateKind, DeviceId, Endpoint, Millis, PeerSpec, PublicKey, RelayId,
};

use crate::ApiError;

/// A one-time token a person hands out of band, which is what lets a device into the mesh.
///
/// It is spent at enrollment and never stored, but it is still redacted in `Debug` — a token in
/// a log line is a token in everyone's log line.
#[derive(Clone, PartialEq, Eq)]
pub struct JoinToken(String);

impl JoinToken {
    /// A token from its text.
    pub fn new(secret: impl Into<String>) -> Self {
        Self(secret.into())
    }

    /// The token's text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for JoinToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JoinToken(<redacted>)")
    }
}

impl fmt::Display for JoinToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// What a device asks for when it enrolls.
///
/// Two public keys, because a device has two identities: the API key it signs requests with, and
/// the WireGuard key the kernel uses. The coordinator needs the second to publish this device to
/// its peers, and it is a public key, so it crosses this boundary freely.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct EnrollRequest {
    /// The one-time token.
    pub token: JoinToken,
    /// The device's API public key — the identity it signs with.
    pub signer: PublicKey,
    /// The device's WireGuard public key.
    pub wireguard: PublicKey,
    /// What the device calls itself.
    pub hostname: Option<String>,
}

/// The relay a device was paired with.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RelayAssignment {
    /// Which relay.
    pub relay: RelayId,
    /// The UDP port on that relay this device's traffic arrives on.
    pub slot_port: u16,
}

/// What enrollment gives back.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Enrollment {
    /// The id this device is now known by.
    pub device: DeviceId,
    /// Which network it joined.
    pub network: String,
    /// The address it holds inside the tunnel.
    pub tunnel_ip: Allowed,
    /// The relay it was paired with, if the coordinator wants it relayed.
    pub assignment: Option<RelayAssignment>,
    /// The configuration version to start from.
    pub etag: Option<String>,
}

/// The world, as the coordinator wants this device to see it.
///
/// `advertised` is the union of the bands the peers say they can reach — and it is separate from
/// either peer's `AllowedIPs`, because AllowedIPs are cryptokey routing and the routes the kernel
/// installs are chosen from these bands by policy, not by the coordinator.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ConfigSnapshot {
    /// The version this answer carries.
    pub etag: String,
    /// The mesh's own bands.
    pub network: Vec<Allowed>,
    /// Every band the peers advertise.
    pub advertised: Vec<Allowed>,
    /// The peers this device should have.
    pub peers: Vec<PeerSpec>,
}

/// Where a device turned out to be reachable from.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Observation {
    /// The device that was observed.
    pub device: DeviceId,
    /// The endpoint it was seen at.
    pub endpoint: Endpoint,
    /// What kind of observation it was.
    pub kind: CandidateKind,
    /// When it was made.
    pub at: Millis,
}

/// How a punch attempt ended.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PunchOutcome {
    /// The peers reached each other directly.
    Direct,
    /// They fell back to the relay.
    Relayed,
    /// Nothing came back.
    Failed,
}

/// What a device reports about a punch it attempted.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PunchReport {
    /// The device reporting.
    pub device: DeviceId,
    /// The peer it was punching toward.
    pub peer: DeviceId,
    /// How it ended.
    pub outcome: PunchOutcome,
    /// When it ended.
    pub at: Millis,
}

/// The coordination plane, as the agent needs it.
///
/// This is the one port that is asynchronous: every call is a network round trip, and the daemon
/// is a tokio program. The rest of the ports are synchronous and are called from the daemon's
/// own worker, so a slow coordinator cannot stall a traversal timer.
#[async_trait]
pub trait CoordinatorApi: Send + Sync {
    /// Enroll this device. The first call it ever makes.
    async fn enroll(&self, request: EnrollRequest) -> Result<Enrollment, ApiError>;

    /// Ask for the desired world, naming the version the device already has.
    async fn config(&self, etag: Option<&str>) -> Result<ConfigSnapshot, ApiError>;

    /// Report where this device and its peers were observed from.
    async fn report_observations(&self, observations: &[Observation]) -> Result<(), ApiError>;

    /// Report how a punch ended.
    async fn report_punch(&self, report: PunchReport) -> Result<(), ApiError>;

    /// Rotate the pin the coordinator presents.
    ///
    /// A trust decision, and an explicit one: `wgmesh trust --rotate` is the only thing that
    /// calls it, and nothing in the agent calls it because a connection failed.
    async fn rotate(&self, key: PublicKey) -> Result<(), ApiError>;
}
