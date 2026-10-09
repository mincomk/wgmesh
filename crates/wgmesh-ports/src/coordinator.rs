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
    /// A trust decision, and an explicit one: `wgmesh trust rotate` is the only thing that
    /// calls it, and nothing in the agent calls it because a connection failed.
    async fn rotate(&self, key: PublicKey) -> Result<(), ApiError>;
}

use crate::PortError;

/// Which kind of principal a join token admits.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TokenKind {
    Device,
    Relay,
}

impl TokenKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Device => "device",
            Self::Relay => "relay",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "device" => Some(Self::Device),
            "relay" => Some(Self::Relay),
            _ => None,
        }
    }
}

/// What a consumed join token tells the coordinator. Nothing else about the
/// token survives consumption: the row is counted, not read.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TokenGrant {
    pub network_id: u32,
    pub kind: TokenKind,
    pub auto_approve: bool,
}

#[derive(Clone, Debug)]
pub struct NewJoinToken {
    pub network_id: u32,
    pub kind: TokenKind,
    pub token_hash: [u8; 32],
    pub max_uses: u32,
    pub auto_approve: bool,
    pub expires_at: Millis,
    pub created_by: String,
    pub created_at: Millis,
}

#[derive(Clone, Debug)]
pub struct Network {
    pub id: u32,
    pub name: String,
    pub cidr: String,
    pub mtu: u32,
    pub relay_policy: String,
}

#[derive(Clone, Debug)]
pub struct NewNetwork {
    pub name: String,
    pub cidr: String,
    pub mtu: u32,
    pub relay_policy: String,
    pub created_at: Millis,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DeviceState {
    Pending,
    Active,
    Revoked,
}

impl DeviceState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Revoked => "revoked",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "pending" => Some(Self::Pending),
            "active" => Some(Self::Active),
            "revoked" => Some(Self::Revoked),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Device {
    pub id: DeviceId,
    pub network_id: u32,
    pub name: String,
    pub wg_pubkey: PublicKey,
    pub api_pubkey: PublicKey,
    pub tunnel_ip: String,
    pub state: DeviceState,
    /// Bands this device routes for others, as CIDR text. Always contains at
    /// least its own tunnel address.
    pub advertised: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct NewDevice {
    pub network_id: u32,
    pub name: String,
    pub wg_pubkey: PublicKey,
    pub api_pubkey: PublicKey,
    pub tunnel_ip: String,
    pub state: DeviceState,
    pub advertised: Vec<String>,
    pub created_at: Millis,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RelayState {
    Pending,
    Active,
    Retired,
}

impl RelayState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Retired => "retired",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "pending" => Some(Self::Pending),
            "active" => Some(Self::Active),
            "retired" => Some(Self::Retired),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Relay {
    pub id: RelayId,
    pub name: String,
    pub api_pubkey: PublicKey,
    pub state: RelayState,
    pub endpoint_host: String,
    pub port_range: String,
    pub region: Option<String>,
    pub provider: Option<String>,
    pub operator: Option<String>,
    pub last_heartbeat_at: Option<Millis>,
    pub agent_version: Option<String>,
    /// Whether the relay says it is draining: it takes no new pairs and its pairs are
    /// being handed over to another relay.
    pub draining: bool,
}

#[derive(Clone, Debug)]
pub struct NewRelay {
    pub name: String,
    pub api_pubkey: PublicKey,
    pub state: RelayState,
    pub endpoint_host: String,
    pub port_range: String,
    pub region: Option<String>,
    pub provider: Option<String>,
    pub operator: Option<String>,
    pub created_at: Millis,
}

#[derive(Clone, Debug)]
pub struct AuditEntry {
    pub at: Millis,
    pub actor: String,
    pub action: String,
    pub network_id: Option<u32>,
    pub device_id: Option<DeviceId>,
    pub relay_id: Option<RelayId>,
    pub detail: Option<String>,
}

/// Join tokens: issued by an operator, spent exactly once, and never read back.
#[async_trait]
pub trait TokenStore: Send + Sync {
    async fn insert_join_token(&self, token: &NewJoinToken) -> Result<(), PortError>;

    /// Spend one use of `hash` in a single atomic step.
    ///
    /// `Ok(None)` means the token was refused, and says nothing about why:
    /// unknown, expired, revoked and exhausted are deliberately the same
    /// answer, so a caller cannot use the difference to probe the store.
    async fn consume_join_token(
        &self,
        hash: &[u8; 32],
        kind: TokenKind,
        at: Millis,
    ) -> Result<Option<TokenGrant>, PortError>;

    async fn revoke_join_token(&self, hash: &[u8; 32], at: Millis) -> Result<bool, PortError>;
}

/// Networks, devices and relays: the directory the coordinator serves.
#[async_trait]
pub trait Directory: Send + Sync {
    async fn insert_network(&self, spec: &NewNetwork) -> Result<Network, PortError>;
    async fn network_by_name(&self, name: &str) -> Result<Option<Network>, PortError>;
    async fn network_by_id(&self, id: u32) -> Result<Option<Network>, PortError>;
    async fn networks(&self) -> Result<Vec<Network>, PortError>;

    async fn insert_device(&self, spec: &NewDevice) -> Result<Device, PortError>;
    async fn device_by_id(&self, id: DeviceId) -> Result<Option<Device>, PortError>;
    async fn device_by_api_pubkey(&self, key: &PublicKey) -> Result<Option<Device>, PortError>;
    async fn device_by_name(
        &self,
        network_id: u32,
        name: &str,
    ) -> Result<Option<Device>, PortError>;
    async fn devices_of(&self, network_id: u32) -> Result<Vec<Device>, PortError>;
    async fn set_device_state(&self, id: DeviceId, state: DeviceState) -> Result<(), PortError>;
    async fn set_device_wg_pubkey(&self, id: DeviceId, key: &PublicKey) -> Result<(), PortError>;
    async fn set_device_advertised(&self, id: DeviceId, bands: &[String]) -> Result<(), PortError>;
    async fn touch_device(&self, id: DeviceId, at: Millis) -> Result<(), PortError>;

    async fn insert_relay(&self, spec: &NewRelay) -> Result<Relay, PortError>;
    async fn relay_by_id(&self, id: RelayId) -> Result<Option<Relay>, PortError>;
    async fn relay_by_name(&self, name: &str) -> Result<Option<Relay>, PortError>;
    async fn relay_by_api_pubkey(&self, key: &PublicKey) -> Result<Option<Relay>, PortError>;
    async fn relays_of(&self, network_id: u32) -> Result<Vec<Relay>, PortError>;
    async fn link_relay_network(&self, relay: RelayId, network_id: u32) -> Result<(), PortError>;
    async fn set_relay_state(&self, id: RelayId, state: RelayState) -> Result<(), PortError>;
    /// Record what a relay said about draining. It arrives on the heartbeat, and it is
    /// what stops a pair being placed on a relay that is on its way out.
    async fn set_relay_draining(&self, id: RelayId, draining: bool) -> Result<(), PortError>;
    async fn record_heartbeat(
        &self,
        id: RelayId,
        at: Millis,
        agent_version: Option<&str>,
    ) -> Result<(), PortError>;
}

/// Ports and pair placement: which device sits on which relay port, and which
/// relay a pair uses.
#[async_trait]
pub trait Placement: Send + Sync {
    async fn assign_slot(
        &self,
        relay: RelayId,
        device: DeviceId,
        port: u16,
    ) -> Result<(), PortError>;
    async fn slot_for(&self, relay: RelayId, device: DeviceId) -> Result<Option<u16>, PortError>;
    async fn slots_of(&self, relay: RelayId) -> Result<Vec<(DeviceId, u16)>, PortError>;

    async fn assign_pair(
        &self,
        device_a: DeviceId,
        device_b: DeviceId,
        relay: RelayId,
        at: Millis,
    ) -> Result<(), PortError>;
    async fn relay_for_pair(
        &self,
        device_a: DeviceId,
        device_b: DeviceId,
    ) -> Result<Option<RelayId>, PortError>;
    async fn pairs_of(&self, relay: RelayId) -> Result<Vec<(DeviceId, DeviceId)>, PortError>;
}

/// Everything the relays tell the coordinator: where they saw a device, and how
/// much they carried.
#[async_trait]
pub trait Reports: Send + Sync {
    async fn record_observation(
        &self,
        relay: RelayId,
        device: DeviceId,
        endpoint: Endpoint,
        at: Millis,
    ) -> Result<(), PortError>;
    async fn observation(
        &self,
        relay: RelayId,
        device: DeviceId,
    ) -> Result<Option<(Endpoint, Millis)>, PortError>;

    async fn record_traffic(
        &self,
        relay: RelayId,
        device: DeviceId,
        rx_bytes: u64,
        tx_bytes: u64,
        period_start: Millis,
    ) -> Result<(), PortError>;

    async fn audit(&self, entry: &AuditEntry) -> Result<(), PortError>;
    async fn recent_audit(&self, limit: u32) -> Result<Vec<AuditEntry>, PortError>;
}
