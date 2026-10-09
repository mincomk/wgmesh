// The wire types of the coordinator API (design document section 7), plus the conversions
// between the wire representation and the pure domain types of `wgmesh-core`.
//
// The JSON shape is snake_case and the paths live in `paths` so the client and the
// coordinator cannot drift apart. Public keys, nonces and signatures travel as standard
// base64 text; prefixes travel as CIDR text such as `10.77.3.0/24`.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

use base64ct::{Base64, Encoding};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Every request path this API defines, as one source of truth for both sides.
pub mod paths {
    /// POST: enroll a device with a join token.
    pub const JOIN: &str = "/v1/join";
    /// GET: the peer list, relay assignment and slot for a device.
    pub const CONFIG: &str = "/v1/config";
    /// POST: report our own observed endpoints and candidates.
    pub const ENDPOINT: &str = "/v1/endpoint";
    /// POST: send punch results, receive punch directives.
    pub const PUNCH: &str = "/v1/punch";
    /// POST: submit a new tunnel public key.
    pub const ROTATE: &str = "/v1/rotate";
    /// POST: enroll a relay with a relay join token.
    pub const RELAY_ENROLL: &str = "/v1/relay/enroll";
    /// GET: slots, pairs and keysets for a relay.
    pub const RELAY_ASSIGNMENT: &str = "/v1/relay/assignment";
    /// POST: batch of source addresses a relay has seen.
    pub const RELAY_OBSERVATIONS: &str = "/v1/relay/observations";
    /// POST: relay health and traffic counters.
    pub const RELAY_HEARTBEAT: &str = "/v1/relay/heartbeat";
    /// GET: incremental public key update for a relay.
    pub const RELAY_KEYSET: &str = "/v1/relay/keyset";
    /// POST: exchange a join token for a session (administrator surface, M2).
    pub const ADMIN_TOKEN: &str = "/admin/v1/token";
}

/// The scheme name of the Authorization header.
pub const AUTH_SCHEME: &str = "WGMESH";

/// The header carrying the signature. Kept as a constant so both sides spell it the same.
pub const AUTHORIZATION_HEADER: &str = "authorization";

/// Anything that can be wrong with a value on the wire, before it reaches the domain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WireError {
    /// A key that is not 32 bytes once decoded.
    KeyLength(usize),
    /// Base64 text that does not decode.
    Base64(String),
    /// Hex text that does not decode.
    Hex(String),
    /// A prefix that is not `address/bits`.
    Prefix(String),
    /// A prefix length outside the range of its family.
    PrefixBits {
        /// The prefix length as written.
        bits: u8,
        /// The largest length the family allows.
        max: u8,
    },
    /// An endpoint that is not `ip:port`.
    Endpoint(String),
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyLength(len) => write!(f, "a wire key must be 32 bytes, got {len}"),
            Self::Base64(text) => write!(f, "not standard base64: {text}"),
            Self::Hex(text) => write!(f, "not hex: {text}"),
            Self::Prefix(text) => write!(f, "not a prefix: {text}"),
            Self::PrefixBits { bits, max } => write!(f, "prefix length {bits} is above {max}"),
            Self::Endpoint(text) => write!(f, "not an ip:port endpoint: {text}"),
        }
    }
}

impl std::error::Error for WireError {}

/// A 32 byte public key (X25519 for the tunnel, Ed25519 for the API) as base64 text.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct PubKeyB64([u8; 32]);

impl PubKeyB64 {
    /// The raw length of every key on this API.
    pub const LEN: usize = 32;

    /// Wrap raw key bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The raw key bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for PubKeyB64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&Base64::encode_string(&self.0))
    }
}

impl FromStr for PubKeyB64 {
    type Err = WireError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let bytes = Base64::decode_vec(text).map_err(|_| WireError::Base64(text.to_owned()))?;
        let len = bytes.len();
        let key: [u8; Self::LEN] = bytes.try_into().map_err(|_| WireError::KeyLength(len))?;
        Ok(Self(key))
    }
}

impl TryFrom<&[u8]> for PubKeyB64 {
    type Error = WireError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let key: [u8; Self::LEN] = bytes
            .try_into()
            .map_err(|_| WireError::KeyLength(bytes.len()))?;
        Ok(Self(key))
    }
}

impl Serialize for PubKeyB64 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for PubKeyB64 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

impl From<wgmesh_core::PublicKey> for PubKeyB64 {
    fn from(key: wgmesh_core::PublicKey) -> Self {
        Self(*key.as_bytes())
    }
}

impl From<PubKeyB64> for wgmesh_core::PublicKey {
    fn from(key: PubKeyB64) -> Self {
        wgmesh_core::PublicKey::from_bytes(key.0)
    }
}

impl From<&wgmesh_core::PublicKey> for PubKeyB64 {
    fn from(key: &wgmesh_core::PublicKey) -> Self {
        Self(*key.as_bytes())
    }
}

/// An `ip:port` endpoint as text.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct EndpointB64(SocketAddr);

impl EndpointB64 {
    /// Wrap a socket address.
    pub const fn new(addr: SocketAddr) -> Self {
        Self(addr)
    }

    /// The socket address.
    pub const fn addr(self) -> SocketAddr {
        self.0
    }

    /// Parse `ip:port`.
    pub fn parse(text: &str) -> Result<Self, WireError> {
        text.parse::<SocketAddr>()
            .map(Self)
            .map_err(|_| WireError::Endpoint(text.to_owned()))
    }
}

impl fmt::Display for EndpointB64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for EndpointB64 {
    type Err = WireError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}

impl Serialize for EndpointB64 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for EndpointB64 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

impl From<wgmesh_core::Endpoint> for EndpointB64 {
    fn from(endpoint: wgmesh_core::Endpoint) -> Self {
        Self(endpoint.addr())
    }
}

impl From<EndpointB64> for wgmesh_core::Endpoint {
    fn from(endpoint: EndpointB64) -> Self {
        wgmesh_core::Endpoint::new(endpoint.0)
    }
}

/// An IPv4 or IPv6 prefix as CIDR text, the form the coordinator advertises bands in.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct Prefix {
    octets: [u8; 16],
    bits: u8,
    v6: bool,
}

impl Prefix {
    /// An IPv4 prefix. `bits` must not exceed 32.
    pub fn v4(addr: [u8; 4], bits: u8) -> Result<Self, WireError> {
        if bits > 32 {
            return Err(WireError::PrefixBits { bits, max: 32 });
        }
        let mut octets = [0u8; 16];
        octets[..4].copy_from_slice(&addr);
        Ok(Self {
            octets,
            bits,
            v6: false,
        })
    }

    /// An IPv6 prefix. `bits` must not exceed 128.
    pub fn v6(addr: [u8; 16], bits: u8) -> Result<Self, WireError> {
        if bits > 128 {
            return Err(WireError::PrefixBits { bits, max: 128 });
        }
        Ok(Self {
            octets: addr,
            bits,
            v6: true,
        })
    }

    /// Whether this is an IPv6 prefix.
    pub const fn is_v6(&self) -> bool {
        self.v6
    }

    /// The prefix length.
    pub const fn bits(&self) -> u8 {
        self.bits
    }

    /// The address bytes, zero padded to 16 for IPv4.
    pub const fn octets(&self) -> &[u8; 16] {
        &self.octets
    }

    /// Parse `address/bits` in either family.
    pub fn parse(text: &str) -> Result<Self, WireError> {
        let (addr, bits) = text
            .split_once('/')
            .ok_or_else(|| WireError::Prefix(text.to_owned()))?;
        let bits: u8 = bits
            .parse()
            .map_err(|_| WireError::Prefix(text.to_owned()))?;
        if let Ok(v4) = Ipv4Addr::from_str(addr) {
            return Self::v4(v4.octets(), bits);
        }
        if let Ok(v6) = Ipv6Addr::from_str(addr) {
            return Self::v6(v6.octets(), bits);
        }
        Err(WireError::Prefix(text.to_owned()))
    }
}

impl fmt::Display for Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.v6 {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&self.octets);
            write!(f, "{}/{}", Ipv6Addr::from(octets), self.bits)
        } else {
            let mut octets = [0u8; 4];
            octets.copy_from_slice(&self.octets[..4]);
            write!(f, "{}/{}", Ipv4Addr::from(octets), self.bits)
        }
    }
}

impl FromStr for Prefix {
    type Err = WireError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}

impl Serialize for Prefix {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Prefix {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

impl From<wgmesh_core::Allowed> for Prefix {
    fn from(allowed: wgmesh_core::Allowed) -> Self {
        match allowed {
            wgmesh_core::Allowed::V4(addr, bits) => Self {
                octets: [
                    addr[0], addr[1], addr[2], addr[3], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ],
                bits,
                v6: false,
            },
            wgmesh_core::Allowed::V6(addr, bits) => Self {
                octets: addr,
                bits,
                v6: true,
            },
        }
    }
}

impl From<Prefix> for wgmesh_core::Allowed {
    fn from(prefix: Prefix) -> Self {
        if prefix.v6 {
            Self::V6(prefix.octets, prefix.bits)
        } else {
            Self::V4(
                [
                    prefix.octets[0],
                    prefix.octets[1],
                    prefix.octets[2],
                    prefix.octets[3],
                ],
                prefix.bits,
            )
        }
    }
}

/// Re-exported so callers of this crate can name the domain type without depending on core.
pub use wgmesh_core::Allowed as AllowedPrefix;

/// One end of a UDP port range a relay may assign.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct PortRange {
    /// First assignable port.
    pub start: u16,
    /// Last assignable port.
    pub end: u16,
}

impl PortRange {
    /// Whether `port` falls inside the range.
    pub const fn contains(&self, port: u16) -> bool {
        port >= self.start && port <= self.end
    }

    /// How many ports the range holds.
    pub const fn len(&self) -> u32 {
        self.end as u32 - self.start as u32 + 1
    }

    /// Whether the range holds no port at all, which cannot happen for a valid range.
    pub const fn is_empty(&self) -> bool {
        self.end < self.start
    }
}

/// What a node is told about its network.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct NetworkInfo {
    /// Coordinator side network id.
    pub id: u32,
    /// Human readable network name.
    pub name: String,
    /// The tunnel subnet, CIDR text.
    pub cidr: Prefix,
    /// Interface MTU the network wants.
    pub mtu: u16,
    /// DNS servers pushed to nodes.
    #[serde(default)]
    pub dns: Vec<String>,
}

/// What a device may know about a peer.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct PeerInfo {
    /// Device id of the peer.
    pub device_id: u32,
    /// Human readable device name.
    pub name: String,
    /// The peer's tunnel public key.
    pub wg_pubkey: PubKeyB64,
    /// The peer's tunnel address, CIDR text.
    pub tunnel_ip: Prefix,
    /// Bands the peer advertises, CIDR text. This is what `prefixes = "auto"` routes.
    #[serde(default)]
    pub advertised_prefixes: Vec<Prefix>,
}

/// One relay a device may use.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct RelayPoolEntry {
    /// Relay id.
    pub relay_id: u32,
    /// The host nodes send UDP to.
    pub endpoint_host: String,
    /// Ports this relay may assign.
    pub port_range: PortRange,
    /// Optional region label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// Optional provider label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
}

/// The relay a device was assigned, and the slot it answers on.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct RelayAssignment {
    /// The relay to use.
    pub relay_id: u32,
    /// The host to send UDP to.
    pub endpoint_host: String,
    /// The device's own UDP port on that relay, the sender identity.
    pub slot: u16,
    /// Per pair overrides: the relay chosen for one peer, when it is not the default.
    #[serde(default)]
    pub pairs: Vec<PairRelay>,
}

/// A per pair relay choice.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct PairRelay {
    /// The peer of this pair.
    pub peer: u32,
    /// The relay assigned to this pair.
    pub relay_id: u32,
}

/// A source address some relay has seen, for one device.
///
/// This is both what a relay reports (`POST /v1/relay/observations`) and what a device is
/// told about itself and its peers (`GET /v1/config`), so the two sides cannot disagree
/// about the shape.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct EndpointObservation {
    /// The device the address belongs to.
    pub device_id: u32,
    /// Source IP as text.
    pub ip: String,
    /// Source port.
    pub port: u16,
    /// When the relay saw it, unix seconds.
    pub seen_at: u64,
}

/// Why a candidate is on the list, mirroring `wgmesh_core::CandidateKind`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateKind {
    /// A local network address.
    Lan,
    /// A global IPv6 address.
    Ipv6,
    /// An address a relay observed.
    Observed,
    /// An address discovered by a mapping protocol.
    Mapping,
    /// The relay's own address.
    Relay,
}

impl From<wgmesh_core::CandidateKind> for CandidateKind {
    fn from(kind: wgmesh_core::CandidateKind) -> Self {
        match kind {
            wgmesh_core::CandidateKind::Lan => Self::Lan,
            wgmesh_core::CandidateKind::Ipv6 => Self::Ipv6,
            wgmesh_core::CandidateKind::Observed => Self::Observed,
            wgmesh_core::CandidateKind::Mapping => Self::Mapping,
            wgmesh_core::CandidateKind::Relay => Self::Relay,
        }
    }
}

impl From<CandidateKind> for wgmesh_core::CandidateKind {
    fn from(kind: CandidateKind) -> Self {
        match kind {
            CandidateKind::Lan => Self::Lan,
            CandidateKind::Ipv6 => Self::Ipv6,
            CandidateKind::Observed => Self::Observed,
            CandidateKind::Mapping => Self::Mapping,
            CandidateKind::Relay => Self::Relay,
        }
    }
}

/// One endpoint a device believes it can be reached at.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct CandidateReport {
    /// Where the candidate came from.
    pub kind: CandidateKind,
    /// The address.
    pub endpoint: EndpointB64,
}

/// What the coordinator hands a device along with the peer list.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ConfigSnapshot {
    /// The network.
    pub network: NetworkInfo,
    /// Every active peer, with the bands each one advertises.
    pub peers: Vec<PeerInfo>,
    /// The relay this device is assigned to, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay: Option<RelayAssignment>,
    /// Source addresses relays have seen, for this device and for its peers.
    #[serde(default)]
    pub observations: Vec<EndpointObservation>,
    /// When the coordinator built this snapshot, unix seconds.
    pub generated_at: u64,
}

/// A device's enrollment request, authenticated by the join token.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct JoinRequest {
    /// The one time join token.
    pub token: String,
    /// The tunnel public key.
    pub wg_pubkey: PubKeyB64,
    /// The API public key requests are signed with.
    pub api_pubkey: PubKeyB64,
    /// Device name.
    pub name: String,
    /// Operating system, free text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    /// Agent version.
    pub agent_version: String,
}

/// What a device is told when it enrolls.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct JoinResponse {
    /// The device id the coordinator assigned.
    pub device_id: u32,
    /// The network.
    pub network: NetworkInfo,
    /// Peers already active.
    #[serde(default)]
    pub peers: Vec<PeerInfo>,
    /// Relays available to this network.
    #[serde(default)]
    pub relay_pool: Vec<RelayPoolEntry>,
    /// Whether the device must wait for an administrator before it is used.
    #[serde(default)]
    pub pending: bool,
}

/// A device's own view of where it can be reached.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct EndpointReport {
    /// Candidates gathered locally and from relays.
    #[serde(default)]
    pub candidates: Vec<CandidateReport>,
    /// When the device gathered them, unix seconds.
    pub reported_at: u64,
}

/// How a punch attempt ended.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PunchOutcome {
    /// The handshake packet went out and a reply came back.
    Answered,
    /// The packet went out, nothing came back inside the window.
    Timeout,
    /// The attempt was not made.
    Skipped,
    /// The attempt failed before the packet left.
    Failed,
}

/// The result of one punch attempt.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct PunchResult {
    /// The peer the attempt was aimed at.
    pub peer: u32,
    /// The endpoint that was tried.
    pub endpoint: EndpointB64,
    /// How it ended.
    pub outcome: PunchOutcome,
    /// When it ended, unix milliseconds.
    pub at_ms: u64,
}

/// What a device reports after a punch round.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct PunchReport {
    /// One entry per attempt.
    #[serde(default)]
    pub results: Vec<PunchResult>,
    /// When the round was reported, unix seconds.
    pub reported_at: u64,
}

/// One simultaneous send the coordinator asks a device to make.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct PunchDirective {
    /// The peer to aim at.
    pub peer: u32,
    /// The endpoint to aim at.
    pub endpoint: EndpointB64,
    /// Wait this long before sending, milliseconds from receipt.
    pub start_after_ms: u64,
    /// How long the attempt window stays open, milliseconds.
    pub window_ms: u64,
}

/// What a device receives from a punch round.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct PunchResponse {
    /// Directives to carry out.
    #[serde(default)]
    pub directives: Vec<PunchDirective>,
}

/// A device's request to replace its tunnel public key.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct RotateRequest {
    /// The new tunnel public key.
    pub wg_pubkey: PubKeyB64,
}

/// The answer to a rotation.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct RotateResponse {
    /// The device the key belongs to.
    pub device_id: u32,
    /// The key that is now in force.
    pub wg_pubkey: PubKeyB64,
}

/// A relay's enrollment request, authenticated by a relay join token.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct RelayEnrollRequest {
    /// The one time relay join token.
    pub token: String,
    /// The relay's API public key.
    pub api_pubkey: PubKeyB64,
    /// Relay name.
    pub name: String,
    /// The public host nodes are told to send UDP to.
    pub endpoint_host: String,
    /// The ports this relay may assign.
    pub port_range: PortRange,
    /// Optional region label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// Optional provider label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// Optional operator label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator: Option<String>,
    /// Relay daemon version.
    pub agent_version: String,
}

/// What a relay is told when it enrolls.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct RelayEnrollment {
    /// The relay id the coordinator assigned.
    pub relay_id: u32,
    /// The host nodes are told to send UDP to.
    pub endpoint_host: String,
    /// The ports this relay may assign.
    pub port_range: PortRange,
    /// Whether the relay must wait for an administrator before it serves traffic.
    #[serde(default)]
    pub pending: bool,
}

/// One device's slot on a relay.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct SlotAssignment {
    /// The device that owns the slot.
    pub device_id: u32,
    /// The UDP port that identifies it on this relay.
    pub udp_port: u16,
}

/// One pair that is allowed to talk through a relay.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct PairAssignment {
    /// One end of the pair.
    pub a: u32,
    /// The other end.
    pub b: u32,
}

/// One device a relay must be able to recognise.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct RelayPeerKey {
    /// The device.
    pub device_id: u32,
    /// Its tunnel public key.
    pub wg_pubkey: PubKeyB64,
}

/// The keyset of one network a relay serves.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct RelayNetworkKeyset {
    /// The network.
    pub network_id: u32,
    /// Its active devices.
    #[serde(default)]
    pub peers: Vec<RelayPeerKey>,
}

/// What a relay needs to route: slots, pairs and keysets.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct RelayAssignmentResponse {
    /// The relay this assignment belongs to.
    pub relay_id: u32,
    /// One slot per device on this relay.
    #[serde(default)]
    pub slots: Vec<SlotAssignment>,
    /// Pairs assigned to this relay.
    #[serde(default)]
    pub pairs: Vec<PairAssignment>,
    /// Keysets, one per served network.
    #[serde(default)]
    pub networks: Vec<RelayNetworkKeyset>,
    /// When the coordinator built this assignment, unix seconds.
    pub generated_at: u64,
}

/// A relay's batch of observed source addresses.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct RelayObservationBatch {
    /// One entry per (relay, device) pair, replacing what the coordinator held.
    #[serde(default)]
    pub observations: Vec<EndpointObservation>,
}

/// Traffic counters for one device, without decrypting anything.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct TrafficSample {
    /// The device.
    pub device_id: u32,
    /// Bytes received from it.
    pub rx_bytes: u64,
    /// Bytes sent to it.
    pub tx_bytes: u64,
    /// Start of the accounting period, unix seconds.
    pub period_start: u64,
}

/// A relay's health report and traffic counters.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct RelayHeartbeat {
    /// The relay reporting.
    pub relay_id: u32,
    /// Whether the relay considers itself healthy.
    pub healthy: bool,
    /// Relay daemon version.
    pub agent_version: String,
    /// How many pairs are currently assigned.
    #[serde(default)]
    pub assigned_pairs: u32,
    /// Counters, one per device.
    #[serde(default)]
    pub traffic: Vec<TrafficSample>,
    /// When the report was sent, unix seconds.
    pub sent_at: u64,
}

/// An incremental key update for a relay.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct RelayKeysetResponse {
    /// The revision this response is cut at, for the next `since`.
    pub revision: u64,
    /// Full keysets; a relay replaces what it held for each named network.
    #[serde(default)]
    pub networks: Vec<RelayNetworkKeyset>,
    /// Networks whose devices were all removed; a relay drops them.
    #[serde(default)]
    pub retired_networks: Vec<u32>,
}

/// A minimal acknowledgement, the answer to requests whose result carries no data.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Ack {
    /// Whether the coordinator accepted the report.
    pub ok: bool,
    /// Optional detail, for logs and for `doctor`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// The coordinator's error body.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ApiErrorBody {
    /// A stable machine readable code.
    pub code: ApiErrorCode,
    /// A human readable message that never distinguishes "no such token" from "expired".
    pub message: String,
}

/// The stable error codes of this API.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiErrorCode {
    /// A request body or a value in it is not acceptable.
    BadRequest,
    /// The join token is unknown, expired or spent.
    InvalidToken,
    /// No signature, or one that does not verify.
    Unauthorized,
    /// The identity exists but is not allowed to act yet.
    Pending,
    /// The identity was revoked.
    Revoked,
    /// The timestamp is too far from the coordinator's clock.
    ClockSkew,
    /// The nonce was already used inside its window.
    NonceReused,
    /// The caller is known and allowed, but not for this resource.
    Forbidden,
    /// The resource does not exist.
    NotFound,
    /// The same key is already registered.
    Conflict,
    /// The caller is over a rate limit.
    RateLimited,
    /// The coordinator failed.
    Internal,
    /// The resource or the operation does not exist yet in this version.
    NotImplemented,
}

impl ApiErrorCode {
    /// The HTTP status this code is carried with.
    pub const fn status(self) -> u16 {
        match self {
            Self::BadRequest => 400,
            Self::InvalidToken | Self::Unauthorized => 401,
            Self::Pending => 403,
            Self::Revoked | Self::Forbidden => 403,
            Self::ClockSkew | Self::NonceReused => 401,
            Self::NotFound => 404,
            Self::Conflict => 409,
            Self::RateLimited => 429,
            Self::Internal => 500,
            Self::NotImplemented => 501,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn a_public_key_round_trips_through_base64_text() {
        let bytes = [
            0x9d, 0x1f, 0x00, 0xff, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0,
            0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
            0x0a, 0x0b, 0x0c, 0x0d,
        ];
        let key = PubKeyB64::from_bytes(bytes);
        let text = key.to_string();
        assert_eq!(text, "nR8A/xAgMEBQYHCAkKCwwNDg8AECAwQFBgcICQoLDA0=");
        assert_eq!(text.parse::<PubKeyB64>().expect("parses"), key);
        assert_eq!(key.as_bytes(), &bytes);
    }

    #[test]
    fn a_short_or_long_key_is_rejected() {
        let short = Base64::encode_string(&[0u8; 31]);
        let long = Base64::encode_string(&[0u8; 33]);
        assert_eq!(short.parse::<PubKeyB64>(), Err(WireError::KeyLength(31)));
        assert_eq!(long.parse::<PubKeyB64>(), Err(WireError::KeyLength(33)));
        assert!(matches!(
            "not base64!".parse::<PubKeyB64>(),
            Err(WireError::Base64(_))
        ));
    }

    #[test]
    fn a_key_converts_to_and_from_the_core_type() {
        let key = PubKeyB64::from_bytes([7u8; 32]);
        let core: wgmesh_core::PublicKey = key.into();
        assert_eq!(core.as_bytes(), &[7u8; 32]);
        assert_eq!(PubKeyB64::from(core), key);
        assert_eq!(PubKeyB64::from(&core), key);
    }

    #[test]
    fn an_endpoint_round_trips_through_text() {
        let text = "203.0.113.7:51820";
        let endpoint: EndpointB64 = text.parse().expect("parses");
        assert_eq!(endpoint.to_string(), text);
        assert_eq!(endpoint.addr().port(), 51820);
        assert!(matches!(
            "no-port".parse::<EndpointB64>(),
            Err(WireError::Endpoint(_))
        ));
    }

    #[test]
    fn an_endpoint_converts_to_and_from_the_core_type() {
        let endpoint: EndpointB64 = "198.51.100.9:1234".parse().expect("parses");
        let core: wgmesh_core::Endpoint = endpoint.into();
        assert_eq!(core.addr().to_string(), "198.51.100.9:1234");
        assert_eq!(EndpointB64::from(core), endpoint);
    }

    #[test]
    fn an_ipv4_prefix_round_trips_through_text() {
        let prefix: Prefix = "10.77.3.0/24".parse().expect("parses");
        assert!(!prefix.is_v6());
        assert_eq!(prefix.bits(), 24);
        assert_eq!(prefix.to_string(), "10.77.3.0/24");
    }

    #[test]
    fn an_ipv6_prefix_round_trips_through_text() {
        let prefix: Prefix = "fd00:77::/64".parse().expect("parses");
        assert!(prefix.is_v6());
        assert_eq!(prefix.bits(), 64);
        assert_eq!(prefix.to_string(), "fd00:77::/64");
    }

    #[test]
    fn a_catch_all_prefix_survives_the_round_trip_in_both_families() {
        let v4: Prefix = "0.0.0.0/0".parse().expect("parses");
        let v6: Prefix = "::/0".parse().expect("parses");
        assert_eq!(v4, Prefix::from(wgmesh_core::Allowed::V4([0, 0, 0, 0], 0)));
        assert_eq!(v6, Prefix::from(wgmesh_core::Allowed::V6([0; 16], 0)));
        assert!(wgmesh_core::route::is_catch_all(
            &wgmesh_core::Allowed::from(v4)
        ));
        assert!(wgmesh_core::route::is_catch_all(
            &wgmesh_core::Allowed::from(v6)
        ));
    }

    #[test]
    fn a_prefix_with_a_bad_length_or_shape_is_rejected() {
        assert_eq!(
            Prefix::parse("10.0.0.0/33"),
            Err(WireError::PrefixBits { bits: 33, max: 32 })
        );
        assert_eq!(
            Prefix::parse("fd00::/129"),
            Err(WireError::PrefixBits {
                bits: 129,
                max: 128
            })
        );
        assert!(matches!(
            Prefix::parse("10.0.0.0"),
            Err(WireError::Prefix(_))
        ));
        assert!(matches!(
            Prefix::parse("not-an-address/8"),
            Err(WireError::Prefix(_))
        ));
    }

    #[test]
    fn every_prefix_converts_to_and_from_the_core_type() {
        for text in [
            "10.77.0.0/16",
            "0.0.0.0/0",
            "fd00:77::/64",
            "::/0",
            "2001:db8::/32",
            "192.0.2.1/32",
        ] {
            let prefix: Prefix = text.parse().expect("parses");
            let allowed: wgmesh_core::Allowed = prefix.into();
            assert_eq!(
                Prefix::from(allowed),
                prefix,
                "round trip failed for {text}"
            );
        }
    }

    #[test]
    fn a_port_range_knows_its_bounds() {
        let range = PortRange {
            start: 20000,
            end: 20009,
        };
        assert!(range.contains(20000));
        assert!(range.contains(20009));
        assert!(!range.contains(19999));
        assert!(!range.contains(20010));
        assert_eq!(range.len(), 10);
        assert!(!range.is_empty());
    }

    #[test]
    fn a_candidate_kind_converts_both_ways() {
        for kind in [
            wgmesh_core::CandidateKind::Lan,
            wgmesh_core::CandidateKind::Ipv6,
            wgmesh_core::CandidateKind::Observed,
            wgmesh_core::CandidateKind::Mapping,
            wgmesh_core::CandidateKind::Relay,
        ] {
            let wire = CandidateKind::from(kind);
            assert_eq!(wgmesh_core::CandidateKind::from(wire), kind);
        }
    }

    #[test]
    fn every_path_is_versioned_and_unique() {
        let all = [
            paths::JOIN,
            paths::CONFIG,
            paths::ENDPOINT,
            paths::PUNCH,
            paths::ROTATE,
            paths::RELAY_ENROLL,
            paths::RELAY_ASSIGNMENT,
            paths::RELAY_OBSERVATIONS,
            paths::RELAY_HEARTBEAT,
            paths::RELAY_KEYSET,
        ];
        for path in all {
            assert!(
                path.starts_with("/v1/") || path.starts_with("/admin/"),
                "{path} is not versioned"
            );
        }
        let unique: std::collections::BTreeSet<&&str> = all.iter().collect();
        assert_eq!(unique.len(), all.len(), "two endpoints share a path");
    }

    #[test]
    fn an_error_code_carries_the_status_the_design_asks_for() {
        assert_eq!(ApiErrorCode::InvalidToken.status(), 401);
        assert_eq!(ApiErrorCode::Pending.status(), 403);
        assert_eq!(ApiErrorCode::Revoked.status(), 403);
        assert_eq!(ApiErrorCode::NonceReused.status(), 401);
        assert_eq!(ApiErrorCode::Conflict.status(), 409);
        assert_eq!(ApiErrorCode::RateLimited.status(), 429);
        assert_eq!(ApiErrorCode::Internal.status(), 500);
    }

    #[test]
    fn the_wire_error_explains_itself() {
        assert!(WireError::KeyLength(31).to_string().contains("31"));
        assert!(
            WireError::PrefixBits { bits: 33, max: 32 }
                .to_string()
                .contains("33")
        );
        assert!(WireError::Endpoint("x".into()).to_string().contains('x'));
    }
}
