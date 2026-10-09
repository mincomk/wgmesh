// The coordinator API as two sides see it: the wire types of the design document section 7
// and the signing preimage of section 5.5. `wgmesh-client` and `wgmesh-coordinator` both
// depend on this crate, so a change in the JSON shape or in the preimage breaks one of them
// at compile time or at the conformance vectors, not in production.

pub mod api;
pub mod canonical;

// The serialisation traits the wire types are built on are re-exported here so an adapter can
// name them without taking a serde dependency of its own: the design document lists the
// external crates each crate may hold, and serde belongs to this one.
pub use serde;

pub use api::{
    AUTH_SCHEME, AUTHORIZATION_HEADER, Ack, AllowedPrefix, ApiErrorBody, ApiErrorCode,
    CandidateKind, CandidateReport, ConfigSnapshot, EndpointB64, EndpointObservation,
    EndpointReport, JoinRequest, JoinResponse, NetworkInfo, PairAssignment, PairRelay, PeerInfo,
    PortRange, Prefix, PubKeyB64, PunchDirective, PunchOutcome, PunchReport, PunchResponse,
    PunchResult, RelayAssignment, RelayAssignmentResponse, RelayEnrollRequest, RelayEnrollment,
    RelayHeartbeat, RelayKeysetResponse, RelayNetworkKeyset, RelayObservationBatch, RelayPeerKey,
    RelayPoolEntry, RotateRequest, RotateResponse, SlotAssignment, TrafficSample, WireError, paths,
};
pub use canonical::{
    CANONICAL_PREFIX, CanonicalVector, canonical, conformance_vectors, hex_decode, hex_encode,
};
