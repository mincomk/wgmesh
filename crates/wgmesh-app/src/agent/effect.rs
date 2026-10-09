// What the traversal asks the world to do, and how that becomes a port call.
//
// `wgmesh-core` decides and returns `wgmesh_core::Effect` values — a decision, with no peer
// identity attached and no idea what an endpoint change means to a kernel. This module is where
// a decision becomes an instruction that names a peer, and where an instruction becomes a call.
//
// The mapping is one short table, and it is the table the blueprint's section 3.2 describes.
//
// | `Effect`               | what it does                                             |
// |------------------------|----------------------------------------------------------|
// | `SetPeerEndpoint(..)`  | `wireguard.apply(&[Change::Update(..)])` — routes are not touched |
// | `SendHandshake(..)`    | a kick at the peer endpoint: the peer is re-applied, which makes the kernel initiate a handshake |
// | `ReportObservation(..)`| `coordinator.report_observations(&[..])`                 |
//
// The kick is a re-apply rather than a verb of its own because WireGuard has no configuration
// verb that means "handshake now": the kernel initiates when there is traffic and nothing else.
// Writing the peer again is the closest thing to a kick that the interface offers, and it keeps
// the port surface at the four operations the blueprint names.

use wgmesh_core::{Change, PeerSpec};
use wgmesh_ports::{CoordinatorApi, Observation, WireGuard};

use crate::agent::error::AppError;

/// Something the traversal wants done.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Effect {
    /// Point a peer at a new endpoint.
    SetPeerEndpoint(PeerSpec),
    /// Push a handshake toward a peer now.
    SendHandshake(PeerSpec),
    /// Tell the coordinator where this device was observed.
    ReportObservation(Observation),
}

/// Perform one effect through the ports.
pub async fn dispatch<W: WireGuard, C: CoordinatorApi>(
    wireguard: &W,
    coordinator: &C,
    effect: &Effect,
) -> Result<(), AppError> {
    match effect {
        Effect::SetPeerEndpoint(spec) | Effect::SendHandshake(spec) => wireguard
            .apply(&[Change::Update(spec.clone())])
            .map_err(AppError::WireGuard),
        Effect::ReportObservation(observation) => coordinator
            .report_observations(std::slice::from_ref(observation))
            .await
            .map_err(AppError::Coordinator),
    }
}

/// Perform a list of effects, in order, stopping at the first failure.
pub async fn dispatch_all<W: WireGuard, C: CoordinatorApi>(
    wireguard: &W,
    coordinator: &C,
    effects: &[Effect],
) -> Result<(), AppError> {
    for effect in effects {
        dispatch(wireguard, coordinator, effect).await?;
    }
    Ok(())
}
