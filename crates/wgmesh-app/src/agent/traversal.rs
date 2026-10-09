// One peer's traversal, run as a round: read what the kernel says, feed the state
// machine, and do what it asks.
//
// `wgmesh_core::step` is the whole decision and it is pure. What it cannot see is
// the two things only a running node knows:
//
// * **whether a direct path is still alive.** WireGuard roams a peer's endpoint
//   on authenticated packets, so a direct path that has gone quiet produces no
//   event of its own. The kernel's `last_handshake` is the only signal there is,
//   and turning "no handshake for too long" into `Event::Degraded` is this
//   module's job — the core deliberately does not second-guess a path that is
//   still working.
// * **where the locally derived candidates are.** `Lan` and `Ipv6` addresses are
//   read from this node's interfaces, and `Event::Observed` is the only door into
//   the candidate list, so without `offer_candidates` the ranking that orders
//   those classes would be a pure function nobody calls.
//
// A round is: the relay slot, the relay's observations, the kernel's handshake
// and its absence, then a tick. Every effect the state machine asks for is
// applied at the end of the round, so the machine never observes a half-applied
// interface.

use std::time::Duration;

use wgmesh_core::{
    DeviceId, DiscoveryPolicy, DiscoverySources, Endpoint, Event, Millis, Path, PeerSpec,
    Traversal, TraversalConfig, discover,
};
use wgmesh_ports::{Clock, CoordinatorApi, Observation, WireGuard};

use crate::agent::effect::{Effect, dispatch_all};
use crate::agent::error::AppError;

use super::TraversePeers;

/// The keepalive put on every peer, when the settings name none.
///
/// It is not only a NAT mapping keepalive: it is what makes the simultaneous
/// send happen when neither side has anything to say, and therefore what turns a
/// punch attempt into two packets crossing in flight. Every peer of this mesh
/// gets it.
pub const DEFAULT_KEEPALIVE: Duration = Duration::from_secs(25);

/// How long a direct path may go without a handshake before it is called dead.
///
/// A live but idle direct path only rekeys every `RekeyAfterTime` (120s in
/// wireguard-go), and `persistent-keepalive` sends an authenticated empty data
/// packet, which does not advance the handshake timestamp. WireGuard tears a
/// session down at `RejectAfterTime` (180s). A deadline shorter than that would
/// bounce a perfectly healthy path onto the relay every few minutes, so the
/// deadline is scaled with the keepalive interval but never falls below the
/// teardown window.
pub const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(180);

/// Whether a direct path that is not producing handshakes is dead.
///
/// Only a direct path can degrade: a relayed path has no handshake of its own to
/// miss, and an unknown one has not been tried yet.
pub fn degraded(
    path: Path,
    last_handshake: Option<Millis>,
    now: Millis,
    keepalive: Duration,
) -> bool {
    if path != Path::Direct {
        return false;
    }
    let deadline = keepalive.saturating_mul(3).max(HANDSHAKE_DEADLINE);
    match last_handshake {
        Some(at) => now.elapsed_since(at) > deadline,
        None => true,
    }
}

/// One peer's traversal, plus the kernel state the state machine cannot see.
///
/// `last_handshake` is what makes the handshake event fire once per handshake
/// rather than once per round: the kernel reports the same timestamp every time
/// it is asked. `last_observation` does the same for the relay's observations.
pub struct PeerTraversal<'a, W, C>
where
    W: WireGuard,
    C: CoordinatorApi,
{
    /// The state machine and the effects it turns into, as the crate ships them.
    pub traversal: TraversePeers<'a, W, C>,
    last_handshake: Option<Millis>,
    last_observation: Option<Millis>,
}

impl<'a, W, C> PeerTraversal<'a, W, C>
where
    W: WireGuard,
    C: CoordinatorApi,
{
    /// A traversal for one peer, starting from `Unknown`.
    pub fn new(
        wireguard: &'a W,
        coordinator: &'a C,
        device: DeviceId,
        peer: PeerSpec,
        timing: TraversalConfig,
    ) -> Self {
        Self {
            traversal: TraversePeers::new(wireguard, coordinator, device, peer, timing),
            last_handshake: None,
            last_observation: None,
        }
    }

    /// The peer this traversal is for.
    pub fn device(&self) -> DeviceId {
        self.traversal.peer().id
    }

    /// Which way traffic is going right now.
    pub fn path(&self) -> Path {
        self.traversal.path()
    }

    /// The traversal state, for a caller that wants to look at it.
    pub fn state(&self) -> &Traversal {
        self.traversal.traversal()
    }

    /// The last handshake this traversal has already reacted to.
    pub fn last_handshake(&self) -> Option<Millis> {
        self.last_handshake
    }
}

/// Runs one peer's traversal rounds.
pub struct TraversalRunner<'a, W, C, K>
where
    W: WireGuard,
    C: CoordinatorApi,
    K: Clock,
{
    wireguard: &'a W,
    coordinator: &'a C,
    clock: &'a K,
    timing: TraversalConfig,
    keepalive: Duration,
}

impl<'a, W, C, K> TraversalRunner<'a, W, C, K>
where
    W: WireGuard,
    C: CoordinatorApi,
    K: Clock,
{
    /// A runner over the three ports a traversal needs, with the timings and the
    /// keepalive every peer is given.
    pub fn new(
        wireguard: &'a W,
        coordinator: &'a C,
        clock: &'a K,
        timing: TraversalConfig,
        keepalive: Duration,
    ) -> Self {
        Self {
            wireguard,
            coordinator,
            clock,
            timing,
            keepalive,
        }
    }

    /// The timings in force.
    pub fn timing(&self) -> &TraversalConfig {
        &self.timing
    }

    /// The keepalive every re-pin carries.
    pub fn keepalive(&self) -> Duration {
        self.keepalive
    }

    /// A traversal for one peer.
    pub fn peer(&self, device: DeviceId, peer: PeerSpec) -> PeerTraversal<'a, W, C> {
        PeerTraversal::new(
            self.wireguard,
            self.coordinator,
            device,
            peer,
            self.timing.clone(),
        )
    }

    /// Feed the locally derived candidates into one peer's traversal.
    ///
    /// A relay observation is one of five classes. A same-LAN address, a global
    /// IPv6 address and a NAT-PMP/UPnP mapping are produced on this node, and
    /// `Event::Observed` is the only door into the candidate list — so this is
    /// where a `Lan` or `Ipv6` candidate gets the chance to outrank the address
    /// the relay observed. Returns how many candidates were offered.
    pub fn offer_candidates(
        &self,
        peer: &mut PeerTraversal<'a, W, C>,
        sources: &DiscoverySources,
        policy: DiscoveryPolicy,
    ) -> usize {
        let candidates = discover(sources, policy);
        for candidate in &candidates {
            peer.traversal.on_event(Event::Observed {
                endpoint: candidate.endpoint,
                kind: candidate.kind,
                at: candidate.observed_at,
            });
        }
        candidates.len()
    }

    /// One round for one peer.
    ///
    /// `relay` is the slot the coordinator assigned, when there is one; the
    /// endpoint of a relay is configuration rather than something an observation
    /// carries, so the daemon resolves it and hands it in. `observations` are the
    /// addresses a relay reported for this peer.
    pub async fn step(
        &self,
        peer: &mut PeerTraversal<'a, W, C>,
        relay: Option<Endpoint>,
        observations: &[Observation],
    ) -> Result<Vec<Effect>, AppError> {
        let now = self.clock.now();
        let mut effects = Vec::new();

        // The relay slot first: without it there is no fallback to fall back to,
        // and `Assignment` is what arms the fallback path.
        if peer.traversal.traversal().relay.is_none() {
            if let Some(relay) = relay {
                effects.extend(
                    peer.traversal
                        .on_event(Event::Assignment { relay, at: now }),
                );
            }
        }

        // Then the freshest thing a relay has to say about this peer.
        if let Some(freshest) = observations.iter().max_by_key(|observation| observation.at) {
            if Some(freshest.at) != peer.last_observation {
                peer.last_observation = Some(freshest.at);
                effects.extend(peer.traversal.on_event(Event::Observed {
                    endpoint: freshest.endpoint,
                    kind: freshest.kind,
                    at: freshest.at,
                }));
            }
        }

        // Then what the kernel knows. A handshake is fed once, and its absence —
        // which is what a broken direct path looks like — becomes `Degraded`.
        let status = self
            .wireguard
            .status(&[peer.device()])
            .map_err(AppError::WireGuard)?
            .into_iter()
            .next();
        if let Some(status) = &status {
            if let (Some(at), Some(via)) = (status.last_handshake, status.endpoint) {
                if peer.last_handshake != Some(at) {
                    peer.last_handshake = Some(at);
                    effects.extend(peer.traversal.on_event(Event::Handshake { via, at }));
                }
            }
            if degraded(peer.path(), status.last_handshake, now, self.keepalive) {
                effects.extend(peer.traversal.on_event(Event::Degraded { at: now }));
            }
        }

        // Only now may a tick start or abandon a direct attempt.
        effects.extend(peer.traversal.on_event(Event::Tick { at: now }));

        dispatch_all(self.wireguard, self.coordinator, &effects).await?;
        Ok(effects)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_direct_path_that_keeps_handshaking_is_healthy() {
        assert!(!degraded(
            Path::Direct,
            Some(Millis::from_secs(100)),
            Millis::from_secs(160),
            DEFAULT_KEEPALIVE
        ));
    }

    #[test]
    fn a_direct_path_without_handshakes_past_the_teardown_window_is_degraded() {
        assert!(degraded(
            Path::Direct,
            Some(Millis::from_secs(100)),
            Millis::from_secs(281),
            DEFAULT_KEEPALIVE
        ));
        assert!(degraded(
            Path::Direct,
            None,
            Millis::from_secs(1),
            DEFAULT_KEEPALIVE
        ));
    }

    #[test]
    fn an_idle_direct_path_inside_the_rekey_window_is_not_degraded() {
        // 150 seconds without a handshake is longer than three keepalives but
        // shorter than RejectAfterTime: an idle-but-alive path looks exactly like
        // this, so calling it dead would bounce a working path onto the relay.
        assert!(!degraded(
            Path::Direct,
            Some(Millis::from_secs(100)),
            Millis::from_secs(250),
            DEFAULT_KEEPALIVE
        ));
    }

    #[test]
    fn a_relayed_or_unknown_path_is_never_degraded() {
        assert!(!degraded(
            Path::Relayed,
            Some(Millis::ZERO),
            Millis::from_secs(10_000),
            DEFAULT_KEEPALIVE
        ));
        assert!(!degraded(
            Path::Unknown,
            None,
            Millis::from_secs(10_000),
            DEFAULT_KEEPALIVE
        ));
    }

    #[test]
    fn a_longer_keepalive_moves_the_deadline_but_never_under_the_teardown_window() {
        let long = degraded(
            Path::Direct,
            Some(Millis::ZERO),
            Millis::from_secs(1300),
            Duration::from_secs(400),
        );
        assert!(long, "3 * 400s is past 1300s");
        let short = degraded(
            Path::Direct,
            Some(Millis::ZERO),
            Millis::from_secs(100),
            Duration::from_secs(1),
        );
        assert!(
            !short,
            "a keepalive of 1s must not shrink the deadline under RejectAfterTime"
        );
    }
}
