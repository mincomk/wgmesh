use std::fmt;
use std::time::Duration;

use wgmesh_core::{
    CandidateKind, Change, DeviceId, Effect, Event, Millis, Path, PeerSpec, PublicKey, Traversal,
    TraversalConfig, step,
};
use wgmesh_ports::{ApiError, Clock, CoordinatorApi, Observation, WireGuard, WireGuardError};

/// One peer's traversal, plus the two pieces of kernel state the state machine
/// cannot see for itself: the last handshake we have already reacted to, and
/// the last relay observation we have already fed in.
#[derive(Clone, Debug)]
pub struct PeerTraversal {
    pub peer: DeviceId,
    pub key: PublicKey,
    pub state: Traversal,
    pub last_handshake: Option<Millis>,
    pub last_observation: Option<Millis>,
}

impl PeerTraversal {
    pub fn new(peer: DeviceId, key: PublicKey, config: &TraversalConfig) -> Self {
        let mut state = Traversal::new();
        state.phase = wgmesh_core::Phase::Idle {
            next_attempt: Millis::ZERO,
        };
        let _ = config;
        Self {
            peer,
            key,
            state,
            last_handshake: None,
            last_observation: None,
        }
    }
}

/// Is a direct path that is not producing handshakes dead?
///
/// The kernel roams the endpoint on authenticated packets, so a direct path
/// that has gone quiet produces no event of its own. A missing handshake for
/// several keepalive periods is the only signal there is, and it is the agent's
/// job to turn it into `Event::Degraded` — the core deliberately does not
/// second-guess a path that is still working.
pub fn degraded(
    path: Path,
    last_handshake: Option<Millis>,
    now: Millis,
    keepalive: Duration,
) -> bool {
    if path != Path::Direct {
        return false;
    }
    let deadline = keepalive.saturating_mul(3);
    match last_handshake {
        Some(at) => now.elapsed_since(at) > deadline,
        None => true,
    }
}

pub struct TraversalRunner<W, C, K> {
    wireguard: W,
    coordinator: C,
    clock: K,
    config: TraversalConfig,
    keepalive: Duration,
}

impl<W, C, K> TraversalRunner<W, C, K>
where
    W: WireGuard,
    C: CoordinatorApi,
    K: Clock,
{
    pub fn new(
        wireguard: W,
        coordinator: C,
        clock: K,
        config: TraversalConfig,
        keepalive: Duration,
    ) -> Self {
        Self {
            wireguard,
            coordinator,
            clock,
            config,
            keepalive,
        }
    }

    pub fn config(&self) -> &TraversalConfig {
        &self.config
    }

    pub fn keepalive(&self) -> Duration {
        self.keepalive
    }

    /// One round of the agent loop for one peer.
    ///
    /// Order matters: the relay observation is fed in first, then the kernel is
    /// read and turned into `Handshake` / `Degraded`, and only then does a tick
    /// get the chance to start or abandon a direct attempt. Everything the loop
    /// decides arrives as `Effect` and is applied at the end, so the state
    /// machine never observes a half-applied interface.
    pub async fn step_peer(&self, peer: &mut PeerTraversal) -> Result<Vec<Effect>, AgentError> {
        let now = self.clock.now();
        let mut effects = Vec::new();

        if peer.state.relay.is_none() {
            if let Some(relay) = self.coordinator.relay_slot(peer.peer).await? {
                effects.extend(step(
                    &mut peer.state,
                    Event::Assignment { relay, at: now },
                    &self.config,
                ));
            }
        }

        let observations = self.coordinator.observations(peer.peer).await?;
        if let Some(freshest) = observations.iter().max_by_key(|o| o.seen_at) {
            if Some(freshest.seen_at) != peer.last_observation {
                peer.last_observation = Some(freshest.seen_at);
                step(
                    &mut peer.state,
                    Event::Observed {
                        endpoint: freshest.endpoint,
                        kind: CandidateKind::Observed,
                        at: freshest.seen_at,
                    },
                    &self.config,
                );
            }
        }

        if let Some(status) = self.wireguard.status(&[peer.peer])?.into_iter().next() {
            if let (Some(at), Some(via)) = (status.last_handshake, status.endpoint) {
                if Some(at) != peer.last_handshake {
                    peer.last_handshake = Some(at);
                    step(&mut peer.state, Event::Handshake { via, at }, &self.config);
                }
            }
            if degraded(peer.state.path, status.last_handshake, now, self.keepalive) {
                effects.extend(step(
                    &mut peer.state,
                    Event::Degraded { at: now },
                    &self.config,
                ));
            }
        }

        effects.extend(step(&mut peer.state, Event::Tick { at: now }, &self.config));

        for effect in &effects {
            match effect {
                Effect::SetPeerEndpoint(endpoint) => {
                    let spec = PeerSpec {
                        id: peer.peer,
                        key: peer.key,
                        allowed: Vec::new(),
                        endpoint: Some(*endpoint),
                        keepalive: Some(self.keepalive),
                    };
                    self.wireguard.apply(&[Change::Update(spec)])?;
                }
                Effect::SendHandshake => {
                    // The kernel sends the handshake itself; the persistent
                    // keepalive is what makes the simultaneous send happen even
                    // when neither side has anything to say.
                }
                Effect::ReportObservation(endpoint) => {
                    let observation = Observation::new(*endpoint, now);
                    self.coordinator
                        .report_observations(peer.peer, &[observation])
                        .await?;
                }
            }
        }

        Ok(effects)
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum AgentError {
    WireGuard(WireGuardError),
    Api(ApiError),
}

impl fmt::Display for AgentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WireGuard(err) => write!(f, "{err}"),
            Self::Api(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for AgentError {}

impl From<WireGuardError> for AgentError {
    fn from(err: WireGuardError) -> Self {
        Self::WireGuard(err)
    }
}

impl From<ApiError> for AgentError {
    fn from(err: ApiError) -> Self {
        Self::Api(err)
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
            Duration::from_secs(25)
        ));
    }

    #[test]
    fn a_direct_path_without_handshakes_for_three_keepalives_is_degraded() {
        assert!(degraded(
            Path::Direct,
            Some(Millis::from_secs(100)),
            Millis::from_secs(176),
            Duration::from_secs(25)
        ));
        assert!(degraded(
            Path::Direct,
            None,
            Millis::from_secs(1),
            Duration::from_secs(25)
        ));
    }

    #[test]
    fn a_relayed_path_is_never_degraded() {
        assert!(!degraded(
            Path::Relayed,
            Some(Millis::from_secs(0)),
            Millis::from_secs(10_000),
            Duration::from_secs(25)
        ));
        assert!(!degraded(
            Path::Unknown,
            None,
            Millis::from_secs(10_000),
            Duration::from_secs(25)
        ));
    }
}
