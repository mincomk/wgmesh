use std::sync::{Arc, Mutex};
use std::time::Duration;

use wgmesh_core::{Change, DeviceId, Endpoint, Millis};
use wgmesh_ports::{PeerStatus, WireGuard, WireGuardError};

use crate::clock::VirtualClock;
use crate::nat::NatSim;

#[derive(Debug)]
struct WgState {
    endpoint: Option<Endpoint>,
    last_handshake: Option<Millis>,
    due: Option<Millis>,
    applied: Vec<Change>,
    listen_port: u16,
}

/// A kernel WireGuard that keeps exactly the properties the traversal depends
/// on: the peer endpoint can hold one address at a time, a handshake arrives
/// only if the pinned address is reachable through the simulated NAT, and the
/// relay path refreshes on keepalive.
#[derive(Clone, Debug)]
pub struct FakeWireGuard {
    peer: DeviceId,
    nat: NatSim,
    clock: VirtualClock,
    rtt: Duration,
    keepalive: Duration,
    state: Arc<Mutex<WgState>>,
}

impl FakeWireGuard {
    pub fn new(
        peer: DeviceId,
        nat: NatSim,
        clock: VirtualClock,
        rtt: Duration,
        keepalive: Duration,
    ) -> Self {
        Self {
            peer,
            nat,
            clock,
            rtt,
            keepalive,
            state: Arc::new(Mutex::new(WgState {
                endpoint: None,
                last_handshake: None,
                due: None,
                applied: Vec::new(),
                listen_port: 51820,
            })),
        }
    }

    pub fn current_endpoint(&self) -> Option<Endpoint> {
        self.state.lock().expect("wg mutex").endpoint
    }

    pub fn last_handshake(&self) -> Option<Millis> {
        self.state.lock().expect("wg mutex").last_handshake
    }

    pub fn applied(&self) -> Vec<Change> {
        self.state.lock().expect("wg mutex").applied.clone()
    }
}

impl WireGuard for FakeWireGuard {
    fn apply(&self, changes: &[Change]) -> Result<(), WireGuardError> {
        let now = self.clock.now();
        let mut state = self.state.lock().expect("wg mutex");
        for change in changes {
            state.applied.push(change.clone());
            let endpoint = match change {
                Change::Add(spec) | Change::Update(spec) => spec.endpoint,
                Change::Remove(_) => None,
            };
            if let Some(endpoint) = endpoint {
                state.endpoint = Some(endpoint);
                state.due = self.nat.reachable(endpoint).then(|| now.plus(self.rtt));
            }
        }
        Ok(())
    }

    fn status(&self, peers: &[DeviceId]) -> Result<Vec<PeerStatus>, WireGuardError> {
        let now = self.clock.now();
        let mut state = self.state.lock().expect("wg mutex");

        if let Some(due) = state.due {
            if now >= due {
                state.last_handshake = Some(due);
                state.due = None;
            }
        }

        // Whatever the peer endpoint currently is, `persistent-keepalive` keeps
        // the session alive on it: a real WireGuard rekeys on schedule, so a
        // reachable path always shows a recent handshake and an unreachable one
        // goes quiet. That difference is the agent's only liveness signal.
        let reachable = state
            .endpoint
            .is_some_and(|endpoint| self.nat.reachable(endpoint));
        if reachable {
            let stale = match state.last_handshake {
                Some(at) => now.elapsed_since(at) >= self.keepalive,
                None => true,
            };
            if stale {
                state.last_handshake = Some(now);
            }
        }

        let snapshot = PeerStatus {
            peer: self.peer,
            endpoint: state.endpoint,
            last_handshake: state.last_handshake,
        };
        Ok(peers
            .iter()
            .filter(|peer| **peer == self.peer)
            .map(|_| snapshot)
            .collect())
    }

    fn listen_port(&self) -> Result<u16, WireGuardError> {
        Ok(self.state.lock().expect("wg mutex").listen_port)
    }
}
