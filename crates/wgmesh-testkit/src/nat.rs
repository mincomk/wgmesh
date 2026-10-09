use std::sync::{Arc, Mutex};

use wgmesh_core::Endpoint;

/// How the simulated NAT in front of the node behaves.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NatProfile {
    /// Endpoint independent mapping: the port the relay observed is the same
    /// port the peer will see, so a simultaneous send gets through.
    Cone,
    /// Endpoint dependent mapping: the relay observed one external port and the
    /// peer will see a different one, so the direct attempt cannot succeed.
    Symmetric,
}

#[derive(Debug)]
struct NatState {
    profile: NatProfile,
    relay_endpoint: Endpoint,
    peer_observed: Endpoint,
    direct_broken: bool,
}

/// A NAT simulator reduced to the one question the traversal asks it: "if the
/// peer endpoint is pinned to this address, does traffic actually arrive".
#[derive(Clone, Debug)]
pub struct NatSim {
    state: Arc<Mutex<NatState>>,
}

impl NatSim {
    pub fn new(profile: NatProfile, relay_endpoint: Endpoint, peer_observed: Endpoint) -> Self {
        Self {
            state: Arc::new(Mutex::new(NatState {
                profile,
                relay_endpoint,
                peer_observed,
                direct_broken: false,
            })),
        }
    }

    pub fn reachable(&self, endpoint: Endpoint) -> bool {
        let state = self.state.lock().expect("nat mutex");
        if endpoint == state.relay_endpoint {
            return true;
        }
        if endpoint == state.peer_observed {
            return state.profile == NatProfile::Cone && !state.direct_broken;
        }
        false
    }

    /// The direct path stops carrying traffic after it had worked. The relay is
    /// unaffected: that asymmetry is the whole reason the fallback exists.
    pub fn break_direct(&self) {
        self.state.lock().expect("nat mutex").direct_broken = true;
    }

    pub fn heal_direct(&self) {
        self.state.lock().expect("nat mutex").direct_broken = false;
    }

    pub fn profile(&self) -> NatProfile {
        self.state.lock().expect("nat mutex").profile
    }

    pub fn relay_endpoint(&self) -> Endpoint {
        self.state.lock().expect("nat mutex").relay_endpoint
    }

    pub fn peer_observed(&self) -> Endpoint {
        self.state.lock().expect("nat mutex").peer_observed
    }
}
