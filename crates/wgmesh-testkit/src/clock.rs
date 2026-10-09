use std::sync::{Arc, Mutex};
use std::time::Duration;

use wgmesh_core::Millis;
use wgmesh_ports::Clock;

/// A clock the test moves by hand.
///
/// The traversal state machine is entirely a function of time, so every
/// interval the design promises (a 5 second window, a 30 second backoff) can be
/// asserted exactly and instantly instead of slept through.
#[derive(Clone, Debug)]
pub struct VirtualClock {
    now: Arc<Mutex<Millis>>,
}

impl Default for VirtualClock {
    fn default() -> Self {
        Self::starting_at(Millis::ZERO)
    }
}

impl VirtualClock {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn starting_at(at: Millis) -> Self {
        Self {
            now: Arc::new(Mutex::new(at)),
        }
    }

    pub fn set(&self, at: Millis) {
        *self.now.lock().expect("clock mutex") = at;
    }

    pub fn now(&self) -> Millis {
        *self.now.lock().expect("clock mutex")
    }

    pub fn advance(&self, by: Duration) {
        let mut guard = self.now.lock().expect("clock mutex");
        *guard = guard.plus(by);
    }
}

impl Clock for VirtualClock {
    fn now(&self) -> Millis {
        *self.now.lock().expect("clock mutex")
    }
}
