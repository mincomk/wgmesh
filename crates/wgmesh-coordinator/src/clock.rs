use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use wgmesh_app::coordinator::Clock;
use wgmesh_core::Millis;

#[derive(Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Millis {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|since| since.as_millis() as u64)
            .unwrap_or(0);
        Millis::from_millis(millis)
    }
}

/// A clock that stands still until it is moved, so a scenario can be replayed.
#[derive(Debug)]
pub struct FixedClock {
    at: AtomicU64,
}

impl FixedClock {
    pub fn new(at: Millis) -> Self {
        Self {
            at: AtomicU64::new(at.0),
        }
    }

    pub fn set(&self, at: Millis) {
        self.at.store(at.0, Ordering::Relaxed);
    }

    pub fn advance(&self, by: Millis) {
        self.at.fetch_add(by.0, Ordering::Relaxed);
    }
}

impl Clock for FixedClock {
    fn now(&self) -> Millis {
        Millis::from_millis(self.at.load(Ordering::Relaxed))
    }
}
