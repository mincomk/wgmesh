use std::collections::HashMap;
use std::sync::Mutex;

use wgmesh_core::Millis;
use wgmesh_proto::sign::NONCE_TTL_SECS;

/// Replay defence. A nonce is good once, and is forgotten after the token's
/// lifetime — which the wire contract sets longer than the signature's own
/// timestamp window, so a captured request cannot be replayed inside the window
/// the timestamp still permits.
#[derive(Debug, Default)]
pub struct NonceCache {
    seen: Mutex<HashMap<String, u64>>,
}

impl NonceCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// True the first time this nonce is presented, false while it is fresh.
    pub fn accept(&self, nonce: &str, now: Millis) -> bool {
        let now_secs = now.0 / 1000;
        let Ok(mut seen) = self.seen.lock() else {
            return false;
        };
        if seen.len() > 8192 {
            seen.retain(|_, expiry| *expiry > now_secs);
        }
        match seen.get(nonce) {
            Some(expiry) if *expiry > now_secs => false,
            _ => {
                seen.insert(nonce.to_string(), now_secs + NONCE_TTL_SECS);
                true
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_nonce_is_spent_once_and_expires() {
        let cache = NonceCache::new();
        assert!(cache.accept("n", Millis::from_secs(100)));
        assert!(!cache.accept("n", Millis::from_secs(101)));
        assert!(cache.accept("n", Millis::from_secs(100 + NONCE_TTL_SECS + 1)));
    }
}
