use std::collections::HashMap;
use std::hash::Hash;

/// The decision one admission check produced.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Admission {
    Allow,
    Deny { retry_after_secs: u64 },
}

impl Admission {
    pub const fn is_allowed(self) -> bool {
        matches!(self, Admission::Allow)
    }
}

/// A bucket that refills at a fixed rate and is spent in units of the caller's
/// choosing — one request, one packet, one byte.
///
/// The clock is an argument, never a call: the same sequence of `take` calls
/// always produces the same decisions, which is what lets the coordinator's
/// request limiter and the relay's per-slot traffic limiter be tested without
/// sleeping.
#[derive(Clone, Copy, Debug)]
pub struct TokenBucket {
    capacity: f64,
    tokens: f64,
    refill_per_ms: f64,
    refilled_at: u64,
    /// When this bucket was last consulted, which is what a key is forgotten
    /// by: the least recently used one goes first.
    touched_at: u64,
}

impl TokenBucket {
    /// A bucket holding `capacity` units that refills over `window_ms`, so an
    /// idle caller may spend `capacity` at once and is then held to the refill
    /// rate.
    pub fn new(capacity: f64, window_ms: u64) -> Self {
        let window = window_ms.max(1) as f64;
        Self {
            capacity,
            tokens: capacity,
            refill_per_ms: capacity / window,
            refilled_at: 0,
            touched_at: 0,
        }
    }

    pub const fn capacity(&self) -> f64 {
        self.capacity
    }

    /// How many units are available at `now_ms`, without spending any.
    pub fn projected(&self, now_ms: u64) -> f64 {
        let elapsed = now_ms.saturating_sub(self.refilled_at);
        (self.tokens + elapsed as f64 * self.refill_per_ms).min(self.capacity)
    }

    /// Whether a bucket has refilled completely and has not been touched since
    /// `now_ms - idle_for_ms`, which is when a key may safely be forgotten.
    pub fn is_idle(&self, now_ms: u64, idle_for_ms: u64) -> bool {
        self.projected(now_ms) >= self.capacity
            && now_ms.saturating_sub(self.touched_at) > idle_for_ms
    }

    /// Spend `amount` units, or report how long the caller must wait.
    pub fn take(&mut self, amount: f64, now_ms: u64) -> Admission {
        let available = self.projected(now_ms);
        self.tokens = available;
        self.refilled_at = now_ms;
        self.touched_at = now_ms;
        if available >= amount {
            self.tokens -= amount;
            Admission::Allow
        } else {
            let missing = amount - available;
            let wait_ms = (missing / self.refill_per_ms).ceil() as u64;
            Admission::Deny {
                retry_after_secs: wait_ms.div_ceil(1000).max(1),
            }
        }
    }

    /// Spend only if the bucket can afford it, leaving it untouched otherwise.
    pub fn take_or_leave(&mut self, amount: f64, now_ms: u64) -> Admission {
        if self.projected(now_ms) >= amount {
            self.take(amount, now_ms)
        } else {
            let missing = amount - self.projected(now_ms);
            let wait_ms = (missing / self.refill_per_ms).ceil() as u64;
            Admission::Deny {
                retry_after_secs: wait_ms.div_ceil(1000).max(1),
            }
        }
    }
}

/// A set of token buckets keyed by whatever the caller counts with — a client
/// address at the API edge, a slot at the relay.
///
/// Keys that have refilled and gone quiet are dropped once the map grows past
/// `max_keys`, so an unfriendly client cannot grow it without bound. A key
/// still inside its window is never dropped: dropping it would hand the caller
/// a fresh allowance.
#[derive(Clone, Debug)]
pub struct Metered<K> {
    buckets: HashMap<K, TokenBucket>,
    capacity: f64,
    window_ms: u64,
    max_keys: usize,
}

impl<K: Eq + Hash + Copy> Metered<K> {
    pub fn new(capacity: f64, window_ms: u64, max_keys: usize) -> Self {
        Self {
            buckets: HashMap::new(),
            capacity,
            window_ms,
            max_keys,
        }
    }

    pub fn take(&mut self, key: K, amount: f64, now_ms: u64) -> Admission {
        let capacity = self.capacity;
        let decision = match self.buckets.get_mut(&key) {
            Some(bucket) => bucket.take_or_leave(amount, now_ms),
            None => {
                let mut bucket = TokenBucket::new(capacity, self.window_ms);
                let decision = bucket.take_or_leave(amount, now_ms);
                self.buckets.insert(key, bucket);
                decision
            }
        };
        self.prune(now_ms, key);
        decision
    }

    /// Whether the key can afford `amount` right now, spending nothing.
    pub fn projected(&self, key: K, now_ms: u64) -> f64 {
        match self.buckets.get(&key) {
            Some(bucket) => bucket.projected(now_ms),
            None => self.capacity,
        }
    }

    pub fn tracked_keys(&self) -> usize {
        self.buckets.len()
    }

    fn prune(&mut self, now_ms: u64, keep: K) {
        if self.buckets.len() <= self.max_keys {
            return;
        }
        let idle = self.window_ms;
        let capacity = self.capacity;
        self.buckets.retain(|_, bucket| {
            !(bucket.projected(now_ms) >= capacity && bucket.is_idle(now_ms, idle))
        });
        if self.buckets.len() <= self.max_keys {
            return;
        }
        let excess = self.buckets.len() - self.max_keys;
        // Oldest first, by when the key was last consulted. A key that was
        // just asked about is therefore never the one dropped, which matters:
        // dropping it would hand the caller a fresh allowance.
        // Oldest first, by when the key was last consulted — and never the key
        // in hand. Every key touched at the same millisecond ties, and on a tie
        // the order is `HashMap`'s; dropping the caller's own key would hand it
        // a fresh allowance, which is the one thing this must not do.
        let mut by_age: Vec<(K, u64)> = self
            .buckets
            .iter()
            .filter(|(key, _)| **key != keep)
            .map(|(key, bucket)| (*key, bucket.touched_at))
            .collect();
        by_age.sort_by_key(|(_, touched_at)| *touched_at);
        for (key, _) in by_age.into_iter().take(excess) {
            self.buckets.remove(&key);
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn a_burst_up_to_the_capacity_is_admitted_and_the_next_unit_is_refused() {
        let mut bucket = TokenBucket::new(30.0, 60_000);
        for index in 0..30 {
            assert!(bucket.take(1.0, 1_000).is_allowed(), "unit {index}");
        }
        assert!(matches!(bucket.take(1.0, 1_000), Admission::Deny { .. }));
    }

    #[test]
    fn a_refused_bucket_recovers_at_the_refill_rate() {
        let mut bucket = TokenBucket::new(30.0, 60_000);
        for _ in 0..30 {
            bucket.take(1.0, 0);
        }
        // One unit is 60s / 30 = 2s of quiet.
        assert!(matches!(bucket.take(1.0, 1_000), Admission::Deny { .. }));
        assert!(matches!(bucket.take(1.0, 1_500), Admission::Deny { .. }));
        assert!(bucket.take(1.0, 2_100).is_allowed());
    }

    #[test]
    fn a_bucket_never_holds_more_than_its_capacity() {
        let bucket = TokenBucket::new(4.0, 1_000);
        assert_eq!(bucket.projected(10_000_000), 4.0);
    }

    #[test]
    fn take_or_leave_does_not_spend_when_it_refuses() {
        let mut bucket = TokenBucket::new(2.0, 1_000);
        assert!(bucket.take(1.0, 0).is_allowed());
        assert!(matches!(bucket.take(1.0, 0), Admission::Allow));
        // Asking for more than the bucket holds must not empty it.
        assert!(matches!(
            bucket.take_or_leave(5.0, 0),
            Admission::Deny { .. }
        ));
        assert_eq!(bucket.projected(0), 0.0);
    }

    #[test]
    fn a_byte_bucket_bounds_the_bytes_per_second() {
        // 1 Mbit/s is 125_000 bytes per second.
        let mut bucket = TokenBucket::new(125_000.0, 1_000);
        let packet = 1_420.0;
        let mut forwarded = 0.0f64;
        for ms in 0..10_000u64 {
            if bucket.take(packet, ms).is_allowed() {
                forwarded += packet;
            }
        }
        // Ten seconds at 1 Mbit/s, plus the single bucket of burst an idle
        // caller starts with. It cannot spend more than that.
        assert!(forwarded <= 125_000.0 * 10.0 + 125_000.0);
        assert!(forwarded >= 125_000.0 * 10.0);
    }

    #[test]
    fn keys_are_counted_separately() {
        let mut metered = Metered::new(5.0, 60_000, 64);
        for _ in 0..5 {
            assert!(metered.take(1u32, 1.0, 0).is_allowed());
        }
        assert!(matches!(metered.take(1u32, 1.0, 0), Admission::Deny { .. }));
        for _ in 0..5 {
            assert!(metered.take(2u32, 1.0, 0).is_allowed());
        }
    }

    #[test]
    fn an_unknown_key_starts_full() {
        let metered: Metered<u32> = Metered::new(30.0, 60_000, 64);
        assert_eq!(metered.projected(7, 0), 30.0);
    }

    #[test]
    fn idle_keys_are_pruned_once_the_map_is_full() {
        let mut metered = Metered::new(10.0, 60_000, 8);
        for key in 0..64u32 {
            metered.take(key, 1.0, 0);
        }
        assert!(metered.tracked_keys() <= 8);
        assert!(metered.take(999, 1.0, 0).is_allowed());
    }

    #[test]
    fn the_key_in_hand_is_never_the_one_dropped_when_the_map_is_full() {
        // One key in the map, and two units of allowance: every call after the
        // first is over capacity, so a call that dropped its own key would hand
        // itself a fresh bucket — and the refusal below would never come.
        let mut metered = Metered::new(2.0, 60_000, 1);
        assert!(metered.take(1u32, 1.0, 0).is_allowed());
        assert!(metered.take(2u32, 1.0, 0).is_allowed());
        assert!(metered.take(2u32, 1.0, 0).is_allowed());
        assert!(matches!(metered.take(2u32, 1.0, 0), Admission::Deny { .. }));
        assert!(metered.tracked_keys() <= 2);
    }

    #[test]
    fn steady_traffic_under_the_allowance_is_never_refused() {
        let mut metered = Metered::new(30.0, 60_000, 64);
        let mut now = 0u64;
        for _ in 0..720 {
            assert!(metered.take(9u32, 1.0, now).is_allowed());
            now += 5_000;
        }
    }
}
