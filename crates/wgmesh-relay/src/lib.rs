pub mod engine;
pub mod node;

pub use engine::{Admission, Handling, RelayEngine, SlotCounters, SlotLimits};
pub use node::{RelayError, RelayNode};

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}
