use wgmesh_core::Millis;

// One slot's ingress budget, evaluated over whole seconds of engine time. A limit
// of zero means "unmetered" for that dimension, which is what the config defaults to
// when an operator leaves the knob unset.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SlotLimit {
    pps: u32,
    bytes_per_second: u64,
    window: u64,
    packets: u64,
    bytes: u64,
}

impl SlotLimit {
    pub const fn new(pps: u32, mbit_per_second: u32) -> Self {
        Self {
            pps,
            bytes_per_second: (mbit_per_second as u64) * 1_000_000 / 8,
            window: u64::MAX,
            packets: 0,
            bytes: 0,
        }
    }

    pub fn charge(&mut self, length: usize, at: Millis) -> bool {
        let second = at.as_millis() / 1000;
        if second != self.window {
            self.window = second;
            self.packets = 0;
            self.bytes = 0;
        }
        if self.pps != 0 && self.packets >= u64::from(self.pps) {
            return false;
        }
        let length = length as u64;
        if self.bytes_per_second != 0 && self.bytes.saturating_add(length) > self.bytes_per_second {
            return false;
        }
        self.packets += 1;
        self.bytes += length;
        true
    }

    pub fn packets(&self) -> u64 {
        self.packets
    }

    pub fn bytes(&self) -> u64 {
        self.bytes
    }
}
