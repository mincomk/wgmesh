// These are the control-plane types the coordinator hands to a relay. They use
// plain integers rather than the core newtypes so that they can round-trip through
// the HTTPS API without teaching `wgmesh-core` about serde; the engine converts at
// the boundary (`DeviceId(slot.device_id)`).

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct SlotAssignment {
    pub device_id: u32,
    pub port: u16,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct PairAssignment {
    pub device_a: u32,
    pub device_b: u32,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct KeysetPeer {
    pub device_id: u32,
    pub wg_pubkey: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct KeysetNetwork {
    pub id: u32,
    pub name: String,
    pub peers: Vec<KeysetPeer>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Keyset {
    pub networks: Vec<KeysetNetwork>,
}

impl Keyset {
    pub fn empty() -> Self {
        Self {
            networks: Vec::new(),
        }
    }

    pub fn contains(&self, device: u32) -> bool {
        self.networks
            .iter()
            .any(|network| network.peers.iter().any(|peer| peer.device_id == device))
    }

    pub fn len(&self) -> usize {
        self.networks
            .iter()
            .map(|network| network.peers.len())
            .sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Assignment {
    pub generation: u64,
    pub slots: Vec<SlotAssignment>,
    pub pairs: Vec<PairAssignment>,
    pub keyset: Keyset,
}
