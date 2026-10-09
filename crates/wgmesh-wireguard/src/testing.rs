use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard};

use wgmesh_core::{Allowed, Change, DeviceId, PeerSpec};
use wgmesh_ports::{InterfaceSpec, PeerStatus, WireGuard, WireGuardError};

#[derive(Default)]
struct State {
    interface: Option<InterfaceSpec>,
    peers: BTreeMap<DeviceId, PeerSpec>,
    listen_port: u16,
}

// An interface that behaves the way the kernel's does in the one respect the
// revocation path depends on: WireGuard routes by cryptokey, so a peer that is
// not in the table owns no address, and a packet whose source or destination is
// in nobody's AllowedIPs is dropped rather than delivered. Removing the peer is
// therefore the whole of revocation, and nothing has to be cancelled.
#[derive(Default)]
pub struct FakeWireGuard {
    state: Mutex<State>,
}

fn covers(allowed: &Allowed, address: &Allowed) -> Option<u8> {
    match (allowed, address) {
        (Allowed::V4(network, length), Allowed::V4(bytes, _)) => {
            matches_prefix(network, bytes, *length).then_some(*length)
        }
        (Allowed::V6(network, length), Allowed::V6(bytes, _)) => {
            matches_prefix(network, bytes, *length).then_some(*length)
        }
        _ => None,
    }
}

fn matches_prefix(network: &[u8], address: &[u8], length: u8) -> bool {
    let whole = usize::from(length / 8);
    if network.len() < length.div_ceil(8) as usize || address.len() < network.len() {
        return false;
    }
    if address[..whole] != network[..whole] {
        return false;
    }
    let remainder = length % 8;
    if remainder == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - remainder);
    match (address.get(whole), network.get(whole)) {
        (Some(left), Some(right)) => left & mask == right & mask,
        _ => false,
    }
}

impl FakeWireGuard {
    pub fn new() -> Self {
        Self::default()
    }

    fn state(&self) -> MutexGuard<'_, State> {
        match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    pub fn peers(&self) -> BTreeMap<DeviceId, PeerSpec> {
        self.state().peers.clone()
    }

    pub fn interface(&self) -> Option<InterfaceSpec> {
        self.state().interface.clone()
    }

    // Which peer, if any, owns this address. Longest prefix wins, as in the
    // kernel's lookup.
    pub fn owner_of(&self, address: Allowed) -> Option<DeviceId> {
        let state = self.state();
        let mut best: Option<(u8, DeviceId)> = None;
        for (id, spec) in &state.peers {
            for allowed in &spec.allowed {
                if let Some(length) = covers(allowed, &address) {
                    let better = match best {
                        None => true,
                        Some((best_length, _)) => length > best_length,
                    };
                    if better {
                        best = Some((length, *id));
                    }
                }
            }
        }
        best.map(|(_, id)| id)
    }

    // A packet arriving from this source is delivered only if a peer claims it.
    pub fn accepts_from(&self, source: Allowed) -> Option<DeviceId> {
        self.owner_of(source)
    }

    // A packet addressed here goes to the peer that claims it, and nowhere else.
    pub fn route_to(&self, destination: Allowed) -> Option<DeviceId> {
        self.owner_of(destination)
    }
}

impl WireGuard for FakeWireGuard {
    fn ensure_interface(&self, spec: &InterfaceSpec) -> Result<(), WireGuardError> {
        let mut state = self.state();
        if spec.name.is_empty() {
            return Err(WireGuardError::NoInterface(String::from(
                "an interface needs a name",
            )));
        }
        state.listen_port = spec.listen_port;
        state.interface = Some(spec.clone());
        Ok(())
    }

    fn apply(&self, changes: &[Change]) -> Result<(), WireGuardError> {
        let mut state = self.state();
        if state.interface.is_none() {
            return Err(WireGuardError::NoInterface(String::from(
                "the interface has not been created yet",
            )));
        }
        for change in changes {
            match change {
                Change::Add(spec) | Change::Update(spec) => {
                    state.peers.insert(spec.id, spec.clone());
                }
                Change::Remove(id) => {
                    state.peers.remove(id);
                }
            }
        }
        Ok(())
    }

    fn status(&self, peers: &[DeviceId]) -> Result<Vec<PeerStatus>, WireGuardError> {
        let state = self.state();
        Ok(peers
            .iter()
            .filter_map(|id| {
                state.peers.get(id).map(|spec| PeerStatus {
                    id: spec.id,
                    endpoint: spec.endpoint,
                    last_handshake: None,
                    rx_bytes: 0,
                    tx_bytes: 0,
                    allowed: spec.allowed.clone(),
                })
            })
            .collect())
    }

    fn listen_port(&self) -> Result<u16, WireGuardError> {
        Ok(self.state().listen_port)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use wgmesh_core::{PublicKey, diff};

    fn spec(id: u32, address: [u8; 4]) -> PeerSpec {
        PeerSpec {
            id: DeviceId(id),
            key: PublicKey::from_bytes([id as u8; 32]),
            allowed: vec![Allowed::V4(address, 32)],
            endpoint: None,
            keepalive: None,
        }
    }

    fn interface() -> InterfaceSpec {
        InterfaceSpec {
            name: String::from("wg0"),
            address: Allowed::V4([10, 77, 0, 1], 16),
            listen_port: 51820,
            mtu: 1420,
        }
    }

    #[test]
    fn a_peer_owns_only_the_addresses_it_is_allowed() {
        let wireguard = FakeWireGuard::new();
        wireguard.ensure_interface(&interface()).unwrap();
        wireguard
            .apply(&[
                Change::Add(spec(1, [10, 77, 0, 7])),
                Change::Add(spec(2, [10, 77, 0, 8])),
            ])
            .unwrap();
        assert_eq!(
            wireguard.accepts_from(Allowed::V4([10, 77, 0, 7], 32)),
            Some(DeviceId(1))
        );
        assert_eq!(
            wireguard.route_to(Allowed::V4([10, 77, 0, 8], 32)),
            Some(DeviceId(2))
        );
        assert_eq!(
            wireguard.accepts_from(Allowed::V4([10, 77, 0, 9], 32)),
            None
        );
    }

    #[test]
    fn removing_a_peer_takes_its_addresses_with_it() {
        let wireguard = FakeWireGuard::new();
        wireguard.ensure_interface(&interface()).unwrap();
        wireguard
            .apply(&[Change::Add(spec(1, [10, 77, 0, 7]))])
            .unwrap();
        wireguard.apply(&[Change::Remove(DeviceId(1))]).unwrap();
        assert!(wireguard.peers().is_empty());
        assert_eq!(
            wireguard.accepts_from(Allowed::V4([10, 77, 0, 7], 32)),
            None
        );
    }

    #[test]
    fn a_change_against_a_missing_interface_is_refused() {
        let wireguard = FakeWireGuard::new();
        assert!(matches!(
            wireguard.apply(&[Change::Add(spec(1, [10, 77, 0, 7]))]),
            Err(WireGuardError::NoInterface(_))
        ));
        assert!(wireguard.ensure_interface(&interface()).is_ok());
        assert_eq!(wireguard.listen_port().unwrap(), 51820);
        assert_eq!(wireguard.interface().unwrap().name, "wg0");
    }

    #[test]
    fn a_diff_against_the_installed_table_is_what_removes_a_peer() {
        let wireguard = FakeWireGuard::new();
        wireguard.ensure_interface(&interface()).unwrap();
        let alpha = spec(1, [10, 77, 0, 7]);
        let beta = spec(2, [10, 77, 0, 8]);
        wireguard
            .apply(&[Change::Add(alpha.clone()), Change::Add(beta.clone())])
            .unwrap();

        let changes = diff(&[alpha], &wireguard.peers());
        assert_eq!(changes, vec![Change::Remove(DeviceId(2))]);
        wireguard.apply(&changes).unwrap();
        assert_eq!(wireguard.route_to(Allowed::V4([10, 77, 0, 8], 32)), None);
        assert_eq!(
            wireguard.accepts_from(Allowed::V4([10, 77, 0, 7], 32)),
            Some(DeviceId(1))
        );
    }

    #[test]
    fn the_longest_prefix_decides_who_owns_an_address() {
        let wireguard = FakeWireGuard::new();
        wireguard.ensure_interface(&interface()).unwrap();
        let mut gateway = spec(9, [10, 77, 0, 0]);
        gateway.allowed = vec![Allowed::V4([0, 0, 0, 0], 0)];
        wireguard
            .apply(&[Change::Add(gateway), Change::Add(spec(1, [10, 77, 0, 7]))])
            .unwrap();
        assert_eq!(
            wireguard.route_to(Allowed::V4([10, 77, 0, 7], 32)),
            Some(DeviceId(1))
        );
        assert_eq!(
            wireguard.route_to(Allowed::V4([8, 8, 8, 8], 32)),
            Some(DeviceId(9))
        );
        assert_eq!(wireguard.route_to(Allowed::V6([0; 16], 0)), None);
    }
}
