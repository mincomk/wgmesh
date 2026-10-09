// The translation from core values into netlink message content, and nothing
// else: no socket, no runtime, no kernel.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use nl_wireguard::{
    WireguardIpAddress, WireguardParsed, WireguardParsedPeerFlags, WireguardPeerParsed,
};
use wgmesh_core::{Allowed, Change, DeviceId, Endpoint, PeerSpec, PublicKey};

use crate::base64;

/// One `Allowed` in the shape a `WGPEER_A_ALLOWEDIPS` entry takes.
///
/// A catch-all prefix — `Allowed::V4([0, 0, 0, 0], 0)`, the one
/// `AllowedIpsPolicy::ExitPeer` hands out — lands here as
/// `WireguardIpAddress { ip_addr: 0.0.0.0, prefix_length: 0 }`, which is
/// exactly what the kernel's `WGALLOWEDIP_A_CIDR_MASK` takes.
pub fn allowed_ip(prefix: &Allowed) -> WireguardIpAddress {
    let (ip_addr, prefix_length) = match prefix {
        Allowed::V4(bytes, mask) => (IpAddr::V4(Ipv4Addr::from(*bytes)), *mask),
        Allowed::V6(bytes, mask) => (IpAddr::V6(Ipv6Addr::from(*bytes)), *mask),
    };
    WireguardIpAddress {
        ip_addr,
        prefix_length,
        flags: None,
    }
}

/// The inverse of [`allowed_ip`], for a device read back out of the kernel.
pub fn allowed_from_ip(allowed: &WireguardIpAddress) -> Allowed {
    match allowed.ip_addr {
        IpAddr::V4(address) => Allowed::V4(address.octets(), allowed.prefix_length),
        IpAddr::V6(address) => Allowed::V6(address.octets(), allowed.prefix_length),
    }
}

/// One kernel facing write for one [`Change`].
///
/// Keeping the translation as a value rather than as a call is what makes it
/// testable without a kernel: the netlink call is a later, separate step.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum PeerOp {
    /// Add or update a peer, with exactly these attributes.
    Set(WireguardPeerParsed),
    /// Remove the peer holding this public key.
    Remove(WireguardPeerParsed),
}

impl PeerOp {
    /// The peer attribute set this operation writes.
    pub fn peer(&self) -> &WireguardPeerParsed {
        match self {
            Self::Set(peer) | Self::Remove(peer) => peer,
        }
    }
}

/// Translate one [`Change`] into the netlink peer it writes.
///
/// `known` maps the device ids this adapter has already written to their public
/// keys. A `Change::Remove` carries only the id — `core::diff` has nothing else
/// to go on — so the key has to come from there. `None` means the adapter has
/// never seen that peer and can not name it to the kernel.
pub fn peer_op(change: &Change, known: &BTreeMap<DeviceId, PublicKey>) -> Option<PeerOp> {
    match change {
        Change::Add(spec) | Change::Update(spec) => Some(PeerOp::Set(peer_config(spec))),
        Change::Remove(id) => known.get(id).map(|key| PeerOp::Remove(removal_peer(key))),
    }
}

/// The peer attributes a [`PeerSpec`] becomes.
///
/// `ReplaceAllowedIps` is on every set operation because the desired allowed IP
/// list is authoritative: a peer whose advertised bands shrank must lose the
/// bands it no longer advertises, and appending would keep them.
pub fn peer_config(spec: &PeerSpec) -> WireguardPeerParsed {
    let mut peer = WireguardPeerParsed::default();
    fill_peer(&mut peer, spec);
    peer
}

/// The peer attributes that remove one peer.
///
/// The kernel ignores every property of a peer that carries `RemoveMe`, so the
/// public key is the whole message.
pub fn removal_peer(key: &PublicKey) -> WireguardPeerParsed {
    let mut peer = WireguardPeerParsed::default();
    peer.public_key = Some(base64::encode(key.as_bytes()));
    peer.flags = Some(vec![WireguardParsedPeerFlags::RemoveMe]);
    peer
}

/// The device configuration one batch of operations becomes.
pub fn device_config(ifname: &str, ops: &[PeerOp]) -> WireguardParsed {
    let mut config = WireguardParsed::default();
    fill_device(&mut config, ifname, ops);
    config
}

/// The device configuration that carries only the interface properties.
///
/// The peer list is left absent rather than empty: an empty
/// `WGDEVICE_A_PEERS` would be a message about peers, and this one is not.
pub fn device_properties(
    ifname: &str,
    private_key: Option<String>,
    listen_port: Option<u16>,
) -> WireguardParsed {
    let mut config = WireguardParsed::default();
    fill_properties(&mut config, ifname, private_key, listen_port);
    config
}

fn fill_peer(peer: &mut WireguardPeerParsed, spec: &PeerSpec) {
    peer.public_key = Some(base64::encode(spec.key.as_bytes()));
    peer.endpoint = spec.endpoint.map(endpoint_addr);
    peer.persistent_keepalive = spec.keepalive.map(keepalive_seconds);
    peer.allowed_ips = Some(spec.allowed.iter().map(allowed_ip).collect());
    peer.flags = Some(vec![WireguardParsedPeerFlags::ReplaceAllowedIps]);
}

fn fill_device(config: &mut WireguardParsed, ifname: &str, ops: &[PeerOp]) {
    config.iface_name = Some(ifname.to_string());
    config.peers = Some(ops.iter().map(|op| op.peer().clone()).collect());
}

fn fill_properties(
    config: &mut WireguardParsed,
    ifname: &str,
    private_key: Option<String>,
    listen_port: Option<u16>,
) {
    config.iface_name = Some(ifname.to_string());
    config.private_key = private_key;
    config.listen_port = listen_port;
}

fn endpoint_addr(endpoint: Endpoint) -> std::net::SocketAddr {
    endpoint.addr()
}

/// `WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL` is a `u16` of seconds.
fn keepalive_seconds(keepalive: Duration) -> u16 {
    u16::try_from(keepalive.as_secs()).unwrap_or(u16::MAX)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::net::SocketAddr;
    use std::time::Duration;

    use nl_wireguard::WireguardParsedPeerFlags;
    use wgmesh_core::{AllowedIpsPolicy, CATCH_ALL, program_allowed_ips};

    use super::*;

    fn spec(id: u32, allowed: Vec<Allowed>) -> PeerSpec {
        PeerSpec {
            id: DeviceId(id),
            key: PublicKey::from_bytes([id as u8; 32]),
            allowed,
            endpoint: Some(Endpoint::new(SocketAddr::from((
                [10, 77, 0, id as u8],
                51820,
            )))),
            keepalive: Some(Duration::from_secs(25)),
        }
    }

    fn host(last: u8) -> Allowed {
        Allowed::V4([10, 77, 0, last], 32)
    }

    #[test]
    fn a_peer_spec_becomes_the_kernel_attributes() {
        let peer = peer_config(&spec(1, vec![host(1)]));

        assert_eq!(
            peer.public_key.as_deref(),
            Some(base64::encode(&[1u8; 32]).as_str())
        );
        assert_eq!(
            peer.endpoint,
            Some(SocketAddr::from(([10, 77, 0, 1], 51820)))
        );
        assert_eq!(peer.persistent_keepalive, Some(25));
        assert_eq!(
            peer.allowed_ips,
            Some(vec![WireguardIpAddress {
                ip_addr: IpAddr::V4(Ipv4Addr::new(10, 77, 0, 1)),
                prefix_length: 32,
                flags: None,
            }])
        );
        assert_eq!(
            peer.flags,
            Some(vec![WireguardParsedPeerFlags::ReplaceAllowedIps])
        );
    }

    #[test]
    fn a_keepalive_too_large_for_the_attribute_is_clamped() {
        let mut peer = spec(1, vec![host(1)]);
        peer.keepalive = Some(Duration::from_secs(200_000));
        assert_eq!(peer_config(&peer).persistent_keepalive, Some(u16::MAX));
    }

    #[test]
    fn a_change_becomes_one_peer_operation() {
        let peer = spec(1, vec![host(1)]);
        let known = BTreeMap::from([(DeviceId(1), peer.key)]);

        assert_eq!(
            peer_op(&Change::Add(peer.clone()), &known),
            Some(PeerOp::Set(peer_config(&peer)))
        );
        assert_eq!(
            peer_op(&Change::Update(peer.clone()), &known),
            Some(PeerOp::Set(peer_config(&peer)))
        );
        assert_eq!(
            peer_op(&Change::Remove(DeviceId(1)), &known),
            Some(PeerOp::Remove(removal_peer(&peer.key)))
        );
    }

    #[test]
    fn removing_a_peer_we_never_wrote_has_no_public_key() {
        assert_eq!(
            peer_op(&Change::Remove(DeviceId(9)), &BTreeMap::new()),
            None
        );
    }

    #[test]
    fn a_removal_peer_carries_the_key_and_the_flag() {
        let peer = removal_peer(&PublicKey::from_bytes([2u8; 32]));
        assert_eq!(
            peer.public_key.as_deref(),
            Some(base64::encode(&[2u8; 32]).as_str())
        );
        assert_eq!(peer.flags, Some(vec![WireguardParsedPeerFlags::RemoveMe]));
    }

    #[test]
    fn the_device_config_carries_every_operation_in_order() {
        let first = spec(1, vec![host(1)]);
        let second = spec(2, vec![host(2)]);
        let ops = vec![
            PeerOp::Set(peer_config(&first)),
            PeerOp::Remove(removal_peer(&second.key)),
        ];

        let config = device_config("wgmesh0", &ops);

        assert_eq!(config.iface_name.as_deref(), Some("wgmesh0"));
        let peers = config.peers.expect("peers are written");
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0], peer_config(&first));
        assert_eq!(peers[1], removal_peer(&second.key));
    }

    #[test]
    fn the_device_properties_carry_no_peer_list() {
        let config = device_properties("wgmesh0", Some("key".to_string()), Some(51820));
        assert_eq!(config.iface_name.as_deref(), Some("wgmesh0"));
        assert_eq!(config.private_key.as_deref(), Some("key"));
        assert_eq!(config.listen_port, Some(51820));
        assert!(config.peers.is_none(), "an absent list, not an empty one");
    }

    #[test]
    fn an_exit_peer_catch_all_reaches_the_attribute_as_prefix_length_zero() {
        let peers = [spec(1, vec![host(1)]), spec(2, vec![host(2)])];
        let assigned = program_allowed_ips(AllowedIpsPolicy::ExitPeer(DeviceId(2)), &peers)
            .expect("the exit peer exists");

        let exit = assigned
            .iter()
            .find(|(id, _)| *id == DeviceId(2))
            .map(|(_, allowed)| allowed.clone())
            .expect("the exit peer is assigned");
        assert_eq!(exit, CATCH_ALL.to_vec());

        let peer = peer_config(&PeerSpec {
            allowed: exit,
            ..spec(2, vec![host(2)])
        });

        let mut written = peer.allowed_ips.expect("allowed ips are written");
        written.sort_by_key(|allowed| allowed.ip_addr.is_ipv6());
        assert_eq!(
            written,
            vec![
                WireguardIpAddress {
                    ip_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    prefix_length: 0,
                    flags: None,
                },
                WireguardIpAddress {
                    ip_addr: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                    prefix_length: 0,
                    flags: None,
                },
            ]
        );
    }

    #[test]
    fn a_catch_all_reads_back_as_the_prefix_it_was_written_from() {
        for prefix in CATCH_ALL {
            assert_eq!(allowed_from_ip(&allowed_ip(&prefix)), prefix);
        }
        assert_eq!(
            allowed_from_ip(&WireguardIpAddress {
                ip_addr: IpAddr::V6(Ipv6Addr::LOCALHOST),
                prefix_length: 128,
                flags: None,
            }),
            Allowed::V6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 128)
        );
    }
}
