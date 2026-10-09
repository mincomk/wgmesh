use std::collections::BTreeSet;

use crate::{Allowed, DeviceId, PeerSpec};

pub const CATCH_ALL: [Allowed; 2] = [Allowed::V4([0, 0, 0, 0], 0), Allowed::V6([0; 16], 0)];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AllowedIpsPolicy {
    Peer,
    Any,
    ExitPeer(DeviceId),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RouteTable {
    Unmanaged,
    Main,
    Number(u32),
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum RoutePrefixes {
    Auto,
    None,
    Only(Vec<Allowed>),
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RouteSpec {
    pub prefix: Allowed,
    pub table: RouteTable,
    pub metric: Option<u32>,
}

impl RouteSpec {
    pub fn new(prefix: Allowed, table: RouteTable, metric: Option<u32>) -> Self {
        Self {
            prefix,
            table,
            metric,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum RouteChange {
    Add(RouteSpec),
    Remove(RouteSpec),
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum RoutingError {
    CatchAllPrefix(Allowed),
    AnyPolicyNeedsOnePeer(usize),
    UnknownExitPeer(DeviceId),
    PrefixesWithUnmanagedTable(usize),
}

/// Whether this prefix covers every address, which is what makes it a default route.
///
/// Only the mask decides: the kernel masks the bits past the prefix length before it looks
/// at them, so `10.0.0.0/0` is the same route as `0.0.0.0/0`. Reading the host bits as
/// well let a non-canonical spelling through every check that guards the table.
pub fn is_catch_all(prefix: &Allowed) -> bool {
    match prefix {
        Allowed::V4(_, mask) => *mask == 0,
        Allowed::V6(_, mask) => *mask == 0,
    }
}

pub fn validate_route_prefixes(prefixes: &[Allowed]) -> Result<(), RoutingError> {
    match prefixes.iter().find(|prefix| is_catch_all(prefix)) {
        Some(prefix) => Err(RoutingError::CatchAllPrefix(prefix.clone())),
        None => Ok(()),
    }
}

pub fn program_allowed_ips(
    policy: AllowedIpsPolicy,
    peers: &[PeerSpec],
) -> Result<Vec<(DeviceId, Vec<Allowed>)>, RoutingError> {
    match policy {
        AllowedIpsPolicy::Peer => Ok(peers
            .iter()
            .map(|peer| (peer.id, peer.allowed.clone()))
            .collect()),
        AllowedIpsPolicy::Any => {
            if peers.len() != 1 {
                return Err(RoutingError::AnyPolicyNeedsOnePeer(peers.len()));
            }
            Ok(peers
                .iter()
                .map(|peer| (peer.id, CATCH_ALL.to_vec()))
                .collect())
        }
        AllowedIpsPolicy::ExitPeer(exit) => {
            if !peers.iter().any(|peer| peer.id == exit) {
                return Err(RoutingError::UnknownExitPeer(exit));
            }
            Ok(peers
                .iter()
                .map(|peer| {
                    let allowed = if peer.id == exit {
                        CATCH_ALL.to_vec()
                    } else {
                        peer.allowed.clone()
                    };
                    (peer.id, allowed)
                })
                .collect())
        }
    }
}

pub fn desired_routes(
    network: &[Allowed],
    advertised: &[Allowed],
    prefixes: &RoutePrefixes,
    table: RouteTable,
    metric: Option<u32>,
) -> Result<Vec<RouteSpec>, RoutingError> {
    let selected: BTreeSet<Allowed> = match prefixes {
        RoutePrefixes::Auto => network.iter().chain(advertised).cloned().collect(),
        RoutePrefixes::None => BTreeSet::new(),
        RoutePrefixes::Only(list) => {
            if table == RouteTable::Unmanaged && !list.is_empty() {
                return Err(RoutingError::PrefixesWithUnmanagedTable(list.len()));
            }
            list.iter().cloned().collect()
        }
    };
    validate_route_prefixes(&selected.iter().cloned().collect::<Vec<_>>())?;
    if table == RouteTable::Unmanaged {
        return Ok(Vec::new());
    }
    Ok(selected
        .into_iter()
        .map(|prefix| RouteSpec::new(prefix, table, metric))
        .collect())
}

pub fn plan_routes(desired: &[RouteSpec], installed: &[RouteSpec]) -> Vec<RouteChange> {
    let mut changes = Vec::new();
    for route in desired {
        if !installed.contains(route) {
            changes.push(RouteChange::Add(route.clone()));
        }
    }
    for route in installed {
        if !desired.contains(route) {
            changes.push(RouteChange::Remove(route.clone()));
        }
    }
    changes
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn host(last: u8) -> Allowed {
        Allowed::V4([10, 77, 0, last], 32)
    }

    fn net() -> Allowed {
        Allowed::V4([10, 77, 0, 0], 16)
    }

    fn lan() -> Allowed {
        Allowed::V4([192, 168, 5, 0], 24)
    }

    fn peer(id: u32, allowed: Vec<Allowed>) -> PeerSpec {
        PeerSpec {
            id: DeviceId(id),
            key: crate::PublicKey::from_bytes([id as u8; 32]),
            allowed,
            endpoint: None,
            keepalive: Some(Duration::from_secs(25)),
        }
    }

    fn lookup(assigned: &[(DeviceId, Vec<Allowed>)], id: u32) -> Vec<Allowed> {
        assigned
            .iter()
            .find(|(device, _)| *device == DeviceId(id))
            .map(|(_, allowed)| allowed.clone())
            .expect("peer present")
    }

    #[test]
    fn peer_policy_keeps_each_peer_on_its_own_prefixes() {
        let peers = [peer(1, vec![host(1)]), peer(2, vec![host(2), lan()])];
        let assigned = program_allowed_ips(AllowedIpsPolicy::Peer, &peers).unwrap();
        assert_eq!(lookup(&assigned, 1), vec![host(1)]);
        assert_eq!(lookup(&assigned, 2), vec![host(2), lan()]);
    }

    #[test]
    fn exit_peer_carries_the_catch_all_while_the_mesh_stays_specific() {
        let peers = [peer(1, vec![host(1)]), peer(2, vec![host(2)])];
        let assigned =
            program_allowed_ips(AllowedIpsPolicy::ExitPeer(DeviceId(2)), &peers).unwrap();
        assert_eq!(lookup(&assigned, 1), vec![host(1)]);
        assert_eq!(lookup(&assigned, 2), CATCH_ALL.to_vec());
    }

    #[test]
    fn any_policy_is_only_meaningful_for_a_single_peer() {
        let single = [peer(1, vec![host(1)])];
        let assigned = program_allowed_ips(AllowedIpsPolicy::Any, &single).unwrap();
        assert_eq!(lookup(&assigned, 1), CATCH_ALL.to_vec());

        let mesh = [peer(1, vec![host(1)]), peer(2, vec![host(2)])];
        assert_eq!(
            program_allowed_ips(AllowedIpsPolicy::Any, &mesh),
            Err(RoutingError::AnyPolicyNeedsOnePeer(2))
        );
    }

    #[test]
    fn exit_peer_must_name_a_configured_peer() {
        let peers = [peer(1, vec![host(1)])];
        assert_eq!(
            program_allowed_ips(AllowedIpsPolicy::ExitPeer(DeviceId(9)), &peers),
            Err(RoutingError::UnknownExitPeer(DeviceId(9)))
        );
    }

    #[test]
    fn the_default_route_is_never_installed() {
        assert_eq!(
            validate_route_prefixes(&[net(), Allowed::V4([0, 0, 0, 0], 0)]),
            Err(RoutingError::CatchAllPrefix(Allowed::V4([0, 0, 0, 0], 0)))
        );
        assert_eq!(
            validate_route_prefixes(&[Allowed::V6([0; 16], 0)]),
            Err(RoutingError::CatchAllPrefix(Allowed::V6([0; 16], 0)))
        );
        assert_eq!(
            desired_routes(
                &[net()],
                &[],
                &RoutePrefixes::Only(vec![CATCH_ALL[0].clone()]),
                RouteTable::Main,
                None
            ),
            Err(RoutingError::CatchAllPrefix(Allowed::V4([0, 0, 0, 0], 0)))
        );
        // A mask of zero covers everything whatever the host bits say, so these are the
        // same route written differently and must not reach a table either.
        assert_eq!(
            validate_route_prefixes(&[Allowed::V4([10, 0, 0, 0], 0)]),
            Err(RoutingError::CatchAllPrefix(Allowed::V4([10, 0, 0, 0], 0)))
        );
        assert_eq!(
            validate_route_prefixes(&[Allowed::V6(
                [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                0
            )]),
            Err(RoutingError::CatchAllPrefix(Allowed::V6(
                [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                0
            )))
        );
        assert_eq!(
            desired_routes(
                &[net()],
                &[],
                &RoutePrefixes::Only(vec![Allowed::V4([10, 0, 0, 0], 0)]),
                RouteTable::Main,
                None
            ),
            Err(RoutingError::CatchAllPrefix(Allowed::V4([10, 0, 0, 0], 0)))
        );
    }

    #[test]
    fn auto_prefixes_take_the_network_and_advertised_bands() {
        let routes = desired_routes(
            &[net()],
            &[lan()],
            &RoutePrefixes::Auto,
            RouteTable::Main,
            None,
        )
        .unwrap();
        assert_eq!(
            routes,
            vec![
                RouteSpec::new(net(), RouteTable::Main, None),
                RouteSpec::new(lan(), RouteTable::Main, None),
            ]
        );
    }

    #[test]
    fn only_prefixes_selects_the_band_and_drops_the_rest() {
        let routes = desired_routes(
            &[net()],
            &[lan()],
            &RoutePrefixes::Only(vec![lan()]),
            RouteTable::Main,
            Some(50),
        )
        .unwrap();
        assert_eq!(
            routes,
            vec![RouteSpec::new(lan(), RouteTable::Main, Some(50))]
        );
    }

    #[test]
    fn none_prefixes_and_an_unmanaged_table_install_nothing() {
        assert!(
            desired_routes(
                &[net()],
                &[lan()],
                &RoutePrefixes::None,
                RouteTable::Main,
                None
            )
            .unwrap()
            .is_empty()
        );
        assert!(
            desired_routes(
                &[net()],
                &[lan()],
                &RoutePrefixes::Auto,
                RouteTable::Unmanaged,
                None
            )
            .unwrap()
            .is_empty()
        );
        assert_eq!(
            desired_routes(
                &[net()],
                &[],
                &RoutePrefixes::Only(vec![lan()]),
                RouteTable::Unmanaged,
                None
            ),
            Err(RoutingError::PrefixesWithUnmanagedTable(1))
        );
    }

    #[test]
    fn a_numbered_table_is_carried_into_every_route() {
        let routes = desired_routes(
            &[net()],
            &[],
            &RoutePrefixes::Auto,
            RouteTable::Number(51820),
            None,
        )
        .unwrap();
        assert_eq!(
            routes,
            vec![RouteSpec::new(net(), RouteTable::Number(51820), None)]
        );
    }

    #[test]
    fn plan_routes_adds_and_removes_against_what_is_installed() {
        let wide = RouteSpec::new(net(), RouteTable::Main, None);
        let band = RouteSpec::new(lan(), RouteTable::Main, None);
        assert_eq!(
            plan_routes(&[wide.clone(), band.clone()], std::slice::from_ref(&wide)),
            vec![RouteChange::Add(band.clone())]
        );
        assert_eq!(
            plan_routes(&[], std::slice::from_ref(&wide)),
            vec![RouteChange::Remove(wide.clone())]
        );
        let current = [wide.clone()];
        assert_eq!(
            plan_routes(std::slice::from_ref(&wide), &current),
            Vec::new()
        );
    }
}
