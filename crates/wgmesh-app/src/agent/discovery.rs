use std::net::SocketAddr;
use std::time::Duration;

use wgmesh_core::{DiscoveryPolicy, DiscoverySources, Endpoint, Millis};
use wgmesh_ports::{AddressScope, DiscoveryError, InterfaceInventory, PortMapper};

/// Gathers the raw material for candidate ranking.
///
/// The one decision this use case owns is whether the router is involved at
/// all. `upnp` defaults to off, and off means the port mapper is never called:
/// NAT-PMP and UPnP-IGD both mean talking to a device we do not control, and
/// neither is required for the traversal to work.
pub struct CandidateDiscovery<I, M> {
    inventory: I,
    mapper: M,
    mapping_lifetime: Duration,
}

impl<I, M> CandidateDiscovery<I, M>
where
    I: InterfaceInventory,
    M: PortMapper,
{
    pub fn new(inventory: I, mapper: M, mapping_lifetime: Duration) -> Self {
        Self {
            inventory,
            mapper,
            mapping_lifetime,
        }
    }

    pub fn mapping_lifetime(&self) -> Duration {
        self.mapping_lifetime
    }

    pub async fn collect(
        &self,
        policy: DiscoveryPolicy,
        upnp: bool,
        now: Millis,
    ) -> Result<DiscoverySources, DiscoveryError> {
        let listen_port = self.inventory.listen_port()?;
        let mut sources = DiscoverySources::default();

        for address in self.inventory.addresses()? {
            let endpoint = Endpoint::new(SocketAddr::new(address.ip, listen_port));
            match address.scope {
                AddressScope::Lan => sources.lan.push((endpoint, now)),
                AddressScope::Ipv6Global => sources.ipv6.push((endpoint, now)),
            }
        }

        if upnp {
            let mapped = self.mapper.map(listen_port, self.mapping_lifetime).await?;
            sources.mapping = Some((mapped.endpoint, now));
        }

        let _ = policy;
        Ok(sources)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use wgmesh_core::{DiscoveryPolicy, discover, rank};
    use wgmesh_testkit::{FakeInventory, RecordingPortMapper, block_on};

    fn ep(port: u16) -> Endpoint {
        Endpoint::new(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            port,
        ))
    }

    fn inventory() -> FakeInventory {
        FakeInventory::new(
            vec![
                FakeInventory::lan(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20))),
                FakeInventory::ipv6(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            ],
            51820,
        )
    }

    fn discovery(
        mapper: RecordingPortMapper,
    ) -> CandidateDiscovery<FakeInventory, RecordingPortMapper> {
        CandidateDiscovery::new(inventory(), mapper, Duration::from_secs(3600))
    }

    #[test]
    fn upnp_off_never_touches_the_port_mapper() {
        let mapper = RecordingPortMapper::new(Some(ep(40000)));
        let discovery = discovery(mapper.clone());

        let sources = block_on(discovery.collect(DiscoveryPolicy::default(), false, Millis::ZERO))
            .expect("discovery without a port mapper must succeed");

        assert_eq!(
            mapper.calls(),
            0,
            "upnp = false means no NAT-PMP and no UPnP request is made at all"
        );
        assert!(sources.mapping.is_none());
        assert_eq!(sources.lan.len(), 1);
        assert_eq!(sources.ipv6.len(), 1);
    }

    #[test]
    fn upnp_on_asks_the_gateway_once_and_keeps_the_mapped_port() {
        let mapper = RecordingPortMapper::new(Some(ep(40000)));
        let discovery = discovery(mapper.clone());

        let sources = block_on(discovery.collect(DiscoveryPolicy::default(), true, Millis::ZERO))
            .expect("the fake gateway answers");

        assert_eq!(mapper.calls(), 1);
        assert_eq!(mapper.call_log(), vec![(51820, Duration::from_secs(3600))]);
        assert_eq!(sources.mapping, Some((ep(40000), Millis::ZERO)));
        assert_eq!(
            rank(&discover(&sources, DiscoveryPolicy::default()))
                .into_iter()
                .map(|candidate| candidate.kind)
                .collect::<Vec<_>>(),
            vec![
                wgmesh_core::CandidateKind::Lan,
                wgmesh_core::CandidateKind::Ipv6,
                wgmesh_core::CandidateKind::Mapping,
            ]
        );
    }

    #[test]
    fn a_failing_gateway_fails_the_round_rather_than_silently_dropping_the_class() {
        let mapper = RecordingPortMapper::new(None);
        let discovery = discovery(mapper.clone());
        assert!(
            block_on(discovery.collect(DiscoveryPolicy::default(), true, Millis::ZERO)).is_err()
        );
        assert_eq!(mapper.calls(), 1);
    }

    #[test]
    fn the_policy_decides_which_classes_are_made() {
        let mapper = RecordingPortMapper::new(None);
        let discovery = discovery(mapper);
        let policy = DiscoveryPolicy {
            lan_candidates: false,
            ipv6: true,
        };
        let sources = block_on(discovery.collect(policy, false, Millis::ZERO)).expect("addresses");
        let kinds: Vec<wgmesh_core::CandidateKind> = rank(&discover(&sources, policy))
            .into_iter()
            .map(|candidate| candidate.kind)
            .collect();
        assert_eq!(kinds, vec![wgmesh_core::CandidateKind::Ipv6]);
    }
}
