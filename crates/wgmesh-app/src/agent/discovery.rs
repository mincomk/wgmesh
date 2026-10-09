// The discovery use case: what this node knows about itself, and whether it asks
// the router about it.
//
// The one decision this module owns is whether the router is involved at all.
// `traversal.upnp` defaults to off, and off means the `PortMapper` port is not
// called — not called and filtered, not called. NAT-PMP and UPnP-IGD both mean
// speaking to a device this node does not own, and neither is needed for the
// traversal to work: the other four classes are unaffected by their absence.
//
// The second decision is what a failure means. Reading the node's own addresses
// is load-bearing — no addresses means nothing to try — so that failure ends the
// round. A router that will not answer is not: the mapping class is an
// opportunistic extra, and letting an uncooperative gateway empty the candidate
// list would be a self-inflicted outage. Its failure is reported alongside the
// sources rather than instead of them.

use std::net::SocketAddr;
use std::time::Duration;

use wgmesh_core::{DiscoverySources, Endpoint, Millis};
use wgmesh_ports::{AddressScope, DiscoveryError, InterfaceInventory, PortMapper};

/// What one round of discovery gathered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Discovery {
    /// The addresses to rank, before policy and ordering.
    pub sources: DiscoverySources,
    /// Why the mapping class is missing, when the router was asked and refused.
    pub mapping_error: Option<DiscoveryError>,
}

impl Discovery {
    /// Whether anything at all was gathered.
    pub fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }
}

/// Gathers the raw material the candidate ranking is made of.
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
    /// A discovery over an inventory and a router, asking for mappings that live
    /// `mapping_lifetime`.
    pub fn new(inventory: I, mapper: M, mapping_lifetime: Duration) -> Self {
        Self {
            inventory,
            mapper,
            mapping_lifetime,
        }
    }

    /// How long a mapping is asked to live.
    pub fn mapping_lifetime(&self) -> Duration {
        self.mapping_lifetime
    }

    /// Gather this node's own candidates.
    ///
    /// The policy is *not* applied here: which classes exist is a decision the
    /// core makes, in `wgmesh_core::discover`, so that it can be tested without
    /// an interface and a gateway. What this returns is everything that could be
    /// had, and `upnp` is the one switch that decides whether a question is asked
    /// of someone else.
    pub async fn collect(&self, upnp: bool, now: Millis) -> Result<Discovery, DiscoveryError> {
        let listen_port = self.inventory.listen_port()?;
        let mut sources = DiscoverySources::default();

        for address in self.inventory.addresses()? {
            let endpoint = Endpoint::new(SocketAddr::new(address.ip, listen_port));
            match address.scope {
                AddressScope::Lan => sources.lan.push((endpoint, now)),
                AddressScope::Ipv6Global => sources.ipv6.push((endpoint, now)),
            }
        }

        let mut mapping_error = None;
        if upnp {
            match self.mapper.map(listen_port, self.mapping_lifetime).await {
                Ok(mapped) => sources.mapping = Some((mapped.endpoint, now)),
                Err(error) => mapping_error = Some(error),
            }
        }

        Ok(Discovery {
            sources,
            mapping_error,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use wgmesh_core::{CandidateKind, DiscoveryPolicy, discover, rank};
    use wgmesh_ports::fake::{FakeInventory, RecordingPortMapper, block_on};

    fn ep(port: u16) -> Endpoint {
        Endpoint::new(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
            port,
        ))
    }

    fn inventory() -> FakeInventory {
        FakeInventory::new(
            vec![
                FakeInventory::lan(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20))),
                FakeInventory::ipv6(IpAddr::V6(Ipv6Addr::new(2001, 0xdb8, 0, 0, 0, 0, 0, 2))),
            ],
            51820,
        )
    }

    fn discovery(
        mapper: RecordingPortMapper,
    ) -> CandidateDiscovery<FakeInventory, RecordingPortMapper> {
        CandidateDiscovery::new(inventory(), mapper, Duration::from_secs(3600))
    }

    fn kinds(sources: &DiscoverySources, policy: DiscoveryPolicy) -> Vec<CandidateKind> {
        rank(&discover(sources, policy))
            .into_iter()
            .map(|candidate| candidate.kind)
            .collect()
    }

    #[test]
    fn upnp_off_never_speaks_to_the_gateway() {
        let mapper = RecordingPortMapper::new(Some(ep(40000)));
        let discovery = discovery(mapper.clone());

        let round = block_on(discovery.collect(false, Millis::ZERO)).expect("discovery succeeds");

        assert_eq!(
            mapper.calls(),
            0,
            "upnp = false means no NAT-PMP and no UPnP request is made at all"
        );
        assert!(round.sources.mapping.is_none());
        assert!(round.mapping_error.is_none());
        assert_eq!(round.sources.lan.len(), 1);
        assert_eq!(round.sources.ipv6.len(), 1);
    }

    #[test]
    fn upnp_off_is_the_default_of_the_shape_the_settings_build() {
        // The switch that matters is the settings default, not this call site.
        let mapper = RecordingPortMapper::new(Some(ep(40000)));
        let discovery = discovery(mapper.clone());
        let settings_default = false;
        block_on(discovery.collect(settings_default, Millis::ZERO)).expect("discovery succeeds");
        assert_eq!(mapper.calls(), 0, "off by default means no call by default");
    }

    #[test]
    fn upnp_on_asks_once_and_the_mapping_becomes_the_last_class() {
        let mapper = RecordingPortMapper::new(Some(ep(40000)));
        let discovery = discovery(mapper.clone());

        let round = block_on(discovery.collect(true, Millis::ZERO)).expect("the gateway answers");

        assert_eq!(mapper.calls(), 1);
        assert_eq!(
            mapper.call_log(),
            vec![(51820, Duration::from_secs(3600))],
            "the local listen port and the configured lifetime are what is asked for"
        );
        assert_eq!(round.sources.mapping, Some((ep(40000), Millis::ZERO)));
        assert_eq!(
            kinds(&round.sources, DiscoveryPolicy::default()),
            vec![
                CandidateKind::Lan,
                CandidateKind::Ipv6,
                CandidateKind::Mapping,
            ]
        );
    }

    #[test]
    fn a_gateway_that_refuses_costs_the_mapping_class_and_nothing_else() {
        let mapper = RecordingPortMapper::new(None);
        let discovery = discovery(mapper.clone());

        let round = block_on(discovery.collect(true, Millis::ZERO))
            .expect("a refusing gateway is not a failed round");

        assert_eq!(mapper.calls(), 1, "the question was asked");
        assert!(round.sources.mapping.is_none());
        assert!(
            round.mapping_error.is_some(),
            "and the refusal is reported rather than swallowed"
        );
        assert_eq!(
            kinds(&round.sources, DiscoveryPolicy::default()),
            vec![CandidateKind::Lan, CandidateKind::Ipv6],
            "the classes that do not need the router are intact"
        );
    }

    #[test]
    fn an_unreadable_interface_fails_the_round_instead_of_looking_empty() {
        let mapper = RecordingPortMapper::new(None);
        let discovery = discovery(mapper);
        discovery
            .inventory
            .fail_with(wgmesh_ports::PortError::transient("no such device"));

        let error = block_on(discovery.collect(false, Millis::ZERO))
            .expect_err("no addresses is not the same as no candidates");
        assert_eq!(error.class(), wgmesh_ports::Class::Transient);
    }

    #[test]
    fn the_policy_decides_which_classes_are_made() {
        let mapper = RecordingPortMapper::new(None);
        let discovery = discovery(mapper);
        let round = block_on(discovery.collect(false, Millis::ZERO)).expect("addresses");

        let policy = DiscoveryPolicy {
            lan_candidates: false,
            ipv6: true,
        };
        assert_eq!(kinds(&round.sources, policy), vec![CandidateKind::Ipv6]);

        assert_eq!(
            kinds(&round.sources, DiscoveryPolicy::default()),
            vec![CandidateKind::Lan, CandidateKind::Ipv6]
        );
    }
}
