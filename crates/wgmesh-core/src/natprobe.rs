use std::net::SocketAddr;

/// A probe that tells us how our own mapping behaves: we sent from one local
/// socket to `server`, and `observed` is the source address that server saw us
/// come from. The external port is what a peer would have to aim at.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MappingProbe {
    pub server: SocketAddr,
    pub observed: SocketAddr,
}

/// RFC 4787 §4.1 — how the NAT picks the external port.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mapping {
    /// The same external port whatever we talk to. Hole punching works.
    EndpointIndependent,
    /// The external port depends on the destination address.
    AddressDependent,
    /// The external port depends on the destination address and port —
    /// the "symmetric" case, where an observed port is useless to a peer.
    AddressAndPortDependent,
    /// Not enough probes to say.
    Unknown,
}

/// RFC 4787 §5.1 — what the NAT lets back in.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Filtering {
    /// Anything aimed at our mapping arrives. The easiest case.
    EndpointIndependent,
    /// Only from an address we have sent to.
    AddressDependent,
    /// Only from the exact address and port we have sent to — the classic
    /// "restricted" case, where both sides must fire at once.
    AddressAndPortDependent,
    Unknown,
}

/// What a filtering probe did: we had the probe server send us something from
/// an endpoint we had (or had not) contacted first.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FilterProbe {
    /// A reply from the server we actually queried.
    SameEndpoint { delivered: bool },
    /// A packet from a different address of that server, which we never
    /// contacted.
    DifferentAddress { delivered: bool },
    /// A packet from the same address but a different port, which we never
    /// contacted.
    DifferentPort { delivered: bool },
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Profile {
    pub mapping: Mapping,
    pub filtering: Filtering,
}

impl Profile {
    /// Whether a direct WireGuard path has a realistic chance, which is what
    /// `wgmesh doctor` tells the operator before they spend time on it.
    pub const fn punch_plausible(self) -> bool {
        !matches!(
            self.mapping,
            Mapping::AddressAndPortDependent | Mapping::Unknown
        ) && !matches!(self.filtering, Filtering::Unknown)
    }

    pub fn summary(self) -> String {
        format!(
            "mapping {}, filtering {}{}",
            describe_mapping(self.mapping),
            describe_filtering(self.filtering),
            if self.punch_plausible() {
                ""
            } else {
                " — expect the relay to carry this peer"
            }
        )
    }
}

pub fn describe_mapping(mapping: Mapping) -> &'static str {
    match mapping {
        Mapping::EndpointIndependent => "endpoint-independent (cone)",
        Mapping::AddressDependent => "address-dependent",
        Mapping::AddressAndPortDependent => "address-and-port-dependent (symmetric)",
        Mapping::Unknown => "unknown",
    }
}

pub fn describe_filtering(filtering: Filtering) -> &'static str {
    match filtering {
        Filtering::EndpointIndependent => "endpoint-independent (cone)",
        Filtering::AddressDependent => "address-dependent",
        Filtering::AddressAndPortDependent => "address-and-port-dependent (restricted)",
        Filtering::Unknown => "unknown",
    }
}

/// Classify the mapping behaviour from probes aimed at different servers.
///
/// Endpoint-independent mapping is shown by the same external port everywhere.
/// When the ports differ we need two probes to the *same* server address on
/// different ports to separate "depends on the address" from "depends on the
/// address and the port": if those two come back with different external ports,
/// the port is part of the key too. With only different-address probes we
/// report the weaker of the two conclusions.
pub fn classify_mapping(probes: &[MappingProbe]) -> Mapping {
    if probes.len() < 2 {
        return Mapping::Unknown;
    }
    let first = probes[0].observed.port();
    if probes.iter().all(|probe| probe.observed.port() == first) {
        return Mapping::EndpointIndependent;
    }
    let mut address_paired = false;
    for (index, left) in probes.iter().enumerate() {
        for right in probes.iter().skip(index + 1) {
            if left.server.ip() == right.server.ip() && left.server.port() != right.server.port() {
                address_paired = true;
                if left.observed.port() != right.observed.port() {
                    return Mapping::AddressAndPortDependent;
                }
            }
        }
    }
    if address_paired {
        return Mapping::AddressDependent;
    }
    // Ports differ between different destinations, but we never probed one
    // destination on two ports, so we cannot rule out that the port is keyed on
    // the destination port as well. The weaker claim is the honest one.
    Mapping::AddressDependent
}

/// Classify the filtering behaviour from probes the server made back at us.
pub fn classify_filtering(probes: &[FilterProbe]) -> Filtering {
    if probes.is_empty() {
        return Filtering::Unknown;
    }
    let delivered = |wanted: fn(&FilterProbe) -> Option<bool>| {
        probes.iter().filter_map(wanted).any(|value| value)
    };
    let same_endpoint = delivered(|probe| match probe {
        FilterProbe::SameEndpoint { delivered } => Some(*delivered),
        _ => None,
    });
    let different_address = delivered(|probe| match probe {
        FilterProbe::DifferentAddress { delivered } => Some(*delivered),
        _ => None,
    });
    let different_port = delivered(|probe| match probe {
        FilterProbe::DifferentPort { delivered } => Some(*delivered),
        _ => None,
    });

    if different_address {
        Filtering::EndpointIndependent
    } else if different_port {
        Filtering::AddressDependent
    } else if same_endpoint {
        Filtering::AddressAndPortDependent
    } else {
        // Nothing got through at all; the mapping is unusable, which is worse
        // than any of the three grades.
        Filtering::Unknown
    }
}

pub fn classify(probes: &[MappingProbe], filter: &[FilterProbe]) -> Profile {
    Profile {
        mapping: classify_mapping(probes),
        filtering: classify_filtering(filter),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn addr(ip: [u8; 4], port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port)
    }

    fn probe(server: ([u8; 4], u16), observed_port: u16) -> MappingProbe {
        MappingProbe {
            server: addr(server.0, server.1),
            observed: addr([198, 51, 100, 9], observed_port),
        }
    }

    #[test]
    fn one_probe_is_not_enough() {
        assert_eq!(
            classify_mapping(&[probe(([192, 0, 2, 1], 3478), 40000)]),
            Mapping::Unknown
        );
    }

    #[test]
    fn the_same_external_port_for_two_servers_is_a_cone() {
        let probes = [
            probe(([192, 0, 2, 1], 3478), 40000),
            probe(([198, 51, 100, 2], 3478), 40000),
        ];
        assert_eq!(classify_mapping(&probes), Mapping::EndpointIndependent);
        assert_eq!(
            classify(&probes, &[FilterProbe::SameEndpoint { delivered: true }]).filtering,
            Filtering::AddressAndPortDependent
        );
    }

    #[test]
    fn different_ports_for_two_different_addresses_is_address_dependent() {
        let probes = [
            probe(([192, 0, 2, 1], 3478), 40000),
            probe(([198, 51, 100, 2], 3478), 40001),
        ];
        assert_eq!(classify_mapping(&probes), Mapping::AddressDependent);
    }

    #[test]
    fn different_ports_for_one_address_on_two_ports_is_symmetric() {
        let probes = [
            probe(([192, 0, 2, 1], 3478), 40000),
            probe(([192, 0, 2, 1], 5349), 40001),
        ];
        assert_eq!(classify_mapping(&probes), Mapping::AddressAndPortDependent);
    }

    #[test]
    fn same_port_for_one_address_on_two_ports_stays_address_dependent() {
        let probes = [
            probe(([192, 0, 2, 1], 3478), 40000),
            probe(([192, 0, 2, 1], 5349), 40000),
            probe(([198, 51, 100, 2], 3478), 40001),
        ];
        assert_eq!(classify_mapping(&probes), Mapping::AddressDependent);
    }

    #[test]
    fn a_reply_from_an_uncontacted_address_means_endpoint_independent_filtering() {
        assert_eq!(
            classify_filtering(&[FilterProbe::DifferentAddress { delivered: true }]),
            Filtering::EndpointIndependent
        );
    }

    #[test]
    fn a_reply_only_from_a_new_port_of_a_known_address_is_address_dependent() {
        assert_eq!(
            classify_filtering(&[
                FilterProbe::SameEndpoint { delivered: true },
                FilterProbe::DifferentAddress { delivered: false },
                FilterProbe::DifferentPort { delivered: true },
            ]),
            Filtering::AddressDependent
        );
    }

    #[test]
    fn a_reply_only_from_the_contacted_endpoint_is_restricted() {
        assert_eq!(
            classify_filtering(&[
                FilterProbe::SameEndpoint { delivered: true },
                FilterProbe::DifferentAddress { delivered: false },
                FilterProbe::DifferentPort { delivered: false },
            ]),
            Filtering::AddressAndPortDependent
        );
    }

    #[test]
    fn nothing_delivered_is_unknown_rather_than_a_grade() {
        assert_eq!(
            classify_filtering(&[FilterProbe::SameEndpoint { delivered: false }]),
            Filtering::Unknown
        );
    }

    #[test]
    fn a_symmetric_nat_is_reported_as_relay_territory() {
        let profile = classify(
            &[
                probe(([192, 0, 2, 1], 3478), 40000),
                probe(([192, 0, 2, 1], 5349), 40001),
            ],
            &[FilterProbe::SameEndpoint { delivered: true }],
        );
        assert!(!profile.punch_plausible());
        assert!(profile.summary().contains("symmetric"));
        assert!(profile.summary().contains("relay"));
    }

    #[test]
    fn a_cone_behind_restricted_filtering_is_still_punchable() {
        let profile = classify(
            &[
                probe(([192, 0, 2, 1], 3478), 40000),
                probe(([198, 51, 100, 2], 3478), 40000),
            ],
            &[
                FilterProbe::SameEndpoint { delivered: true },
                FilterProbe::DifferentAddress { delivered: false },
                FilterProbe::DifferentPort { delivered: false },
            ],
        );
        assert!(profile.punch_plausible());
    }
}
