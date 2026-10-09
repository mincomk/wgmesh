use crate::{Candidate, CandidateKind, Endpoint, Millis, rank};

/// Which candidate classes the agent is allowed to synthesise.
///
/// `lan_candidates` and `ipv6` gate the local, self-derived classes. The
/// `Observed` (relay-observed) and `Relay` classes are not gateable: a relay
/// observation is the primary path both sides actually agree on, and the relay
/// itself is the fallback that must always remain.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DiscoveryPolicy {
    pub lan_candidates: bool,
    pub ipv6: bool,
}

impl Default for DiscoveryPolicy {
    fn default() -> Self {
        Self {
            lan_candidates: true,
            ipv6: true,
        }
    }
}

/// Raw material gathered by the adapters, before policy and ordering.
///
/// Every entry carries the time it was seen so that `rank` can break ties
/// inside one class by freshness.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DiscoverySources {
    pub lan: Vec<(Endpoint, Millis)>,
    pub ipv6: Vec<(Endpoint, Millis)>,
    pub observed: Vec<(Endpoint, Millis)>,
    pub mapping: Option<(Endpoint, Millis)>,
}

/// Turn discovered addresses into candidates, dropping the classes the policy
/// has switched off.
///
/// The result is unordered: pass it to `rank` for the priority order
/// `Lan -> Ipv6 -> Observed -> Mapping -> Relay`, freshest first within a class.
pub fn discover(sources: &DiscoverySources, policy: DiscoveryPolicy) -> Vec<Candidate> {
    let mut out = Vec::new();
    if policy.lan_candidates {
        out.extend(sources.lan.iter().map(|(endpoint, at)| Candidate {
            kind: CandidateKind::Lan,
            endpoint: *endpoint,
            observed_at: *at,
        }));
    }
    if policy.ipv6 {
        out.extend(sources.ipv6.iter().map(|(endpoint, at)| Candidate {
            kind: CandidateKind::Ipv6,
            endpoint: *endpoint,
            observed_at: *at,
        }));
    }
    out.extend(sources.observed.iter().map(|(endpoint, at)| Candidate {
        kind: CandidateKind::Observed,
        endpoint: *endpoint,
        observed_at: *at,
    }));
    if let Some((endpoint, at)) = sources.mapping {
        out.push(Candidate {
            kind: CandidateKind::Mapping,
            endpoint,
            observed_at: at,
        });
    }
    out
}

/// The candidate an agent would try next, given sources and policy.
///
/// `relay` is appended as the last-resort candidate so the ranking is total:
/// with no other candidate the relay is still the best one.
pub fn best_candidate(
    sources: &DiscoverySources,
    policy: DiscoveryPolicy,
    relay: Endpoint,
    relay_seen_at: Millis,
) -> Candidate {
    let mut candidates = discover(sources, policy);
    candidates.push(Candidate {
        kind: CandidateKind::Relay,
        endpoint: relay,
        observed_at: relay_seen_at,
    });
    rank(&candidates).into_iter().next().unwrap_or(Candidate {
        kind: CandidateKind::Relay,
        endpoint: relay,
        observed_at: relay_seen_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use crate::CandidateKind;

    fn ep(port: u16) -> Endpoint {
        Endpoint::new(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            port,
        ))
    }

    fn sources() -> DiscoverySources {
        DiscoverySources {
            lan: vec![(ep(1000), Millis::from_secs(1))],
            ipv6: vec![(ep(1001), Millis::from_secs(2))],
            observed: vec![(ep(1002), Millis::from_secs(3))],
            mapping: Some((ep(1003), Millis::from_secs(4))),
        }
    }

    #[test]
    fn candidates_are_ordered_lan_then_ipv6_then_observed_then_mapping_then_relay() {
        let ordered = rank(&discover(&sources(), DiscoveryPolicy::default()));
        let kinds: Vec<CandidateKind> = ordered.iter().map(|c| c.kind).collect();
        assert_eq!(
            kinds,
            vec![
                CandidateKind::Lan,
                CandidateKind::Ipv6,
                CandidateKind::Observed,
                CandidateKind::Mapping,
            ]
        );

        let best = best_candidate(
            &sources(),
            DiscoveryPolicy::default(),
            ep(9000),
            Millis::from_secs(9),
        );
        assert_eq!(best.kind, CandidateKind::Lan);

        let mut with_relay = discover(&sources(), DiscoveryPolicy::default());
        with_relay.push(Candidate {
            kind: CandidateKind::Relay,
            endpoint: ep(9000),
            observed_at: Millis::from_secs(9),
        });
        let ranked = rank(&with_relay);
        assert_eq!(ranked[4].kind, CandidateKind::Relay);
    }

    #[test]
    fn within_one_class_the_newest_candidate_wins() {
        let sources = DiscoverySources {
            observed: vec![
                (ep(2001), Millis::from_secs(5)),
                (ep(2002), Millis::from_secs(30)),
                (ep(2003), Millis::from_secs(11)),
            ],
            ..DiscoverySources::default()
        };
        let ranked = rank(&discover(&sources, DiscoveryPolicy::default()));
        let ports: Vec<u16> = ranked.iter().map(|c| c.endpoint.addr().port()).collect();
        assert_eq!(ports, vec![2002, 2003, 2001]);
    }

    #[test]
    fn ipv6_off_produces_no_ipv6_candidate() {
        let policy = DiscoveryPolicy {
            ipv6: false,
            ..DiscoveryPolicy::default()
        };
        let candidates = discover(&sources(), policy);
        assert!(
            candidates.iter().all(|c| c.kind != CandidateKind::Ipv6),
            "ipv6 = false must not synthesise an Ipv6 candidate"
        );
        assert_eq!(candidates.len(), 3);
        assert_eq!(
            best_candidate(&sources(), policy, ep(9000), Millis::ZERO).kind,
            CandidateKind::Lan
        );
    }

    #[test]
    fn lan_off_drops_the_lan_candidate() {
        let policy = DiscoveryPolicy {
            lan_candidates: false,
            ..DiscoveryPolicy::default()
        };
        let candidates = discover(&sources(), policy);
        assert!(
            candidates.iter().all(|c| c.kind != CandidateKind::Lan),
            "lan_candidates = false must drop the Lan candidate"
        );
        let best = best_candidate(&sources(), policy, ep(9000), Millis::ZERO);
        assert_eq!(best.kind, CandidateKind::Ipv6);
    }

    #[test]
    fn both_local_classes_off_leaves_the_relay_as_the_best_candidate() {
        let policy = DiscoveryPolicy {
            lan_candidates: false,
            ipv6: false,
        };
        let best = best_candidate(&DiscoverySources::default(), policy, ep(9000), Millis::ZERO);
        assert_eq!(best.kind, CandidateKind::Relay);
        assert_eq!(best.endpoint, ep(9000));
    }

    #[test]
    fn no_mapping_source_produces_no_mapping_candidate() {
        let sources = DiscoverySources {
            mapping: None,
            ..sources()
        };
        let candidates = discover(&sources, DiscoveryPolicy::default());
        assert!(candidates.iter().all(|c| c.kind != CandidateKind::Mapping));
    }
}
