// The five classes a direct endpoint can come from, and the policy that decides
// which of them this node is allowed to synthesise.
//
// `wgmesh_core::rank` already orders candidates: `Lan -> Ipv6 -> Observed ->
// Mapping -> Relay`, freshest first inside one class. What it cannot know is
// where candidates come from. Two of the five classes are derived on this node
// (`Lan`, `Ipv6`), one comes from a router that may not want to talk to us
// (`Mapping`), one is handed over by the relay (`Observed`), and the last is the
// relay itself (`Relay`).
//
// This module is the pure half: sources in, ordered candidates out, with the
// policy applied. Reading the kernel's addresses and asking a router for a
// mapping are port calls and live in `wgmesh-ports` and `wgmesh-app`.

use crate::{Candidate, CandidateKind, Endpoint, Millis, rank};

/// Which candidate classes this node is allowed to synthesise.
///
/// `lan_candidates` and `ipv6` gate the two classes the node derives for itself.
/// `Observed` and `Relay` are deliberately not gateable: the relay-observed
/// address is the path both sides actually agree on, and the relay is the
/// fallback that has to remain whatever else is switched off.
///
/// The defaults are both on. A switch exists for the operator who knows that the
/// LAN candidates are useless (a mesh that is never same-LAN) or that some peer
/// publishes an IPv6 address that does not route, not because either class is
/// risky.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DiscoveryPolicy {
    /// Derive candidates from private addresses on this node's own interfaces.
    pub lan_candidates: bool,
    /// Derive candidates from global IPv6 addresses on this node's interfaces.
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

impl DiscoveryPolicy {
    /// Both classes off. The node still tries the relay-observed address.
    pub const fn observed_only() -> Self {
        Self {
            lan_candidates: false,
            ipv6: false,
        }
    }
}

/// Raw material gathered before policy and ordering.
///
/// Every entry carries the time it was seen, because `rank` breaks ties inside
/// one class by freshness — a class with two entries is a class where the older
/// one may still be the right answer, and only the ordering knows which.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DiscoverySources {
    /// Private addresses on this node's interfaces.
    pub lan: Vec<(Endpoint, Millis)>,
    /// Global IPv6 addresses on this node's interfaces.
    pub ipv6: Vec<(Endpoint, Millis)>,
    /// Addresses a relay observed this node at.
    pub observed: Vec<(Endpoint, Millis)>,
    /// The external address a NAT-PMP or UPnP-IGD mapping handed back.
    pub mapping: Option<(Endpoint, Millis)>,
}

impl DiscoverySources {
    /// Whether anything at all was gathered.
    pub fn is_empty(&self) -> bool {
        self.lan.is_empty()
            && self.ipv6.is_empty()
            && self.observed.is_empty()
            && self.mapping.is_none()
    }
}

/// Turn discovered addresses into candidates, dropping the classes the policy
/// has switched off.
///
/// The result is unordered on purpose — pass it to [`rank`] for the priority
/// order. `discover` answers "which candidates exist", `rank` answers "which one
/// to try", and keeping the two apart means a policy question never has to be
/// answered twice.
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

/// The candidate this node would try next, given sources and policy.
///
/// The relay is appended as the last class rather than special-cased, so the
/// ranking is total: with nothing else discovered, the relay is still the best
/// candidate there is, and a caller never has to ask "what if there is no
/// candidate".
pub fn best_candidate(
    sources: &DiscoverySources,
    policy: DiscoveryPolicy,
    relay: Endpoint,
    relay_seen_at: Millis,
) -> Candidate {
    let fallback = Candidate {
        kind: CandidateKind::Relay,
        endpoint: relay,
        observed_at: relay_seen_at,
    };
    let mut candidates = discover(sources, policy);
    candidates.push(fallback);
    rank(&candidates).into_iter().next().unwrap_or(fallback)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use crate::{CandidateKind, rank};

    fn ep(port: u16) -> Endpoint {
        Endpoint::new(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            port,
        ))
    }

    /// One of every class, each newer than the last, so a wrong order cannot
    /// hide behind equal timestamps.
    fn sources() -> DiscoverySources {
        DiscoverySources {
            lan: vec![(ep(1000), Millis::from_secs(1))],
            ipv6: vec![(ep(1001), Millis::from_secs(2))],
            observed: vec![(ep(1002), Millis::from_secs(3))],
            mapping: Some((ep(1003), Millis::from_secs(4))),
        }
    }

    #[test]
    fn candidates_are_ordered_lan_ipv6_observed_mapping_relay() {
        let mut candidates = discover(&sources(), DiscoveryPolicy::default());
        candidates.push(Candidate {
            kind: CandidateKind::Relay,
            endpoint: ep(9000),
            observed_at: Millis::from_secs(9),
        });
        let ranked = rank(&candidates);
        let kinds: Vec<CandidateKind> = ranked.iter().map(|c| c.kind).collect();
        assert_eq!(
            kinds,
            vec![
                CandidateKind::Lan,
                CandidateKind::Ipv6,
                CandidateKind::Observed,
                CandidateKind::Mapping,
                CandidateKind::Relay,
            ]
        );
    }

    #[test]
    fn within_one_class_the_newest_candidate_comes_first() {
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
    fn the_best_candidate_is_the_first_of_the_order() {
        let best = best_candidate(
            &sources(),
            DiscoveryPolicy::default(),
            ep(9000),
            Millis::from_secs(9),
        );
        assert_eq!(best.kind, CandidateKind::Lan);
        assert_eq!(best.endpoint, ep(1000));
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
            CandidateKind::Lan,
            "and the LAN candidate is still the one it would try"
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
        assert_eq!(candidates.len(), 3);
        assert_eq!(
            best_candidate(&sources(), policy, ep(9000), Millis::ZERO).kind,
            CandidateKind::Ipv6,
            "the next class takes over, it is not skipped"
        );
    }

    #[test]
    fn both_local_classes_off_leaves_the_relay_as_the_best_candidate() {
        // The sources are non-empty on purpose: with an empty fixture this test
        // would pass even if the policy were ignored entirely.
        let sources = DiscoverySources {
            lan: vec![(ep(1000), Millis::from_secs(1))],
            ipv6: vec![(ep(1001), Millis::from_secs(2))],
            ..DiscoverySources::default()
        };
        let policy = DiscoveryPolicy::observed_only();
        assert!(discover(&sources, policy).is_empty());

        let best = best_candidate(&sources, policy, ep(9000), Millis::ZERO);
        assert_eq!(best.kind, CandidateKind::Relay);
        assert_eq!(best.endpoint, ep(9000));
    }

    #[test]
    fn an_observed_address_survives_both_switches_being_off() {
        let sources = DiscoverySources {
            lan: vec![(ep(1000), Millis::from_secs(1))],
            observed: vec![(ep(1002), Millis::from_secs(3))],
            ..DiscoverySources::default()
        };
        let candidates = discover(&sources, DiscoveryPolicy::observed_only());
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].kind, CandidateKind::Observed);
    }
}
