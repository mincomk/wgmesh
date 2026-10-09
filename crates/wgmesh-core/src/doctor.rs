use crate::Allowed;
use crate::route::{RoutePrefixes, RouteTable, is_catch_all};

/// Whether `inner` lies inside `outer`. Address families never contain each
/// other.
pub fn contains(outer: &Allowed, inner: &Allowed) -> bool {
    match (outer, inner) {
        (Allowed::V4(mine, my_bits), Allowed::V4(theirs, their_bits)) => {
            my_bits <= their_bits && prefix_matches(mine, theirs, *my_bits)
        }
        (Allowed::V6(mine, my_bits), Allowed::V6(theirs, their_bits)) => {
            my_bits <= their_bits && prefix_matches(mine, theirs, *my_bits)
        }
        _ => false,
    }
}

fn prefix_matches(mine: &[u8], theirs: &[u8], bits: u8) -> bool {
    let whole = usize::from(bits / 8);
    let rest = bits % 8;
    if mine[..whole] != theirs[..whole] {
        return false;
    }
    if rest == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - rest);
    mine[whole] & mask == theirs[whole] & mask
}

/// Render a prefix the way an operator writes it, which is the form the
/// messages in a report have to use to be worth reading.
pub fn format_prefix(prefix: &Allowed) -> String {
    match prefix {
        Allowed::V4(octets, bits) => format!(
            "{}.{}.{}.{}/{}",
            octets[0], octets[1], octets[2], octets[3], bits
        ),
        Allowed::V6(octets, bits) => {
            let groups: Vec<String> = (0..8)
                .map(|index| {
                    format!(
                        "{:x}",
                        u16::from_be_bytes([octets[index * 2], octets[index * 2 + 1]])
                    )
                })
                .collect();
            format!("{}/{}", groups.join(":"), bits)
        }
    }
}

/// One peer as the node would program it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DoctorPeer {
    pub name: String,
    /// AllowedIPs programmed for this peer (cryptokey routing), not routes.
    pub allowed: Vec<Allowed>,
    /// Bands the coordinator says this peer carries, beyond its tunnel address.
    pub advertised: Vec<Allowed>,
    /// This peer's tunnel address.
    pub tunnel: Option<Allowed>,
}

/// Everything the routing and forwarding checks read. The caller gathers it —
/// from a config file, a state file, a coordinator snapshot and the kernel — so
/// the checks themselves need no kernel, no network and no filesystem.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DoctorInputs {
    pub route_table: RouteTable,
    pub prefixes: RoutePrefixes,
    pub peers: Vec<DoctorPeer>,
    /// Bands the coordinator gave this network.
    pub network: Vec<Allowed>,
    /// This node's own tunnel prefix.
    pub local_tunnel: Option<Allowed>,
    pub forwarding_enabled: bool,
    /// `net.ipv4.ip_forward`, or `None` when it could not be read.
    pub ipv4_forward: Option<bool>,
    /// `net.ipv6.conf.all.forwarding`, or `None` when it could not be read.
    pub ipv6_forward: Option<bool>,
}

impl DoctorInputs {
    /// The bands a correct node wants a route for: the network plus every band
    /// its peers advertise.
    pub fn desired_prefixes(&self) -> Vec<Allowed> {
        let mut wanted = self.network.clone();
        for peer in &self.peers {
            for prefix in &peer.advertised {
                if !wanted.contains(prefix) {
                    wanted.push(prefix.clone());
                }
            }
        }
        wanted
    }

    /// The bands a route to a peer may legitimately point at.
    fn reachable_bands(&self) -> Vec<Allowed> {
        let mut bands = self.desired_prefixes();
        bands.extend(self.local_tunnel.clone());
        for peer in &self.peers {
            bands.extend(peer.tunnel.clone());
        }
        bands
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Severity {
    Error,
    Warning,
    Info,
}

impl Severity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Severity::Error => "error",
            Severity::Warning => "warning",
            Severity::Info => "info",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Code {
    /// Routes are wanted but the routing table is unmanaged.
    RoutesNeededButTableOff,
    /// `table = "off"` together with an explicit prefix list.
    PrefixesWithUnmanagedTable,
    /// A catch-all is programmed for more than one peer.
    CatchAllOnMultiplePeers,
    /// Forwarding is on while the kernel refuses to forward.
    ForwardingEnabledWithoutIpForward,
    /// A configured prefix lies outside everything the coordinator handed out.
    PrefixesOutsideCoordinatorBands,
    /// A configured prefix is a default route.
    CatchAllPrefix,
}

impl Code {
    pub const fn as_str(self) -> &'static str {
        match self {
            Code::RoutesNeededButTableOff => "routes-needed-but-table-off",
            Code::PrefixesWithUnmanagedTable => "prefixes-with-unmanaged-table",
            Code::CatchAllOnMultiplePeers => "catch-all-on-multiple-peers",
            Code::ForwardingEnabledWithoutIpForward => "forwarding-enabled-without-ip-forward",
            Code::PrefixesOutsideCoordinatorBands => "prefixes-outside-coordinator-bands",
            Code::CatchAllPrefix => "catch-all-prefix",
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Finding {
    pub code: Code,
    pub severity: Severity,
    /// One line, already phrased for a human.
    pub summary: String,
    /// What to do about it.
    pub remedy: String,
}

fn finding(code: Code, severity: Severity, summary: String, remedy: &str) -> Finding {
    Finding {
        code,
        severity,
        summary,
        remedy: remedy.to_owned(),
    }
}

/// Run every routing and forwarding check and return what is wrong.
pub fn diagnose(inputs: &DoctorInputs) -> Vec<Finding> {
    let mut findings = Vec::new();

    if inputs.route_table == RouteTable::Unmanaged && inputs.prefixes != RoutePrefixes::None {
        let wanted = inputs.desired_prefixes();
        if !wanted.is_empty() {
            let list = describe(&wanted);
            findings.push(finding(
                Code::RoutesNeededButTableOff,
                Severity::Warning,
                format!("route.table is \"off\" while {list} needs a route and none is installed"),
                "set route.table = \"main\" (or a table number); leave it off only if another \
                 routing daemon installs these prefixes itself",
            ));
        }
    }

    if inputs.route_table == RouteTable::Unmanaged {
        if let RoutePrefixes::Only(list) = &inputs.prefixes {
            if !list.is_empty() {
                findings.push(finding(
                    Code::PrefixesWithUnmanagedTable,
                    Severity::Error,
                    format!(
                        "route.table = \"off\" contradicts route.prefixes, whose {} entries can \
                         never be installed",
                        list.len()
                    ),
                    "drop the prefix list, or give route.table a managed value",
                ));
            }
        }
    }

    if let RoutePrefixes::Only(list) = &inputs.prefixes {
        if let Some(prefix) = list.iter().find(|prefix| is_catch_all(prefix)) {
            findings.push(finding(
                Code::CatchAllPrefix,
                Severity::Error,
                format!(
                    "route.prefixes contains the default route {}",
                    format_prefix(prefix)
                ),
                "a default route belongs in AllowedIPs (peers.exit_peer), never in the kernel \
                 routing table",
            ));
        }
    }

    let catch_alls: Vec<&DoctorPeer> = inputs
        .peers
        .iter()
        .filter(|peer| peer.allowed.iter().any(is_catch_all))
        .collect();
    if catch_alls.len() > 1 {
        let names = catch_alls
            .iter()
            .map(|peer| peer.name.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        findings.push(finding(
            Code::CatchAllOnMultiplePeers,
            Severity::Error,
            format!(
                "{} peers carry a catch-all AllowedIPs ({names}); only the last one inserted \
                 wins, and it wins silently",
                catch_alls.len()
            ),
            "keep peers.allowed_ips = \"peer\" and name exactly one peers.exit_peer",
        ));
    }

    if inputs.forwarding_enabled {
        if inputs.ipv4_forward == Some(false) {
            findings.push(finding(
                Code::ForwardingEnabledWithoutIpForward,
                Severity::Error,
                "forwarding.enabled = true while net.ipv4.ip_forward is 0".to_owned(),
                "let wgmesh set net.ipv4.ip_forward = 1 (forwarding.sysctl = true), or turn \
                 forwarding off",
            ));
        }
        let peer_carries_v6 = inputs.peers.iter().any(|peer| {
            peer.allowed
                .iter()
                .chain(peer.advertised.iter())
                .any(|prefix| matches!(prefix, Allowed::V6(..)))
        });
        if peer_carries_v6 && inputs.ipv6_forward == Some(false) {
            findings.push(finding(
                Code::ForwardingEnabledWithoutIpForward,
                Severity::Warning,
                "forwarding.enabled = true and a peer carries IPv6 while \
                 net.ipv6.conf.all.forwarding is 0"
                    .to_owned(),
                "set net.ipv6.conf.all.forwarding = 1, or stop advertising IPv6 bands",
            ));
        }
    }

    if let RoutePrefixes::Only(list) = &inputs.prefixes {
        let bands = inputs.reachable_bands();
        let stray: Vec<String> = list
            .iter()
            .filter(|prefix| !bands.iter().any(|band| contains(band, prefix)))
            .map(format_prefix)
            .collect();
        if !stray.is_empty() {
            let advertised: Vec<Allowed> = inputs
                .peers
                .iter()
                .flat_map(|peer| peer.advertised.clone())
                .collect();
            findings.push(finding(
                Code::PrefixesOutsideCoordinatorBands,
                Severity::Error,
                format!(
                    "route.prefixes points at {} which the coordinator never handed out \
                     (network {}; peers advertise {})",
                    stray.join(", "),
                    describe(&inputs.network),
                    describe(&advertised),
                ),
                "correct the prefix, or have the peer advertise the band so the coordinator \
                 hands it out",
            ));
        }
    }

    findings
}

fn describe(prefixes: &[Allowed]) -> String {
    if prefixes.is_empty() {
        return "(nothing)".to_owned();
    }
    prefixes
        .iter()
        .map(format_prefix)
        .collect::<Vec<_>>()
        .join(", ")
}

/// The human-readable lines `wgmesh doctor` prints for a diagnosis.
pub fn render(findings: &[Finding]) -> String {
    if findings.is_empty() {
        return "routing and forwarding: no problems found\n".to_owned();
    }
    let mut out = String::new();
    for item in findings {
        out.push_str(&format!(
            "[{}] {}\n    {} — {}\n",
            item.severity.as_str(),
            item.code.as_str(),
            item.summary,
            item.remedy
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn net() -> Vec<Allowed> {
        vec![Allowed::V4([10, 77, 0, 0], 16)]
    }

    fn host(last: u8) -> Allowed {
        Allowed::V4([10, 77, 0, last], 32)
    }

    fn peer(
        name: &str,
        tunnel: Allowed,
        allowed: Vec<Allowed>,
        advertised: Vec<Allowed>,
    ) -> DoctorPeer {
        DoctorPeer {
            name: name.to_owned(),
            allowed,
            advertised,
            tunnel: Some(tunnel),
        }
    }

    fn healthy() -> DoctorInputs {
        DoctorInputs {
            route_table: RouteTable::Main,
            prefixes: RoutePrefixes::Auto,
            network: net(),
            local_tunnel: Some(Allowed::V4([10, 77, 0, 7], 16)),
            peers: vec![
                peer("b", host(8), vec![host(8)], vec![]),
                peer("c", host(9), vec![host(9)], vec![]),
            ],
            forwarding_enabled: false,
            ipv4_forward: Some(false),
            ipv6_forward: Some(false),
        }
    }

    fn codes(findings: &[Finding]) -> Vec<Code> {
        findings.iter().map(|item| item.code).collect()
    }

    #[test]
    fn a_healthy_node_reports_nothing() {
        assert!(diagnose(&healthy()).is_empty());
    }

    #[test]
    fn an_unmanaged_table_with_routes_to_install_is_caught() {
        let mut inputs = healthy();
        inputs.route_table = RouteTable::Unmanaged;
        assert!(codes(&diagnose(&inputs)).contains(&Code::RoutesNeededButTableOff));
    }

    #[test]
    fn an_unmanaged_table_with_no_route_wanted_is_fine() {
        let mut inputs = healthy();
        inputs.route_table = RouteTable::Unmanaged;
        inputs.prefixes = RoutePrefixes::None;
        inputs.network = vec![];
        inputs.peers = vec![];
        assert!(diagnose(&inputs).is_empty());
    }

    #[test]
    fn an_unmanaged_table_with_an_explicit_prefix_list_is_caught() {
        let mut inputs = healthy();
        inputs.route_table = RouteTable::Unmanaged;
        inputs.prefixes = RoutePrefixes::Only(net());
        assert!(codes(&diagnose(&inputs)).contains(&Code::PrefixesWithUnmanagedTable));
    }

    #[test]
    fn an_unmanaged_table_with_auto_prefixes_only_warns() {
        let mut inputs = healthy();
        inputs.route_table = RouteTable::Unmanaged;
        let findings = diagnose(&inputs);
        assert_eq!(codes(&findings), vec![Code::RoutesNeededButTableOff]);
        assert_eq!(findings[0].severity, Severity::Warning);
    }

    #[test]
    fn a_catch_all_on_two_peers_is_caught() {
        let mut inputs = healthy();
        for peer in &mut inputs.peers {
            peer.allowed = vec![Allowed::V4([0, 0, 0, 0], 0)];
        }
        let findings = diagnose(&inputs);
        assert!(codes(&findings).contains(&Code::CatchAllOnMultiplePeers));
        assert_eq!(findings[0].severity, Severity::Error);
        assert!(findings[0].summary.contains("b, c"));
    }

    #[test]
    fn a_single_catch_all_on_the_exit_peer_is_fine() {
        let mut inputs = healthy();
        inputs.peers[0].allowed = vec![Allowed::V4([0, 0, 0, 0], 0), Allowed::V6([0; 16], 0)];
        assert!(diagnose(&inputs).is_empty());
    }

    #[test]
    fn forwarding_on_with_ip_forward_off_is_caught() {
        let mut inputs = healthy();
        inputs.forwarding_enabled = true;
        inputs.ipv4_forward = Some(false);
        assert!(codes(&diagnose(&inputs)).contains(&Code::ForwardingEnabledWithoutIpForward));
    }

    #[test]
    fn forwarding_on_with_ip_forward_on_is_fine() {
        let mut inputs = healthy();
        inputs.forwarding_enabled = true;
        inputs.ipv4_forward = Some(true);
        assert!(diagnose(&inputs).is_empty());
    }

    #[test]
    fn forwarding_on_with_an_unreadable_sysctl_is_not_a_finding() {
        let mut inputs = healthy();
        inputs.forwarding_enabled = true;
        inputs.ipv4_forward = None;
        assert!(diagnose(&inputs).is_empty());
    }

    #[test]
    fn prefixes_outside_the_coordinator_bands_are_caught() {
        let mut inputs = healthy();
        inputs.prefixes = RoutePrefixes::Only(vec![
            Allowed::V4([10, 77, 0, 0], 16),
            Allowed::V4([192, 168, 5, 0], 24),
        ]);
        let findings = diagnose(&inputs);
        assert!(codes(&findings).contains(&Code::PrefixesOutsideCoordinatorBands));
        assert!(findings[0].summary.contains("192.168.5.0/24"));
    }

    #[test]
    fn a_prefix_a_peer_advertises_is_inside_the_bands() {
        let mut inputs = healthy();
        inputs.prefixes = RoutePrefixes::Only(vec![
            Allowed::V4([10, 77, 0, 0], 16),
            Allowed::V4([192, 168, 5, 0], 24),
        ]);
        inputs.peers[1].advertised = vec![Allowed::V4([192, 168, 5, 0], 24)];
        assert!(diagnose(&inputs).is_empty());
    }

    #[test]
    fn the_default_route_in_the_prefix_list_is_caught() {
        let mut inputs = healthy();
        inputs.prefixes = RoutePrefixes::Only(vec![Allowed::V4([0, 0, 0, 0], 0)]);
        assert!(codes(&diagnose(&inputs)).contains(&Code::CatchAllPrefix));
    }

    #[test]
    fn containment_is_bit_exact() {
        let wide = Allowed::V4([10, 77, 0, 0], 16);
        assert!(contains(&wide, &Allowed::V4([10, 77, 5, 4], 32)));
        assert!(contains(&wide, &Allowed::V4([10, 77, 255, 255], 32)));
        assert!(!contains(&wide, &Allowed::V4([10, 78, 0, 1], 32)));
        assert!(!contains(
            &wide,
            &Allowed::V6([0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 16)
        ));
        let block = Allowed::V4([10, 64, 0, 0], 12);
        assert!(contains(&block, &wide));
        assert!(contains(&block, &Allowed::V4([10, 79, 0, 0], 16)));
        assert!(!contains(&block, &Allowed::V4([10, 80, 0, 0], 16)));
        let odd = Allowed::V4([10, 77, 0, 0], 20);
        assert!(contains(&odd, &Allowed::V4([10, 77, 15, 255], 32)));
        assert!(!contains(&odd, &Allowed::V4([10, 77, 16, 0], 32)));
    }

    #[test]
    fn the_render_names_the_code_and_the_remedy() {
        let mut inputs = healthy();
        inputs.route_table = RouteTable::Unmanaged;
        let text = render(&diagnose(&inputs));
        assert!(text.contains("routes-needed-but-table-off"));
        assert!(text.contains("route.table = \"main\""));
    }

    #[test]
    fn a_clean_node_renders_a_single_line() {
        assert_eq!(
            render(&diagnose(&healthy())),
            "routing and forwarding: no problems found\n"
        );
    }
}
