use std::net::UdpSocket;
use std::time::Duration;

use wgmesh_core::natprobe::{
    FilterProbe, Filtering, Mapping, MappingProbe, Profile, classify, describe_filtering,
    describe_mapping,
};

/// `WGMP1 M` asks the prober to report the source address it saw us come from.
const MAPPING: &[u8] = b"WGMP1 M";
/// `WGMP1 F` asks it to send us three datagrams — from the endpoint we
/// contacted, from a fresh port on that address, and from a fresh address —
/// so the filter's behaviour can be read off which of them arrive.
const FILTER: &[u8] = b"WGMP1 F";

const REPLY_TIMEOUT: Duration = Duration::from_millis(1_500);

#[derive(Debug, thiserror::Error)]
pub enum ProbeError {
    #[error("could not open a probe socket: {0}")]
    Socket(#[source] std::io::Error),
    #[error("no prober answered")]
    NoAnswer,
}

/// What the NAT probes concluded, and on what they concluded it.
#[derive(Clone, Debug)]
pub struct NatProbe {
    pub profile: Profile,
    pub observations: Vec<MappingProbe>,
    /// Probe servers that stayed silent, which is itself a finding: a silent
    /// prober may mean outbound UDP is blocked.
    pub silent: Vec<std::net::SocketAddr>,
}

impl NatProbe {
    pub fn summary(&self) -> String {
        self.profile.summary()
    }
}

/// Ask each prober what it sees, then ask one of them to probe back.
pub fn probe(servers: &[std::net::SocketAddr]) -> Result<NatProbe, ProbeError> {
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(ProbeError::Socket)?;
    socket
        .set_read_timeout(Some(REPLY_TIMEOUT))
        .map_err(ProbeError::Socket)?;

    let mut observations = Vec::new();
    let mut silent = Vec::new();
    for server in servers {
        let _ = socket.send_to(MAPPING, server);
        let mut buffer = [0u8; 256];
        match socket.recv_from(&mut buffer) {
            Ok((len, _)) => match parse_mapping(&buffer[..len]) {
                Some(observed) => observations.push(MappingProbe {
                    server: *server,
                    observed,
                }),
                None => silent.push(*server),
            },
            Err(_) => silent.push(*server),
        }
    }
    if observations.is_empty() {
        return Err(ProbeError::NoAnswer);
    }

    let mut filter = Vec::new();
    if let Some(server) = servers.first() {
        let _ = socket.send_to(FILTER, server);
        let mut buffer = [0u8; 256];
        let deadline = std::time::Instant::now() + REPLY_TIMEOUT;
        while std::time::Instant::now() < deadline {
            match socket.recv_from(&mut buffer) {
                Ok((len, _)) => {
                    if let Some(probe) = parse_filter(&buffer[..len]) {
                        filter.push(probe);
                    }
                }
                Err(_) => break,
            }
        }
    }

    Ok(NatProbe {
        profile: classify(&observations, &filter),
        observations,
        silent,
    })
}

/// A mapping reply is `WGMP1 <ip>:<port>`.
fn parse_mapping(payload: &[u8]) -> Option<std::net::SocketAddr> {
    let text = std::str::from_utf8(payload).ok()?;
    let rest = text.strip_prefix("WGMP1 ")?;
    rest.trim().parse().ok()
}

/// A filter datagram is `WGMP1 SAME|PORT|ADDR`.
fn parse_filter(payload: &[u8]) -> Option<FilterProbe> {
    let text = std::str::from_utf8(payload).ok()?;
    match text.strip_prefix("WGMP1 ")?.trim() {
        "SAME" => Some(FilterProbe::SameEndpoint { delivered: true }),
        "PORT" => Some(FilterProbe::DifferentPort { delivered: true }),
        "ADDR" => Some(FilterProbe::DifferentAddress { delivered: true }),
        _ => None,
    }
}

/// The three datagrams a prober is expected to send. Kept here beside the
/// client so a prober's author has the shape in front of them.
pub const FILTER_KINDS: [&[u8]; 3] = [b"WGMP1 SAME", b"WGMP1 PORT", b"WGMP1 ADDR"];

/// The lines `wgmesh doctor` prints for the NAT section.
pub fn render(probe: &NatProbe) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "nat: mapping {}, filtering {}\n",
        describe_mapping(probe.profile.mapping),
        describe_filtering(probe.profile.filtering)
    ));
    for observation in &probe.observations {
        out.push_str(&format!(
            "    probe {} saw us as {}\n",
            observation.server, observation.observed
        ));
    }
    if !probe.silent.is_empty() {
        let names: Vec<String> = probe
            .silent
            .iter()
            .map(|server| server.to_string())
            .collect();
        out.push_str(&format!(
            "    no answer from {} — outbound UDP may be blocked\n",
            names.join(", ")
        ));
    }
    match (probe.profile.mapping, probe.profile.filtering) {
        (Mapping::AddressAndPortDependent, _) => out.push_str(
            "    this is a symmetric NAT: the observed port is useless to a peer, so \
             expect the relay to carry this node\n",
        ),
        (_, Filtering::AddressAndPortDependent) => {
            out.push_str("    both ends must fire at the same moment for a direct path to open\n")
        }
        _ => out.push_str("    a direct path is plausible from here\n"),
    }
    out
}

/// The NAT section as data, for `--json`.
pub fn as_json(probe: &NatProbe) -> serde_json::Value {
    serde_json::json!({
        "mapping": describe_mapping(probe.profile.mapping),
        "filtering": describe_filtering(probe.profile.filtering),
        "punch_plausible": probe.profile.punch_plausible(),
        "observations": probe
            .observations
            .iter()
            .map(|observation| serde_json::json!({
                "server": observation.server.to_string(),
                "observed": observation.observed.to_string(),
            }))
            .collect::<Vec<_>>(),
        "silent": probe.silent.iter().map(|server| server.to_string()).collect::<Vec<_>>(),
    })
}
