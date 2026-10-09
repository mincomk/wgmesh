use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::net::IpAddr;
use std::path::Path;

use serde::Deserialize;

use wgmesh_config::agent::Settings;
use wgmesh_config::route::AllowedIpsSetting;
use wgmesh_core::doctor::{DoctorInputs, DoctorPeer, Finding, diagnose, render as render_findings};
use wgmesh_core::{
    Allowed, AllowedIpsPolicy, DeviceId, PeerSpec, PublicKey, RoutePrefixes, program_allowed_ips,
};

use crate::natprobe::NatProbe;

pub const IPV4_FORWARD: &str = "/proc/sys/net/ipv4/ip_forward";
pub const IPV6_FORWARD: &str = "/proc/sys/net/ipv6/conf/all/forwarding";

/// The coordinator's `/v1/config` body, as much of it as the checks read.
///
/// The wire type is `Serialize` only — it is the server's answer, not a request
/// — so reading one back off disk needs a mirror that can be deserialized. It
/// is this file's business alone.
#[derive(Clone, Debug, Deserialize)]
pub struct Snapshot {
    pub network: NetworkView,
    #[serde(default)]
    pub me: Option<MeView>,
    #[serde(default)]
    pub peers: Vec<PeerView>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct NetworkView {
    pub cidr: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct MeView {
    #[serde(default)]
    pub tunnel_ip: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct PeerView {
    #[serde(default)]
    pub device_id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub tunnel_ip: String,
    #[serde(default)]
    pub advertised: Vec<String>,
    #[serde(default)]
    pub endpoint: Option<String>,
}

/// Everything `wgmesh doctor` concluded, and the inputs it concluded it from —
/// so a report can be argued with instead of merely believed.
pub struct Report {
    pub findings: Vec<Finding>,
    pub inputs: DoctorInputs,
    /// Things doctor could not check, and why. A check that silently does
    /// nothing is worse than one that says it did nothing.
    pub notes: Vec<String>,
}

/// Where the forwarding check reads the kernel's answer from. It is a port so a
/// test can answer for a machine it is not running on.
pub trait Sysctl {
    fn read(&self, key: &str) -> Option<bool>;
}

/// The real thing: `/proc/sys`, under a root that can be moved.
///
/// The root exists so a test — or an operator diagnosing a chroot or an image —
/// can point the forwarding check at a tree that is not this machine's. It is
/// the same port either way; only where it reads from moves.
#[derive(Clone, Debug)]
pub struct ProcSysctl {
    root: std::path::PathBuf,
}

impl ProcSysctl {
    /// This machine's `/proc/sys`.
    pub fn new() -> Self {
        Self::rooted(PROC_SYS)
    }

    /// A directory to read the same keys from, in place of this machine's
    /// `/proc/sys`.
    pub fn rooted(root: impl Into<std::path::PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Where this reader looks.
    pub fn root(&self) -> &std::path::Path {
        &self.root
    }
}

impl Default for ProcSysctl {
    fn default() -> Self {
        Self::new()
    }
}

/// The directory the default reader reads: this machine's kernel settings.
pub const PROC_SYS: &str = "/proc/sys";

impl Sysctl for ProcSysctl {
    fn read(&self, key: &str) -> Option<bool> {
        // The keys are absolute paths under `/proc/sys`; the root replaces that
        // prefix rather than being prepended to it, so `--proc-root /tmp/p` reads
        // `/proc/sys/net/ipv4/ip_forward` out of `/tmp/p/net/ipv4/ip_forward`.
        let relative = key
            .strip_prefix(PROC_SYS)
            .unwrap_or_else(|| key.trim_start_matches('/'))
            .trim_start_matches('/');
        let path = self.root.join(relative);
        let text = std::fs::read_to_string(path).ok()?;
        match text.trim() {
            "1" => Some(true),
            "0" => Some(false),
            _ => None,
        }
    }
}

/// Read `10.77.0.0/16` or `fd00::/64` into the core prefix type.
pub fn parse_cidr(text: &str) -> Option<Allowed> {
    let (address, bits) = text.split_once('/')?;
    let bits: u8 = bits.parse().ok()?;
    match address.parse::<IpAddr>().ok()? {
        IpAddr::V4(address) => (bits <= 32).then_some(Allowed::V4(address.octets(), bits)),
        IpAddr::V6(address) => (bits <= 128).then_some(Allowed::V6(address.octets(), bits)),
    }
}

fn parse_list(entries: &[String]) -> Vec<Allowed> {
    entries
        .iter()
        .filter_map(|entry| parse_cidr(entry))
        .collect()
}

/// Gather what the checks need from the settings file, the kernel and — when
/// one was given — a coordinator snapshot.
pub fn gather(settings: &Settings, snapshot: Option<&Snapshot>, sysctl: &dyn Sysctl) -> Report {
    let mut notes = Vec::new();
    let mut network = Vec::new();
    let mut peers = Vec::new();

    match snapshot {
        Some(snapshot) => {
            network = parse_cidr(&snapshot.network.cidr).into_iter().collect();
            if network.is_empty() {
                notes.push(format!(
                    "the snapshot's network cidr \"{}\" is not a CIDR",
                    snapshot.network.cidr
                ));
            }

            let mut ids: BTreeMap<String, DeviceId> = BTreeMap::new();
            if let Some(me) = &snapshot.me {
                ids.insert(me.tunnel_ip.clone(), DeviceId(0));
            }
            for (index, peer) in snapshot.peers.iter().enumerate() {
                ids.insert(peer.device_id.clone(), DeviceId(index as u32 + 1));
            }

            let specs: Vec<PeerSpec> = snapshot
                .peers
                .iter()
                .map(|peer| {
                    let mut allowed = Vec::new();
                    allowed.extend(parse_cidr(&peer.tunnel_ip));
                    allowed.extend(parse_list(&peer.advertised));
                    PeerSpec {
                        id: ids[&peer.device_id],
                        key: PublicKey::from_bytes([0u8; 32]),
                        allowed,
                        endpoint: peer
                            .endpoint
                            .as_deref()
                            .and_then(|text| text.parse().ok())
                            .map(wgmesh_core::Endpoint::new),
                        keepalive: None,
                    }
                })
                .collect();

            let exit_peer = if settings.peers.exit_peer.is_empty() {
                None
            } else {
                snapshot
                    .peers
                    .iter()
                    .find(|peer| peer.name == settings.peers.exit_peer)
                    .and_then(|peer| ids.get(&peer.device_id).copied())
            };
            if !settings.peers.exit_peer.is_empty() && exit_peer.is_none() {
                notes.push(format!(
                    "peers.exit_peer = \"{}\" names no device in the current snapshot",
                    settings.peers.exit_peer
                ));
            }

            let policy = match (exit_peer, settings.peers.allowed_ips) {
                (Some(id), _) => AllowedIpsPolicy::ExitPeer(id),
                (None, AllowedIpsSetting::Peer) => AllowedIpsPolicy::Peer,
                (None, AllowedIpsSetting::Any) => AllowedIpsPolicy::Any,
            };
            match program_allowed_ips(policy, &specs) {
                Ok(programmed) => {
                    let by_id: BTreeMap<DeviceId, Vec<Allowed>> = programmed.into_iter().collect();
                    for peer in &snapshot.peers {
                        let id = ids[&peer.device_id];
                        peers.push(DoctorPeer {
                            name: peer.name.clone(),
                            allowed: by_id.get(&id).cloned().unwrap_or_default(),
                            advertised: parse_list(&peer.advertised),
                            tunnel: parse_cidr(&peer.tunnel_ip),
                        });
                    }
                }
                Err(error) => notes.push(format!(
                    "the AllowedIPs policy does not hold, so the peer checks were skipped: {error:?}"
                )),
            }
        }
        None => {
            notes.push(
                "no --snapshot was given: the peer AllowedIPs and the coordinator's bands are \
                 unknown, so only the table and forwarding checks ran"
                    .to_owned(),
            );
        }
    }

    let ipv4_forward = sysctl.read(IPV4_FORWARD);
    let ipv6_forward = sysctl.read(IPV6_FORWARD);
    if settings.forwarding.enabled && ipv4_forward.is_none() {
        notes.push(format!(
            "{IPV4_FORWARD} could not be read, so the forwarding check was skipped"
        ));
    }

    let inputs = DoctorInputs {
        route_table: settings.route.table.to_core(),
        prefixes: settings.route.prefixes.to_core(),
        peers,
        network,
        local_tunnel: snapshot.and_then(|snapshot| {
            snapshot
                .me
                .as_ref()
                .and_then(|me| parse_cidr(&me.tunnel_ip))
        }),
        forwarding_enabled: settings.forwarding.enabled,
        ipv4_forward,
        ipv6_forward,
    };
    let findings = diagnose(&inputs);
    Report {
        findings,
        inputs,
        notes,
    }
}

pub fn run(settings: &Settings, snapshot: Option<&Snapshot>, sysctl: &dyn Sysctl) -> Report {
    gather(settings, snapshot, sysctl)
}

/// Read a snapshot off disk.
pub fn load_snapshot(path: &Path) -> Result<Snapshot, String> {
    let text =
        std::fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))?;
    serde_json::from_str(&text).map_err(|error| format!("{}: {error}", path.display()))
}

/// The whole human-readable report: the routing and forwarding findings, then
/// what could not be checked, then the NAT section.
pub fn render(report: &Report, nat: Option<&NatProbe>) -> String {
    let mut out = String::new();
    let _ = write!(out, "{}", render_findings(&report.findings));
    for note in &report.notes {
        let _ = writeln!(out, "note: {note}");
    }
    match nat {
        Some(probe) => out.push_str(&crate::natprobe::render(probe)),
        None => out.push_str(
            "nat: not probed — pass --nat-probe <address> (twice, for two addresses) to classify \
             this node's NAT\n",
        ),
    }
    out
}

pub fn as_json(report: &Report, nat: Option<&NatProbe>) -> serde_json::Value {
    serde_json::json!({
        "findings": report
            .findings
            .iter()
            .map(|finding| serde_json::json!({
                "code": finding.code.as_str(),
                "severity": finding.severity.as_str(),
                "summary": finding.summary,
                "remedy": finding.remedy,
            }))
            .collect::<Vec<_>>(),
        "notes": report.notes,
        "route_table": format!("{:?}", report.inputs.route_table),
        "prefixes": match &report.inputs.prefixes {
            RoutePrefixes::Auto => "auto".to_owned(),
            RoutePrefixes::None => "none".to_owned(),
            RoutePrefixes::Only(list) => format!("{list:?}"),
        },
        "nat": nat.map(crate::natprobe::as_json),
    })
}
