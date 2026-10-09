use std::collections::BTreeMap;
use std::fmt::Write as _;

use wgmesh_config::agent as settings;
use wgmesh_config::validate::parse_allowed;
use wgmesh_core::doctor::{DoctorInputs, DoctorPeer, Finding, diagnose, render as render_findings};
use wgmesh_core::{Allowed, DeviceId, PeerSpec, PublicKey, RoutePrefixes, program_allowed_ips};
use wgmesh_proto::ConfigSnapshot;

use crate::natprobe::NatProbe;

/// Everything `wgmesh doctor` concluded, and the inputs it concluded it from —
/// so a report can be argued with instead of merely believed.
pub struct Report {
    pub findings: Vec<Finding>,
    pub inputs: DoctorInputs,
    /// Things doctor could not check, and why. A check that silently does
    /// nothing is worse than one that says it did nothing.
    pub notes: Vec<String>,
}

pub const IPV4_FORWARD: &str = "/proc/sys/net/ipv4/ip_forward";
pub const IPV6_FORWARD: &str = "/proc/sys/net/ipv6/conf/all/forwarding";

/// Where the forwarding check reads the kernel's answer from. It is a port so
/// a test can answer for a machine it is not running on.
pub trait Sysctl {
    fn read(&self, key: &str) -> Option<bool>;
}

/// The real thing: `/proc/sys`.
pub struct ProcSysctl;

impl Sysctl for ProcSysctl {
    fn read(&self, key: &str) -> Option<bool> {
        let text = std::fs::read_to_string(key).ok()?;
        match text.trim() {
            "1" => Some(true),
            "0" => Some(false),
            _ => None,
        }
    }
}

fn parse_list(entries: &[String]) -> Vec<Allowed> {
    entries
        .iter()
        .filter_map(|entry| parse_allowed(entry))
        .collect()
}

/// Gather what the checks need from the settings file, the kernel and — when
/// one was given — a coordinator snapshot.
pub fn gather(
    settings: &settings::Settings,
    snapshot: Option<&ConfigSnapshot>,
    sysctl: &dyn Sysctl,
) -> Result<Report, String> {
    let route_table = settings
        .route_table()
        .map_err(|problem| format!("{}: {}", problem.field, problem.message))?;
    let prefixes = settings
        .route_prefixes()
        .map_err(|problem| format!("{}: {}", problem.field, problem.message))?;

    let mut notes = Vec::new();
    let mut network = Vec::new();
    let mut peers = Vec::new();

    match snapshot {
        Some(snapshot) => {
            network = parse_allowed(&snapshot.network.cidr).into_iter().collect();
            if network.is_empty() {
                notes.push(format!(
                    "the snapshot's network cidr \"{}\" is not a CIDR",
                    snapshot.network.cidr
                ));
            }

            let mut ids: BTreeMap<String, DeviceId> = BTreeMap::new();
            ids.insert(snapshot.device.device_id.clone(), DeviceId(0));
            for (index, peer) in snapshot.peers.iter().enumerate() {
                ids.insert(peer.device_id.clone(), DeviceId(index as u32 + 1));
            }

            let specs: Vec<PeerSpec> = snapshot
                .peers
                .iter()
                .map(|peer| {
                    let mut allowed = Vec::new();
                    allowed.extend(parse_allowed(&peer.tunnel_ip));
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

            let policy = settings
                .allowed_ips_policy(exit_peer, specs.len())
                .map_err(|problem| format!("{}: {}", problem.field, problem.message))?;
            let programmed: BTreeMap<DeviceId, Vec<Allowed>> = program_allowed_ips(policy, &specs)
                .map_err(|error| format!("the AllowedIPs policy does not hold: {error:?}"))?
                .into_iter()
                .collect();

            for peer in &snapshot.peers {
                let id = ids[&peer.device_id];
                peers.push(DoctorPeer {
                    name: peer.name.clone(),
                    allowed: programmed.get(&id).cloned().unwrap_or_default(),
                    advertised: parse_list(&peer.advertised),
                    tunnel: parse_allowed(&peer.tunnel_ip),
                });
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

    Ok(Report {
        findings: Vec::new(),
        inputs: DoctorInputs {
            route_table,
            prefixes,
            peers,
            network,
            local_tunnel: snapshot.and_then(|snapshot| parse_allowed(&snapshot.device.tunnel_ip)),
            forwarding_enabled: settings.forwarding.enabled,
            ipv4_forward,
            ipv6_forward,
        },
        notes,
    })
}

pub fn run(
    settings: &settings::Settings,
    snapshot: Option<&ConfigSnapshot>,
    sysctl: &dyn Sysctl,
) -> Result<Report, String> {
    let mut report = gather(settings, snapshot, sysctl)?;
    report.findings = diagnose(&report.inputs);
    Ok(report)
}

/// The whole human-readable report: config problems first, then the routing
/// and forwarding findings, then the NAT section.
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
