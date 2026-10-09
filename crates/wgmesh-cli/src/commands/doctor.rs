use std::io::Write;

use wgmesh_app::{ForwardingObservation, forwarding_checks};
use wgmesh_config::RoutingConfig;
use wgmesh_ports::{ForwardingPolicy, Sysctl};
use wgmesh_wireguard::{IPV4_FORWARD, IPV6_FORWARD, ProcSysctl, as_flag};

use crate::CliError;
use crate::args::Args;
use crate::commands::{catch_all, write_line};
use crate::json::Json;
use crate::state::StateFile;

/// `wgmesh doctor`, the routing and forwarding part.
///
/// The point of this command is that it always says what to do next — including when the
/// answer is "set `sysctl = true`" or "open forwarding on the host yourself" — and that it
/// says it without changing anything. The tunables are read from `/proc/sys` so a host that
/// nothing may be written to can still be diagnosed.
pub fn run(args: &Args, out: &mut dyn Write) -> Result<(), CliError> {
    let config = RoutingConfig::load(&args.config)?;
    let sysctl = ProcSysctl::new();
    let observed = ForwardingObservation {
        ipv4_forward: sysctl
            .read(IPV4_FORWARD)
            .ok()
            .and_then(|value| as_flag(value.as_str())),
        ipv6_forward: sysctl
            .read(IPV6_FORWARD)
            .ok()
            .and_then(|value| as_flag(value.as_str())),
    };
    let policy = ForwardingPolicy {
        enabled: config.forwarding.enabled,
        sysctl: config.forwarding.sysctl,
        manage_firewall: config.forwarding.firewall.is_managed(),
    };
    let checks = forwarding_checks(policy, observed);

    let catch_all = catch_all(&config.peers);
    let peer_note = match &catch_all {
        wgmesh_app::CatchAllPolicy::ExitPeer(name) => {
            format!("the catch-all is programmed for the peer `{name}`")
        }
        wgmesh_app::CatchAllPolicy::Any => String::from(
            "`allowed_ips = \"any\"` gives the catch-all to every peer, which is only valid \
             while there is exactly one",
        ),
        wgmesh_app::CatchAllPolicy::Peer => String::from(
            "every peer keeps its own prefixes; no peer carries a catch-all, so the tunnel \
             reaches the mesh and nothing else",
        ),
    };
    let route_note = format!(
        "table {} prefixes {} metric {}",
        config.route.table.label(),
        config.route.prefixes.label(),
        config.route.metric().unwrap_or(0)
    );
    let peers_seen = match StateFile::load(&args.state) {
        Ok(state) => state.peers.len().to_string(),
        Err(_) => String::from("unknown (no readable state file)"),
    };

    if args.json {
        let document = Json::Object(vec![
            (
                "checks",
                Json::Array(
                    checks
                        .iter()
                        .map(|check| {
                            Json::Object(vec![
                                ("name", Json::from(check.name)),
                                ("state", Json::from(check.state.as_str())),
                                ("detail", Json::from(check.detail.as_str())),
                                ("remedy", Json::from(check.remedy.as_str())),
                            ])
                        })
                        .collect(),
                ),
            ),
            ("peers", Json::from(peers_seen.as_str())),
            ("policy", Json::from(peer_note.as_str())),
            ("route", Json::from(route_note.as_str())),
        ]);
        write_line(out, document.render_pretty().trim_end())?;
    } else {
        write_line(out, &format!("routing  {route_note}"))?;
        write_line(out, &format!("peers    {peers_seen} known; {peer_note}"))?;
        for check in &checks {
            write_line(out, &check.line())?;
        }
    }
    Ok(())
}
