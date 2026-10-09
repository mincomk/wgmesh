use std::io::Write;

use wgmesh_app::peers_view;
use wgmesh_ports::PeerReport;

use crate::CliError;
use crate::args::Args;
use crate::commands::{catch_all, write_line};
use crate::json::Json;
use crate::state::StateFile;

/// `wgmesh peers`: what each peer is programmed with, next to what this device knows about it.
///
/// The one thing this command exists for is seeing where the catch-all went. Under
/// `exit_peer = "gw"` exactly one row carries `0.0.0.0/0` and `::/0` and every other row
/// carries its own `/32`; under `allowed_ips = "any"` that is true only while there is one
/// peer, which is why the policy refuses two.
///
/// The state file carries each peer's own tunnel address and not the bands it advertised, so
/// `advertised` in this output is what the state knows: the peer's own band.
pub fn run(args: &Args, out: &mut dyn Write) -> Result<(), CliError> {
    let config = wgmesh_config::load(&args.config)?;
    let state = StateFile::load(&args.state)?;
    let policy = catch_all(config.peers.allowed_ips, &config.peers.exit_peer);
    let rows = peers_view(&policy, &state.peer_bands()?)?;

    if args.json {
        let document = Json::Array(rows.iter().map(row_json).collect());
        write_line(out, document.render_pretty().trim_end())?;
    } else {
        write_line(
            out,
            &format!(
                "{:<1} {:<24} {:<6} {:<12} {}",
                "", "peer", "id", "policy", "allowed ips"
            ),
        )?;
        for row in &rows {
            write_line(out, &row.line())?;
        }
        write_line(
            out,
            &format!(
                "\n{} peer(s), {} carrying the catch-all, policy {}",
                rows.len(),
                rows.iter().filter(|row| row.carries_catch_all).count(),
                rows.first()
                    .map(|row| row.policy.as_str())
                    .unwrap_or("none")
            ),
        )?;
    }
    Ok(())
}

fn row_json(row: &PeerReport) -> Json {
    Json::Object(vec![
        ("device", Json::from(row.id)),
        ("name", Json::from(row.name.as_str())),
        ("policy", Json::from(row.policy.as_str())),
        ("carries_catch_all", Json::from(row.carries_catch_all)),
        (
            "allowed_ips",
            Json::Array(
                row.allowed_ips
                    .iter()
                    .map(|value| Json::from(value.as_str()))
                    .collect(),
            ),
        ),
        (
            "advertised",
            Json::Array(
                row.advertised
                    .iter()
                    .map(|value| Json::from(value.as_str()))
                    .collect(),
            ),
        ),
    ])
}
