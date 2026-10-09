use std::io::Write;

use wgmesh_app::{desired_routes_of, route_plan_view, unmanaged_plan_view};
use wgmesh_core::{RouteSpec, RouteTable};
use wgmesh_ports::{RouteChangeView, Routes, format_prefix};
use wgmesh_wireguard::{IpRoutes, ProcessRunner};

use crate::CliError;
use crate::args::Args;
use crate::commands::write_line;
use crate::json::Json;
use crate::state::StateFile;

/// `wgmesh routes plan`: what would be added and what would be removed, without touching
/// anything.
///
/// The desired side comes from `prefixes` alone, so a default route can never appear here —
/// `core::desired_routes` refuses one — and `table = "off"` plans nothing at all. The
/// installed side is the kernel's own answer, filtered by our marker; when the kernel cannot
/// be asked (no `iproute2`, or no privileges) the state file's memory of what we installed is
/// used instead, and the output says which side it came from.
pub fn plan(args: &Args, out: &mut dyn Write) -> Result<(), CliError> {
    let config = wgmesh_config::load(&args.config)?;
    let state = StateFile::load(&args.state)?;
    let table = config.route.table.to_core();
    let (network, advertised) = state.advertised_bands()?;

    // The desired side is pure, so an impossible configuration is refused before any
    // command is run: `prefixes` may not carry a default route, and `table = "off"` may not
    // come with a list of bands.
    let desired = desired_routes_of(
        &config.route.prefixes.to_core(),
        table,
        config.route.metric(),
        &network,
        &advertised,
    )?;

    if !config.route.table.is_managed() {
        let view = unmanaged_plan_view(&config.route.prefixes.to_core());
        if args.json {
            write_line(out, plan_json(&view, "none").render_pretty().trim_end())?;
        } else {
            write_line(out, view.text().trim_end())?;
            write_line(out, "installed (none) 0")?;
        }
        return Ok(());
    }

    let adapter = IpRoutes::new(ProcessRunner, args.interface.clone(), table);
    let (installed, source) = match adapter.installed() {
        Ok(installed) => (installed, "kernel"),
        Err(error) => {
            let remembered = state.installed()?;
            let note = format!(
                "the kernel could not be asked ({error}); planning against the routes the \
                 state file remembers"
            );
            if args.json {
                // Standard output has to stay parseable, so the note goes to diagnostics.
                eprintln!("wgmesh: {note}");
            } else {
                write_line(out, &format!("note: {note}"))?;
            }
            (remembered, "state")
        }
    };

    let view = route_plan_view(
        &desired,
        &config.route.prefixes.to_core(),
        table,
        &installed,
    );

    if args.json {
        write_line(out, plan_json(&view, source).render_pretty().trim_end())?;
    } else {
        write_line(out, view.text().trim_end())?;
        write_line(
            out,
            &format!("installed ({source}) {}", view.installed.len()),
        )?;
    }
    Ok(())
}

/// `wgmesh routes reset`: delete every route this package installed, and nothing else.
///
/// The adapter asks the kernel for the routes that carry our marker and deletes exactly what
/// it gets back, so a route the host put in the same table is not touched.
pub fn reset(args: &Args, out: &mut dyn Write) -> Result<(), CliError> {
    let config = wgmesh_config::load(&args.config)?;
    let table = config.route.table.to_core();
    let adapter = IpRoutes::new(ProcessRunner, args.interface.clone(), table);
    let removed = adapter.reset()?;

    if args.json {
        let document = Json::Object(vec![
            ("interface", Json::from(args.interface.as_str())),
            ("removed", payload(&removed)),
            ("count", Json::Number(removed.len() as i64)),
        ]);
        write_line(out, document.render_pretty().trim_end())?;
    } else if removed.is_empty() {
        write_line(
            out,
            &format!(
                "no route carrying the wgmesh marker on {}; nothing was deleted",
                args.interface
            ),
        )?;
    } else {
        for spec in &removed {
            write_line(out, &format!("remove {}", format_prefix(&spec.prefix)))?;
        }
        write_line(out, &format!("{} route(s) removed", removed.len()))?;
    }
    Ok(())
}

fn payload(removed: &[RouteSpec]) -> Json {
    Json::Array(
        removed
            .iter()
            .map(|spec| {
                Json::Object(vec![
                    ("prefix", Json::from(format_prefix(&spec.prefix))),
                    ("table", Json::from(label(spec.table))),
                    (
                        "metric",
                        match spec.metric {
                            Some(metric) => Json::from(metric),
                            None => Json::Null,
                        },
                    ),
                ])
            })
            .collect(),
    )
}

fn label(table: RouteTable) -> String {
    wgmesh_app::table_label(table)
}

/// The plan as JSON, with the same words the text output uses.
fn plan_json(view: &wgmesh_ports::RoutePlanView, source: &str) -> Json {
    Json::Object(vec![
        ("table", Json::from(view.table.as_str())),
        ("prefixes", Json::from(view.prefixes.as_str())),
        (
            "address",
            match &view.address {
                Some(address) => Json::from(address.as_str()),
                None => Json::Null,
            },
        ),
        ("installed_from", Json::from(source)),
        (
            "changes",
            Json::Array(view.changes.iter().map(change_json).collect()),
        ),
        (
            "installed",
            Json::Array(
                view.installed
                    .iter()
                    .map(|prefix| Json::from(prefix.as_str()))
                    .collect(),
            ),
        ),
    ])
}

fn change_json(change: &RouteChangeView) -> Json {
    Json::Object(vec![
        ("action", Json::from(change.action.as_str())),
        ("prefix", Json::from(change.prefix.as_str())),
        ("table", Json::from(change.table.as_str())),
        (
            "metric",
            match change.metric {
                Some(metric) => Json::from(metric),
                None => Json::Null,
            },
        ),
    ])
}
