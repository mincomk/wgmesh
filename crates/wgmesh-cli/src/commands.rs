// The commands, one function each.
//
// They print, they return an exit code, and they do nothing else: every decision they make is a
// call into the container, and every fact they print comes from the configuration, the state file
// or the device.

use std::path::Path;

use wgmesh_config::Layers;
use wgmesh_core::RouteChange;
use wgmesh_ports::{Clock, JoinToken, Routes, StateStore, WireGuard};

use crate::adapters::{FileSecrets, FileState, encode_public_key};
use crate::agent;
use crate::cli::{
    Cli, Command, ConfigAction, DoctorArgs, KeyAction, KeyKind, RoutesAction, StateAction,
    TrustAction,
};
use crate::container::{Container, Paths};
use crate::error::{CliError, Problem, Severity};
use crate::output;
use crate::view::{
    CheckReportView, CheckView, ConfigView, CoordinatorView, DoctorView, JoinView, KeyView,
    PeerView, PeersView, ProblemView, RelaySlotView, RelayView, RelaysView, RouteView, RoutesView,
    StateView, StatusView, TrustView,
};

/// Configure logging: everything goes to stderr, so stdout stays a single document.
///
/// The level is the one the resolved configuration names — `[log] level` in the file, which
/// `WGMESH__LOG__LEVEL` overrides — rather than the environment variable alone, which is how a
/// configuration file that asked for `debug` ended up logging at `info`. The variable keeps its
/// second reading as a whole `tracing-subscriber` filter expression (`wgmesh=debug,info`), which
/// is what it has to be for the environment layer to reach a schema that holds a level word.
pub fn init_logging(cli: &Cli) {
    let level = match std::env::var("WGMESH__LOG__LEVEL") {
        Ok(raw) if !raw.trim().is_empty() => raw,
        _ => load(cli)
            .map(|(settings, _problems)| level_word(settings.log.level).to_string())
            .unwrap_or_else(|_| "info".to_string()),
    };
    let filter = tracing_subscriber::EnvFilter::try_new(level)
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .try_init();
}

/// The filter directive `[log] level` names.
fn level_word(level: wgmesh_config::LogLevel) -> &'static str {
    match level {
        wgmesh_config::LogLevel::Error => "error",
        wgmesh_config::LogLevel::Warn => "warn",
        wgmesh_config::LogLevel::Info => "info",
        wgmesh_config::LogLevel::Debug => "debug",
        wgmesh_config::LogLevel::Trace => "trace",
    }
}

/// Run the command the command line asked for.
pub async fn dispatch(cli: Cli) -> Result<(), CliError> {
    match &cli.command {
        Command::Config(args) => match &args.action {
            ConfigAction::Defaults(json) => {
                let settings = wgmesh_config::agent::Settings::default();
                print_config(&settings, json.json)
            }
            ConfigAction::Show(json) => {
                let (settings, _problems) = load(&cli)?;
                print_config(&settings, json.json)
            }
            ConfigAction::Check(json) => check(&cli, json.json),
        },
        Command::Key(args) => match &args.action {
            KeyAction::Show(args) => show_key(&cli, args.kind, args.json.json),
            KeyAction::Rotate(args) => rotate_key(&cli, args.yes),
        },
        Command::State(args) => match &args.action {
            StateAction::Show(json) => show_state(&cli, json.json),
            StateAction::Reset(args) => reset_state(&cli, args.yes),
        },
        Command::Trust(args) => match &args.action {
            TrustAction::Show(json) => show_trust(&cli, json.json),
            TrustAction::Rotate(args) => rotate_trust(&cli, args.yes),
        },
        Command::Join(args) => {
            let token =
                match (&args.token, &args.token_file) {
                    (Some(token), _) => Some(token.clone()),
                    (None, Some(path)) => Some(std::fs::read_to_string(path).map_err(|error| {
                        CliError::runtime(format!("{}: {error}", path.display()))
                    })?),
                    (None, None) => None,
                };
            join(&cli, token, args.json.json).await
        }
        Command::Run(args) => run(&cli, args.check).await,
        Command::Status(json) => status(&cli, json.json),
        Command::Peers(json) => peers(&cli, json.json),
        Command::Routes(args) => routes(&cli, args),
        Command::Relays(json) => relays(&cli, json.json),
        Command::Doctor(args) => doctor(&cli, args).await,
        Command::Pin(args) => pin_command(&args.url, args.json).await,
    }
}

/// Resolve the configuration from every layer, and validate it.
///
/// A configuration file that is not there is not an error: the defaults are a perfectly good
/// configuration, and commands like `key show` and `state reset` have nothing to say about the
/// coordination plane. `config check` and `run` are the commands that then report what a
/// configuration is missing.
pub fn load(cli: &Cli) -> Result<(wgmesh_config::agent::Settings, Vec<Problem>), CliError> {
    let mut layers = Layers::new();
    if cli.config.exists() {
        layers = layers.file(cli.config.clone());
    }
    let layers = layers.environment();
    let settings = wgmesh_config::resolve(&layers)
        .map_err(|error| CliError::runtime(format!("{}: {error}", cli.config.display())))?;
    let problems = settings
        .validate()
        .into_iter()
        .map(problem)
        .collect::<Vec<_>>();
    Ok((settings, problems))
}

fn problem(problem: wgmesh_config::validate::Problem) -> Problem {
    match problem.severity {
        wgmesh_config::validate::Severity::Error => Problem::error(problem.path, problem.message),
        wgmesh_config::validate::Severity::Warning => {
            Problem::warning(problem.path, problem.message)
        }
    }
}

fn print_config(settings: &wgmesh_config::agent::Settings, json: bool) -> Result<(), CliError> {
    if json {
        let value =
            serde_json::to_value(settings).map_err(|error| CliError::runtime(error.to_string()))?;
        println!(
            "{}",
            output::json(&ConfigView {
                schema: output::SCHEMA,
                settings: value,
            })
        );
        return Ok(());
    }
    let text =
        wgmesh_config::to_toml(settings).map_err(|error| CliError::runtime(error.to_string()))?;
    print!("{text}");
    Ok(())
}

fn check(cli: &Cli, json: bool) -> Result<(), CliError> {
    let (_settings, problems) = load(cli)?;
    let errors = problems
        .iter()
        .filter(|problem| problem.severity == Severity::Error)
        .count();
    let warnings = problems.len() - errors;
    if json {
        let report = CheckReportView {
            schema: output::SCHEMA,
            errors: problems
                .iter()
                .filter(|problem| problem.severity == Severity::Error)
                .map(problem_view)
                .collect(),
            warnings: problems
                .iter()
                .filter(|problem| problem.severity == Severity::Warning)
                .map(problem_view)
                .collect(),
        };
        println!("{}", output::json(&report));
    } else if problems.is_empty() {
        println!("configuration ok");
    } else {
        for problem in &problems {
            println!("{}", problem.line());
        }
        println!(
            "{} problem{} ({errors} error{}, {warnings} warning{})",
            problems.len(),
            if problems.len() == 1 { "" } else { "s" },
            if errors == 1 { "" } else { "s" },
            if warnings == 1 { "" } else { "s" }
        );
    }
    if errors > 0 {
        return Err(CliError::configuration(problems));
    }
    Ok(())
}

fn problem_view(problem: &Problem) -> ProblemView {
    ProblemView {
        path: problem.field.clone(),
        message: problem.message.clone(),
    }
}

fn show_key(cli: &Cli, kind: KeyKind, json: bool) -> Result<(), CliError> {
    let container = container(cli)?;
    let (private, public) = match kind {
        KeyKind::Wg => container
            .secrets()
            .tunnel_pair()
            .map_err(CliError::runtime)?,
        KeyKind::Api => container
            .secrets()
            .identity_pair()
            .map_err(CliError::runtime)?,
    };
    if json {
        println!(
            "{}",
            output::json(&KeyView {
                schema: output::SCHEMA,
                private_key: private,
                public_key: public,
            })
        );
    } else {
        println!("private_key: {private}");
        println!("public_key:  {public}");
    }
    Ok(())
}

fn rotate_key(cli: &Cli, yes: bool) -> Result<(), CliError> {
    if !yes {
        return Err(CliError::usage(
            "wgmesh key rotate replaces this device's tunnel key, which every peer has to be told \
             about; pass --yes to confirm",
        ));
    }
    let container = container(cli)?;
    let public = container
        .secrets()
        .rotate_tunnel()
        .map_err(CliError::runtime)?;
    println!("rotated; the interface now uses public key {public}");
    println!("every peer has to converge again before it can reach this device");
    Ok(())
}

fn show_state(cli: &Cli, json: bool) -> Result<(), CliError> {
    let container = container(cli)?;
    let path = container.state().path().to_path_buf();
    let Some(document) = container
        .state()
        .document()
        .map_err(|error| CliError::runtime(error.to_string()))?
    else {
        return Err(CliError::runtime(format!(
            "no state at {}; this device has not enrolled yet",
            path.display()
        )));
    };
    if json {
        let value = serde_json::to_value(&document)
            .map_err(|error| CliError::runtime(error.to_string()))?;
        println!(
            "{}",
            output::json(&StateView {
                schema: output::SCHEMA,
                state: Some(value),
            })
        );
    } else {
        let text = std::fs::read_to_string(&path)
            .map_err(|error| CliError::runtime(format!("{}: {error}", path.display())))?;
        print!("{text}");
    }
    Ok(())
}

fn reset_state(cli: &Cli, yes: bool) -> Result<(), CliError> {
    if !yes {
        return Err(CliError::usage(
            "wgmesh state reset forgets the identity the coordinator assigned; the keys stay, and \
             the next run enrols again; pass --yes to confirm",
        ));
    }
    let container = container(cli)?;
    let path = container.state().path().to_path_buf();
    container
        .state()
        .clear()
        .map_err(|error| CliError::runtime(error.to_string()))?;
    println!(
        "state cleared at {}; the next run re-enrols with the same keys",
        path.display()
    );
    Ok(())
}

fn show_trust(cli: &Cli, json: bool) -> Result<(), CliError> {
    let container = container(cli)?;
    let configured = container
        .settings()
        .coordinator
        .spki_sha256
        .trim()
        .to_lowercase();
    let pinned = container
        .state()
        .document()
        .map_err(|error| CliError::runtime(error.to_string()))?
        .map(|document| document.coordinator.spki_sha256.to_lowercase());
    let matches = pinned.as_deref() == Some(configured.as_str());
    let view = TrustView {
        schema: output::SCHEMA,
        configured,
        pinned,
        matches,
    };
    if json {
        println!("{}", output::json(&view));
    } else {
        print!("{}", view.human());
    }
    Ok(())
}

fn rotate_trust(cli: &Cli, yes: bool) -> Result<(), CliError> {
    if !yes {
        return Err(CliError::usage(
            "wgmesh trust rotate moves the pin this device holds for the coordinator; pass --yes \
             to confirm",
        ));
    }
    let container = container(cli)?;
    let spki = container.configured_spki()?;
    let mut document = container
        .state()
        .document()
        .map_err(|error| CliError::runtime(error.to_string()))?
        .ok_or_else(|| CliError::runtime("there is no state to re-pin; enrol first"))?;
    document.coordinator.spki_sha256 = crate::container::hex_of(spki.as_bytes());
    container
        .state()
        .save_document(&document)
        .map_err(|error| CliError::runtime(error.to_string()))?;
    println!(
        "the pin is now {}",
        container.settings().coordinator.spki_sha256
    );
    Ok(())
}

async fn join(cli: &Cli, token: Option<String>, json: bool) -> Result<(), CliError> {
    // The settings are resolved once, here, so the token's path is the one every other command
    // reads: the file, the environment (which is where the NixOS module puts the systemd
    // credential) and the flags, in that order.
    let (settings, _problems) = load(cli)?;
    let token = match crate::container::read_token(&settings, token)? {
        Some(token) => token,
        None => {
            return Err(CliError::usage(
                "enrolment needs a token: pass --token, --token-file, or point \
                 enrollment.token_file at one",
            ));
        }
    };
    let container = container_with(cli, settings, Some(token))?;
    let settings = container.agent_settings()?;
    let agent = container.agent(settings)?;
    let state = agent
        .enroll(container.clock().now())
        .await
        .map_err(agent::app_error)?;
    container
        .state()
        .save(&state)
        .map_err(|error| CliError::runtime(error.to_string()))?;
    let view = JoinView {
        schema: output::SCHEMA,
        device_id: state.device.0.to_string(),
        addresses: vec![crate::simulated::write_prefix(&state.tunnel_ip)],
        relay: state.relay.assigned.map(|relay| relay.0.to_string()),
        config_version: 0,
        peers: state.peers.len(),
    };
    if json {
        println!("{}", output::json(&view));
    } else {
        println!(
            "enrolled as device {} on {}",
            view.device_id,
            container.settings().coordinator.network
        );
        println!("addresses {}", view.addresses.join(", "));
    }
    Ok(())
}

async fn run(cli: &Cli, check_only: bool) -> Result<(), CliError> {
    let (settings, problems) = load(cli)?;
    let errors = problems
        .iter()
        .filter(|problem| problem.severity == Severity::Error)
        .count();
    if errors > 0 {
        for problem in &problems {
            println!("{}", problem.line());
        }
        return Err(CliError::configuration(problems));
    }
    for problem in &problems {
        println!("{}", problem.line());
    }
    if check_only {
        println!("configuration ok; nothing was started");
        return Ok(());
    }
    // The token is read from the settings this command already resolved, so an agent configured
    // with nothing but `WGMESH__ENROLLMENT__TOKEN_FILE` — the credential the NixOS module hands
    // it — can enrol on a run that has no state to resume from.
    let token = crate::container::read_token(&settings, None)?;
    let container = container_with(cli, settings, token)?;
    let started = agent::run(&container).await?;
    println!(
        "wgmesh agent stopped: device {} on {} with {} peers",
        started.device.0, started.interface, started.peers
    );
    Ok(())
}

fn status(cli: &Cli, json: bool) -> Result<(), CliError> {
    let view = status_view(cli)?;
    if json {
        println!("{}", output::json(&view));
    } else {
        print!("{}", view.human());
    }
    Ok(())
}

fn peers(cli: &Cli, json: bool) -> Result<(), CliError> {
    let container = container(cli)?;
    let view = peers_view(&container)?;
    if json {
        println!("{}", output::json(&view));
    } else {
        print!("{}", view.human());
    }
    Ok(())
}

fn routes(cli: &Cli, args: &crate::cli::RoutesArgs) -> Result<(), CliError> {
    let container = container(cli)?;
    match &args.action {
        None => {
            let installed = installed_routes(&container)?;
            let view = RoutesView {
                schema: output::SCHEMA,
                table: table_word(&container),
                proto: "wgmesh".to_string(),
                routes: installed
                    .iter()
                    .map(|spec| RouteView {
                        prefix: crate::simulated::write_prefix(&spec.prefix),
                        table: route_table_word(spec),
                        metric: spec.metric,
                    })
                    .collect(),
            };
            if args.json {
                println!("{}", output::json(&view));
            } else if view.routes.is_empty() {
                println!("no routes installed by wgmesh");
            } else {
                for route in &view.routes {
                    println!(
                        "{:<20} {:<8} {}",
                        route.prefix,
                        route.table,
                        route
                            .metric
                            .map(|metric| metric.to_string())
                            .unwrap_or_else(|| "-".to_string())
                    );
                }
            }
        }
        Some(RoutesAction::Plan) => {
            let installed = installed_routes(&container)?;
            let desired = container
                .joined_state()?
                .map(|state| state.routes)
                .unwrap_or_default();
            let changes = wgmesh_core::plan_routes(&desired, &installed);
            if changes.is_empty() {
                println!("nothing to do");
            }
            for change in changes {
                match change {
                    RouteChange::Add(spec) => println!(
                        "add     {:<20} table {}",
                        crate::simulated::write_prefix(&spec.prefix),
                        route_table_word(&spec)
                    ),
                    RouteChange::Remove(spec) => println!(
                        "remove  {:<20} table {}",
                        crate::simulated::write_prefix(&spec.prefix),
                        route_table_word(&spec)
                    ),
                }
            }
        }
        Some(RoutesAction::Reset) => {
            let installed = installed_routes(&container)?;
            let changes: Vec<RouteChange> = installed
                .iter()
                .map(|spec| RouteChange::Remove(spec.clone()))
                .collect();
            container
                .ports()?
                .routes
                .apply(&changes)
                .map_err(|error| CliError::runtime(error.to_string()))?;
            println!("removed {} routes", changes.len());
        }
    }
    Ok(())
}

fn relays(cli: &Cli, json: bool) -> Result<(), CliError> {
    let container = container(cli)?;
    let document = container
        .state()
        .document()
        .map_err(|error| CliError::runtime(error.to_string()))?;
    let view = RelaysView {
        schema: output::SCHEMA,
        pool: format!("{:?}", container.settings().relay.pool).to_lowercase(),
        assigned: document
            .as_ref()
            .map(|document| document.relay.assigned.clone())
            .filter(|assigned| !assigned.is_empty()),
        slot_port: document
            .as_ref()
            .map(|document| document.relay.slot_port)
            .filter(|port| *port > 0),
        slots: document
            .as_ref()
            .map(|document| {
                document
                    .relay
                    .slots
                    .iter()
                    .map(|(relay, port)| RelaySlotView {
                        relay: relay.clone(),
                        port: *port,
                    })
                    .collect()
            })
            .unwrap_or_default(),
    };
    if json {
        println!("{}", output::json(&view));
    } else {
        println!(
            "pool {}  assigned {}  slot {}",
            view.pool,
            view.assigned.as_deref().unwrap_or("-"),
            view.slot_port
                .map(|port| port.to_string())
                .unwrap_or_else(|| "-".to_string())
        );
        for slot in &view.slots {
            println!("  relay {}  port {}", slot.relay, slot.port);
        }
    }
    Ok(())
}

async fn doctor(cli: &Cli, args: &DoctorArgs) -> Result<(), CliError> {
    let (settings, problems) = load(cli)?;
    let checked = settings.clone();
    let exit_peer = settings.peers.exit_peer.clone();
    let allowed_ips = settings.peers.allowed_ips;
    let forwarding_enabled = settings.forwarding.enabled;
    let container = container_with(cli, settings, None)?;
    let mut checks = Vec::new();
    let errors = problems
        .iter()
        .filter(|problem| problem.severity == Severity::Error)
        .count();
    checks.push(CheckView {
        name: "configuration".to_string(),
        status: if errors == 0 { "ok" } else { "fail" }.to_string(),
        detail: format!(
            "{} problem{} ({} error{})",
            problems.len(),
            if problems.len() == 1 { "" } else { "s" },
            errors,
            if errors == 1 { "" } else { "s" }
        ),
    });
    checks.push(CheckView {
        name: "backend".to_string(),
        status: match container.backend() {
            crate::container::Backend::Kernel => "fail",
            crate::container::Backend::Simulated => "ok",
        }
        .to_string(),
        detail: match container.backend() {
            crate::container::Backend::Simulated => {
                format!(
                    "simulated: peers, routes and handshakes are recorded here; world {}",
                    container.world_path().display()
                )
            }
            crate::container::Backend::Kernel => {
                "not available in this build: the kernel adapter does not yet implement this \
                 workspace's ports"
                    .to_string()
            }
        },
    });
    checks.push(CheckView {
        name: "state".to_string(),
        status: if container.state().exists() {
            "ok"
        } else {
            "warn"
        }
        .to_string(),
        detail: if container.state().exists() {
            container.state().path().display().to_string()
        } else {
            format!("no state at {}", container.state().path().display())
        },
    });
    match container.secrets().tunnel_pair() {
        Ok((_private, public)) => checks.push(CheckView {
            name: "wireguard key".to_string(),
            status: "ok".to_string(),
            detail: public,
        }),
        Err(error) => checks.push(CheckView {
            name: "wireguard key".to_string(),
            status: "fail".to_string(),
            detail: error,
        }),
    }
    // The routing and forwarding checks, over whatever this build can actually see.
    //
    // The peer-dependent half of them needs the coordinator's answer: which peers exist and which
    // bands they advertise. The device fetches that itself, over the HTTPS client, with the pin the
    // configuration names and the identity the state file holds — so the checks run on a host that
    // is simply not enrolled yet no further than on one that is. `--snapshot` remains for the case
    // this cannot cover: reading an answer that was captured somewhere else.
    let (snapshot, snapshot_note) = match &args.snapshot {
        Some(path) => match crate::doctor::load_snapshot(path) {
            Ok(snapshot) => (Some(snapshot), None),
            Err(error) => (
                None,
                Some(format!("--snapshot {path:?} could not be read: {error}")),
            ),
        },
        None => match fetch_snapshot(&container).await {
            Ok(snapshot) => (Some(snapshot), None),
            Err(detail) => (
                None,
                Some(format!(
                    "the coordinator's answer was not fetched, so which peers exist and which \
                     bands they advertise are unknown: {detail}"
                )),
            ),
        },
    };
    let sysctl = crate::doctor::ProcSysctl::rooted(&args.proc_root);
    let report = crate::doctor::run(&checked, snapshot.as_ref(), &sysctl);
    for finding in &report.findings {
        checks.push(CheckView {
            name: finding.code.as_str().to_string(),
            status: match finding.severity {
                wgmesh_core::doctor::Severity::Error => "fail",
                wgmesh_core::doctor::Severity::Warning => "warn",
                wgmesh_core::doctor::Severity::Info => "ok",
            }
            .to_string(),
            detail: format!("{} — {}", finding.summary, finding.remedy),
        });
    }
    for note in report.notes.iter().chain(snapshot_note.iter()) {
        checks.push(CheckView {
            name: "routing".to_string(),
            status: "warn".to_string(),
            detail: note.clone(),
        });
    }
    let _ = (forwarding_enabled, &exit_peer, allowed_ips);
    let view = DoctorView {
        schema: output::SCHEMA,
        checks,
    };
    if args.json {
        println!("{}", output::json(&view));
    } else {
        print!("{}", view.human());
    }
    if view.failed() {
        return Err(CliError::runtime("doctor found problems"));
    }
    Ok(())
}

/// The coordinator's answer, for a command that would otherwise need a person to fetch one.
///
/// The pin comes from the configuration and the identity from the state file, which is what a
/// device that has already enrolled signs with: nothing here enrols, and nothing here learns a pin.
/// The body is read rather than the port's snapshot because `doctor` reports on more of it than the
/// port keeps — the peer names, and the bands each peer advertises rather than the union.
async fn fetch_snapshot(container: &Container) -> Result<crate::doctor::Snapshot, String> {
    let settings = container.settings();
    let url = settings.coordinator.url.trim();
    if url.is_empty() {
        return Err("no coordinator.url is configured".to_string());
    }
    let pin = container
        .configured_spki()
        .map_err(|error| error.to_string())?;
    let state = container
        .joined_state()
        .map_err(|error| error.to_string())?
        .ok_or_else(|| {
            "this device has not enrolled yet, so it has no identity to sign a request with"
                .to_string()
        })?;
    let client = wgmesh_client::Coordinator::new(url, pin, container.secrets(), container.clock())
        .map_err(|error| error.to_string())?
        .with_identity(wgmesh_proto::device_id(state.device));
    match client.exchange_config(None).await {
        Ok(wgmesh_client::ConfigExchange::Fresh { body, .. }) => {
            crate::doctor::read_snapshot(&body)
        }
        Ok(wgmesh_client::ConfigExchange::NotModified { .. }) => {
            Err("the coordinator answered 304 to a request that carried no version".to_string())
        }
        Err(error) => Err(error.to_string()),
    }
}

/// `wgmesh pin <url>`: the key the coordinator presents, for a person to write down.
///
/// It is the one command that completes a handshake with nothing pinned, because answering what
/// should be pinned is its whole job. Everything else fails closed on a key it was not told to
/// expect.
async fn pin_command(url: &str, json: bool) -> Result<(), CliError> {
    let pin = wgmesh_client::learn_pin(url)
        .await
        .map_err(|error| CliError::runtime(error.to_string()))?
        .to_string();
    if json {
        println!(
            "{}",
            output::json(&serde_json::json!({
                "schema": output::SCHEMA,
                "url": url,
                "pin": pin,
                "error": serde_json::Value::Null,
            }))
        );
        return Ok(());
    }
    println!("{pin}");
    Ok(())
}

/// The status a person or a script reads.
pub fn status_view(cli: &Cli) -> Result<StatusView, CliError> {
    let container = container(cli)?;
    let document = container
        .state()
        .document()
        .map_err(|error| CliError::runtime(error.to_string()))?;
    let peers = peers_view(&container)?;
    let config_version = document
        .as_ref()
        .and_then(|document| document.coordinator.etag.parse().ok())
        .unwrap_or(0);
    Ok(StatusView {
        schema: output::SCHEMA,
        device_id: document
            .as_ref()
            .map(|document| document.device_id.clone())
            .filter(|id| !id.is_empty()),
        network: document
            .as_ref()
            .map(|document| document.network.clone())
            .filter(|network| !network.is_empty())
            .unwrap_or_else(|| container.settings().coordinator.network.clone()),
        interface: container.settings().interface.name.clone(),
        tunnel_ip: document
            .as_ref()
            .map(|document| document.tunnel_ip.clone())
            .filter(|text| !text.is_empty())
            .unwrap_or_else(|| "-".to_string()),
        coordinator: CoordinatorView {
            url: container.settings().coordinator.url.clone(),
            spki_sha256: container.settings().coordinator.spki_sha256.clone(),
            last_sync_unix: document
                .as_ref()
                .map(|document| document.coordinator.last_sync_unix)
                .filter(|seconds| *seconds > 0),
            config_version,
        },
        relay: document.as_ref().and_then(|document| {
            (document.relay.slot_port > 0).then(|| RelayView {
                assigned: if document.relay.assigned.is_empty() {
                    "-".to_string()
                } else {
                    document.relay.assigned.clone()
                },
                slot_port: document.relay.slot_port,
            })
        }),
        peers: peers.peers,
    })
}

/// The peers, as the state file and the device together describe them.
pub fn peers_view(container: &Container) -> Result<PeersView, CliError> {
    let settings = container.settings();
    let document = container
        .state()
        .document()
        .map_err(|error| CliError::runtime(error.to_string()))?;
    let now = container.clock().now().as_millis() / 1000;
    let exit_peer =
        crate::container::non_empty(&settings.peers.exit_peer).map(|name| name.to_string());
    let peers = document
        .as_ref()
        .map(|document| document.peers.clone())
        .unwrap_or_default();
    let statuses = match container.ports() {
        Ok(ports) => ports.wireguard.status(&[]).unwrap_or_default(),
        Err(_) => Vec::new(),
    };
    Ok(PeersView {
        schema: output::SCHEMA,
        policy: policy_word(settings),
        exit_peer,
        peers: peers
            .into_iter()
            .map(|peer| {
                let live = statuses
                    .iter()
                    .find(|status| status.device.0.to_string() == peer.id);
                let handshake_unix = live
                    .and_then(|status| status.last_handshake)
                    .map(|at| at.as_millis() / 1000)
                    .or_else(|| (peer.last_handshake_unix > 0).then_some(peer.last_handshake_unix));
                let path = match live.and_then(|status| status.last_handshake) {
                    Some(at) => {
                        crate::agent::live_path(Some(at), wgmesh_core::Millis::from_secs(now))
                    }
                    None => match peer.path {
                        wgmesh_state::PeerPath::Direct => wgmesh_core::Path::Direct,
                        wgmesh_state::PeerPath::Relayed => wgmesh_core::Path::Relayed,
                        wgmesh_state::PeerPath::Unknown => wgmesh_core::Path::Unknown,
                    },
                };
                let allowed_ips: Vec<String> = match live {
                    Some(status) if !status.allowed.is_empty() => status
                        .allowed
                        .iter()
                        .map(crate::simulated::write_prefix)
                        .collect(),
                    _ => {
                        if peer.tunnel_ip.is_empty() {
                            Vec::new()
                        } else {
                            vec![peer.tunnel_ip.clone()]
                        }
                    }
                };
                PeerView {
                    id: peer.id.clone(),
                    name: if peer.name.is_empty() {
                        peer.id.clone()
                    } else {
                        peer.name.clone()
                    },
                    wg_pubkey: peer.wg_pubkey.clone(),
                    endpoint: live
                        .and_then(|status| status.endpoint)
                        .map(|endpoint| endpoint.addr().to_string())
                        .or_else(|| peer.endpoint.clone()),
                    path: output::path(path).to_string(),
                    last_handshake_unix: handshake_unix,
                    handshake_age_secs: handshake_unix.map(|at| now.saturating_sub(at)),
                    allowed_ips,
                    rx_bytes: live.map(|status| status.rx_bytes),
                    tx_bytes: live.map(|status| status.tx_bytes),
                }
            })
            .collect(),
    })
}

fn policy_word(settings: &wgmesh_config::agent::Settings) -> String {
    match settings.peers.allowed_ips {
        wgmesh_config::route::AllowedIpsSetting::Any => "any".to_string(),
        _ => "peer".to_string(),
    }
}

fn table_word(container: &Container) -> String {
    format!("{:?}", container.settings().route.table).to_lowercase()
}

fn route_table_word(spec: &wgmesh_core::RouteSpec) -> String {
    match spec.table {
        wgmesh_core::RouteTable::Unmanaged => "off".to_string(),
        wgmesh_core::RouteTable::Main => "main".to_string(),
        wgmesh_core::RouteTable::Number(number) => number.to_string(),
    }
}

fn installed_routes(container: &Container) -> Result<Vec<wgmesh_core::RouteSpec>, CliError> {
    container
        .ports()?
        .routes
        .installed()
        .map_err(|error| CliError::runtime(error.to_string()))
}

/// Build a container from the command line alone, with no join token.
fn container(cli: &Cli) -> Result<Container, CliError> {
    let (settings, _problems) = load(cli)?;
    container_with(cli, settings, None)
}

fn container_with(
    cli: &Cli,
    mut settings: wgmesh_config::agent::Settings,
    token: Option<JoinToken>,
) -> Result<Container, CliError> {
    // The flag wins over the file, and everything downstream — the state file, the keys, the
    // lock, the simulated world — hangs off this one directory.
    if let Some(dir) = &cli.state_dir {
        settings.state.dir = dir.clone();
    }
    let state_dir = settings.state.dir.clone();
    let paths = Paths {
        config: cli.config.clone(),
        state_dir: state_dir.clone(),
        run_dir: state_dir.join("run"),
    };
    let backend = match cli.backend {
        crate::cli::BackendKind::Kernel => crate::container::Backend::Kernel,
        crate::cli::BackendKind::Simulated => crate::container::Backend::Simulated,
    };
    Container::new(settings, paths, backend, token)
}

/// The keys a device has, base64, for anything that wants to print them.
pub fn secrets_of(container: &Container) -> (&FileSecrets, &FileState) {
    (container.secrets(), container.state())
}

/// A peer's key, in the encoding `wg(8)` writes.
pub fn key_text(key: &wgmesh_core::PublicKey) -> String {
    encode_public_key(key)
}

/// A path, as a person would type it.
pub fn display(path: &Path) -> String {
    path.display().to_string()
}
