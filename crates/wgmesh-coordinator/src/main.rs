#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;

use wgmesh_config::coordinator as settings;
use wgmesh_coordinator::store::TokenKind;
use wgmesh_coordinator::{AppState, Store, router};

/// `wgmeshd` is deliberately hand-rolled rather than built on a CLI framework:
/// it has two commands, and the coordinator crate should not grow a dependency
/// for them.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let command = arguments.first().map(String::as_str).unwrap_or("run");
    let flags = parse_flags(&arguments)?;
    let config_path = flags
        .get("config")
        .cloned()
        .unwrap_or_else(|| "/etc/wgmesh/coordinator.toml".to_owned());

    match command {
        "run" => {
            let settings: settings::Settings =
                match wgmesh_config::load(PathBuf::from(&config_path).as_path()) {
                    Ok(settings) => settings,
                    Err(error) => {
                        eprintln!("wgmeshd: {error}");
                        settings::Settings::default()
                    }
                };
            let problems = settings.validate();
            if !problems.is_empty() {
                for problem in &problems {
                    eprintln!("wgmeshd: {}: {}", problem.field, problem.message);
                }
                return Err("the coordinator configuration is not valid".into());
            }
            tracing_subscriber::fmt()
                .with_env_filter(&settings.log.level)
                .init();
            run(settings, flags.get("listen").cloned())
        }
        "token" => {
            let settings: settings::Settings =
                wgmesh_config::load(PathBuf::from(&config_path).as_path())
                    .map_err(|error| format!("{error}"))?;
            let kind = match flags.get("kind").map(String::as_str) {
                Some("relay") => TokenKind::Relay,
                _ => TokenKind::Device,
            };
            let mut store =
                Store::load_from(PathBuf::from(settings.state_path()).as_path(), &settings);
            let uses = flags
                .get("uses")
                .and_then(|value| value.parse().ok())
                .unwrap_or(1);
            let ttl_hours: u64 = flags
                .get("ttl-hours")
                .and_then(|value| value.parse().ok())
                .unwrap_or(24);
            let auto_approve = flags.contains_key("auto-approve");
            let token = store.issue_token(kind, auto_approve, uses, ttl_hours * 3600, "operator");
            store.save_to(PathBuf::from(settings.state_path()).as_path())?;
            println!("{token}");
            if !auto_approve {
                println!("# the device will wait for approval: wgmeshd device approve <device-id>");
            }
            Ok(())
        }
        other => Err(format!("unknown command: {other}").into()),
    }
}

fn parse_flags(arguments: &[String]) -> Result<std::collections::BTreeMap<String, String>, String> {
    let mut flags = std::collections::BTreeMap::new();
    let mut rest = arguments.iter().skip(1);
    while let Some(argument) = rest.next() {
        let Some(name) = argument.strip_prefix("--") else {
            continue;
        };
        let (name, inline) = match name.split_once('=') {
            Some((name, value)) => (name, Some(value.to_owned())),
            None => (name, None),
        };
        let value = match inline {
            Some(value) => value,
            None => match rest.next() {
                Some(next) if !next.starts_with("--") => next.clone(),
                _ => "true".to_owned(),
            },
        };
        flags.insert(name.to_owned(), value);
    }
    Ok(flags)
}

fn run(
    settings: settings::Settings,
    listen_override: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let address: String = listen_override.unwrap_or_else(|| settings.api.listen.clone());
    let state_path = PathBuf::from(settings.state_path());
    let store = Store::load_from(&state_path, &settings);
    let state = AppState::new(settings);
    {
        let mut live = state
            .store
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *live = store;
    }
    let policy = state.settings.relay.clone();
    let state = Arc::new(state);

    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async move {
        let listener = TcpListener::bind(&address).await?;
        let bound = listener.local_addr()?;
        tracing::info!(%bound, "wgmeshd is listening");

        let health = {
            let state = Arc::clone(&state);
            let state_path = state_path.clone();
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(Duration::from_secs(5));
                loop {
                    ticker.tick().await;
                    let now = wgmesh_coordinator::now_unix();
                    let mut store = state
                        .store
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    let rehomed = store.check_relay_health(
                        now,
                        policy.heartbeat_timeout_secs,
                        policy.reassign_after_misses,
                    );
                    if !rehomed.is_empty() {
                        tracing::warn!(pairs = rehomed.len(), "re-homed pairs off a silent relay");
                    }
                    let _ = store.save_to(&state_path);
                }
            })
        };

        let app = router(AppState::clone(&state));
        let served = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown_signal())
        .await;
        health.abort();
        served?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
