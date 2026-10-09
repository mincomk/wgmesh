#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, UdpSocket};

use wgmesh_config::relay as settings;
use wgmesh_proto::RelayAssignment;
use wgmesh_relay::{RelayEngine, RelayNode};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let command = arguments.first().map(String::as_str).unwrap_or("run");
    let flags = parse_flags(&arguments)?;

    match command {
        "run" => {
            let config = flags
                .get("config")
                .cloned()
                .unwrap_or_else(|| "/etc/wgmesh/relay.toml".to_owned());
            let settings: settings::Settings =
                wgmesh_config::load(PathBuf::from(&config).as_path())
                    .map_err(|error| format!("{error}"))?;
            tracing_subscriber::fmt()
                .with_env_filter(&settings.log.level)
                .init();
            let assignment_path = flags
                .get("assignment")
                .cloned()
                .unwrap_or_else(|| format!("{}/relay-assignment.json", settings.state.dir));
            let assignment: RelayAssignment =
                serde_json::from_str(&std::fs::read_to_string(&assignment_path)?)?;
            let metrics_listen = flags.get("metrics-listen").cloned();
            run(settings, assignment, metrics_listen)
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
    assignment: RelayAssignment,
    metrics_listen: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let problems = settings.validate();
    if !problems.is_empty() {
        for problem in &problems {
            eprintln!("wgmesh-relayd: {}: {}", problem.field, problem.message);
        }
        return Err("the relay configuration is not valid".into());
    }

    let mut engine = RelayEngine::from_config(&settings.limits);
    engine.apply(&assignment);
    let ports = engine.slot_ports();
    let listen: IpAddr = settings.relay.listen.parse().map_err(|_| {
        format!(
            "relay.listen \"{}\" is not an address",
            settings.relay.listen
        )
    })?;

    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async move {
        let node = Arc::new(RelayNode::new(engine));
        {
            let mut node_mut = Arc::clone(&node);
            Arc::get_mut(&mut node_mut)
                .ok_or("the relay node is already shared")?
                .bind(listen, ports.iter().copied())
                .await?;
        }
        tracing::info!(
            ports = ?node.ports(),
            "wgmesh-relayd is carrying {} slot socket(s)",
            node.ports().len()
        );

        let shutdown = Arc::new(AtomicBool::new(false));
        let serving = {
            let node = Arc::clone(&node);
            let shutdown = Arc::clone(&shutdown);
            tokio::spawn(async move { node.serve(shutdown).await })
        };

        let metrics = metrics_listen.map(|address| {
            let node = Arc::clone(&node);
            let shutdown = Arc::clone(&shutdown);
            tokio::spawn(async move { serve_metrics(node, address, shutdown).await })
        });

        {
            let node = Arc::clone(&node);
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(Duration::from_secs(10));
                loop {
                    ticker.tick().await;
                    let totals = node.engine().totals();
                    tracing::info!(
                        forwarded_packets = totals.tx_packets,
                        forwarded_bytes = totals.tx_bytes,
                        throttled_packets = totals.throttled_packets,
                        dropped_packets = totals.dropped_packets,
                        "relay traffic"
                    );
                }
            })
        };

        let _ = tokio::signal::ctrl_c().await;
        shutdown.store(true, Ordering::Relaxed);
        let _ = serving.await;
        if let Some(metrics) = metrics {
            metrics.abort();
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    Ok(())
}

/// A metrics endpoint small enough to be read in one screen: one request per
/// connection, one body, no keep-alive. Relays carry traffic; they should not
/// carry a web framework.
async fn serve_metrics(
    node: Arc<RelayNode>,
    address: String,
    shutdown: Arc<AtomicBool>,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(&address).await?;
    tracing::info!(%address, "serving Prometheus metrics");
    loop {
        if shutdown.load(Ordering::Relaxed) {
            return Ok(());
        }
        let accepted = tokio::time::timeout(Duration::from_millis(200), listener.accept()).await;
        let Ok(Ok((mut stream, _peer))) = accepted else {
            continue;
        };
        let node = Arc::clone(&node);
        tokio::spawn(async move {
            let mut request = [0u8; 1024];
            let _ = stream.read(&mut request).await;
            let body = node.engine().render_metrics();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
        });
    }
}

/// Kept so `SocketAddr` stays in use for the assignment's endpoint parsing.
#[allow(dead_code)]
fn parse_endpoint(text: &str) -> Option<SocketAddr> {
    text.parse().ok()
}

/// Kept so the slot socket type is named where the socket binding lives.
#[allow(dead_code)]
type SlotSocket = UdpSocket;
