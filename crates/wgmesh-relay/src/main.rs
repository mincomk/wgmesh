#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde::Deserialize;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

use wgmesh_config::{Layers, RelaySettings};
use wgmesh_proto::api::{AssignmentResponse, KeysetNetwork, KeysetPeer, PairBody, SlotBody};
use wgmesh_relay::{RelayEngine, RelayNode};

/// `AssignmentResponse` is the shape the coordinator sends, so it is
/// `Serialize` and not `Deserialize`. Reading one back off disk therefore needs
/// a mirror that can be deserialized; it is this file's business alone.
#[derive(Debug, Deserialize)]
struct AssignmentFile {
    relay_id: String,
    #[serde(default)]
    endpoint_host: String,
    #[serde(default)]
    slots: Vec<SlotFile>,
    #[serde(default)]
    pairs: Vec<PairFile>,
    #[serde(default)]
    networks: Vec<NetworkFile>,
}

#[derive(Debug, Deserialize)]
struct SlotFile {
    device_id: String,
    udp_port: u16,
}

#[derive(Debug, Deserialize)]
struct PairFile {
    a: String,
    b: String,
}

#[derive(Debug, Deserialize)]
struct NetworkFile {
    #[serde(default)]
    id: u32,
    name: String,
    #[serde(default)]
    peers: Vec<PeerFile>,
}

#[derive(Debug, Deserialize)]
struct PeerFile {
    device_id: String,
    wg_pubkey: String,
}

impl From<AssignmentFile> for AssignmentResponse {
    fn from(file: AssignmentFile) -> Self {
        Self {
            relay_id: file.relay_id,
            endpoint_host: file.endpoint_host,
            slots: file
                .slots
                .into_iter()
                .map(|slot| SlotBody {
                    device_id: slot.device_id,
                    udp_port: slot.udp_port,
                })
                .collect(),
            pairs: file
                .pairs
                .into_iter()
                .map(|pair| PairBody {
                    a: pair.a,
                    b: pair.b,
                })
                .collect(),
            networks: file
                .networks
                .into_iter()
                .map(|network| KeysetNetwork {
                    id: network.id,
                    name: network.name,
                    peers: network
                        .peers
                        .into_iter()
                        .map(|peer| KeysetPeer {
                            device_id: peer.device_id,
                            wg_pubkey: peer.wg_pubkey,
                        })
                        .collect(),
                })
                .collect(),
        }
    }
}

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
            let settings = wgmesh_config::resolve_relay(
                &Layers::new().file(PathBuf::from(&config)).environment(),
            )?;
            let problems = settings.validate();
            if !problems.is_empty() {
                for problem in &problems {
                    eprintln!("wgmesh-relayd: {}: {}", problem.path, problem.message);
                }
                return Err("the relay configuration is not valid".into());
            }
            let assignment_path = flags.get("assignment").cloned().unwrap_or_else(|| {
                format!("{}/relay-assignment.json", settings.state.dir.display())
            });
            let assignment: AssignmentResponse = serde_json::from_str::<AssignmentFile>(
                &std::fs::read_to_string(&assignment_path)?,
            )?
            .into();
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
    settings: RelaySettings,
    assignment: AssignmentResponse,
    metrics_listen: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
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
        let mut node = RelayNode::new(engine);
        node.bind(listen, ports.iter().copied()).await?;
        let node = Arc::new(node);
        let carried = node.ports().len();
        eprintln!("wgmesh-relayd: carrying {carried} slot socket(s)");

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
                    eprintln!(
                        "wgmesh-relayd: forwarded {} packets / {} bytes, {} throttled, {} dropped",
                        totals.tx_packets,
                        totals.tx_bytes,
                        totals.throttled_packets,
                        totals.dropped_packets
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

/// A metrics endpoint small enough to read in one screen: one request per
/// connection, one body, no keep-alive. A relay carries traffic; it should not
/// carry a web framework.
async fn serve_metrics(
    node: Arc<RelayNode>,
    address: String,
    shutdown: Arc<AtomicBool>,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(&address).await?;
    eprintln!("wgmesh-relayd: serving Prometheus metrics on {address}");
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
