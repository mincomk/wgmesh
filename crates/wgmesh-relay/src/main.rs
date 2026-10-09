#![allow(clippy::print_stdout)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

// The relay daemon. It is its own binary from the first commit on purpose: the relay is
// a separate deployment unit, a separate systemd service, and the only process that
// binds the UDP slot ports. Pulling it out of the agent later would cost far more than
// starting here.
//
// What this build does, and does not:
//   * `enroll` generates the relay key, registers with the coordinator over the pinned HTTPS
//     connection, remembers the id it is given, and reads `GET /v1/relay/assignment`.
//   * `run` fetches that assignment from the coordinator on startup and serves it. An assignment
//     is read once and not re-read: a relay whose pairs move is restarted. `--assignment-file`
//     serves one from a file instead, for a host that cannot reach the coordinator at all.

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::signal::unix::{SignalKind, signal};
use wgmesh_ports::{Clock, PortError, SecretError, SecretStore, Signature, Spki};
use wgmesh_proto as naming;
use wgmesh_proto::api::{AssignmentResponse, RelayEnrollBody};
use wgmesh_relay::wgmesh_core::{Millis, PublicKey};
use wgmesh_relay::{
    Assignment, EstablishedSessions, Keyset, KeysetNetwork, KeysetPeer, PairAssignment,
    RelayConfig, RelayEngine, SlotAssignment, UdpSlotSockets, shutdown,
};
use wgmesh_secrets::{FileSecretStore, KeyKind, SecretSource};

const DEFAULT_CONFIG: &str = "/etc/wgmesh/relay.toml";
const DEFAULT_STATE_DIR: &str = "/var/lib/wgmesh";

/// The file holding the relay id the coordinator assigned, under the state directory.
///
/// It is the relay's own name rather than an assignment: it is what signs every request after
/// enrollment, and `run` cannot fetch anything without it.
const RELAY_ID_FILE: &str = "relay-id";
const USAGE: &str = "\
wgmesh-relayd - wgmesh relay data plane

USAGE:
    wgmesh-relayd [--config PATH] [--state-dir PATH] <COMMAND> [OPTIONS]

COMMANDS:
    enroll    Generate the relay key, register with the coordinator and read the assignment
    run       Serve the slot sockets and forward between the assigned pairs
    status    Print the running relay's last status snapshot
    drain     Stop taking new pairs and hand over what it is carrying (--off to resume)
    keyset    Show the keyset the relay is serving, or ask it to refresh (--refresh)

OPTIONS:
    --config PATH          relay.toml to read (default /etc/wgmesh/relay.toml)
    --state-dir PATH       key and status directory (default /var/lib/wgmesh)
    --coordinator URL      override the coordinator URL (enroll, run)
    --pin HEX              the coordinator's SPKI SHA-256, 64 hex (enroll, run)
    --token TOKEN          relay join token (enroll)
    --endpoint-host HOST   the address nodes reach this relay at (enroll)
    --name NAME            what this relay is called (enroll)
    --networks A,B         the networks to serve; empty means every one (enroll)
    --region NAME          region label reported at enroll (enroll)
    --provider NAME        provider label reported at enroll (enroll)
    --assignment-file PATH serve the assignment in this file instead of fetching one (run)
    --off                  clear the drain request instead of writing it (drain)
    --refresh              ask the running relay to re-read its keyset (keyset)
    -h, --help             print this text

The coordinator URL and its pin come from relay.toml ([coordinator] url and
spki_sha256) when the flags do not name them, which is how the NixOS module
invokes this binary. A pin is never learned here: without one, the relay refuses
to connect rather than trusting whatever answers. `wgmesh pin <url>` prints the
pin a coordinator presents.

`enroll` registers the relay, remembers the id the coordinator assigned in
<state-dir>/relay-id, and reads `GET /v1/relay/assignment` over the signed path.
`run` fetches the same assignment from the coordinator on startup. The
assignment file is the debugging stopgap: one directive per line,

    slot <device_id> <port>
    pair <device_a> <device_b>
    keyset <device_id> ...

relay.toml is read in both shapes the project writes: the flat keys of the
blueprint's section 8, and the sectioned file the NixOS module renders
([coordinator] url, [relay] port_range, [state] dir). Unknown keys are ignored.
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match dispatch(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("wgmesh-relayd: {error}");
            ExitCode::FAILURE
        }
    }
}

fn dispatch(args: &[String]) -> Result<(), String> {
    let flags = Flags::parse(args)?;
    if flags.switched("help") {
        print!("{USAGE}");
        return Ok(());
    }
    let Some(command) = flags.positional.first() else {
        print!("{USAGE}");
        return Err("no command given".to_string());
    };

    let config_path = flags
        .value("config")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG));
    // A missing config file is normal before enrollment, and every command except
    // `run` works from defaults alone; only a malformed file is fatal.
    let parsed = match read_config(&config_path) {
        Ok(parsed) => parsed,
        Err(ConfigError::Missing) => ParsedConfig::default(),
        Err(ConfigError::Invalid(detail)) => return Err(detail),
    };
    // `--state-dir` wins, then the `[state] dir` the NixOS module renders into
    // relay.toml, then systemd's default StateDirectory.
    let state_dir = flags
        .value("state-dir")
        .map(PathBuf::from)
        .or(parsed.state_dir.clone())
        .unwrap_or_else(|| PathBuf::from(DEFAULT_STATE_DIR));

    match command.as_str() {
        "enroll" => enroll(&flags, &parsed, &state_dir),
        "run" => serve(&flags, &parsed, &state_dir),
        "status" => status(&state_dir),
        "drain" => drain(&flags, &state_dir),
        "keyset" => keyset(&flags, &state_dir),
        other => Err(format!("unknown command `{other}`\n\n{USAGE}")),
    }
}

struct Flags {
    values: BTreeMap<String, String>,
    switches: Vec<String>,
    positional: Vec<String>,
}

impl Flags {
    const SWITCHES: [&'static str; 4] = ["help", "off", "refresh", "version"];

    fn parse(args: &[String]) -> Result<Self, String> {
        let mut values = BTreeMap::new();
        let mut switches = Vec::new();
        let mut positional = Vec::new();
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            let Some(name) = arg.strip_prefix("--").or_else(|| arg.strip_prefix('-')) else {
                positional.push(arg.clone());
                continue;
            };
            if let Some((key, value)) = name.split_once('=') {
                values.insert(key.to_string(), value.to_string());
            } else if Self::SWITCHES.contains(&name) {
                switches.push(name.to_string());
            } else {
                let value = iter
                    .next()
                    .ok_or_else(|| format!("--{name} needs a value"))?;
                values.insert(name.to_string(), value.clone());
            }
        }
        Ok(Self {
            values,
            switches,
            positional,
        })
    }

    fn value(&self, name: &str) -> Option<String> {
        self.values.get(name).cloned()
    }

    fn switched(&self, name: &str) -> bool {
        self.switches.iter().any(|switch| switch == name)
    }
}

enum ConfigError {
    Missing,
    Invalid(String),
}

#[derive(Default)]
struct ParsedConfig {
    relay: RelayConfig,
    state_dir: Option<PathBuf>,
    /// The key the coordinator is expected to present, as 64 hex characters.
    spki: Option<String>,
    /// The address nodes reach this relay at, when the configuration names one.
    endpoint_host: Option<String>,
}

fn read_config(path: &Path) -> Result<ParsedConfig, ConfigError> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(ConfigError::Missing);
        }
        Err(error) => return Err(ConfigError::Invalid(format!("{}: {error}", path.display()))),
    };
    parse_config(&text)
        .map_err(|detail| ConfigError::Invalid(format!("{}: {detail}", path.display())))
}

// A deliberately small reader for `/etc/wgmesh/relay.toml`. It accepts both shapes the
// project writes: the flat file the blueprint prints in section 8, and the sectioned one
// the NixOS module renders (`[coordinator] url = ...`, `[state] dir = ...`). The full file
// format -- nested tables, lists, unknown-key policy -- belongs to `wgmesh-config`, and
// this is the seam that goes away when that crate lands.
fn parse_config(text: &str) -> Result<ParsedConfig, String> {
    let mut relay = RelayConfig::default();
    let mut state_dir = None;
    let mut spki = None;
    let mut endpoint_host = None;
    let mut section = String::new();

    for (index, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let number = index + 1;
        if let Some(name) = line
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
        {
            section = name.trim().to_string();
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(format!("line {number}: expected `key = value`"));
        };
        let key = key.trim();
        let value = value.trim().trim_matches('"').trim_matches('\'');
        match (section.as_str(), key) {
            ("", "coordinator") | ("coordinator", "url") => {
                relay.coordinator = Some(value.to_string());
            }
            ("", "coordinator_spki_sha256") | ("coordinator", "spki_sha256") => {
                spki = Some(value.to_string());
            }
            ("", "endpoint_host") | ("relay", "endpoint_host") => {
                endpoint_host = Some(value.to_string());
            }
            ("", "relay_id") | ("relay", "id" | "name" | "relay_id") => {
                relay.relay_id = value.to_string();
            }
            ("", "listen") | ("relay", "listen") => {
                relay.listen = value
                    .parse()
                    .map_err(|_| format!("line {number}: `{value}` is not a listen address"))?;
            }
            ("", "port_range") | ("relay", "port_range") => {
                relay.port_range = parse_range(value, number)?;
            }
            ("", "keyset_ttl_secs") | ("relay", "keyset_ttl_secs" | "keyset_ttl") => {
                relay.keyset_ttl = Duration::from_secs(parse_number(value, number)?);
            }
            ("", "established_sessions") | ("relay", "established_sessions") => {
                relay.established_sessions = match value {
                    "serve" => EstablishedSessions::Serve,
                    "refuse" => EstablishedSessions::Refuse,
                    _ => {
                        return Err(format!(
                            "line {number}: `{value}` is not `serve` or `refuse`"
                        ));
                    }
                };
            }
            // The ceiling is written two ways in this project and both are real: the
            // blueprint's `[limits]` table, which `wgmesh-config` parses
            // (`RelaySettings.limits`), and this binary's older `rate_limit_*` keys.
            // Accepting only the second is how a ceiling gets silently ignored — the
            // catch-all below drops unknown keys without a word.
            ("", "rate_limit_pps_per_slot")
            | ("relay", "rate_limit_pps_per_slot")
            | ("limits", "pps_per_slot") => {
                relay.pps_per_slot = parse_number(value, number)?;
            }
            ("", "rate_limit_mbit_per_slot")
            | ("relay", "rate_limit_mbit_per_slot")
            | ("limits", "mbit_per_slot") => {
                relay.mbit_per_slot = parse_number(value, number)?;
            }
            ("state", "dir") | ("", "state_dir") => {
                state_dir = Some(PathBuf::from(value));
            }
            _ => {}
        }
    }
    Ok(ParsedConfig {
        relay,
        state_dir,
        spki,
        endpoint_host,
    })
}

fn parse_number<T: std::str::FromStr>(value: &str, line: usize) -> Result<T, String> {
    value
        .parse()
        .map_err(|_| format!("line {line}: `{value}` is not a number"))
}

fn parse_range(value: &str, line: usize) -> Result<(u16, u16), String> {
    let inner = value.trim_start_matches('[').trim_end_matches(']');
    let (low, high) = inner
        .split_once(',')
        .ok_or_else(|| format!("line {line}: expected `[low, high]`"))?;
    Ok((
        parse_number(low.trim(), line)?,
        parse_number(high.trim(), line)?,
    ))
}

fn enroll(flags: &Flags, parsed: &ParsedConfig, state_dir: &Path) -> Result<(), String> {
    let config = &parsed.relay;
    let url = flags
        .value("coordinator")
        .or_else(|| config.coordinator.clone())
        .ok_or("enroll needs --coordinator <https://...> ")?;
    let token = flags
        .value("token")
        .ok_or("enroll needs --token <RELAY TOKEN>")?;
    if token.trim().is_empty() {
        return Err("enroll needs a non-empty --token".to_string());
    }

    let key_path = state_dir.join("relay.key");
    let created = ensure_relay_key(&key_path)?;
    println!(
        "relay key      {} (0600, {})",
        key_path.display(),
        if created { "created" } else { "existing" }
    );

    let pin = pin_of(flags, parsed)?;
    let key = RelayKey::open(&key_path);
    let clock = SystemClock;
    let client = coordinator_client(&url, pin, &key, &clock)?;
    let api_pubkey = naming::encode_key(&key.public_key().map_err(|error| error.to_string())?);
    let endpoint_host = flags.value("endpoint-host").or_else(|| parsed.endpoint_host.clone()).ok_or(
        "enroll needs the address nodes reach this relay at: pass --endpoint-host <host> or set \
         endpoint_host in relay.toml",
    )?;
    let (low, high) = config.port_range;
    let body = RelayEnrollBody {
        token,
        name: flags
            .value("name")
            .or_else(|| non_empty(&config.relay_id))
            .or_else(hostname)
            .unwrap_or_else(|| "wgmesh-relay".to_string()),
        api_pubkey,
        endpoint_host,
        port_range: format!("{low}-{high}"),
        region: flags.value("region").and_then(|value| non_empty(&value)),
        provider: flags.value("provider").and_then(|value| non_empty(&value)),
        operator: None,
        networks: flags.value("networks").map(networks_of).unwrap_or_default(),
    };

    let runtime = runtime()?;
    let enrolled = runtime
        .block_on(async { client.relay_enroll(&body).await })
        .map_err(|error| coordinator_error(&url, &error))?;

    println!("relay id       {}", enrolled.relay_id);
    println!("relay name     {}", enrolled.name);
    println!("state          {}", enrolled.state);
    println!(
        "endpoint       {} ports {}",
        enrolled.endpoint_host, enrolled.port_range
    );
    for network in &enrolled.networks {
        println!("network        {} {}", network.name, network.cidr);
    }
    if enrolled.state != "active" {
        println!(
            "this relay is not active yet: the coordinator has to approve it before it serves \
             anything"
        );
    }

    // The id signs every later request, so it is written down before the assignment is asked for:
    // an assignment that cannot be read now must not cost a second join token.
    let id_file = state_dir.join(RELAY_ID_FILE);
    fs::write(&id_file, format!("{}\n", enrolled.relay_id))
        .map_err(|error| format!("{}: {error}", id_file.display()))?;
    println!("relay id file  {}", id_file.display());

    match runtime.block_on(async { client.relay_assignment().await }) {
        Ok(assignment) => {
            println!(
                "assignment     {} slots, {} pairs, {} keyed devices",
                assignment.slots.len(),
                assignment.pairs.len(),
                assignment
                    .networks
                    .iter()
                    .map(|network| network.peers.len())
                    .sum::<usize>()
            );
            Ok(())
        }
        // The enrollment stands, and `run` asks again: only the assignment could not be read.
        Err(error) => Err(format!("the assignment was not read: {error}")),
    }
}

/// The HTTPS client for one coordinator, built from what the flags and the file name.
fn coordinator_client<'a>(
    url: &str,
    pin: Spki,
    key: &'a RelayKey,
    clock: &'a SystemClock,
) -> Result<wgmesh_client::Coordinator<'a, RelayKey, SystemClock>, String> {
    wgmesh_client::Coordinator::new(url, pin, key, clock).map_err(|error| error.to_string())
}

/// The key the coordinator must present, from `--pin` or the configuration.
///
/// A pin is never learned here. A relay that accepted whatever answered would be a relay an
/// interposer could point anywhere, and the coordinator is what hands out the pairs it forwards.
fn pin_of(flags: &Flags, parsed: &ParsedConfig) -> Result<Spki, String> {
    let Some(text) = flags.value("pin").or_else(|| parsed.spki.clone()) else {
        return Err(
            "the coordinator's pin is required: pass --pin <64 hex> or set \
             coordinator_spki_sha256 in relay.toml (`wgmesh pin <url>` prints it)"
                .to_string(),
        );
    };
    parse_spki(&text).map_err(|error| format!("coordinator_spki_sha256: {error}"))
}

/// What a failed call to the coordinator means to an operator.
///
/// A coordinator that cannot be reached is the common case and reads better as itself, but the
/// class is the client's: a `429` or a `503` is transient too, and the message says so rather than
/// claiming nothing answered. A refused token or a wrong pin keeps the message it was given.
fn coordinator_error(url: &str, error: &PortError) -> String {
    if error.class() == wgmesh_ports::Class::Transient {
        format!("coordinator unreachable or refusing at {url}: {error}")
    } else {
        error.to_string()
    }
}

fn ensure_relay_key(path: &Path) -> Result<bool, String> {
    if path.exists() {
        return Ok(false);
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| format!("{}: {error}", parent.display()))?;
    }
    let mut seed = [0_u8; 32];
    let mut source =
        fs::File::open("/dev/urandom").map_err(|error| format!("/dev/urandom: {error}"))?;
    source
        .read_exact(&mut seed)
        .map_err(|error| format!("/dev/urandom: {error}"))?;
    write_private(path, &seed)?;
    Ok(true)
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    file.write_all(bytes)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    let _ = file.sync_all();
    Ok(())
}

fn serve(flags: &Flags, parsed: &ParsedConfig, state_dir: &Path) -> Result<(), String> {
    fs::create_dir_all(state_dir).map_err(|error| format!("{}: {error}", state_dir.display()))?;

    // The id the coordinator assigned is what this relay is called, and it is what the engine
    // reports in its status snapshot and its heartbeats. `relay.toml` is the operator's file and
    // carries no id — nothing generates one but enrollment — so the file enrollment wrote fills it
    // in. Without this a relay signs its requests as `relay_…` and reports an empty name.
    let mut config = parsed.relay.clone();
    if let Some(identity) = relay_id_of(state_dir) {
        config.relay_id = identity;
    }

    let sockets = UdpSlotSockets::new(config.listen);
    let mut engine = RelayEngine::new(sockets, config.clone());
    let runtime = runtime()?;

    match flags.value("assignment-file") {
        Some(path) => {
            let path = PathBuf::from(path);
            let text = fs::read_to_string(&path)
                .map_err(|error| format!("{}: {error}", path.display()))?;
            let assignment = parse_assignment(&text)
                .map_err(|detail| format!("{}: {detail}", path.display()))?;
            engine
                .on_assignment(assignment, Millis::ZERO)
                .map_err(|error| error.to_string())?;
            println!(
                "wgmesh-relayd {} serving {} slots, {} pairs",
                engine.config().relay_id,
                engine.slots().len(),
                engine.pairs().len()
            );
        }
        // The assignment comes from the coordinator, which is the only thing that knows which
        // pairs this relay carries and which keys they are reached by.
        None => match runtime.block_on(fetch_assignment(flags, parsed, state_dir)) {
            Ok(assignment) => {
                engine
                    .on_assignment(assignment, Millis::ZERO)
                    .map_err(|error| error.to_string())?;
                println!(
                    "wgmesh-relayd {} serving {} slots, {} pairs",
                    engine.config().relay_id,
                    engine.slots().len(),
                    engine.pairs().len()
                );
            }
            Err(detail) => println!(
                "wgmesh-relayd: no assignment was fetched from {}: {detail} It will not look \
                 again: restart this relay once the coordinator answers, or pass \
                 --assignment-file to serve one from a file.",
                flags
                    .value("coordinator")
                    .or_else(|| config.coordinator.clone())
                    .unwrap_or_else(|| "<no coordinator configured>".to_string())
            ),
        },
    }

    runtime.block_on(async move {
        let (handle, shutdown) = shutdown();
        let mut terminate = signal(SignalKind::terminate()).map_err(|error| error.to_string())?;
        let mut interrupt = signal(SignalKind::interrupt()).map_err(|error| error.to_string())?;
        let trigger = handle.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = terminate.recv() => {}
                _ = interrupt.recv() => {}
            }
            trigger.trigger();
        });

        let drain_request = state_dir.join("drain");
        let status_file = state_dir.join("status");
        let mut last_status: Option<Instant> = None;
        if drain_request.exists() {
            engine.set_draining(true);
        }

        engine
            .run_with(shutdown, move |engine, at| {
                engine.set_draining(drain_request.exists());
                for report in engine.drain_reports() {
                    println!("{}", render_report(&report));
                }
                let due = last_status.is_none_or(|last| last.elapsed() >= Duration::from_secs(1));
                if due {
                    last_status = Some(Instant::now());
                    let _ = fs::write(&status_file, render_status(engine, at));
                }
            })
            .await
            .map_err(|error| error.to_string())
    })
}

fn render_report(report: &wgmesh_relay::Report) -> String {
    match report {
        wgmesh_relay::Report::Heartbeat(heartbeat) => format!(
            "heartbeat relay={} uptime_ms={} slots={} pairs={} draining={} keyset_devices={} \
             forwarded={} dropped={}",
            heartbeat.relay_id,
            heartbeat.uptime_ms,
            heartbeat.slots,
            heartbeat.pairs,
            heartbeat.draining,
            heartbeat.keyset_devices,
            heartbeat.counters.forwarded,
            heartbeat.counters.drops.total()
        ),
        wgmesh_relay::Report::Observations(rows) => {
            let listed: Vec<String> = rows
                .iter()
                .map(|row| format!("{}={}:{}", row.device_id, row.ip, row.port))
                .collect();
            format!("observations {}", listed.join(","))
        }
        wgmesh_relay::Report::Traffic(rows) => {
            let listed: Vec<String> = rows
                .iter()
                .map(|row| {
                    format!(
                        "{}:rx={}/{} tx={}/{}",
                        row.device_id, row.rx_packets, row.rx_bytes, row.tx_packets, row.tx_bytes
                    )
                })
                .collect();
            format!("traffic {}", listed.join(","))
        }
    }
}

// The status snapshot is plain lines rather than JSON: the wire format of the relay's
// reports belongs to `wgmesh-proto`, and this file is a local convenience for
// `wgmesh-relayd status`, not an API.
fn render_status(engine: &RelayEngine<UdpSlotSockets>, at: Millis) -> String {
    let status = engine.status(at);
    let mut lines = vec![
        format!("relay_id={}", status.relay_id),
        format!("at_ms={}", status.at),
        format!("uptime_ms={}", status.uptime_ms),
        format!("draining={}", status.draining),
        format!(
            "established_sessions={}",
            match engine.config().established_sessions {
                EstablishedSessions::Serve => "serve",
                EstablishedSessions::Refuse => "refuse",
            }
        ),
        format!("slots={}", status.slots.len()),
        format!("pairs={}", status.pairs.len()),
        format!("keyset_devices={}", status.keyset_devices),
        format!(
            "keyset_age_ms={}",
            status
                .keyset_age
                .map_or_else(|| String::from("none"), |age| age.as_millis().to_string())
        ),
        format!("datagrams={}", status.counters.datagrams),
        format!("ingress_bytes={}", status.counters.ingress_bytes),
        format!("forwarded={}", status.counters.forwarded),
        format!("forwarded_bytes={}", status.counters.forwarded_bytes),
        format!("socket_errors={}", status.counters.socket_errors),
    ];
    for drop in [
        wgmesh_relay::Drop::UnknownIngress,
        wgmesh_relay::Drop::UnknownDestination,
        wgmesh_relay::Drop::NotAssigned,
        wgmesh_relay::Drop::SourceMoved,
        wgmesh_relay::Drop::Malformed,
        wgmesh_relay::Drop::KeysetStale,
        wgmesh_relay::Drop::KeysetUnknown,
        wgmesh_relay::Drop::RateLimited,
        wgmesh_relay::Drop::Draining,
    ] {
        lines.push(format!(
            "dropped.{drop:?}={}",
            status.counters.drops.get(drop)
        ));
    }
    for slot in &status.slots {
        lines.push(format!(
            "slot.{}=port={} observed_at={}",
            slot.device_id,
            slot.port,
            slot.observed
                .map_or_else(|| String::from("none"), |seen| seen.to_string())
        ));
    }
    lines.push(String::new());
    lines.join("\n")
}

// The stopgap assignment file. `GET /v1/relay/assignment` carries the same three things as typed
// wire values, and is where `run` reads them from unless this file names them instead.
fn parse_assignment(text: &str) -> Result<Assignment, String> {
    let mut slots = Vec::new();
    let mut pairs = Vec::new();
    let mut devices = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let number = index + 1;
        let fields: Vec<&str> = line.split_whitespace().collect();
        match fields.as_slice() {
            ["slot", device, port] => slots.push(SlotAssignment {
                device_id: parse_number(device, number)?,
                port: parse_number(port, number)?,
            }),
            ["pair", a, b] => pairs.push(PairAssignment {
                device_a: parse_number(a, number)?,
                device_b: parse_number(b, number)?,
            }),
            ["keyset", rest @ ..] if !rest.is_empty() => {
                for device in rest {
                    devices.push(KeysetPeer {
                        device_id: parse_number(device, number)?,
                        wg_pubkey: Vec::new(),
                    });
                }
            }
            _ => return Err(format!("line {number}: `{line}` is not a directive")),
        }
    }
    Ok(Assignment {
        generation: 0,
        slots,
        pairs,
        keyset: Keyset {
            networks: vec![KeysetNetwork {
                id: 0,
                name: "default".to_string(),
                peers: devices,
            }],
        },
    })
}

fn status(state_dir: &Path) -> Result<(), String> {
    let path = state_dir.join("status");
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            println!(
                "wgmesh-relayd is not running: {} has never been written.",
                path.display()
            );
            return Ok(());
        }
        Err(error) => return Err(format!("{}: {error}", path.display())),
    };
    println!("status file    {}", path.display());
    match fs::metadata(&path)
        .and_then(|meta| meta.modified())
        .ok()
        .and_then(|time| time.elapsed().ok())
    {
        Some(age) => println!("written        {:.1}s ago", age.as_secs_f64()),
        None => println!("written        (age unknown)"),
    }
    for line in text.lines().filter(|line| !line.is_empty()) {
        println!("  {line}");
    }
    Ok(())
}

fn drain(flags: &Flags, state_dir: &Path) -> Result<(), String> {
    fs::create_dir_all(state_dir).map_err(|error| format!("{}: {error}", state_dir.display()))?;
    let path = state_dir.join("drain");
    if flags.switched("off") {
        match fs::remove_file(&path) {
            Ok(()) => println!("drain cleared    {}", path.display()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                println!("drain already clear");
            }
            Err(error) => return Err(format!("{}: {error}", path.display())),
        }
        return Ok(());
    }
    fs::write(&path, b"drain\n").map_err(|error| format!("{}: {error}", path.display()))?;
    println!("drain requested  {}", path.display());
    println!(
        "a running relay stops taking new pairs within one poll of the flag; the pairs it \
         already carries keep working until the coordinator moves them elsewhere"
    );
    Ok(())
}

fn keyset(flags: &Flags, state_dir: &Path) -> Result<(), String> {
    if flags.switched("refresh") {
        fs::create_dir_all(state_dir)
            .map_err(|error| format!("{}: {error}", state_dir.display()))?;
        let path = state_dir.join("refresh-keyset");
        fs::write(&path, b"refresh\n").map_err(|error| format!("{}: {error}", path.display()))?;
        println!("keyset refresh requested  {}", path.display());
        return Ok(());
    }
    let path = state_dir.join("status");
    match fs::read_to_string(&path) {
        Ok(text) => {
            println!("keyset as of the last status snapshot:");
            for line in text
                .lines()
                .filter(|line| line.starts_with("keyset_") || line.starts_with("relay_id"))
            {
                println!("  {line}");
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            println!("wgmesh-relayd is not running: no keyset is held. Use --refresh once it is.");
            Ok(())
        }
        Err(error) => Err(format!("{}: {error}", path.display())),
    }
}

/// A runtime for the calls that are asynchronous, and the same one the relay serves on.
fn runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("tokio runtime: {error}"))
}

/// The relay's identity, as the client's `SecretStore` port wants it.
///
/// The relay holds one Ed25519 key, in the file `enroll` generates, and this is the only thing
/// that reads it: the client asks for a public half or a signature, never for the key itself.
struct RelayKey {
    store: FileSecretStore,
}

impl RelayKey {
    fn open(path: &Path) -> Self {
        Self {
            store: FileSecretStore::at(path, KeyKind::Ed25519, SecretSource::RequireExisting),
        }
    }
}

impl SecretStore for RelayKey {
    fn wireguard_public_key(&self) -> Result<PublicKey, SecretError> {
        self.public_key()
    }

    fn public_key(&self) -> Result<PublicKey, SecretError> {
        let bytes = self
            .store
            .public_key()
            .map_err(|error| SecretError::fatal(error.to_string()))?;
        Ok(PublicKey::from_bytes(bytes))
    }

    fn sign(&self, message: &[u8]) -> Result<Signature, SecretError> {
        let signature = self
            .store
            .sign(message)
            .map_err(|error| SecretError::fatal(error.to_string()))?;
        Ok(Signature::from_bytes(signature))
    }
}

/// The wall clock, as the client's `Clock` port wants it.
struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Millis {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|since| since.as_millis() as u64)
            .unwrap_or(0);
        Millis::from_millis(millis)
    }
}

/// The assignment `GET /v1/relay/assignment` answers, as the engine wants it.
///
/// The two sides spell a device id the same way and hold the same key, so this is a translation
/// rather than a decision: nothing here is allowed to guess, and anything it cannot read is a
/// failure rather than a silently empty assignment.
fn assignment_of(response: &AssignmentResponse) -> Result<Assignment, String> {
    let device = |text: &str| {
        naming::parse_device_id(text).ok_or_else(|| format!("`{text}` is not a device id"))
    };
    let slots = response
        .slots
        .iter()
        .map(|slot| {
            Ok(SlotAssignment {
                device_id: device(&slot.device_id)?.0,
                port: slot.udp_port,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let pairs = response
        .pairs
        .iter()
        .map(|pair| {
            Ok(PairAssignment {
                device_a: device(&pair.a)?.0,
                device_b: device(&pair.b)?.0,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let networks = response
        .networks
        .iter()
        .map(|network| {
            let peers = network
                .peers
                .iter()
                .map(|peer| {
                    let key = naming::decode_key(&peer.wg_pubkey).ok_or_else(|| {
                        format!("{} has a key that is not a public key", peer.device_id)
                    })?;
                    Ok(KeysetPeer {
                        device_id: device(&peer.device_id)?.0,
                        wg_pubkey: key.as_bytes().to_vec(),
                    })
                })
                .collect::<Result<Vec<_>, String>>()?;
            Ok(KeysetNetwork {
                id: network.id,
                name: network.name.clone(),
                peers,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(Assignment {
        generation: 0,
        slots,
        pairs,
        keyset: Keyset { networks },
    })
}

/// Ask the coordinator for the assignment this relay is to serve.
async fn fetch_assignment(
    flags: &Flags,
    parsed: &ParsedConfig,
    state_dir: &Path,
) -> Result<Assignment, String> {
    let config = &parsed.relay;
    let url = flags
        .value("coordinator")
        .or_else(|| config.coordinator.clone())
        .ok_or(
            "no coordinator is configured: pass --coordinator or set [coordinator] url in \
             relay.toml",
        )?;
    let pin = pin_of(flags, parsed)?;
    let identity = relay_id_of(state_dir).ok_or_else(|| {
        format!(
            "{}: no relay id; run `wgmesh-relayd enroll` first",
            state_dir.join(RELAY_ID_FILE).display()
        )
    })?;
    let key = RelayKey::open(&state_dir.join("relay.key"));
    let clock = SystemClock;
    let answer = coordinator_client(&url, pin, &key, &clock)?
        .with_identity(identity)
        .relay_assignment()
        .await
        .map_err(|error| coordinator_error(&url, &error))?;
    assignment_of(&answer)
}

/// The relay id the coordinator assigned, as enrollment wrote it down.
fn relay_id_of(state_dir: &Path) -> Option<String> {
    fs::read_to_string(state_dir.join(RELAY_ID_FILE))
        .ok()
        .and_then(|text| non_empty(&text))
}

/// One comma-separated list of network names.
fn networks_of(value: String) -> Vec<String> {
    value.split(',').filter_map(non_empty).collect()
}

/// A string, when it has anything in it.
fn non_empty(text: &str) -> Option<String> {
    let trimmed = text.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

/// What this machine calls itself, which is the default name for a relay.
fn hostname() -> Option<String> {
    for path in ["/proc/sys/kernel/hostname", "/etc/hostname"] {
        if let Ok(text) = fs::read_to_string(path) {
            if let Some(name) = non_empty(&text) {
                return Some(name);
            }
        }
    }
    std::env::var("HOSTNAME")
        .ok()
        .and_then(|name| non_empty(&name))
}

/// A pin written as 64 hex characters.
fn parse_spki(text: &str) -> Result<Spki, String> {
    let text = text.trim();
    if text.len() != 64 {
        return Err(format!("expected 64 hex characters, found {}", text.len()));
    }
    let mut bytes = [0u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        let pair = text
            .get(index * 2..index * 2 + 2)
            .ok_or_else(|| format!("not hex: {text}"))?;
        *byte = u8::from_str_radix(pair, 16).map_err(|_| format!("not hex: {pair}"))?;
    }
    Ok(Spki::from_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wgmesh_proto::api::{KeysetNetwork, KeysetPeer, PairBody, SlotBody};
    use wgmesh_relay::wgmesh_core::DeviceId;

    /// An assignment as the coordinator writes one, with two slots and a pair across them.
    fn answer() -> AssignmentResponse {
        let key = naming::encode_key(&PublicKey::from_bytes([4u8; 32]));
        AssignmentResponse {
            relay_id: "relay_1".to_string(),
            endpoint_host: "198.51.100.9".to_string(),
            slots: vec![
                SlotBody {
                    device_id: naming::device_id(DeviceId(3)),
                    udp_port: 52001,
                },
                SlotBody {
                    device_id: naming::device_id(DeviceId(9)),
                    udp_port: 52002,
                },
            ],
            pairs: vec![PairBody {
                a: naming::device_id(DeviceId(3)),
                b: naming::device_id(DeviceId(9)),
            }],
            networks: vec![KeysetNetwork {
                id: 1,
                name: "prod".to_string(),
                peers: vec![KeysetPeer {
                    device_id: naming::device_id(DeviceId(3)),
                    wg_pubkey: key,
                }],
            }],
        }
    }

    #[test]
    fn the_assignment_keeps_the_ids_the_keys_and_the_ports() {
        let assignment = assignment_of(&answer()).expect("the answer is ours");
        assert_eq!(
            assignment.slots,
            vec![
                SlotAssignment {
                    device_id: 3,
                    port: 52001
                },
                SlotAssignment {
                    device_id: 9,
                    port: 52002
                },
            ]
        );
        assert_eq!(
            assignment.pairs,
            vec![PairAssignment {
                device_a: 3,
                device_b: 9
            }]
        );
        assert_eq!(assignment.keyset.networks[0].id, 1);
        assert_eq!(assignment.keyset.networks[0].name, "prod");
        assert_eq!(assignment.keyset.networks[0].peers[0].device_id, 3);
        assert_eq!(assignment.keyset.networks[0].peers[0].wg_pubkey, [4u8; 32]);
        assert!(assignment.keyset.contains(3), "the keyset names the device");
    }

    #[test]
    fn an_assignment_that_does_not_hold_together_is_refused() {
        let mut broken = answer();
        broken.slots[0].device_id = "not-a-device".to_string();
        assert!(
            assignment_of(&broken).is_err(),
            "a slot naming nothing is not a slot"
        );

        let mut broken = answer();
        broken.networks[0].peers[0].wg_pubkey = "AAAA".to_string();
        assert!(
            assignment_of(&broken).is_err(),
            "a key that is not a key is not a key"
        );
    }

    #[test]
    fn a_pin_is_64_hex_characters() {
        let pin = parse_spki(&"ab".repeat(32)).expect("32 bytes of hex");
        assert_eq!(pin.as_bytes()[0], 0xab);
        assert!(parse_spki("").is_err());
        assert!(parse_spki("00").is_err());
        assert!(parse_spki(&"zz".repeat(32)).is_err());
        // Sixty-four bytes that are not sixty-four characters: a slice at a boundary like that
        // would panic, so the reader has to refuse it without one.
        assert!(parse_spki(&"é".repeat(32)).is_err());
    }

    /// The ceiling in the file the documentation specifies has to reach the engine.
    ///
    /// It did not: this parser knew only `rate_limit_pps_per_slot`, and its catch-all
    /// drops unknown keys without a word, so `[limits] pps_per_slot = 2` left the slot
    /// ceiling at its default. Both spellings are accepted now, and this is the test
    /// that would have caught the difference.
    #[test]
    fn the_documented_limits_table_reaches_the_engine_config() {
        let parsed = parse_config(
            "[relay]\nlisten = \"127.0.0.1\"\n\n[limits]\npps_per_slot = 2\nmbit_per_slot = 3\n",
        )
        .unwrap();
        assert_eq!(parsed.relay.pps_per_slot, 2);
        assert_eq!(parsed.relay.mbit_per_slot, 3);
    }

    /// The older spelling still works: a configuration written before this change must
    /// keep meaning what it meant.
    #[test]
    fn the_older_rate_limit_keys_still_work() {
        let parsed =
            parse_config("rate_limit_pps_per_slot = 7\n[relay]\nrate_limit_mbit_per_slot = 9\n")
                .unwrap();
        assert_eq!(parsed.relay.pps_per_slot, 7);
        assert_eq!(parsed.relay.mbit_per_slot, 9);
    }
}
