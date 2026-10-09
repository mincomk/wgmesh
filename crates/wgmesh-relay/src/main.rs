#![allow(clippy::print_stdout)]

// The relay daemon. It is its own binary from the first commit on purpose: the relay is
// a separate deployment unit, a separate systemd service, and the only process that
// binds the UDP slot ports. Pulling it out of the agent later would cost far more than
// starting here.
//
// What this build can and cannot do is stated plainly rather than faked:
//   * `enroll` generates the relay key and reaches for the coordinator. With no
//     coordinator it fails and says why. With one it still stops short of registering,
//     because the enrollment exchange is a signed HTTPS request and `wgmesh-client` is
//     not written yet.
//   * `run` serves an assignment handed to it as a file, or says honestly that it has
//     no assignment source and serves nothing.

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use tokio::signal::unix::{SignalKind, signal};
use wgmesh_relay::wgmesh_core::Millis;
use wgmesh_relay::{
    Assignment, Keyset, KeysetNetwork, KeysetPeer, PairAssignment, RelayConfig, RelayEngine,
    SlotAssignment, UdpSlotSockets, shutdown,
};

const DEFAULT_CONFIG: &str = "/etc/wgmesh/relay.toml";
const DEFAULT_STATE_DIR: &str = "/var/lib/wgmesh";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

const USAGE: &str = "\
wgmesh-relayd - wgmesh relay data plane

USAGE:
    wgmesh-relayd [--config PATH] [--state-dir PATH] <COMMAND> [OPTIONS]

COMMANDS:
    enroll    Generate the relay key and reach for the coordinator
    run       Serve the slot sockets and forward between the assigned pairs
    status    Print the running relay's last status snapshot
    drain     Ask the running relay to stop taking new traffic (--off to resume)
    keyset    Show the keyset the relay is serving, or ask it to refresh (--refresh)

OPTIONS:
    --config PATH          relay.toml to read (default /etc/wgmesh/relay.toml)
    --state-dir PATH       key and status directory (default /var/lib/wgmesh)
    --coordinator URL      override the coordinator URL
    --token TOKEN          relay join token (enroll)
    --region NAME          region label reported at enroll (enroll)
    --provider NAME        provider label reported at enroll (enroll)
    --assignment-file PATH serve the assignment in this file (run)
    --off                  clear the drain request instead of writing it (drain)
    --refresh              ask the running relay to re-read its keyset (keyset)
    -h, --help             print this text

The assignment file is the operator's stopgap until `wgmesh-client` fetches
GET /v1/relay/assignment over the signed control path. One directive per line:

    slot <device_id> <port>
    pair <device_a> <device_b>
    keyset <device_id> ...

relay.toml is read in both shapes the project writes: the flat keys of the
blueprint's section 8, and the sectioned file the NixOS module renders
([coordinator] url, [relay] port_range, [state] dir). Unknown keys are ignored.

[relay] one_port = true switches the data plane to one UDP socket per node,
routing each datagram by its `mac1` (handshakes) or its `receiver_index`
(everything else). The default, false, is the port-per-pair layout.
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
    let (config, file_state_dir) = match read_config(&config_path) {
        Ok(parsed) => (parsed.relay, parsed.state_dir),
        // A missing config file is normal before enrollment, and every command except
        // `run` works from defaults alone; only a malformed file is fatal.
        Err(ConfigError::Missing) => (RelayConfig::default(), None),
        Err(ConfigError::Invalid(detail)) => return Err(detail),
    };
    // `--state-dir` wins, then the `[state] dir` the NixOS module renders into
    // relay.toml, then systemd's default StateDirectory.
    let state_dir = flags
        .value("state-dir")
        .map(PathBuf::from)
        .or(file_state_dir)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_STATE_DIR));

    match command.as_str() {
        "enroll" => enroll(&flags, &config, &state_dir),
        "run" => serve(&flags, &config, &state_dir),
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

struct ParsedConfig {
    relay: RelayConfig,
    state_dir: Option<PathBuf>,
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
            ("", "coordinator_spki_sha256") | ("coordinator", "spki_sha256") => {}
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
            ("", "rate_limit_pps_per_slot") | ("relay", "rate_limit_pps_per_slot") => {
                relay.pps_per_slot = parse_number(value, number)?;
            }
            ("", "rate_limit_mbit_per_slot") | ("relay", "rate_limit_mbit_per_slot") => {
                relay.mbit_per_slot = parse_number(value, number)?;
            }
            // One port per node: the relay reads the destination out of the packet. Either
            // spelling sets the same switch; `one_port = true` is the one the README uses.
            ("", "one_port") | ("relay", "one_port") => {
                relay.one_port = parse_bool(value, number)?;
            }
            ("relay", "mode") => {
                relay.one_port = match value {
                    "one_port" | "one-port" | "per_node" => true,
                    "pair" | "per_pair" | "per-pair" => false,
                    _ => return Err(format!("line {number}: `{value}` is not a relay mode")),
                };
            }
            ("state", "dir") | ("", "state_dir") => {
                state_dir = Some(PathBuf::from(value));
            }
            _ => {}
        }
    }
    Ok(ParsedConfig { relay, state_dir })
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

fn parse_bool(value: &str, line: usize) -> Result<bool, String> {
    match value {
        "true" | "yes" | "on" | "1" => Ok(true),
        "false" | "no" | "off" | "0" => Ok(false),
        _ => Err(format!("line {line}: `{value}` is not a boolean")),
    }
}

fn enroll(flags: &Flags, config: &RelayConfig, state_dir: &Path) -> Result<(), String> {
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

    let coordinator = Coordinator::parse(&url)?;
    let key = state_dir.join("relay.key");
    let created = ensure_relay_key(&key)?;
    println!(
        "relay key      {} (0600, {})",
        key.display(),
        if created { "created" } else { "existing" }
    );

    coordinator
        .probe(CONNECT_TIMEOUT)
        .map_err(|detail| format!("coordinator unreachable at {detail}"))?;

    Err(format!(
        "coordinator {} answered on tcp/{} but the enrollment exchange is a signed HTTPS request \
         and `wgmesh-client` is not written yet. Nothing was registered, no pin was written, and \
         the relay key was left untouched.",
        coordinator.url, coordinator.port
    ))
}

struct Coordinator {
    url: String,
    host: String,
    port: u16,
}

impl Coordinator {
    fn parse(url: &str) -> Result<Self, String> {
        let (scheme, rest) = url
            .split_once("://")
            .ok_or_else(|| format!("{url}: expected an https:// URL"))?;
        let default_port = match scheme {
            "https" => 443,
            "http" => 80,
            other => return Err(format!("{url}: unsupported scheme `{other}`")),
        };
        let rest = rest.trim_end_matches('/');
        let (host, port) = match rest.rsplit_once(':') {
            Some((host, port)) if !host.contains(':') => (
                host.to_string(),
                port.parse()
                    .map_err(|_| format!("{url}: `{port}` is not a port"))?,
            ),
            _ => (rest.to_string(), default_port),
        };
        if host.is_empty() {
            return Err(format!("{url}: missing host"));
        }
        Ok(Self {
            url: url.to_string(),
            host,
            port,
        })
    }

    fn probe(&self, timeout: Duration) -> Result<(), String> {
        let target = format!("{}:{}", self.host, self.port);
        let addresses: Vec<std::net::SocketAddr> =
            std::net::ToSocketAddrs::to_socket_addrs(&target)
                .map_err(|error| format!("{}: {error}", self.url))?
                .collect();
        let first = addresses
            .first()
            .ok_or_else(|| format!("{}: resolved to no address", self.url))?;
        TcpStream::connect_timeout(first, timeout)
            .map(|_| ())
            .map_err(|error| format!("{}: {error}", self.url))
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

fn serve(flags: &Flags, config: &RelayConfig, state_dir: &Path) -> Result<(), String> {
    fs::create_dir_all(state_dir).map_err(|error| format!("{}: {error}", state_dir.display()))?;

    let sockets = UdpSlotSockets::new(config.listen);
    let mut engine = RelayEngine::new(sockets, config.clone());

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
                "wgmesh-relayd {} serving {} slots, {} pairs ({})",
                engine.config().relay_id,
                engine.slots().len(),
                engine.pairs().len(),
                if engine.one_port() {
                    "one port per node, destination from mac1/receiver_index"
                } else {
                    "a port per pair, destination from the ingress port"
                }
            );
        }
        None => println!(
            "wgmesh-relayd: no assignment source. `wgmesh-client` is not written yet, so nothing is \
             fetched from {}. Serving nothing until an assignment arrives; pass --assignment-file \
             to serve one now.",
            config
                .coordinator
                .as_deref()
                .unwrap_or("<no coordinator configured>")
        ),
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("tokio runtime: {error}"))?;

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
             forwarded={} dropped={} rejected={}",
            heartbeat.relay_id,
            heartbeat.uptime_ms,
            heartbeat.slots,
            heartbeat.pairs,
            heartbeat.draining,
            heartbeat.keyset_devices,
            heartbeat.counters.forwarded,
            heartbeat.counters.drops.total(),
            heartbeat.counters.rejected
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
        format!("rejected={}", status.counters.rejected),
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

// The stopgap assignment file. `GET /v1/relay/assignment` carries the same three things
// as typed wire values once `wgmesh-proto` and `wgmesh-client` exist.
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
    println!("a running relay stops taking new traffic within one poll of the flag");
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
