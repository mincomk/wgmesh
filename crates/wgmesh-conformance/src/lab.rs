// The lab: a coordinator process, a relay fleet, and pairs of NAT-ed agents,
// all on loopback.
//
// Everything the tests drive is created here, so a scenario reads as what it is
// -- start a fleet, start a pair, wait for the relayed path, wait for the punch
// to resolve, look at what happened.

use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crate::control::{StateView, get_json};
use wgmesh_core::{Path, Phase, TraversalConfig};

use crate::agent::{Agent, AgentConfig, Snapshot};
use crate::nat::{Nat, NatMode};

/// NAT mapping idle timeout. Longer than any scenario, so a mapping only expires
/// if a path stops using it.
pub const NAT_TTL: Duration = Duration::from_secs(10);

pub const DEVICE_A: u32 = 101;
pub const DEVICE_B: u32 = 102;
pub const DEVICE_C: u32 = 103;
pub const DEVICE_D: u32 = 104;

/// The lab's stand-in for a Curve25519 identity: distinct per device, and the
/// only thing that matters is that both ends agree on it.
pub fn key_of(device: u32) -> [u8; 32] {
    [device as u8; 32]
}

fn binary(name: &str) -> PathBuf {
    let exe = std::env::current_exe().expect("lab: current_exe");
    let dir = exe
        .parent()
        .and_then(|path| path.parent())
        .expect("lab: target directory")
        .to_path_buf();
    let candidate = dir.join(name);
    assert!(
        candidate.exists(),
        "{name} is not built; run `cargo build --workspace` first (looked for {})",
        candidate.display()
    );
    candidate
}

/// Read the one line a child prints when it is ready, then keep draining its
/// stdout so it can never block on a full pipe.
fn read_banner(child: &mut Child) -> String {
    let stdout = child.stdout.take().expect("lab: child stdout");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    reader.read_line(&mut line).expect("lab: read banner");
    thread::spawn(move || {
        let mut sink = String::new();
        loop {
            sink.clear();
            match reader.read_line(&mut sink) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    });
    line.trim().to_string()
}

pub struct CoordinatorProcess {
    child: Child,
    pub addr: SocketAddr,
}

impl CoordinatorProcess {
    pub fn start() -> Self {
        let mut child = Command::new(binary("lab-coordinator"))
            .args(["--listen", "127.0.0.1:0"])
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("lab: spawn wgmeshd");
        let banner = read_banner(&mut child);
        let addr = banner
            .rsplit_once(' ')
            .and_then(|(_, addr)| addr.parse::<SocketAddr>().ok())
            .unwrap_or_else(|| panic!("lab: unexpected wgmeshd banner: {banner}"));
        Self { child, addr }
    }

    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    pub fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.addr, path)
    }

    pub fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub fn state(&self) -> StateView {
        get_json(&self.url("/v1/state")).expect("lab: coordinator state")
    }
}

impl Drop for CoordinatorProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub struct RelayProcess {
    child: Child,
    pub id: String,
}

impl RelayProcess {
    pub fn start(coordinator: &CoordinatorProcess, id: &str) -> Self {
        let mut child = Command::new(binary("lab-relayd"))
            .args(["--id", id, "--coordinator", &coordinator.base_url()])
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("lab: spawn wgmesh-relayd");
        let banner = read_banner(&mut child);
        assert!(
            banner.contains("ready"),
            "lab: unexpected wgmesh-relayd banner: {banner}"
        );
        Self {
            child,
            id: id.to_string(),
        }
    }

    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// The relay goes away the way a machine goes away.
    pub fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for RelayProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub struct Peer {
    pub device: u32,
    pub nat: Arc<Nat>,
    pub agent: Arc<Agent>,
}

pub struct Duo {
    pub a: Peer,
    pub b: Peer,
}

pub fn wait_until(timeout: Duration, mut predicate: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if predicate() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(25));
    }
}

pub fn spawn_fleet(coordinator: &CoordinatorProcess, ids: &[&str]) -> Vec<RelayProcess> {
    let relays: Vec<RelayProcess> = ids
        .iter()
        .map(|id| RelayProcess::start(coordinator, id))
        .collect();
    wait_for_fleet(coordinator, ids);
    relays
}

/// Wait until every named relay has checked in. Pair homing is a pure function
/// of the healthy relay list, so a scenario must not start a pair before the
/// fleet it expects is actually up -- otherwise the first relay to arrive homes
/// the pair and the fleet changes under it.
pub fn wait_for_fleet(coordinator: &CoordinatorProcess, ids: &[&str]) {
    let ready = wait_until(Duration::from_secs(30), || {
        let state = coordinator.state();
        ids.iter().all(|id| {
            state
                .relays
                .iter()
                .any(|relay| relay.id == *id && relay.healthy)
        })
    });
    assert!(ready, "lab: the relay fleet never became healthy");
}

pub fn start_pair(
    coordinator: &CoordinatorProcess,
    a_mode: NatMode,
    b_mode: NatMode,
    device_a: u32,
    device_b: u32,
) -> Duo {
    let nat_a = Nat::start(format!("nat-{device_a}"), a_mode, NAT_TTL);
    let nat_b = Nat::start(format!("nat-{device_b}"), b_mode, NAT_TTL);
    let url = coordinator.base_url();
    let agent_a = Agent::start(AgentConfig {
        id: device_a,
        peer_id: device_b,
        public_key: key_of(device_a),
        peer_public_key: key_of(device_b),
        coordinator: url.clone(),
        nat_port: nat_a.inner_port,
        traversal: TraversalConfig::default(),
    });
    let agent_b = Agent::start(AgentConfig {
        id: device_b,
        peer_id: device_a,
        public_key: key_of(device_b),
        peer_public_key: key_of(device_a),
        coordinator: url,
        nat_port: nat_b.inner_port,
        traversal: TraversalConfig::default(),
    });
    Duo {
        a: Peer {
            device: device_a,
            nat: nat_a,
            agent: agent_a,
        },
        b: Peer {
            device: device_b,
            nat: nat_b,
            agent: agent_b,
        },
    }
}

pub fn relay_of(state: &StateView, device: u32) -> Option<String> {
    state
        .pairs
        .iter()
        .find(|pair| pair.a == device || pair.b == device)
        .map(|pair| pair.relay_id.clone())
}

pub fn relay_forwarded(state: &StateView) -> u64 {
    state.relays.iter().map(|relay| relay.stats.forwarded).sum()
}

/// What one (A NAT, B NAT) campaign run produced.
pub struct CampaignOutcome {
    pub a_mode: &'static str,
    pub b_mode: &'static str,
    /// The path each end reported as soon as the relayed session was up.
    pub start_a: Path,
    pub start_b: Path,
    /// The path each end ended on.
    pub final_a: Path,
    pub final_b: Path,
    pub endpoint_a: u16,
    pub endpoint_b: u16,
    /// External mappings each NAT had to create.
    pub mappings_a: u64,
    pub mappings_b: u64,
    pub attempts_a: u32,
    pub attempts_b: u32,
    /// What each end is waiting before probing again -- the grown backoff.
    pub backoff_a: Option<Duration>,
    pub backoff_b: Option<Duration>,
    /// How long the probe window ran before the fallback, if there was one, as
    /// each end measured it on its own clock.
    pub probe_secs: Option<f64>,
    pub relay_forwarded: u64,
    /// The relay's cumulative forwarded count at the moment the fallback was
    /// observed -- so a test can assert the relayed path resumed *after* the
    /// punch failed rather than merely having carried traffic before it.
    pub forwarded_at_fallback: Option<u64>,
    pub relays: Vec<(String, bool)>,
}

impl CampaignOutcome {
    pub fn print(&self) {
        println!(
            "  {:>10} + {:<10} -> {:?} / {:?}   (start {:?}/{:?}, mappings A={} B={}, \
             attempts {}/{}, probe {}, backoff {}/{:?}, relay forwarded {})",
            self.a_mode,
            self.b_mode,
            self.final_a,
            self.final_b,
            self.start_a,
            self.start_b,
            self.mappings_a,
            self.mappings_b,
            self.attempts_a,
            self.attempts_b,
            self.probe_secs
                .map(|secs| format!("{secs:.1}s"))
                .unwrap_or_else(|| "-".to_string()),
            self.backoff_a
                .map(|value| format!("{:.0}s", value.as_secs_f64()))
                .unwrap_or_else(|| "-".to_string()),
            self.backoff_b
                .map(|value| format!("{:.0}s", value.as_secs_f64()))
                .unwrap_or_else(|| "-".to_string()),
            self.relay_forwarded,
        );
    }
}

/// The whole campaign against one NAT pair: relayed first, then the punch, then
/// either a direct path or the fall back onto the relay with a grown backoff.
pub fn campaign(a_mode: NatMode, b_mode: NatMode) -> CampaignOutcome {
    println!(
        "\n=== campaign: A behind {} NAT, B behind {} NAT ===",
        a_mode.label(),
        b_mode.label()
    );
    let coordinator = CoordinatorProcess::start();
    let _fleet = spawn_fleet(&coordinator, &["relay-1", "relay-2"]);
    let duo = start_pair(&coordinator, a_mode, b_mode, DEVICE_A, DEVICE_B);

    // (1) both ends must come up relayed, through the relay they were homed on.
    let relayed = wait_until(Duration::from_secs(30), || {
        duo.a.agent.up() && duo.b.agent.up()
    });
    assert!(
        relayed,
        "the relayed session never came up: A={:?} B={:?}",
        duo.a.agent.snapshot(),
        duo.b.agent.snapshot()
    );
    // The start path comes from the agents' own record, not from a snapshot at
    // this moment: a descheduled harness thread can miss the relayed second
    // before the punch, and then report the wrong start.
    let start_a = duo.a.agent.initial_path().unwrap_or(Path::Unknown);
    let start_b = duo.b.agent.initial_path().unwrap_or(Path::Unknown);
    let assigned = relay_of(&coordinator.state(), DEVICE_A);
    println!(
        "  relayed: A={start_a:?} B={start_b:?} on {assigned:?}, relay forwarded {}",
        relay_forwarded(&coordinator.state())
    );

    // (2)/(3) the punch: both ends are told each other's observed address and
    // fire. Either a direct path appears, or the probe window runs out and the
    // state machine falls back to the relay and grows the backoff.
    let mut forwarded_at_fallback: Option<u64> = None;
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        let a = duo.a.agent.snapshot();
        let b = duo.b.agent.snapshot();
        if matches!(a.path, Path::Direct) && matches!(b.path, Path::Direct) {
            break;
        }
        // The fallback is read off the agents' own state machines, not off this
        // sampling loop: each end records when its probe gave up, so a
        // descheduled harness cannot miss the moment -- and cannot report a
        // probe window it never saw.
        if a.fallback_ms.is_some() && b.fallback_ms.is_some() {
            forwarded_at_fallback = Some(relay_forwarded(&coordinator.state()));
            // Long enough after the fallback that the relayed path has to have
            // carried traffic again, not merely been scheduled to.
            thread::sleep(Duration::from_millis(2500));
            break;
        }
        thread::sleep(Duration::from_millis(25));
    }

    let a = duo.a.agent.snapshot();
    let b = duo.b.agent.snapshot();
    let state = coordinator.state();
    let outcome = CampaignOutcome {
        a_mode: a_mode.label(),
        b_mode: b_mode.label(),
        start_a,
        start_b,
        final_a: a.path,
        final_b: b.path,
        endpoint_a: a.endpoint,
        endpoint_b: b.endpoint,
        mappings_a: duo.a.nat.mappings_created(),
        mappings_b: duo.b.nat.mappings_created(),
        attempts_a: a.attempts,
        attempts_b: b.attempts,
        backoff_a: a.pending_backoff(),
        backoff_b: b.pending_backoff(),
        probe_secs: probe_window(&a, &b),
        relay_forwarded: relay_forwarded(&state),
        forwarded_at_fallback,
        relays: state
            .relays
            .iter()
            .map(|relay| (relay.id.clone(), relay.healthy))
            .collect(),
    };
    outcome.print();
    for peer in [&duo.a, &duo.b] {
        peer.agent.stop();
        peer.nat.shutdown();
    }
    outcome
}

/// The probe window, as the agents measured it themselves: the longest of the
/// two ends, because both run the same window and the scenario is waiting for
/// the slower one. `None` when no probe has given up yet -- a punch that worked
/// leaves nothing to measure.
fn probe_window(a: &Snapshot, b: &Snapshot) -> Option<f64> {
    let window = |snapshot: &Snapshot| match (snapshot.first_probe_ms, snapshot.fallback_ms) {
        (Some(start), Some(end)) => Some(end.saturating_sub(start) as f64 / 1000.0),
        _ => None,
    };
    match (window(a), window(b)) {
        (Some(x), Some(y)) => Some(x.max(y)),
        (Some(x), None) | (None, Some(x)) => Some(x),
        (None, None) => None,
    }
}

/// Convenience for asserting a phase transition happened in the snapshot.
pub fn probing(snapshot: &crate::agent::Snapshot) -> bool {
    matches!(snapshot.path, Path::Unknown) && snapshot.probing_since_ms.is_some()
}

/// Convenience for asserting the state machine is idle.
pub fn idle(snapshot: &crate::agent::Snapshot) -> bool {
    snapshot.next_attempt_ms.is_some() && snapshot.probing_since_ms.is_none()
}

/// Kept so a test can assert the design's own timings rather than a copy.
pub fn default_traversal() -> TraversalConfig {
    TraversalConfig::default()
}

/// Unused import guard: `Phase` is re-exported for tests that match on it.
pub fn phase_is_probing(phase: Phase) -> bool {
    matches!(phase, Phase::Probing { .. })
}
