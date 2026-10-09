// The one place the concrete adapters meet the use cases.
//
// Everything above this module talks in `wgmesh-ports` traits and `wgmesh-core` values;
// everything below it is a file or a device. `Container::new` decides which adapters a given
// configuration needs, and this is the only module that may name them.

use std::path::{Path, PathBuf};
use std::time::Duration;

use wgmesh_app::{AgentSettings, Ports};
use wgmesh_config::agent::Settings;
use wgmesh_core::{AllowedIpsPolicy, RoutePrefixes, RouteTable, TraversalConfig};
use wgmesh_ports::{Clock, InterfaceSpec, JoinToken, Spki};

use crate::adapters::{FileSecrets, FileState};
use crate::error::CliError;
use crate::simulated::{
    SimulatedCoordinator, SimulatedRoutes, SimulatedWireGuard, SimulatedWorld, SystemClock,
};

/// Which implementation of the device a run uses.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Backend {
    /// The real thing: a netlink WireGuard device and the kernel routing table.
    Kernel,
    /// The offline double: peers, routes and handshakes recorded in this process, so the whole
    /// pipeline can be exercised without `CAP_NET_ADMIN`.
    Simulated,
}

impl Backend {
    /// The word that appears in `doctor`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Kernel => "kernel",
            Self::Simulated => "simulated",
        }
    }
}

/// Where this run keeps its files.
#[derive(Clone, Debug)]
pub struct Paths {
    /// The configuration file that was read.
    pub config: PathBuf,
    /// The state directory.
    pub state_dir: PathBuf,
    /// The runtime directory holding the lock file.
    pub run_dir: PathBuf,
}

/// The adapters, all of them concrete, all of them owned here.
pub struct Device {
    /// The coordination plane.
    pub coordinator: SimulatedCoordinator,
    /// The device.
    pub wireguard: SimulatedWireGuard,
    /// The routing table.
    pub routes: SimulatedRoutes,
}

/// Everything a command needs, assembled once.
pub struct Container {
    settings: Settings,
    backend: Backend,
    paths: Paths,
    world_path: PathBuf,
    token: Option<JoinToken>,
    secrets: FileSecrets,
    state: FileState,
    clock: SystemClock,
    device: std::sync::OnceLock<Device>,
}

/// The ports the use cases see, with this container's adapters behind them.
pub type PortSet<'a> = Ports<
    'a,
    SimulatedCoordinator,
    SimulatedWireGuard,
    SimulatedRoutes,
    FileSecrets,
    FileState,
    SystemClock,
>;

/// The agent, over this container's adapters.
pub type Agent<'a> = wgmesh_app::Agent<
    'a,
    SimulatedCoordinator,
    SimulatedWireGuard,
    SimulatedRoutes,
    FileSecrets,
    FileState,
    SystemClock,
>;

/// One peer's traversal, over this container's adapters.
pub type Traversal<'a> = wgmesh_app::TraversePeers<'a, SimulatedWireGuard, SimulatedCoordinator>;

impl Container {
    /// Assemble the adapters a configuration asks for.
    pub fn new(
        settings: Settings,
        paths: Paths,
        backend: Backend,
        token: Option<JoinToken>,
    ) -> Result<Self, CliError> {
        let secrets_dir = settings.state.dir.join("secrets");
        let secrets = FileSecrets::new(
            &secrets_dir,
            non_empty(&settings.interface.private_key_file).map(PathBuf::from),
            non_empty(&settings.interface.api_key_file).map(PathBuf::from),
        );
        let state = FileState::new(&settings.state.dir);
        let world_path = paths.state_dir.join("simulated-world.json");
        Ok(Self {
            settings,
            backend,
            paths,
            world_path,
            token,
            secrets,
            state,
            clock: SystemClock,
            device: std::sync::OnceLock::new(),
        })
    }

    /// The effective configuration.
    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    /// Which device implementation this run uses.
    pub fn backend(&self) -> Backend {
        self.backend
    }

    /// Where the files for this run live.
    pub fn paths(&self) -> &Paths {
        &self.paths
    }

    /// The runtime directory the lock lives in.
    pub fn run_dir(&self) -> &Path {
        &self.paths.run_dir
    }

    /// The state file this container reads and writes.
    pub fn state(&self) -> &FileState {
        &self.state
    }

    /// The secret store.
    pub fn secrets(&self) -> &FileSecrets {
        &self.secrets
    }

    /// The clock.
    pub fn clock(&self) -> &SystemClock {
        &self.clock
    }

    /// The token this run enrols with, if any.
    pub fn token(&self) -> Option<&JoinToken> {
        self.token.as_ref()
    }

    /// Where the simulated backend reads its world from.
    pub fn world_path(&self) -> &Path {
        &self.world_path
    }

    /// The adapters, refusing when the configured backend is not assembled in this build.
    ///
    /// The simulated device is built the first time something asks for it, so that a command like
    /// `doctor` or `state show` can report on a host whose world file is not there yet instead of
    /// failing to start.
    pub fn device(&self) -> Result<&Device, CliError> {
        match self.backend {
            Backend::Simulated => {
                if let Some(device) = self.device.get() {
                    return Ok(device);
                }
                let world = SimulatedWorld::load(&self.world_path).map_err(CliError::runtime)?;
                let device = Device {
                    coordinator: SimulatedCoordinator::new(world),
                    wireguard: SimulatedWireGuard::new(),
                    routes: SimulatedRoutes::new(),
                };
                Ok(self.device.get_or_init(|| device))
            }
            // The kernel device is the wireguard adapter's, and until that adapter implements
            // this workspace's `WireGuard` and `Routes` ports there is nothing here to assemble.
            // Saying so is better than silently converging nothing.
            Backend::Kernel => Err(CliError::runtime(
                "the kernel backend is not available in this build: the WireGuard adapter does not \
                 yet implement this workspace's ports; run with --backend simulated",
            )),
        }
    }

    /// The adapters, as the use cases want them.
    pub fn ports(&self) -> Result<PortSet<'_>, CliError> {
        let device = self.device()?;
        Ok(Ports {
            coordinator: &device.coordinator,
            wireguard: &device.wireguard,
            routes: &device.routes,
            secrets: &self.secrets,
            state: &self.state,
            clock: &self.clock,
        })
    }

    /// The agent over these adapters.
    pub fn agent(&self, settings: AgentSettings) -> Result<Agent<'_>, CliError> {
        Ok(wgmesh_app::Agent::new(self.ports()?, settings))
    }

    /// The settings the agent runs on, derived from the configuration file.
    pub fn agent_settings(&self) -> Result<AgentSettings, CliError> {
        let spki = self.configured_spki()?;
        let interface = InterfaceSpec {
            name: self.settings.interface.name.clone(),
            mtu: (self.settings.interface.mtu > 0).then_some(self.settings.interface.mtu),
            listen_port: (self.settings.interface.listen_port > 0)
                .then_some(self.settings.interface.listen_port),
            fwmark: None,
        };
        let mut settings = AgentSettings::new(interface, spki);
        if let Some(token) = &self.token {
            settings = settings.with_join_token(token.clone());
        }
        if let Ok(hostname) = hostname() {
            settings = settings.with_hostname(hostname);
        }
        settings = settings.with_traversal(TraversalConfig {
            punch_delay: Duration::from_secs(self.settings.traversal.punch_delay_secs),
            punch_window: Duration::from_secs(self.settings.traversal.punch_window_secs),
            backoff: self
                .settings
                .traversal
                .backoff_secs
                .iter()
                .map(|secs| Duration::from_secs(*secs))
                .collect(),
        });
        if self.settings.traversal.keepalive_secs > 0 {
            settings = settings
                .with_peer_keepalive(Duration::from_secs(self.settings.traversal.keepalive_secs));
        }
        settings = settings.with_allowed_ips(allowed_ips_policy(&self.settings));
        settings = settings.with_route_prefixes(self.settings.route.prefixes.to_core());
        settings = settings.with_route_table(self.settings.route.table.to_core());
        if let Some(metric) = self.settings.route.metric() {
            settings = settings.with_route_metric(metric);
        }
        Ok(settings)
    }

    /// The SPKI the configuration pins.
    pub fn configured_spki(&self) -> Result<Spki, CliError> {
        parse_spki(&self.settings.coordinator.spki_sha256)
            .map_err(|error| CliError::runtime(format!("coordinator.spki_sha256: {error}")))
    }

    /// The state the ports hold, when there is one.
    pub fn joined_state(&self) -> Result<Option<wgmesh_ports::PersistedState>, CliError> {
        use wgmesh_ports::StateStore;
        self.state
            .load()
            .map_err(|error| CliError::runtime(error.to_string()))
    }
}

/// The AllowedIPs policy the configuration asks for.
///
/// `exit_peer` names a peer, and names are the coordinator's to hand out: until a configuration
/// can be resolved against a peer list, an exit peer is a policy this build reports rather than
/// one it programmes.
pub fn allowed_ips_policy(settings: &Settings) -> AllowedIpsPolicy {
    match settings.peers.allowed_ips {
        wgmesh_config::route::AllowedIpsSetting::Any => AllowedIpsPolicy::Any,
        _ => AllowedIpsPolicy::Peer,
    }
}

/// The route prefixes the configuration selects.
pub fn route_prefixes(settings: &Settings) -> RoutePrefixes {
    settings.route.prefixes.to_core()
}

/// The routing table the configuration selects.
pub fn route_table(settings: &Settings) -> RouteTable {
    settings.route.table.to_core()
}

/// Read the join token from the place the resolved configuration names.
///
/// The settings are the ones the command has already resolved, so the token's path comes out of the
/// same layers as every other value. That is what lets `WGMESH__ENROLLMENT__TOKEN_FILE` reach the
/// reader: the NixOS module hands the token over as that environment variable, pointing at the
/// systemd credential (`%d/enrollment-token`, which systemd resolves to
/// `/run/credentials/wgmesh-agent.service/enrollment-token`), and the token's path is deliberately
/// not written into the configuration file. Resolving the file a second time here — from the file
/// layer alone — would leave such a deployment with no token at all, and the agent would refuse to
/// enrol with a message about a token nobody forgot to configure.
pub fn read_token(
    settings: &Settings,
    explicit: Option<String>,
) -> Result<Option<JoinToken>, CliError> {
    if let Some(token) = explicit {
        let token = token.trim().to_string();
        return Ok((!token.is_empty()).then(|| JoinToken::new(token)));
    }
    let Some(path) = non_empty(&settings.enrollment.token_file) else {
        return Ok(None);
    };
    match std::fs::read_to_string(path) {
        Ok(token) => {
            let token = token.trim().to_string();
            Ok((!token.is_empty()).then(|| JoinToken::new(token)))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(CliError::runtime(format!("{path}: {error}"))),
    }
}

/// The host's name, as the coordinator will record it.
pub fn hostname() -> Result<String, CliError> {
    for path in ["/proc/sys/kernel/hostname", "/etc/hostname"] {
        if let Ok(text) = std::fs::read_to_string(path) {
            let name = text.trim();
            if !name.is_empty() {
                return Ok(name.to_string());
            }
        }
    }
    std::env::var("HOSTNAME").map_err(|_| CliError::runtime("the host has no name"))
}

/// Parse a pin written as 64 hex characters.
pub fn parse_spki(text: &str) -> Result<Spki, String> {
    let text = text.trim();
    if text.is_empty() {
        return Err("no pin configured".to_string());
    }
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

/// A pin as 64 hex characters.
pub fn hex_of(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// An empty string is the same as no value at all.
pub fn non_empty(text: &str) -> Option<&str> {
    let text = text.trim();
    (!text.is_empty()).then_some(text)
}

/// The wall clock, so a command can name the time it read something.
pub fn now(clock: &SystemClock) -> u64 {
    clock.now().as_millis() / 1000
}

/// `wgmesh pin`, which needs a TLS handshake and therefore the HTTPS client.
///
/// Learning a pin means completing a handshake and hashing the leaf certificate's SPKI, which is
/// the client adapter's job. Until that adapter is wired into this build the command says so
/// rather than printing a pin nobody verified.
pub fn pin_unavailable(url: &str, json: bool) -> Result<(), CliError> {
    let message = format!(
        "cannot pin {url}: learning a pin needs the HTTPS client, which is not wired into this \
         build"
    );
    if json {
        println!(
            "{}",
            crate::output::json(&serde_json::json!({
                "schema": crate::output::SCHEMA,
                "url": url,
                "pin": serde_json::Value::Null,
                "error": message,
            }))
        );
        return Err(CliError::runtime(message));
    }
    Err(CliError::runtime(message))
}
