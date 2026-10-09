use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

const DEFAULT_CONFIG: &str = "/etc/wgmesh/agent.toml";

#[derive(Debug, Parser)]
#[command(
    name = "wgmesh",
    version,
    about = "WireGuard mesh agent",
    long_about = "A WireGuard mesh with a coordination plane and a relay data plane.\n\n\
                  Configuration is resolved from the file `--config` names and from the\n\
                  environment (WGMESH__SECTION__KEY), which wins over the file; `--state-dir`\n\
                  then overrides the state directory. Run `wgmesh config show` to see the\n\
                  effective values."
)]
pub struct Cli {
    /// The configuration file to read.
    #[arg(long, global = true, value_name = "PATH", default_value = DEFAULT_CONFIG)]
    pub config: PathBuf,

    /// Override the state directory the configuration names.
    #[arg(long, global = true, value_name = "PATH")]
    pub state_dir: Option<PathBuf>,

    /// Which implementation of the device and the coordination plane to use.
    #[arg(long, global = true, value_enum, default_value_t = BackendKind::Kernel)]
    pub backend: BackendKind,

    /// The subcommand to run.
    #[command(subcommand)]
    pub command: Command,
}

/// The backends the binary can run against.
#[derive(Clone, Copy, PartialEq, Eq, Debug, ValueEnum)]
pub enum BackendKind {
    /// The real thing: netlink WireGuard and the kernel routing table.
    Kernel,
    /// The offline double: a simulated coordinator and device, for CI and for hosts without
    /// `CAP_NET_ADMIN`.
    Simulated,
}

#[derive(Clone, Copy, Debug, Default, Args)]
pub struct JsonFlag {
    /// Print one JSON document instead of the human form.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct DoctorArgs {
    /// Print one JSON document instead of the human form.
    #[arg(long)]
    pub json: bool,

    /// A coordinator snapshot — the body of `GET /v1/config` — to check the peers and the bands
    /// against, in place of the one `doctor` fetches from the coordinator itself. It is for an
    /// answer that was captured somewhere else, or for a run on a host that cannot reach the
    /// coordinator at all.
    #[arg(long, value_name = "PATH")]
    pub snapshot: Option<std::path::PathBuf>,

    /// Where the kernel's answers are read from — `/proc/sys` by default. Pointing it at another
    /// tree is how a test, or a diagnosis of an image, answers for a machine that is not this one.
    #[arg(long, value_name = "PATH", default_value = "/proc/sys")]
    pub proc_root: std::path::PathBuf,

    /// A prober that will report the source address it sees us come from — the mapping probe.
    /// Give a second one at a *different* address and the two ports together say whether this
    /// node's NAT is a cone or symmetric. The prober answers `WGMP1 M` with `WGMP1 <addr>`, and
    /// `WGMP1 F` by sending three datagrams (see `natprobe::FILTER_KINDS`).
    #[arg(long = "nat-probe", value_name = "ADDR")]
    pub nat_probe: Vec<std::net::SocketAddr>,
}

#[derive(Debug, Args)]
pub struct JoinArgs {
    /// The one-time enrollment token.
    #[arg(long, value_name = "TOKEN", conflicts_with = "token_file")]
    pub token: Option<String>,

    /// A file holding the enrollment token.
    #[arg(long, value_name = "PATH", conflicts_with = "token")]
    pub token_file: Option<PathBuf>,

    #[command(flatten)]
    pub json: JsonFlag,
}

#[derive(Debug, Args)]
pub struct RunArgs {
    /// Validate the configuration and stop.
    #[arg(long)]
    pub check: bool,
}

#[derive(Debug, Args)]
pub struct RoutesArgs {
    /// Print one JSON document instead of the human form.
    #[arg(long)]
    pub json: bool,

    /// What to do with the routing table.
    #[command(subcommand)]
    pub action: Option<RoutesAction>,
}

#[derive(Debug, Subcommand)]
pub enum RoutesAction {
    /// Print what would be applied, without applying it.
    Plan,
    /// Remove every route this agent installed.
    Reset,
}

#[derive(Debug, Args)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub action: ConfigAction,
}

#[derive(Debug, Subcommand)]
pub enum ConfigAction {
    /// Print the effective configuration, defaults filled in.
    Show(JsonFlag),
    /// Report every problem the configuration has, all at once.
    Check(JsonFlag),
    /// Print the built-in defaults.
    Defaults(JsonFlag),
}

#[derive(Debug, Args)]
pub struct KeyArgs {
    #[command(subcommand)]
    pub action: KeyAction,
}

#[derive(Debug, Subcommand)]
pub enum KeyAction {
    /// Print the key pair, in the encoding `wg(8)` writes.
    Show(KeyShowArgs),
    /// Replace the tunnel key with a fresh one.
    Rotate(RotateArgs),
}

#[derive(Debug, Args)]
pub struct KeyShowArgs {
    #[command(flatten)]
    pub json: JsonFlag,

    /// Which key to print.
    #[arg(long, value_enum, default_value_t = KeyKind::Wg)]
    pub kind: KeyKind,
}

/// Which of the device's two keys to print.
#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub enum KeyKind {
    /// The WireGuard tunnel key.
    #[default]
    Wg,
    /// The identity key this device signs requests with.
    Api,
}

#[derive(Debug, Args)]
pub struct RotateArgs {
    /// Confirm the change.
    #[arg(long)]
    pub yes: bool,
}

#[derive(Debug, Args)]
pub struct StateArgs {
    #[command(subcommand)]
    pub action: StateAction,
}

#[derive(Debug, Subcommand)]
pub enum StateAction {
    /// Print the state file.
    Show(JsonFlag),
    /// Forget the state, keeping the keys.
    Reset(RotateArgs),
}

#[derive(Debug, Args)]
pub struct TrustArgs {
    #[command(subcommand)]
    pub action: TrustAction,
}

#[derive(Debug, Subcommand)]
pub enum TrustAction {
    /// Print the configuration's pin and the state's pin.
    Show(JsonFlag),
    /// Move the state's pin to what the configuration says.
    Rotate(RotateArgs),
}

#[derive(Debug, Args)]
pub struct PinArgs {
    /// The coordinator URL to pin.
    #[arg(value_name = "URL")]
    pub url: String,

    /// Print one JSON document instead of the human form.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Enroll this device with the coordinator.
    Join(JoinArgs),
    /// Run the agent: enroll if needed, converge, and keep the mesh converged.
    Run(RunArgs),
    /// Show this device and the peers it is connected to.
    Status(JsonFlag),
    /// Show every peer and the AllowedIPs programmed for it.
    Peers(JsonFlag),
    /// Inspect, plan or reset the kernel routes this agent installed.
    Routes(RoutesArgs),
    /// Show the relay pool, this device's slot and relay health.
    Relays(JsonFlag),
    /// Inspect, validate or print the configuration.
    Config(ConfigArgs),
    /// Show or rotate the keys in the secret store.
    Key(KeyArgs),
    /// Show or reset the persisted state.
    State(StateArgs),
    /// Show or rotate the pinned coordinator certificate.
    Trust(TrustArgs),
    /// Diagnose configuration, capabilities and routing.
    Doctor(DoctorArgs),
    /// Compute the SPKI pin of a coordinator URL.
    Pin(PinArgs),
}
