// The documents `wgmesh` prints, and the human form of the same facts.
//
// Every `--json` command prints one of these and nothing else on stdout, so a pipeline can read
// it with `jq` and never has to skip a log line.

use serde::Serialize;

use crate::output;

/// `wgmesh status`.
#[derive(Clone, Debug, Serialize)]
pub struct StatusView {
    /// The document schema.
    pub schema: u32,
    /// The device id the coordinator assigned, when there is one.
    pub device_id: Option<String>,
    /// The network this device joined.
    pub network: String,
    /// The interface the agent owns.
    pub interface: String,
    /// The tunnel address, `address/prefix`.
    pub tunnel_ip: String,
    /// The coordination plane as this device knows it.
    pub coordinator: CoordinatorView,
    /// The relay this device was paired with.
    pub relay: Option<RelayView>,
    /// The peers.
    pub peers: Vec<PeerView>,
}

/// The coordination plane, from this device's point of view.
#[derive(Clone, Debug, Serialize)]
pub struct CoordinatorView {
    /// The configured URL.
    pub url: String,
    /// The pinned SPKI, as 64 hex characters.
    pub spki_sha256: String,
    /// When the configuration was last converged.
    pub last_sync_unix: Option<u64>,
    /// The configuration version last converged.
    pub config_version: u64,
}

/// The relay this device was paired with.
#[derive(Clone, Debug, Serialize)]
pub struct RelayView {
    /// The relay's id.
    pub assigned: String,
    /// The UDP port this device's slot listens on.
    pub slot_port: u16,
}

/// One peer.
#[derive(Clone, Debug, Serialize)]
pub struct PeerView {
    /// The device id.
    pub id: String,
    /// The name the peer is known by.
    pub name: String,
    /// The peer's WireGuard public key, base64.
    pub wg_pubkey: String,
    /// The endpoint, when one is known.
    pub endpoint: Option<String>,
    /// `unknown`, `relayed` or `direct`.
    pub path: String,
    /// The last handshake, in Unix seconds.
    pub last_handshake_unix: Option<u64>,
    /// The last handshake, in seconds ago.
    pub handshake_age_secs: Option<u64>,
    /// The AllowedIPs programmed for this peer.
    pub allowed_ips: Vec<String>,
    /// Bytes received, when the kernel can say.
    pub rx_bytes: Option<u64>,
    /// Bytes sent, when the kernel can say.
    pub tx_bytes: Option<u64>,
}

impl StatusView {
    /// The human form.
    pub fn human(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "device       {}  (network {})\n",
            self.device_id.as_deref().unwrap_or("not enrolled"),
            self.network
        ));
        out.push_str(&format!(
            "interface    {}  {}\n",
            self.interface, self.tunnel_ip
        ));
        out.push_str(&format!(
            "coordinator  {}  last sync {}\n",
            self.coordinator.url,
            self.coordinator
                .last_sync_unix
                .map(|seconds| seconds.to_string())
                .unwrap_or_else(|| "never".to_string())
        ));
        match &self.relay {
            Some(relay) => out.push_str(&format!(
                "relay        {}  slot {}\n",
                relay.assigned, relay.slot_port
            )),
            None => out.push_str("relay        -\n"),
        }
        out.push_str(&format!("peers        {}\n", self.peers.len()));
        for peer in &self.peers {
            out.push_str(&format!(
                "  {}  {}  {}  {}  {}  handshake {}  rx {} tx {}\n",
                peer.name,
                peer.id,
                output::prefixes_text(&peer.allowed_ips),
                peer.path,
                peer.endpoint.as_deref().unwrap_or("-"),
                peer.handshake_age_secs
                    .map(output::age)
                    .unwrap_or_else(|| "never".to_string()),
                peer.rx_bytes
                    .map(output::bytes)
                    .unwrap_or_else(|| "-".to_string()),
                peer.tx_bytes
                    .map(output::bytes)
                    .unwrap_or_else(|| "-".to_string()),
            ));
        }
        out
    }
}

/// `wgmesh peers`.
#[derive(Clone, Debug, Serialize)]
pub struct PeersView {
    /// The document schema.
    pub schema: u32,
    /// `peer`, `any` or `exit-peer`.
    pub policy: String,
    /// The peer that carries the catch-all, when one does.
    pub exit_peer: Option<String>,
    /// The peers.
    pub peers: Vec<PeerView>,
}

impl PeersView {
    /// The human form.
    pub fn human(&self) -> String {
        let mut out = format!(
            "policy  {}{}\n",
            self.policy,
            self.exit_peer
                .as_deref()
                .map(|peer| format!("  exit-peer {peer}"))
                .unwrap_or_default()
        );
        for peer in &self.peers {
            out.push_str(&format!(
                "  {}  {}  path {}  allowed {}\n",
                peer.name,
                peer.id,
                peer.path,
                peer.allowed_ips.join(", ")
            ));
        }
        out
    }
}

/// `wgmesh routes`.
#[derive(Clone, Debug, Serialize)]
pub struct RoutesView {
    /// The document schema.
    pub schema: u32,
    /// The routing table the routes are installed into.
    pub table: String,
    /// The marker our routes carry.
    pub proto: String,
    /// The routes.
    pub routes: Vec<RouteView>,
}

/// One installed route.
#[derive(Clone, Debug, Serialize)]
pub struct RouteView {
    /// The destination prefix.
    pub prefix: String,
    /// The routing table.
    pub table: String,
    /// The metric, when one was set.
    pub metric: Option<u32>,
}

/// `wgmesh relays`.
#[derive(Clone, Debug, Serialize)]
pub struct RelaysView {
    /// The document schema.
    pub schema: u32,
    /// The relay pool setting.
    pub pool: String,
    /// The relay this device is paired with.
    pub assigned: Option<String>,
    /// This device's slot port.
    pub slot_port: Option<u16>,
    /// Every relay this device knows a slot on.
    pub slots: Vec<RelaySlotView>,
}

/// One relay slot.
#[derive(Clone, Debug, Serialize)]
pub struct RelaySlotView {
    /// The relay's id.
    pub relay: String,
    /// The UDP port.
    pub port: u16,
}

/// `wgmesh doctor`.
#[derive(Clone, Debug, Serialize)]
pub struct DoctorView {
    /// The document schema.
    pub schema: u32,
    /// What was checked, in order.
    pub checks: Vec<CheckView>,
}

/// One diagnostic check.
#[derive(Clone, Debug, Serialize)]
pub struct CheckView {
    /// The name of the check.
    pub name: String,
    /// `ok`, `warn` or `fail`.
    pub status: String,
    /// What the check found.
    pub detail: String,
}

impl DoctorView {
    /// The human form.
    pub fn human(&self) -> String {
        let mut out = String::new();
        for check in &self.checks {
            out.push_str(&format!(
                "{:<8} {:<24} {}\n",
                check.status, check.name, check.detail
            ));
        }
        out
    }

    /// Whether any check failed.
    pub fn failed(&self) -> bool {
        self.checks.iter().any(|check| check.status == "fail")
    }
}

/// `wgmesh key show`.
#[derive(Clone, Debug, Serialize)]
pub struct KeyView {
    /// The document schema.
    pub schema: u32,
    /// The private key, base64, exactly as `wg genkey` writes it.
    pub private_key: String,
    /// The public key, base64, exactly as `wg pubkey` writes it.
    pub public_key: String,
}

/// `wgmesh trust show`.
#[derive(Clone, Debug, Serialize)]
pub struct TrustView {
    /// The document schema.
    pub schema: u32,
    /// The pin from the configuration, 64 hex characters.
    pub configured: String,
    /// The pin the state holds, 64 hex characters.
    pub pinned: Option<String>,
    /// Whether the two agree.
    pub matches: bool,
}

impl TrustView {
    /// The human form.
    pub fn human(&self) -> String {
        format!(
            "configured  {}\npinned      {}\nmatch       {}\n",
            self.configured,
            self.pinned.as_deref().unwrap_or("-"),
            if self.matches { "yes" } else { "no" }
        )
    }
}

/// `wgmesh state show`.
#[derive(Clone, Debug, Serialize)]
pub struct StateView {
    /// The document schema.
    pub schema: u32,
    /// The persisted state, when there is one.
    pub state: Option<serde_json::Value>,
}

/// `wgmesh join`.
#[derive(Clone, Debug, Serialize)]
pub struct JoinView {
    /// The document schema.
    pub schema: u32,
    /// The device id the coordinator assigned.
    pub device_id: String,
    /// The addresses the mesh gave this device.
    pub addresses: Vec<String>,
    /// The relay this device was paired with.
    pub relay: Option<String>,
    /// The configuration version the join came with.
    pub config_version: u64,
    /// How many peers the coordinator said to expect.
    pub peers: usize,
}

/// `wgmesh config check`.
#[derive(Clone, Debug, Serialize)]
pub struct CheckReportView {
    /// The document schema.
    pub schema: u32,
    /// The problems that make the configuration unusable.
    pub errors: Vec<ProblemView>,
    /// The problems that are worth knowing about.
    pub warnings: Vec<ProblemView>,
}

/// One configuration problem.
#[derive(Clone, Debug, Serialize)]
pub struct ProblemView {
    /// The configuration path the problem is about.
    pub path: String,
    /// What is wrong.
    pub message: String,
}

/// `wgmesh config show` and `config defaults`.
#[derive(Clone, Debug, Serialize)]
pub struct ConfigView {
    /// The document schema.
    pub schema: u32,
    /// The effective settings.
    pub settings: serde_json::Value,
}
