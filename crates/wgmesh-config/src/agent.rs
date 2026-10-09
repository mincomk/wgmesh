use serde::{Deserialize, Serialize};

use wgmesh_core::{AllowedIpsPolicy, RoutePrefixes, RouteTable};

use crate::validate::{
    Problem, check_absolute_dir, check_coordinator_url, check_spki, parse_allowed,
};

/// What a peer may send from.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AllowedIps {
    /// Each peer keeps its own prefixes (the default).
    #[default]
    Peer,
    /// Every peer gets the catch-all. Only meaningful with exactly one peer.
    Any,
}

/// `route.table`. `auto` and `main` mean the same thing here: we never split
/// the default route into two halves, because we never install one.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TableSetting {
    Named(String),
    Number(u32),
}

impl Default for TableSetting {
    fn default() -> Self {
        TableSetting::Named("main".to_owned())
    }
}

/// `route.prefixes`.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PrefixesSetting {
    Named(String),
    List(Vec<String>),
}

impl Default for PrefixesSetting {
    fn default() -> Self {
        PrefixesSetting::Named("auto".to_owned())
    }
}

/// `route.address`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AddressSetting {
    /// Take the tunnel address and prefix from the coordinator.
    #[default]
    #[serde(rename = "auto")]
    Auto,
    /// Take neither.
    #[serde(rename = "none")]
    None,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum FirewallMode {
    #[default]
    Off,
    Manage,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    #[default]
    Text,
    Json,
}

/// `relay.pool`.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PoolSetting {
    Named(String),
    List(Vec<String>),
}

impl Default for PoolSetting {
    fn default() -> Self {
        PoolSetting::Named("any".to_owned())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub interface: Interface,
    pub coordinator: CoordinatorSection,
    pub enrollment: Enrollment,
    pub peers: Peers,
    pub route: Route,
    pub forwarding: Forwarding,
    pub traversal: Traversal,
    pub relay: RelaySection,
    pub sync: Sync,
    pub state: State,
    pub log: Log,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Interface {
    pub name: String,
    pub mtu: u32,
    /// `0` means "any port", which is what keeps a fixed firewall rule from
    /// being needed.
    pub listen_port: u16,
    pub private_key_file: String,
    pub api_key_file: String,
}

impl Default for Interface {
    fn default() -> Self {
        Self {
            name: "wg0".to_owned(),
            mtu: 1420,
            listen_port: 0,
            private_key_file: String::new(),
            api_key_file: String::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CoordinatorSection {
    pub url: String,
    pub spki_sha256: String,
    pub network: String,
}

impl Default for CoordinatorSection {
    fn default() -> Self {
        Self {
            url: String::new(),
            spki_sha256: String::new(),
            network: "default".to_owned(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Enrollment {
    pub token_file: String,
    /// Stay `pending` until an operator approves. The cheapest safety net
    /// there is when a token leaks.
    pub wait_for_approval: bool,
}

impl Default for Enrollment {
    fn default() -> Self {
        Self {
            token_file: String::new(),
            wait_for_approval: true,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Peers {
    pub allowed_ips: AllowedIps,
    /// The one peer that carries the catch-all, by name.
    pub exit_peer: String,
}

impl Default for Peers {
    fn default() -> Self {
        Self {
            allowed_ips: AllowedIps::Peer,
            exit_peer: String::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct Route {
    pub table: TableSetting,
    pub prefixes: PrefixesSetting,
    pub metric: Option<u32>,
    /// `auto` or `none`.
    pub address: AddressSetting,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Forwarding {
    pub enabled: bool,
    /// Whether wgmesh sets the sysctl itself and puts it back on exit.
    pub sysctl: bool,
    pub firewall: FirewallMode,
}

impl Default for Forwarding {
    fn default() -> Self {
        Self {
            enabled: false,
            sysctl: true,
            firewall: FirewallMode::Off,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Traversal {
    pub punch_delay_secs: u64,
    /// The direct attempt must be shorter than a NAT mapping's life, or a
    /// failed punch takes the relay path down with it.
    pub punch_window_secs: u64,
    pub backoff_secs: Vec<u64>,
    pub keepalive_secs: u64,
    pub lan_candidates: bool,
    pub ipv6: bool,
    pub upnp: bool,
}

impl Default for Traversal {
    fn default() -> Self {
        Self {
            punch_delay_secs: 2,
            punch_window_secs: 5,
            backoff_secs: vec![30, 120, 600],
            keepalive_secs: 25,
            lan_candidates: true,
            ipv6: true,
            upnp: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct RelaySection {
    pub pool: PoolSetting,
    pub pin: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Sync {
    pub interval_secs: u64,
    pub sse: bool,
}

impl Default for Sync {
    fn default() -> Self {
        Self {
            interval_secs: 30,
            sse: true,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct State {
    pub dir: String,
}

impl Default for State {
    fn default() -> Self {
        Self {
            dir: "/var/lib/wgmesh".to_owned(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Log {
    pub level: String,
    pub format: LogFormat,
}

impl Default for Log {
    fn default() -> Self {
        Self {
            level: "info".to_owned(),
            format: LogFormat::Text,
        }
    }
}

impl Settings {
    pub fn private_key_path(&self) -> String {
        if self.interface.private_key_file.is_empty() {
            format!("{}/secrets/wg.key", self.state.dir)
        } else {
            self.interface.private_key_file.clone()
        }
    }

    pub fn api_key_path(&self) -> String {
        if self.interface.api_key_file.is_empty() {
            format!("{}/secrets/api.key", self.state.dir)
        } else {
            self.interface.api_key_file.clone()
        }
    }

    /// The routing table the kernel end will use.
    pub fn route_table(&self) -> Result<RouteTable, Problem> {
        match &self.route.table {
            TableSetting::Number(number) => Ok(RouteTable::Number(*number)),
            TableSetting::Named(name) => match name.as_str() {
                "main" | "auto" => Ok(RouteTable::Main),
                "off" => Ok(RouteTable::Unmanaged),
                other => Err(Problem::new(
                    "route.table",
                    format!(
                        "must be \"main\", \"auto\", \"off\" or a table number, not \"{other}\""
                    ),
                )),
            },
        }
    }

    /// The prefix set the kernel end will install.
    pub fn route_prefixes(&self) -> Result<RoutePrefixes, Problem> {
        match &self.route.prefixes {
            PrefixesSetting::Named(name) => match name.as_str() {
                "auto" => Ok(RoutePrefixes::Auto),
                "none" => Ok(RoutePrefixes::None),
                other => Err(Problem::new(
                    "route.prefixes",
                    format!("must be \"auto\", \"none\" or a list of CIDRs, not \"{other}\""),
                )),
            },
            PrefixesSetting::List(list) => {
                let mut parsed = Vec::with_capacity(list.len());
                for entry in list {
                    match parse_allowed(entry) {
                        Some(prefix) => parsed.push(prefix),
                        None => {
                            return Err(Problem::new(
                                "route.prefixes",
                                format!("\"{entry}\" is not a CIDR"),
                            ));
                        }
                    }
                }
                Ok(RoutePrefixes::Only(parsed))
            }
        }
    }

    /// The AllowedIPs policy, once `exit_peer` is resolved against the peers
    /// the coordinator named.
    pub fn allowed_ips_policy(
        &self,
        exit_peer: Option<wgmesh_core::DeviceId>,
        peer_count: usize,
    ) -> Result<AllowedIpsPolicy, Problem> {
        if !self.peers.exit_peer.is_empty() {
            let Some(id) = exit_peer else {
                return Err(Problem::new(
                    "peers.exit_peer",
                    format!(
                        "\"{}\" is not a device in this network",
                        self.peers.exit_peer
                    ),
                ));
            };
            return Ok(AllowedIpsPolicy::ExitPeer(id));
        }
        match self.peers.allowed_ips {
            AllowedIps::Peer => Ok(AllowedIpsPolicy::Peer),
            AllowedIps::Any => {
                if peer_count != 1 {
                    return Err(Problem::new(
                        "peers.allowed_ips",
                        format!(
                            "\"any\" gives every peer the catch-all, which only makes sense with \
                             one peer (there are {peer_count}) — name peers.exit_peer instead"
                        ),
                    ));
                }
                Ok(AllowedIpsPolicy::Any)
            }
        }
    }

    /// Every problem in the settings, collected rather than short-circuited.
    pub fn validate(&self) -> Vec<Problem> {
        let mut problems = Vec::new();
        check_coordinator_url(&self.coordinator.url, "coordinator.url", &mut problems);
        check_spki(
            &self.coordinator.spki_sha256,
            "coordinator.spki_sha256",
            &mut problems,
        );
        check_absolute_dir(&self.state.dir, "state.dir", &mut problems);

        if let Err(problem) = self.route_table() {
            problems.push(problem);
        }
        if let Err(problem) = self.route_prefixes() {
            problems.push(problem);
        }

        if self.interface.name.is_empty() || self.interface.name.len() > 15 {
            problems.push(Problem::new(
                "interface.name",
                "must be a Linux interface name (1–15 characters)",
            ));
        }
        if self.interface.mtu < 576 || self.interface.mtu > 65_535 {
            problems.push(Problem::new(
                "interface.mtu",
                "must be between 576 and 65535",
            ));
        }
        if self.traversal.punch_window_secs == 0 {
            problems.push(Problem::new(
                "traversal.punch_window_secs",
                "must be greater than zero",
            ));
        }
        if self.traversal.punch_window_secs >= self.traversal.keepalive_secs {
            problems.push(Problem::new(
                "traversal.punch_window_secs",
                format!(
                    "must be shorter than traversal.keepalive_secs ({}), or a failed punch \
                     outlives the relay mapping it falls back to",
                    self.traversal.keepalive_secs
                ),
            ));
        }
        if self.traversal.backoff_secs.is_empty() {
            problems.push(Problem::new(
                "traversal.backoff_secs",
                "must not be empty — a symmetric NAT would retry forever",
            ));
        }
        let mut previous = 0;
        for value in &self.traversal.backoff_secs {
            if *value <= previous {
                problems.push(Problem::new(
                    "traversal.backoff_secs",
                    "must strictly increase",
                ));
                break;
            }
            previous = *value;
        }
        if self.sync.interval_secs == 0 {
            problems.push(Problem::new(
                "sync.interval_secs",
                "must be greater than zero",
            ));
        }
        if !matches!(self.relay.pool, PoolSetting::Named(ref name) if name == "any" || name == "operator-only")
            && !matches!(self.relay.pool, PoolSetting::List(_))
        {
            problems.push(Problem::new(
                "relay.pool",
                "must be \"any\", \"operator-only\" or a list of relay names",
            ));
        }
        problems
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use wgmesh_core::Allowed;

    #[test]
    fn a_five_line_file_is_a_complete_configuration() {
        let settings: Settings = crate::parse(
            r#"
            [coordinator]
            url = "https://coord.example.com"
            spki_sha256 = "9f2c9f2c9f2c9f2c9f2c9f2c9f2c9f2c9f2c9f2c9f2c9f2c9f2c9f2c9f2c9f2c"
            "#,
        )
        .unwrap();
        assert_eq!(settings.interface.name, "wg0");
        assert_eq!(settings.interface.mtu, 1420);
        assert_eq!(settings.sync.interval_secs, 30);
        assert!(settings.sync.sse);
        assert!(settings.enrollment.wait_for_approval);
        assert_eq!(settings.traversal.punch_window_secs, 5);
        assert_eq!(settings.route_table().unwrap(), RouteTable::Main);
        assert_eq!(settings.route_prefixes().unwrap(), RoutePrefixes::Auto);
        assert!(settings.validate().is_empty());
    }

    #[test]
    fn the_routing_table_accepts_a_number_and_off() {
        let mut settings = Settings::default();
        settings.route.table = TableSetting::Number(51820);
        assert_eq!(settings.route_table().unwrap(), RouteTable::Number(51820));
        settings.route.table = TableSetting::Named("off".to_owned());
        assert_eq!(settings.route_table().unwrap(), RouteTable::Unmanaged);
        settings.route.table = TableSetting::Named("sideways".to_owned());
        assert!(settings.route_table().is_err());
    }

    #[test]
    fn the_prefix_list_parses_and_a_bad_entry_is_named() {
        let mut settings = Settings::default();
        settings.route.prefixes =
            PrefixesSetting::List(vec!["10.77.0.0/16".to_owned(), "192.168.5.0/24".to_owned()]);
        assert_eq!(
            settings.route_prefixes().unwrap(),
            RoutePrefixes::Only(vec![
                Allowed::V4([10, 77, 0, 0], 16),
                Allowed::V4([192, 168, 5, 0], 24)
            ])
        );
        settings.route.prefixes = PrefixesSetting::List(vec!["nonsense".to_owned()]);
        assert!(settings.route_prefixes().is_err());
    }

    #[test]
    fn an_unknown_key_is_refused_rather_than_ignored() {
        let result: Result<Settings, _> = crate::parse(
            r#"
            [route]
            tabel = "off"
            "#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn a_punch_window_longer_than_the_keepalive_is_refused() {
        let mut settings = Settings::default();
        settings.coordinator.url = "https://coord.example.com".to_owned();
        settings.coordinator.spki_sha256 = "a".repeat(64);
        settings.traversal.punch_window_secs = 40;
        settings.traversal.keepalive_secs = 25;
        let problems = settings.validate();
        assert!(
            problems
                .iter()
                .any(|problem| problem.field == "traversal.punch_window_secs")
        );
    }

    #[test]
    fn any_policy_with_two_peers_is_refused_and_names_the_alternative() {
        let mut settings = Settings::default();
        settings.peers.allowed_ips = AllowedIps::Any;
        let problem = settings.allowed_ips_policy(None, 2).unwrap_err();
        assert!(problem.message.contains("exit_peer"));
        assert_eq!(
            settings.allowed_ips_policy(None, 1).unwrap(),
            AllowedIpsPolicy::Any
        );
    }

    #[test]
    fn exit_peer_resolves_to_an_id_or_is_refused() {
        let mut settings = Settings::default();
        settings.peers.exit_peer = "gw".to_owned();
        assert_eq!(
            settings
                .allowed_ips_policy(Some(wgmesh_core::DeviceId(3)), 4)
                .unwrap(),
            AllowedIpsPolicy::ExitPeer(wgmesh_core::DeviceId(3))
        );
        assert!(settings.allowed_ips_policy(None, 4).is_err());
    }

    #[test]
    fn the_key_paths_default_under_the_state_directory() {
        let settings = Settings::default();
        assert_eq!(
            settings.private_key_path(),
            "/var/lib/wgmesh/secrets/wg.key"
        );
        assert_eq!(settings.api_key_path(), "/var/lib/wgmesh/secrets/api.key");
        let mut settings = Settings::default();
        settings.interface.api_key_file = "/run/credentials/api-key".to_owned();
        assert_eq!(settings.api_key_path(), "/run/credentials/api-key");
    }

    #[test]
    fn settings_round_trip_through_toml_with_every_default_spelled_out() {
        let text = crate::render(&Settings::default());
        let parsed: Settings = crate::parse(&text).unwrap();
        assert_eq!(parsed, Settings::default());
    }
}
