use std::path::Path;

use wgmesh_core::route::{RoutingError, desired_routes};

use crate::agent::Settings;
use crate::coordinator::CoordinatorSettings;
use crate::relay::RelaySettings;
use crate::route::{AllowedIpsSetting, Prefix, RouteSection, RouteTableSetting};

/// The length of a SHA-256 digest in hex characters.
pub const SHA256_HEX_LEN: usize = 64;

/// The longest interface name the kernel accepts, without its terminator.
pub const IFNAMSIZ_MAX: usize = 15;

/// How serious a validation problem is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Severity {
    /// The configuration cannot work as written.
    Error,
    /// The configuration works, but the operator probably does not mean it.
    Warning,
}

impl Severity {
    /// The word this severity prints as.
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Error => "error",
            Severity::Warning => "warning",
        }
    }
}

/// One thing that is wrong with a configuration, named by its path in the schema.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Problem {
    pub path: String,
    pub severity: Severity,
    pub message: String,
}

impl Problem {
    /// A problem the daemon cannot start with.
    pub fn error(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            severity: Severity::Error,
            message: message.into(),
        }
    }

    /// A problem worth saying out loud but not worth refusing to start.
    pub fn warning(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            severity: Severity::Warning,
            message: message.into(),
        }
    }

    /// Whether this problem prevents the daemon from starting.
    pub fn is_error(&self) -> bool {
        self.severity == Severity::Error
    }
}

/// Whether any of these problems prevents the daemon from starting.
pub fn has_errors(problems: &[Problem]) -> bool {
    problems.iter().any(Problem::is_error)
}

/// Render problems one per line, in the form `severity: path: message`.
pub fn render(problems: &[Problem]) -> String {
    let mut rendered = String::new();
    for problem in problems {
        rendered.push_str(problem.severity.as_str());
        rendered.push_str(": ");
        rendered.push_str(&problem.path);
        rendered.push_str(": ");
        rendered.push_str(&problem.message);
        rendered.push('\n');
    }
    rendered
}

/// Whether a string is a SHA-256 digest written as 64 hex characters.
pub fn is_sha256_hex(text: &str) -> bool {
    text.len() == SHA256_HEX_LEN && text.chars().all(|digit| digit.is_ascii_hexdigit())
}

/// Whether a coordinator URL is one this product is willing to talk to.
///
/// It must be `https`, it must name a host, and it must not carry credentials: the
/// agent authenticates with a key, never with a password in a URL.
pub fn check_coordinator_url(url: &str) -> Result<(), String> {
    if url.is_empty() {
        return Err("a coordinator URL is required".to_string());
    }
    if url.chars().any(char::is_whitespace) {
        return Err("a coordinator URL must not contain whitespace".to_string());
    }
    let Some((scheme, rest)) = url.split_once("://") else {
        return Err(
            "a coordinator URL must carry a scheme, for example https://wgmesh.example.com"
                .to_string(),
        );
    };
    if !scheme.eq_ignore_ascii_case("https") {
        return Err(format!("a coordinator URL must use https, not {scheme}"));
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.is_empty() {
        return Err("a coordinator URL must name a host".to_string());
    }
    if authority.contains('@') {
        return Err(
            "a coordinator URL must not carry userinfo; the agent authenticates with a key"
                .to_string(),
        );
    }
    let host = authority.split(':').next().unwrap_or_default();
    if host.is_empty() {
        return Err("a coordinator URL must name a host".to_string());
    }
    Ok(())
}

/// Every problem the agent configuration has, collected rather than short circuited.
pub fn validate(settings: &Settings) -> Vec<Problem> {
    let mut problems = Vec::new();
    check_endpoint(
        "coordinator",
        &settings.coordinator.url,
        &settings.coordinator.spki_sha256,
        &mut problems,
    );
    if settings.coordinator.network.trim().is_empty() {
        problems.push(Problem::error(
            "coordinator.network",
            "the network name must not be empty",
        ));
    }
    check_interface(settings, &mut problems);
    check_state_dir("state.dir", settings.state.dir.as_path(), &mut problems);
    check_key_files(settings, &mut problems);
    check_traversal(settings, &mut problems);
    check_route(&settings.route, &mut problems);
    check_peers(settings, &mut problems);
    check_relay_pool(
        "relay",
        &settings.relay.pool,
        &settings.relay.pin,
        &mut problems,
    );
    if settings.sync.interval_secs == 0 {
        problems.push(Problem::error(
            "sync.interval_secs",
            "a sync interval of zero is not a schedule",
        ));
    }
    if settings.enrollment.token_file.trim().is_empty() && !settings.enrollment.wait_for_approval {
        problems.push(Problem::warning(
            "enrollment",
            "no join token file and no approval wait: the coordinator must auto approve this device",
        ));
    }
    problems
}

/// Every problem the relay configuration has.
pub fn validate_relay(settings: &RelaySettings) -> Vec<Problem> {
    let mut problems = Vec::new();
    check_endpoint(
        "coordinator",
        &settings.coordinator.url,
        &settings.coordinator.spki_sha256,
        &mut problems,
    );
    check_state_dir("state.dir", settings.state.dir.as_path(), &mut problems);
    if settings.relay.listen.trim().is_empty() {
        problems.push(Problem::error(
            "relay.listen",
            "a listen address is required",
        ));
    } else if settings.relay.listen.parse::<std::net::IpAddr>().is_err() {
        problems.push(Problem::error(
            "relay.listen",
            format!(
                "\"{}\" is not an IP address; the relay listens on one",
                settings.relay.listen
            ),
        ));
    }
    let [low, high] = settings.relay.port_range;
    if low == 0 || high == 0 {
        problems.push(Problem::error(
            "relay.port_range",
            "a port number of zero is not a slot",
        ));
    }
    if low > high {
        problems.push(Problem::error(
            "relay.port_range",
            format!("the range {low}-{high} runs backwards"),
        ));
    }
    let span = u32::from(high.saturating_sub(low)) + 1;
    if span > 4096 {
        problems.push(Problem::warning(
            "relay.port_range",
            format!("a range of {span} ports opens more firewall than a relay needs"),
        ));
    }
    if settings.relay.keyset_ttl_secs == 0 {
        problems.push(Problem::error(
            "relay.keyset_ttl_secs",
            "a key set that expires immediately cannot survive a coordinator restart",
        ));
    }
    if settings.limits.pps_per_slot == 0 {
        problems.push(Problem::error(
            "limits.pps_per_slot",
            "a per slot limit of zero drops every packet",
        ));
    }
    if settings.limits.mbit_per_slot == 0 {
        problems.push(Problem::error(
            "limits.mbit_per_slot",
            "a per slot limit of zero drops every packet",
        ));
    }
    problems
}

/// Every problem the coordinator configuration has.
pub fn validate_coordinator(settings: &CoordinatorSettings) -> Vec<Problem> {
    let mut problems = Vec::new();
    if settings.api.listen.parse::<std::net::SocketAddr>().is_err() {
        problems.push(Problem::error(
            "api.listen",
            format!("{} is not an address to listen on", settings.api.listen),
        ));
    }
    if !settings.api.public_url.trim().is_empty()
        && let Err(reason) = check_coordinator_url(&settings.api.public_url)
    {
        problems.push(Problem::error("api.public_url", reason));
    }
    if settings.database.url.trim().is_empty() {
        problems.push(Problem::error("database.url", "a database URL is required"));
    } else if !settings.database.url.starts_with("sqlite:") {
        problems.push(Problem::error(
            "database.url",
            "the coordinator keeps a SQLite database, so the URL must start with sqlite:",
        ));
    }
    if settings.database.max_connections == 0 {
        problems.push(Problem::error(
            "database.max_connections",
            "zero connections is not a pool",
        ));
    }
    if settings.policy.max_devices_per_network == 0 {
        problems.push(Problem::error(
            "policy.max_devices_per_network",
            "a network with no devices is not a network",
        ));
    }
    if settings.relay.heartbeat_timeout_secs == 0 {
        problems.push(Problem::error(
            "relay.heartbeat_timeout_secs",
            "a heartbeat timeout of zero declares every relay dead",
        ));
    }
    if settings.relay.reassign_after_misses == 0 {
        problems.push(Problem::error(
            "relay.reassign_after_misses",
            "reassigning after zero missed heartbeats is not a policy",
        ));
    }
    if settings.relay.keyset_ttl_secs == 0 {
        problems.push(Problem::error(
            "relay.keyset_ttl_secs",
            "a key set that expires immediately cannot survive a relay restart",
        ));
    }
    problems
}

fn check_endpoint(section: &str, url: &str, spki: &str, problems: &mut Vec<Problem>) {
    let url_path = format!("{section}.url");
    if url.trim().is_empty() {
        problems.push(Problem::error(url_path, "a coordinator URL is required"));
    } else if let Err(reason) = check_coordinator_url(url.trim()) {
        problems.push(Problem::error(url_path, reason));
    }
    let spki_path = format!("{section}.spki_sha256");
    let pin = spki.trim();
    if pin.is_empty() {
        problems.push(Problem::error(
            spki_path,
            "an SPKI pin is required; the coordinator is never trusted by default",
        ));
    } else if !is_sha256_hex(pin) {
        problems.push(Problem::error(
            spki_path,
            format!(
                "an SPKI pin is {SHA256_HEX_LEN} hex characters, and {} were given",
                pin.len()
            ),
        ));
    }
}

fn check_interface(settings: &Settings, problems: &mut Vec<Problem>) {
    let name = settings.interface.name.as_str();
    if name.is_empty() {
        problems.push(Problem::error(
            "interface.name",
            "an interface name is required",
        ));
    } else {
        if name.len() > IFNAMSIZ_MAX {
            problems.push(Problem::error(
                "interface.name",
                format!(
                    "the kernel accepts {IFNAMSIZ_MAX} characters, and {name} has {}",
                    name.len()
                ),
            ));
        }
        if !name
            .chars()
            .all(|letter| letter.is_ascii_alphanumeric() || "_-.".contains(letter))
        {
            problems.push(Problem::error(
                "interface.name",
                format!("{name} is not a valid interface name"),
            ));
        }
    }
    if settings.interface.mtu < 576 || settings.interface.mtu > 65_535 {
        problems.push(Problem::error(
            "interface.mtu",
            format!(
                "an MTU of {} is outside the range 576..=65535",
                settings.interface.mtu
            ),
        ));
    }
}

fn check_state_dir(path: &str, dir: &Path, problems: &mut Vec<Problem>) {
    if dir.as_os_str().is_empty() {
        problems.push(Problem::error(path, "a state directory is required"));
    } else if !dir.is_absolute() {
        problems.push(Problem::error(
            path,
            format!(
                "{} is relative; the state directory must be absolute so the daemon's working directory cannot move it",
                dir.display()
            ),
        ));
    }
}

fn check_key_files(settings: &Settings, problems: &mut Vec<Problem>) {
    let files = [
        (
            "interface.private_key_file",
            &settings.interface.private_key_file,
        ),
        ("interface.api_key_file", &settings.interface.api_key_file),
    ];
    for (path, file) in files {
        let file = file.trim();
        if file.is_empty() {
            continue;
        }
        if !Path::new(file).starts_with(&settings.state.dir) {
            problems.push(Problem::warning(
                path,
                format!(
                    "{file} is outside state.dir ({}); that is right only when something else provisions it",
                    settings.state.dir.display()
                ),
            ));
        }
    }
}

fn check_traversal(settings: &Settings, problems: &mut Vec<Problem>) {
    let traversal = &settings.traversal;
    if traversal.punch_window_secs >= traversal.keepalive_secs {
        problems.push(Problem::error(
            "traversal.punch_window_secs",
            format!(
                "the direct attempt window ({}s) must be shorter than traversal.keepalive_secs ({}s), or the relay mapping expires mid attempt",
                traversal.punch_window_secs, traversal.keepalive_secs
            ),
        ));
    }
    if traversal.backoff_secs.is_empty() {
        problems.push(Problem::error(
            "traversal.backoff_secs",
            "at least one backoff step is required",
        ));
    } else {
        if traversal.backoff_secs.contains(&0) {
            problems.push(Problem::error(
                "traversal.backoff_secs",
                "a backoff step of zero retries as fast as the loop runs",
            ));
        }
        for pair in traversal.backoff_secs.windows(2) {
            if pair[1] <= pair[0] {
                problems.push(Problem::error(
                    "traversal.backoff_secs",
                    format!(
                        "the backoff must increase, and {} follows {}",
                        pair[1], pair[0]
                    ),
                ));
            }
        }
    }
}

fn check_route(route: &RouteSection, problems: &mut Vec<Problem>) {
    let prefixes = route.prefixes.to_core();
    let table = route.table.to_core();
    if let Err(error) = desired_routes(&[], &[], &prefixes, table, route.metric()) {
        problems.push(Problem::error(
            "route.prefixes",
            describe_routing_error(&error),
        ));
    }
}

fn check_peers(settings: &Settings, problems: &mut Vec<Problem>) {
    if settings.peers.exit_peer.trim().is_empty() {
        return;
    }
    if settings.peers.allowed_ips == AllowedIpsSetting::Any {
        problems.push(Problem::error(
            "peers.allowed_ips",
            "allowed_ips = \"any\" and peers.exit_peer both decide who carries the catch-all; pick one",
        ));
    }
}

fn check_relay_pool(
    section: &str,
    pool: &crate::RelayPoolSetting,
    pin: &str,
    problems: &mut Vec<Problem>,
) {
    if let crate::RelayPoolSetting::Only(names) = pool {
        if names.is_empty() {
            problems.push(Problem::error(
                format!("{section}.pool"),
                "an empty relay pool accepts no relay at all",
            ));
        }
        if !pin.trim().is_empty() && !names.iter().any(|name| name == pin.trim()) {
            problems.push(Problem::warning(
                format!("{section}.pin"),
                format!("the pinned relay {pin} is not in the pool"),
            ));
        }
    }
}

fn describe_routing_error(error: &RoutingError) -> String {
    match error {
        RoutingError::CatchAllPrefix(prefix) => format!(
            "the default route ({}) must never be installed; express a default through peers.exit_peer instead",
            Prefix::from_core(prefix.clone())
        ),
        RoutingError::PrefixesWithUnmanagedTable(count) => format!(
            "route.table = \"off\" installs no routes, but route.prefixes lists {count}; drop one of the two"
        ),
        RoutingError::AnyPolicyNeedsOnePeer(count) => {
            format!("allowed_ips = \"any\" needs exactly one peer, and {count} are configured")
        }
        RoutingError::UnknownExitPeer(device) => {
            format!("exit_peer does not name a configured peer ({device:?})")
        }
    }
}

/// Whether a route table setting leaves the kernel table alone.
pub fn routes_are_unmanaged(table: RouteTableSetting) -> bool {
    matches!(table, RouteTableSetting::Unmanaged)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::route::{RoutePrefixesSetting, RouteTableSetting};

    fn prefix(text: &str) -> Prefix {
        match Prefix::from_str(text) {
            Ok(prefix) => prefix,
            Err(error) => panic!("{text}: {error}"),
        }
    }

    fn valid() -> Settings {
        let mut settings = Settings::default();
        settings.coordinator.url = "https://wgmesh.example.com".to_string();
        settings.coordinator.spki_sha256 =
            "9f2c000000000000000000000000000000000000000000000000000000000000".to_string();
        settings
    }

    fn paths(problems: &[Problem]) -> Vec<String> {
        problems
            .iter()
            .map(|problem| problem.path.clone())
            .collect()
    }

    #[test]
    fn a_clean_configuration_has_nothing_to_say() {
        let problems = validate(&valid());
        assert_eq!(problems, Vec::new(), "unexpected: {problems:?}");
    }

    #[test]
    fn every_problem_is_reported_at_once() {
        let mut settings = valid();
        settings.coordinator.spki_sha256 = "not-a-pin".to_string();
        settings.route.table = RouteTableSetting::Unmanaged;
        settings.route.prefixes =
            RoutePrefixesSetting::Only(vec![prefix("10.77.0.0/16"), prefix("192.168.5.0/24")]);
        settings.traversal.backoff_secs = vec![120, 30];

        let problems = validate(&settings);
        assert!(has_errors(&problems), "no error was reported");
        assert_eq!(
            problems.len(),
            3,
            "expected the pin, the table/prefix pair and the backoff, got {problems:?}"
        );
        let reported = paths(&problems);
        assert!(reported.contains(&"coordinator.spki_sha256".to_string()));
        assert!(reported.contains(&"route.prefixes".to_string()));
        assert!(reported.contains(&"traversal.backoff_secs".to_string()));
        let rendered = render(&problems);
        assert!(rendered.contains("route.table = \"off\""));
        assert!(rendered.contains("64 hex characters"));
        assert!(rendered.contains("the backoff must increase"));
    }

    #[test]
    fn a_pin_that_is_not_a_digest_is_rejected() {
        let mut settings = valid();
        for pin in ["9f2c", "zzzz", ""] {
            settings.coordinator.spki_sha256 = pin.to_string();
            let problems = validate(&settings);
            assert!(
                paths(&problems).contains(&"coordinator.spki_sha256".to_string()),
                "{pin} was accepted as a pin"
            );
        }
        let mut upper = valid();
        upper.coordinator.spki_sha256 = upper.coordinator.spki_sha256.to_uppercase();
        assert!(
            validate(&upper).is_empty(),
            "an uppercase pin is still a pin"
        );
    }

    #[test]
    fn a_url_that_is_not_https_or_carries_userinfo_is_rejected() {
        assert!(check_coordinator_url("https://wgmesh.example.com").is_ok());
        assert!(check_coordinator_url("https://wgmesh.example.com:8443/base").is_ok());
        for url in [
            "http://wgmesh.example.com",
            "https://user:pass@wgmesh.example.com",
            "https://",
            "https://:8443",
            "wgmesh.example.com",
            "https://wgmesh example.com",
        ] {
            assert!(
                check_coordinator_url(url).is_err(),
                "{url} was accepted as a coordinator URL"
            );
        }
    }

    #[test]
    fn a_missing_url_and_a_missing_pin_are_both_reported() {
        let problems = validate(&Settings::default());
        let reported = paths(&problems);
        assert!(reported.contains(&"coordinator.url".to_string()));
        assert!(reported.contains(&"coordinator.spki_sha256".to_string()));
    }

    #[test]
    fn a_punch_window_that_outlasts_the_keepalive_is_rejected() {
        let mut settings = valid();
        settings.traversal.punch_window_secs = 25;
        settings.traversal.keepalive_secs = 25;
        assert!(
            paths(&validate(&settings)).contains(&"traversal.punch_window_secs".to_string()),
            "a window as long as the keepalive was accepted"
        );
    }

    #[test]
    fn an_empty_or_flat_backoff_is_rejected() {
        let mut settings = valid();
        settings.traversal.backoff_secs = Vec::new();
        assert!(paths(&validate(&settings)).contains(&"traversal.backoff_secs".to_string()));

        let mut flat = valid();
        flat.traversal.backoff_secs = vec![30, 30];
        assert!(paths(&validate(&flat)).contains(&"traversal.backoff_secs".to_string()));

        let mut zero = valid();
        zero.traversal.backoff_secs = vec![0, 30];
        assert!(paths(&validate(&zero)).contains(&"traversal.backoff_secs".to_string()));
    }

    #[test]
    fn a_relative_state_directory_is_rejected() {
        let mut settings = valid();
        settings.state.dir = std::path::PathBuf::from("var/lib/wgmesh");
        assert!(paths(&validate(&settings)).contains(&"state.dir".to_string()));
    }

    #[test]
    fn a_key_file_outside_the_state_directory_is_warned_about_not_refused() {
        let mut settings = valid();
        settings.interface.private_key_file = "/run/secrets/wgmesh/wg.key".to_string();
        let problems = validate(&settings);
        assert!(
            !has_errors(&problems),
            "a provisioned key path is not an error"
        );
        assert!(paths(&problems).contains(&"interface.private_key_file".to_string()));

        let mut inside = valid();
        inside.interface.private_key_file = "/var/lib/wgmesh/secrets/wg.key".to_string();
        assert!(validate(&inside).is_empty());
    }

    #[test]
    fn the_default_route_is_refused_in_the_prefix_list() {
        let mut settings = valid();
        settings.route.prefixes =
            RoutePrefixesSetting::Only(vec![prefix("10.77.0.0/16"), prefix("0.0.0.0/0")]);
        let problems = validate(&settings);
        assert!(has_errors(&problems));
        assert!(render(&problems).contains("peers.exit_peer"));
    }

    #[test]
    fn a_default_route_is_refused_however_its_host_bits_are_written() {
        // The kernel masks the bits past the prefix length, so these are the same route.
        for text in ["10.0.0.0/0", "203.0.113.9/0", "fd00::/0"] {
            let mut settings = valid();
            settings.route.prefixes = RoutePrefixesSetting::Only(vec![prefix(text)]);
            let problems = validate(&settings);
            assert!(
                has_errors(&problems),
                "{text} was accepted as a prefix list"
            );
            assert!(render(&problems).contains("route.prefixes"));
        }
    }

    #[test]
    fn an_unmanaged_table_with_a_prefix_list_is_refused() {
        let mut settings = valid();
        settings.route.table = RouteTableSetting::Unmanaged;
        settings.route.address = crate::AddressSetting::None;
        assert!(
            validate(&settings).is_empty(),
            "auto prefixes with off is a valid pair"
        );

        settings.route.prefixes = RoutePrefixesSetting::Only(vec![prefix("10.77.0.0/16")]);
        assert!(has_errors(&validate(&settings)));
    }

    #[test]
    fn asking_for_two_ways_to_carry_the_catch_all_is_refused() {
        let mut settings = valid();
        settings.peers.allowed_ips = AllowedIpsSetting::Any;
        settings.peers.exit_peer = "gateway".to_string();
        assert!(paths(&validate(&settings)).contains(&"peers.allowed_ips".to_string()));
    }

    #[test]
    fn an_empty_relay_pool_is_refused() {
        let mut settings = valid();
        settings.relay.pool = crate::RelayPoolSetting::Only(Vec::new());
        assert!(paths(&validate(&settings)).contains(&"relay.pool".to_string()));

        settings.relay.pin = "relay-1".to_string();
        settings.relay.pool = crate::RelayPoolSetting::Only(vec!["relay-2".to_string()]);
        assert!(paths(&validate(&settings)).contains(&"relay.pin".to_string()));
    }

    #[test]
    fn an_interface_name_longer_than_the_kernel_accepts_is_refused() {
        let mut settings = valid();
        settings.interface.name = "wgmesh-underlay-0".to_string();
        assert!(paths(&validate(&settings)).contains(&"interface.name".to_string()));

        settings.interface.name = "wg 0".to_string();
        assert!(paths(&validate(&settings)).contains(&"interface.name".to_string()));
    }

    #[test]
    fn the_relay_and_coordinator_configurations_are_checked_too() {
        let relay = RelaySettings::default();
        let problems = validate_relay(&relay);
        assert!(paths(&problems).contains(&"coordinator.url".to_string()));
        assert!(paths(&problems).contains(&"coordinator.spki_sha256".to_string()));

        let mut relay = RelaySettings::default();
        relay.coordinator.url = "https://wgmesh.example.com".to_string();
        relay.coordinator.spki_sha256 =
            "9f2c000000000000000000000000000000000000000000000000000000000000".to_string();
        relay.relay.port_range = [51999, 51820];
        relay.limits.pps_per_slot = 0;
        let problems = validate_relay(&relay);
        assert!(paths(&problems).contains(&"relay.port_range".to_string()));
        assert!(paths(&problems).contains(&"limits.pps_per_slot".to_string()));

        let mut coordinator = CoordinatorSettings::default();
        coordinator.api.listen = "not an address".to_string();
        coordinator.database.url = "postgres://localhost/wgmesh".to_string();
        coordinator.policy.max_devices_per_network = 0;
        let problems = validate_coordinator(&coordinator);
        assert!(paths(&problems).contains(&"api.listen".to_string()));
        assert!(paths(&problems).contains(&"database.url".to_string()));
        assert!(paths(&problems).contains(&"policy.max_devices_per_network".to_string()));
    }

    #[test]
    fn the_shipped_relay_and_coordinator_defaults_are_clean() {
        let mut relay = RelaySettings::default();
        relay.coordinator.url = "https://wgmesh.example.com".to_string();
        relay.coordinator.spki_sha256 =
            "9f2c000000000000000000000000000000000000000000000000000000000000".to_string();
        assert!(validate_relay(&relay).is_empty());

        let coordinator = CoordinatorSettings::default();
        assert!(
            validate_coordinator(&coordinator).is_empty(),
            "{:?}",
            validate_coordinator(&coordinator)
        );
    }
}
