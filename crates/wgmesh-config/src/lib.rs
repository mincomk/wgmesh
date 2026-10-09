pub mod agent;
pub mod coordinator;
pub mod relay;
pub mod route;
pub mod validate;

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use toml::Table;

pub use agent::Settings;
pub use coordinator::CoordinatorSettings;
pub use relay::RelaySettings;
pub use route::{
    AddressSetting, AllowedIpsSetting, FirewallSetting, Prefix, RelayPoolSetting,
    RoutePrefixesSetting, RouteSection, RouteTableSetting,
};
pub use validate::{Problem, Severity};

/// The prefix that marks an environment variable as a configuration layer entry.
pub const ENV_PREFIX: &str = "WGMESH__";

/// The separator that turns one environment variable name into a path through the schema.
pub const ENV_LEVEL_SEPARATOR: &str = "__";

/// Everything that can go wrong while resolving the effective configuration.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The configuration file could not be read.
    #[error("cannot read {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// The configuration file is not valid TOML.
    #[error("cannot parse {path}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
    /// The merged document does not satisfy the schema.
    #[error("the merged configuration does not match the schema: {source}")]
    Schema {
        #[source]
        source: toml::de::Error,
    },
    /// The configuration could not be serialized back to TOML.
    #[error("cannot serialize the configuration: {source}")]
    Serialize {
        #[source]
        source: toml::ser::Error,
    },
}

/// The verbosity a daemon logs at.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum LogLevel {
    Error,
    Warn,
    #[default]
    Info,
    Debug,
    Trace,
}

/// The shape a daemon's log records take.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum LogFormat {
    #[default]
    Text,
    Json,
}

/// The `[log]` table of a daemon whose default record shape is text.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LogSection {
    pub level: LogLevel,
    pub format: LogFormat,
}

impl Default for LogSection {
    fn default() -> Self {
        Self {
            level: LogLevel::Info,
            format: LogFormat::Text,
        }
    }
}

/// The `[state]` table: where the daemon keeps its disposable state.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StateSection {
    pub dir: PathBuf,
}

impl Default for StateSection {
    fn default() -> Self {
        Self {
            dir: PathBuf::from("/var/lib/wgmesh"),
        }
    }
}

/// The coordinator an agent or a relay talks to, with the pin it must present.
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CoordinatorEndpoint {
    pub url: String,
    pub spki_sha256: String,
}

/// The layers a configuration is resolved from, in increasing precedence.
#[derive(Clone, Debug, Default)]
pub struct Layers {
    file: Option<PathBuf>,
    env: Vec<(String, String)>,
    flags: Vec<(String, String)>,
}

impl Layers {
    /// No file, no environment, no flags: the result is the default configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Read the given TOML file as the file layer.
    pub fn file(mut self, path: impl Into<PathBuf>) -> Self {
        self.file = Some(path.into());
        self
    }

    /// Take the process environment as the environment layer.
    pub fn environment(mut self) -> Self {
        self.env = std::env::vars().collect();
        self
    }

    /// Add environment pairs explicitly, as the environment layer.
    pub fn env(mut self, pairs: impl IntoIterator<Item = (String, String)>) -> Self {
        self.env.extend(pairs);
        self
    }

    /// Add one environment pair.
    pub fn env_var(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.push((name.into(), value.into()));
        self
    }

    /// Add one command line flag, given as a dotted path such as `traversal.punch_window_secs`.
    pub fn flag(mut self, path: impl Into<String>, value: impl Into<String>) -> Self {
        self.flags.push((path.into(), value.into()));
        self
    }

    /// Add several command line flags.
    pub fn flags(mut self, pairs: impl IntoIterator<Item = (String, String)>) -> Self {
        self.flags.extend(pairs);
        self
    }

    /// The configuration file this resolution reads, when there is one.
    pub fn file_path(&self) -> Option<&Path> {
        self.file.as_deref()
    }
}

/// Resolve the agent settings from the four layers.
pub fn resolve(layers: &Layers) -> Result<Settings, ConfigError> {
    resolve_for(layers)
}

/// Resolve the relay daemon settings from the four layers.
pub fn resolve_relay(layers: &Layers) -> Result<RelaySettings, ConfigError> {
    resolve_for(layers)
}

/// Resolve the coordinator settings from the four layers.
pub fn resolve_coordinator(layers: &Layers) -> Result<CoordinatorSettings, ConfigError> {
    resolve_for(layers)
}

/// Resolve any settings type from the four layers, in increasing precedence.
pub fn resolve_for<T>(layers: &Layers) -> Result<T, ConfigError>
where
    T: Serialize + serde::de::DeserializeOwned + Default,
{
    let mut merged =
        toml::Value::try_from(T::default()).map_err(|source| ConfigError::Serialize { source })?;
    if let Some(path) = layers.file.as_deref() {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        let parsed: toml::Value = toml::from_str(&text).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source,
        })?;
        merge_into(&mut merged, parsed);
    }
    merge_into(&mut merged, environment_tree(&layers.env));
    merge_into(&mut merged, flag_tree(&layers.flags));
    merged
        .try_into()
        .map_err(|source| ConfigError::Schema { source })
}

/// Resolve the effective settings from a single file.
pub fn load(path: &Path) -> Result<Settings, ConfigError> {
    resolve(&Layers::new().file(path))
}

/// Render settings as the TOML document `config show` prints.
pub fn to_toml(settings: &Settings) -> Result<String, ConfigError> {
    toml::to_string_pretty(settings).map_err(|source| ConfigError::Serialize { source })
}

/// Render the built in defaults as the TOML document `config defaults` prints.
pub fn defaults_toml() -> Result<String, ConfigError> {
    to_toml(&Settings::default())
}

/// Resolve settings and collect every validation problem of the result.
pub fn resolve_and_check(layers: &Layers) -> Result<(Settings, Vec<Problem>), ConfigError> {
    let settings = resolve(layers)?;
    let problems = validate::validate(&settings);
    Ok((settings, problems))
}

fn environment_tree(pairs: &[(String, String)]) -> toml::Value {
    let mut root = Table::new();
    for (name, raw) in pairs {
        let Some(rest) = name.strip_prefix(ENV_PREFIX) else {
            continue;
        };
        let segments: Vec<&str> = rest.split(ENV_LEVEL_SEPARATOR).collect();
        if segments.is_empty() || segments.iter().any(|segment| segment.is_empty()) {
            continue;
        }
        let levels: Vec<String> = segments
            .iter()
            .map(|segment| segment.to_ascii_lowercase())
            .collect();
        insert_path(&mut root, &levels, literal_or_string(raw));
    }
    toml::Value::Table(root)
}

fn flag_tree(pairs: &[(String, String)]) -> toml::Value {
    let mut root = Table::new();
    for (path, raw) in pairs {
        let levels: Vec<String> = path
            .split('.')
            .map(|level| level.trim().to_ascii_lowercase().replace('-', "_"))
            .filter(|level| !level.is_empty())
            .collect();
        if levels.is_empty() {
            continue;
        }
        insert_path(&mut root, &levels, literal_or_string(raw));
    }
    toml::Value::Table(root)
}

/// Read a layer value as the TOML literal it spells, or as a plain string when it spells none.
fn literal_or_string(raw: &str) -> toml::Value {
    if let Ok(parsed) = toml::from_str::<toml::Value>(&format!("value = {raw}"))
        && let Some(inner) = parsed.get("value")
    {
        return inner.clone();
    }
    toml::Value::String(raw.to_string())
}

fn insert_path(root: &mut Table, levels: &[String], value: toml::Value) {
    let Some((head, rest)) = levels.split_first() else {
        return;
    };
    if rest.is_empty() {
        root.insert(head.clone(), value);
        return;
    }
    let slot = root
        .entry(head.clone())
        .or_insert_with(|| toml::Value::Table(Table::new()));
    if !slot.is_table() {
        *slot = toml::Value::Table(Table::new());
    }
    if let Some(table) = slot.as_table_mut() {
        insert_path(table, rest, value);
    }
}

/// Overlay one document on another: tables merge, and every other value replaces.
fn merge_into(base: &mut toml::Value, overlay: toml::Value) {
    match (base, overlay) {
        (toml::Value::Table(base), toml::Value::Table(overlay)) => {
            for (key, value) in overlay {
                match base.get_mut(&key) {
                    Some(slot) => merge_into(slot, value),
                    None => {
                        base.insert(key, value);
                    }
                }
            }
        }
        (base, overlay) => *base = overlay,
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    fn setting(settings: &Settings, section: &str, key: &str) -> toml::Value {
        let document = match toml::Value::try_from(settings) {
            Ok(value) => value,
            Err(error) => panic!("settings serialize: {error}"),
        };
        match document.get(section).and_then(|table| table.get(key)) {
            Some(value) => value.clone(),
            None => panic!("no {section}.{key} in the rendered settings"),
        }
    }

    fn prefix(text: &str) -> Prefix {
        match Prefix::from_str(text) {
            Ok(prefix) => prefix,
            Err(error) => panic!("{text}: {error}"),
        }
    }

    fn write_file(text: &str) -> tempfile::NamedTempFile {
        let file = match tempfile::NamedTempFile::new() {
            Ok(file) => file,
            Err(error) => panic!("temporary file: {error}"),
        };
        if let Err(error) = std::fs::write(file.path(), text) {
            panic!("writing the file: {error}");
        }
        file
    }

    #[test]
    fn the_defaults_render_every_section() {
        let text = match defaults_toml() {
            Ok(text) => text,
            Err(error) => panic!("defaults render: {error}"),
        };
        for section in [
            "[interface]",
            "[coordinator]",
            "[enrollment]",
            "[peers]",
            "[route]",
            "[forwarding]",
            "[traversal]",
            "[relay]",
            "[sync]",
            "[state]",
            "[log]",
        ] {
            assert!(text.contains(section), "defaults do not carry {section}");
        }
    }

    #[test]
    fn the_defaults_survive_a_round_trip_through_a_file() {
        let defaults = Settings::default();
        let text = match defaults_toml() {
            Ok(text) => text,
            Err(error) => panic!("defaults render: {error}"),
        };
        let file = write_file(&text);
        let loaded = match load(file.path()) {
            Ok(settings) => settings,
            Err(error) => panic!("loading the defaults: {error}"),
        };
        assert_eq!(loaded, defaults);
    }

    #[test]
    fn a_file_only_has_to_carry_what_it_wants_to_change() {
        let minimal = r#"
[coordinator]
url = "https://wgmesh.example.com"
spki_sha256 = "9f2c000000000000000000000000000000000000000000000000000000000000"

[enrollment]
token_file = "/run/credentials/wgmesh-agent.service/enrollment-token"
"#;
        let file = write_file(minimal);
        let settings = match load(file.path()) {
            Ok(settings) => settings,
            Err(error) => panic!("loading the file: {error}"),
        };
        assert_eq!(settings.coordinator.url, "https://wgmesh.example.com");
        assert_eq!(settings.state.dir, Settings::default().state.dir);
        assert_eq!(settings.traversal.backoff_secs, vec![30, 120, 600]);
        assert_eq!(settings.interface.name, "wg0");
    }

    #[test]
    fn the_four_layers_are_applied_in_order() {
        let document = r#"
[traversal]
keepalive_secs = 30
punch_window_secs = 7
"#;
        let file = write_file(document);

        let defaults = Settings::default();
        assert_eq!(defaults.traversal.keepalive_secs, 25);
        assert_eq!(defaults.traversal.punch_window_secs, 5);

        let from_file = match resolve(&Layers::new().file(file.path())) {
            Ok(settings) => settings,
            Err(error) => panic!("file layer: {error}"),
        };
        assert_eq!(from_file.traversal.keepalive_secs, 30);
        assert_eq!(from_file.traversal.punch_window_secs, 7);

        let with_env = match resolve(
            &Layers::new()
                .file(file.path())
                .env_var("WGMESH__TRAVERSAL__KEEPALIVE_SECS", "35"),
        ) {
            Ok(settings) => settings,
            Err(error) => panic!("environment layer: {error}"),
        };
        assert_eq!(with_env.traversal.keepalive_secs, 35);
        assert_eq!(with_env.traversal.punch_window_secs, 7);

        let with_flag = match resolve(
            &Layers::new()
                .file(file.path())
                .env_var("WGMESH__TRAVERSAL__KEEPALIVE_SECS", "35")
                .flag("traversal.keepalive_secs", "45"),
        ) {
            Ok(settings) => settings,
            Err(error) => panic!("flag layer: {error}"),
        };
        assert_eq!(with_flag.traversal.keepalive_secs, 45);
        assert_eq!(with_flag.traversal.punch_window_secs, 7);
    }

    #[test]
    fn a_flag_beats_a_file_without_an_environment_in_between() {
        let file = write_file("[traversal]\nkeepalive_secs = 30\n");
        let settings = match resolve(
            &Layers::new()
                .file(file.path())
                .flag("traversal.keepalive_secs", "45"),
        ) {
            Ok(settings) => settings,
            Err(error) => panic!("flag layer: {error}"),
        };
        assert_eq!(settings.traversal.keepalive_secs, 45);
    }

    #[test]
    fn the_environment_layer_understands_nesting_lists_and_bare_words() {
        let settings = match resolve(&Layers::new().env(vec![
            (
                "WGMESH__TRAVERSAL__BACKOFF_SECS".to_string(),
                "[10, 20, 40]".to_string(),
            ),
            ("WGMESH__ROUTE__TABLE".to_string(), "off".to_string()),
            (
                "WGMESH__INTERFACE__LISTEN_PORT".to_string(),
                "51820".to_string(),
            ),
            (
                "WGMESH__PEERS__EXIT_PEER".to_string(),
                "gateway".to_string(),
            ),
            (
                "WGMESH__ROUTE__PREFIXES".to_string(),
                "[\"10.77.0.0/16\"]".to_string(),
            ),
            ("PATH".to_string(), "/usr/bin".to_string()),
        ])) {
            Ok(settings) => settings,
            Err(error) => panic!("environment layer: {error}"),
        };
        assert_eq!(settings.traversal.backoff_secs, vec![10, 20, 40]);
        assert_eq!(settings.route.table, RouteTableSetting::Unmanaged);
        assert_eq!(settings.interface.listen_port, 51820);
        assert_eq!(settings.peers.exit_peer, "gateway");
        assert_eq!(
            settings.route.prefixes,
            RoutePrefixesSetting::Only(vec![prefix("10.77.0.0/16")])
        );
    }

    #[test]
    fn an_environment_variable_without_the_prefix_is_ignored() {
        let settings = match resolve(&Layers::new().env_var("WGMESH_KEEPALIVE", "99")) {
            Ok(settings) => settings,
            Err(error) => panic!("environment layer: {error}"),
        };
        assert_eq!(settings, Settings::default());
    }

    #[test]
    fn an_unknown_key_is_rejected_by_name() {
        let file = write_file("[traversal]\nkeepalive = 25\n");
        let error = match load(file.path()) {
            Ok(settings) => panic!("an unknown key was accepted: {settings:?}"),
            Err(error) => error,
        };
        let text = error.to_string();
        assert!(
            text.contains("keepalive"),
            "error does not name the key: {text}"
        );
    }

    #[test]
    fn the_shipped_defaults_literally_match_the_blueprint() {
        let settings = Settings::default();
        let text = |value: &str| toml::Value::String(value.to_string());
        assert_eq!(setting(&settings, "interface", "name"), text("wg0"));
        assert_eq!(
            setting(&settings, "interface", "mtu"),
            toml::Value::Integer(1420)
        );
        assert_eq!(
            setting(&settings, "interface", "listen_port"),
            toml::Value::Integer(0)
        );
        assert_eq!(
            setting(&settings, "interface", "private_key_file"),
            text("")
        );
        assert_eq!(setting(&settings, "interface", "api_key_file"), text(""));
        assert_eq!(
            setting(&settings, "coordinator", "network"),
            text("default")
        );
        assert_eq!(
            setting(&settings, "enrollment", "wait_for_approval"),
            toml::Value::Boolean(true)
        );
        assert_eq!(setting(&settings, "peers", "allowed_ips"), text("peer"));
        assert_eq!(setting(&settings, "peers", "exit_peer"), text(""));
        assert_eq!(setting(&settings, "route", "table"), text("main"));
        assert_eq!(setting(&settings, "route", "prefixes"), text("auto"));
        assert_eq!(
            setting(&settings, "route", "metric"),
            toml::Value::Integer(0)
        );
        assert_eq!(setting(&settings, "route", "address"), text("auto"));
        assert_eq!(
            setting(&settings, "forwarding", "enabled"),
            toml::Value::Boolean(false)
        );
        assert_eq!(
            setting(&settings, "forwarding", "sysctl"),
            toml::Value::Boolean(true)
        );
        assert_eq!(setting(&settings, "forwarding", "firewall"), text("off"));
        assert_eq!(
            setting(&settings, "traversal", "punch_delay_secs"),
            toml::Value::Integer(2)
        );
        assert_eq!(
            setting(&settings, "traversal", "punch_window_secs"),
            toml::Value::Integer(5)
        );
        assert_eq!(
            setting(&settings, "traversal", "keepalive_secs"),
            toml::Value::Integer(25)
        );
        assert_eq!(
            setting(&settings, "traversal", "lan_candidates"),
            toml::Value::Boolean(true)
        );
        assert_eq!(
            setting(&settings, "traversal", "ipv6"),
            toml::Value::Boolean(true)
        );
        assert_eq!(
            setting(&settings, "traversal", "upnp"),
            toml::Value::Boolean(false)
        );
        assert_eq!(
            setting(&settings, "traversal", "backoff_secs"),
            toml::Value::Array(vec![
                toml::Value::Integer(30),
                toml::Value::Integer(120),
                toml::Value::Integer(600),
            ])
        );
        assert_eq!(setting(&settings, "relay", "pool"), text("any"));
        assert_eq!(setting(&settings, "relay", "pin"), text(""));
        assert_eq!(
            setting(&settings, "sync", "interval_secs"),
            toml::Value::Integer(30)
        );
        assert_eq!(
            setting(&settings, "sync", "sse"),
            toml::Value::Boolean(true)
        );
        assert_eq!(setting(&settings, "state", "dir"), text("/var/lib/wgmesh"));
        assert_eq!(setting(&settings, "log", "level"), text("info"));
        assert_eq!(setting(&settings, "log", "format"), text("text"));
    }
}
