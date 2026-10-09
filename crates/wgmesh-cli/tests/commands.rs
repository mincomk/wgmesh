#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};

use serde_json::Value;
use wgmesh_cli::args::{Args, Command};
use wgmesh_cli::commands;

const CONFIG_EXIT: &str = r#"
[peers]
allowed_ips = "peer"
exit_peer = "gw"

[route]
table = "main"
prefixes = ["10.77.0.0/16", "192.168.5.0/24"]
metric = 50
address = "auto"

[forwarding]
enabled = true
sysctl = false
firewall = "manage"
"#;

const STATE: &str = r#"{
  "schema": 1,
  "device_id": "d_7Hq2Vx9",
  "network": "prod",
  "tunnel_ip": "10.77.0.7/16",
  "peers": [
    { "id": "d_A", "name": "A", "wg_pubkey": "aa", "tunnel_ip": "10.77.0.11/16" },
    { "id": "d_G", "name": "gw", "wg_pubkey": "bb", "tunnel_ip": "10.77.0.12/16" },
    { "id": "d_C", "name": "C", "wg_pubkey": "cc", "tunnel_ip": "10.77.0.13/16" }
  ],
  "routes": [ { "prefix": "192.168.5.0/24", "table": "main", "metric": 50 } ]
}"#;

struct Scratch {
    dir: PathBuf,
}

impl Scratch {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("wgmesh-cli-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch directory");
        Self { dir }
    }

    fn write(&self, name: &str, text: &str) -> PathBuf {
        let path = self.dir.join(name);
        std::fs::write(&path, text).expect("write");
        path
    }

    fn args(&self, command: Command, config: &Path, state: &Path, json: bool) -> Args {
        Args {
            command,
            config: config.to_path_buf(),
            state: state.to_path_buf(),
            json,
            interface: String::from("wg0"),
        }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn run(args: &Args, f: impl Fn(&Args, &mut Vec<u8>) -> Result<(), wgmesh_cli::CliError>) -> String {
    let mut out = Vec::new();
    f(args, &mut out).expect("the command succeeds");
    String::from_utf8(out).expect("utf-8")
}

#[test]
fn peers_json_puts_the_catch_all_on_exactly_one_peer() {
    let scratch = Scratch::new("peers");
    let config = scratch.write("agent.toml", CONFIG_EXIT);
    let state = scratch.write("state.json", STATE);
    let args = scratch.args(Command::Peers, &config, &state, true);

    let text = run(&args, |args, out| commands::peers::run(args, out));
    let document: Value = serde_json::from_str(&text).expect("valid json");
    let rows = document.as_array().expect("an array of peers");
    assert_eq!(rows.len(), 3);

    let carrying: Vec<&str> = rows
        .iter()
        .filter(|row| row["carries_catch_all"] == Value::Bool(true))
        .map(|row| row["name"].as_str().expect("a name"))
        .collect();
    assert_eq!(
        carrying,
        vec!["gw"],
        "exactly one peer carries the catch-all"
    );

    let gw = rows
        .iter()
        .find(|row| row["name"] == "gw")
        .expect("the exit peer");
    assert_eq!(gw["allowed_ips"], serde_json::json!(["0.0.0.0/0", "::/0"]));
    assert_eq!(gw["policy"], "exit:gw");

    for other in ["A", "C"] {
        let row = rows
            .iter()
            .find(|row| row["name"] == other)
            .expect("a peer");
        assert_eq!(row["allowed_ips"].as_array().expect("bands").len(), 1);
        let band = row["allowed_ips"][0].as_str().expect("a band");
        assert!(
            band.ends_with("/32"),
            "{other} kept {band}, not its own /32"
        );
        assert_ne!(row["carries_catch_all"], Value::Bool(true));
    }
}

#[test]
fn peers_in_text_names_the_policy_and_the_catch_all() {
    let scratch = Scratch::new("peers-text");
    let config = scratch.write("agent.toml", CONFIG_EXIT);
    let state = scratch.write("state.json", STATE);
    let args = scratch.args(Command::Peers, &config, &state, false);

    let text = run(&args, |args, out| commands::peers::run(args, out));
    assert!(text.contains("exit:gw"));
    assert!(text.contains("0.0.0.0/0, ::/0"));
    assert!(text.contains("3 peer(s), 1 carrying the catch-all"));
    assert!(text.contains("10.77.0.11/32"));
}

#[test]
fn routes_plan_shows_the_chosen_bands_and_never_a_default() {
    let scratch = Scratch::new("plan");
    let config = scratch.write("agent.toml", CONFIG_EXIT);
    let state = scratch.write("state.json", STATE);
    let args = scratch.args(Command::RoutesPlan, &config, &state, true);

    let text = run(&args, |args, out| commands::routes::plan(args, out));
    let document: Value = serde_json::from_str(&text).expect("stdout is json and nothing else");

    assert_eq!(document["table"], "main");
    assert_eq!(document["prefixes"], "10.77.0.0/16,192.168.5.0/24");
    let changes = document["changes"].as_array().expect("changes");
    let added: Vec<&str> = changes
        .iter()
        .filter(|change| change["action"] == "add")
        .map(|change| change["prefix"].as_str().expect("a prefix"))
        .collect();
    // Which of the two bands has to be added depends on what the installed side holds, and
    // that differs between a host whose kernel answers and one that falls back to the state
    // file. What does not differ is this: nothing outside `prefixes` is ever touched, a band
    // that is already installed is not added again, and a default route never appears.
    let installed: Vec<&str> = document["installed"]
        .as_array()
        .expect("installed")
        .iter()
        .map(|prefix| prefix.as_str().expect("a prefix"))
        .collect();
    let chosen = ["10.77.0.0/16", "192.168.5.0/24"];
    for band in chosen {
        assert!(
            added.contains(&band) || installed.contains(&band),
            "{band} is neither in the plan nor installed: {text}"
        );
    }
    assert!(
        added.iter().all(|band| chosen.contains(band)),
        "a band outside `prefixes` was planned: {added:?}"
    );
    assert!(
        changes
            .iter()
            .filter(|change| change["action"] == "remove")
            .all(|change| !chosen.contains(&change["prefix"].as_str().expect("a prefix"))),
        "a chosen band is never removed"
    );
    for change in changes {
        let prefix = change["prefix"].as_str().expect("a prefix");
        assert_ne!(prefix, "0.0.0.0/0");
        assert_ne!(prefix, "::/0");
        assert_ne!(prefix, "default");
    }
    assert!(document["installed_from"].is_string());
}

#[test]
fn a_table_of_off_plans_no_route_at_all() {
    let scratch = Scratch::new("off");
    let config = scratch.write(
        "agent.toml",
        "[route]\ntable = \"off\"\nprefixes = \"auto\"\n",
    );
    let state = scratch.write("state.json", STATE);
    let args = scratch.args(Command::RoutesPlan, &config, &state, false);

    let text = run(&args, |args, out| commands::routes::plan(args, out));
    assert!(text.contains("table    off"), "{text}");
    assert!(text.contains("changes  none"), "{text}");
    assert!(!text.contains("0.0.0.0/0"));
}

#[test]
fn a_catch_all_in_the_prefix_list_stops_the_plan() {
    let scratch = Scratch::new("catch-all");
    let config = scratch.write("agent.toml", "[route]\nprefixes = [\"0.0.0.0/0\"]\n");
    let state = scratch.write("state.json", STATE);
    let args = scratch.args(Command::RoutesPlan, &config, &state, false);

    let mut out = Vec::new();
    let error = commands::routes::plan(&args, &mut out).unwrap_err();
    assert!(error.to_string().contains("default route"), "{error}");
    assert!(
        out.is_empty(),
        "a refused plan prints nothing at all: {out:?}"
    );
    assert!(
        !String::from_utf8_lossy(&out).contains("note:"),
        "the configuration is refused before the kernel is asked anything"
    );
}

#[test]
fn an_unknown_exit_peer_stops_the_command() {
    let scratch = Scratch::new("unknown-exit");
    let config = scratch.write("agent.toml", "[peers]\nexit_peer = \"ghost\"\n");
    let state = scratch.write("state.json", STATE);
    let args = scratch.args(Command::Peers, &config, &state, false);

    let mut out = Vec::new();
    let error = commands::peers::run(&args, &mut out).unwrap_err();
    assert!(
        error.to_string().contains("`exit_peer = \"ghost\"`"),
        "{error}"
    );
}

#[test]
fn an_any_policy_needs_exactly_one_peer() {
    let scratch = Scratch::new("any");
    let config = scratch.write("agent.toml", "[peers]\nallowed_ips = \"any\"\n");
    let state = scratch.write("state.json", STATE);
    let args = scratch.args(Command::Peers, &config, &state, false);

    let mut out = Vec::new();
    let error = commands::peers::run(&args, &mut out).unwrap_err();
    assert!(error.to_string().contains("3 peers"), "{error}");

    let single = scratch.write(
        "single.json",
        r#"{ "peers": [ { "name": "only", "tunnel_ip": "10.77.0.11/16" } ] }"#,
    );
    let args = scratch.args(Command::Peers, &config, &single, true);
    let text = run(&args, |args, out| commands::peers::run(args, out));
    assert!(text.contains("\"0.0.0.0/0\""));
    assert_eq!(
        text.matches("\"carries_catch_all\": true").count(),
        1,
        "one peer, one catch-all"
    );
}

#[test]
fn doctor_says_what_to_do_about_forwarding() {
    let scratch = Scratch::new("doctor");
    let config = scratch.write("agent.toml", CONFIG_EXIT);
    let state = scratch.write("state.json", STATE);
    let args = scratch.args(Command::Doctor, &config, &state, false);

    let text = run(&args, |args, out| commands::doctor::run(args, out));
    assert!(text.contains("forwarding.sysctl"), "{text}");
    assert!(text.contains("->"), "every check says what to do: {text}");
    assert!(
        text.contains("inet wgmesh"),
        "the managed table is named: {text}"
    );

    let args = scratch.args(Command::Doctor, &config, &state, true);
    let text = run(&args, |args, out| commands::doctor::run(args, out));
    let document: Value = serde_json::from_str(&text).expect("valid json");
    let checks = document["checks"].as_array().expect("checks");
    assert!(!checks.is_empty());
    for check in checks {
        assert!(
            check["remedy"]
                .as_str()
                .is_some_and(|remedy| !remedy.is_empty()),
            "a check without a remedy is not a doctor"
        );
    }
}

#[test]
fn a_missing_configuration_file_is_reported_with_its_path() {
    let scratch = Scratch::new("missing");
    let state = scratch.write("state.json", STATE);
    let args = scratch.args(
        Command::Peers,
        &scratch.dir.join("nowhere.toml"),
        &state,
        false,
    );
    let mut out = Vec::new();
    let error = commands::peers::run(&args, &mut out).unwrap_err();
    assert!(error.to_string().contains("nowhere.toml"), "{error}");
}
