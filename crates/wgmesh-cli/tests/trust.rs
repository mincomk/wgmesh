#![allow(clippy::unwrap_used, clippy::expect_used)]

// `wgmesh trust`: the pin the configuration names against the pin the state holds, and the one
// command that moves the second onto the first.
//
// The refusal half of the story is the agent's, and its test is in `wgmesh-app`: a device whose
// state pins a key the configuration does not expect stops before it talks to anyone. What is
// checked here is the command that gets it moving again — that it is a command and not a
// consequence, that it says what it did, and that it changes nothing else in the state.

use std::path::{Path, PathBuf};

use wgmesh_cli::args::{Args, Command};
use wgmesh_cli::commands;

const PIN_HELD: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const PIN_CONFIGURED: &str = "2222222222222222222222222222222222222222222222222222222222222222";

/// A state document with more in it than the trust command reads, so that a rotation which
/// dropped the rest would be visible.
fn state_document(pin: &str) -> String {
    format!(
        r#"{{
  "schema": 1,
  "device_id": "d_7Hq2Vx9",
  "network": "prod",
  "tunnel_ip": "10.77.0.7/16",
  "coordinator": {{ "spki_sha256": "{pin}", "last_sync_unix": 1760000000, "etag": "\"abc\"" }},
  "relay": {{ "assigned": "r_1" }},
  "peers": [
    {{ "id": "d_A", "name": "A", "wg_pubkey": "aa", "tunnel_ip": "10.77.0.11/16" }}
  ],
  "observations": {{}},
  "routes": [ {{ "prefix": "192.168.5.0/24", "table": "main", "metric": 50 }} ],
  "sysctl": {{ "net.ipv4.ip_forward": "1" }}
}}"#
    )
}

struct Scratch {
    dir: PathBuf,
}

impl Scratch {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("wgmesh-trust-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch directory");
        Self { dir }
    }

    fn write(&self, name: &str, text: &str) -> PathBuf {
        let path = self.dir.join(name);
        std::fs::write(&path, text).expect("write");
        path
    }

    fn config(&self, pin: &str) -> PathBuf {
        self.write(
            "agent.toml",
            &format!(
                "[coordinator]\nurl = \"https://wgmesh.example.com\"\nspki_sha256 = \"{pin}\"\n"
            ),
        )
    }

    fn state(&self, pin: &str) -> PathBuf {
        self.write("state.json", &state_document(pin))
    }

    fn missing(&self) -> PathBuf {
        self.dir.join("nothing-here.json")
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

    /// Run one trust command into a buffer, the way `main` runs it into stdout.
    fn run(
        &self,
        command: Command,
        config: &Path,
        state: &Path,
        json: bool,
    ) -> (String, Result<(), wgmesh_cli::CliError>) {
        let args = self.args(command.clone(), config, state, json);
        let mut out: Vec<u8> = Vec::new();
        let result = match command {
            Command::TrustShow => commands::trust::show(&args, &mut out),
            Command::TrustRotate => commands::trust::rotate(&args, &mut out),
            other => panic!("{other:?} is not a trust command"),
        };
        (String::from_utf8(out).expect("utf-8"), result)
    }

    fn document(&self, path: &Path) -> serde_json::Value {
        serde_json::from_str(&std::fs::read_to_string(path).expect("state file")).expect("json")
    }
}

fn pin_in(document: &serde_json::Value) -> String {
    document["coordinator"]["spki_sha256"]
        .as_str()
        .expect("a pin")
        .to_string()
}

#[test]
fn show_prints_both_pins_and_succeeds_when_they_agree() {
    let scratch = Scratch::new("agree");
    let config = scratch.config(PIN_HELD);
    let state = scratch.state(PIN_HELD);

    let (text, result) = scratch.run(Command::TrustShow, &config, &state, false);

    assert!(result.is_ok(), "{result:?}");
    assert!(text.contains(PIN_HELD), "{text}");
    assert!(text.contains("the pin matches"), "{text}");
}

#[test]
fn show_refuses_when_the_state_pins_another_key() {
    let scratch = Scratch::new("mismatch");
    let config = scratch.config(PIN_CONFIGURED);
    let state = scratch.state(PIN_HELD);

    let (text, result) = scratch.run(Command::TrustShow, &config, &state, false);

    assert!(text.contains(PIN_HELD), "the pin the state holds: {text}");
    assert!(
        text.contains(PIN_CONFIGURED),
        "the pin the configuration names: {text}"
    );
    let error = result.expect_err("a mismatch is a failure").to_string();
    assert!(error.contains("refuses"), "{error}");
    assert!(error.contains("rotate"), "{error}");
}

#[test]
fn show_says_so_when_the_device_has_not_enrolled() {
    let scratch = Scratch::new("empty");
    let config = scratch.config(PIN_CONFIGURED);

    let (text, result) = scratch.run(Command::TrustShow, &config, &scratch.missing(), false);

    assert!(result.is_ok(), "{result:?}");
    assert!(text.contains("has not enrolled"), "{text}");
}

#[test]
fn show_speaks_json_when_asked() {
    let scratch = Scratch::new("json");
    let config = scratch.config(PIN_HELD);
    let state = scratch.state(PIN_HELD);

    let (text, result) = scratch.run(Command::TrustShow, &config, &state, true);

    assert!(result.is_ok(), "{result:?}");
    let document: serde_json::Value = serde_json::from_str(&text).expect("json");
    assert_eq!(document["configured"], serde_json::json!(PIN_HELD));
    assert_eq!(document["pinned"], serde_json::json!(PIN_HELD));
    assert_eq!(document["matches"], serde_json::json!(true));
}

#[test]
fn rotate_moves_the_pin_and_leaves_the_rest_of_the_state_alone() {
    let scratch = Scratch::new("rotate");
    let config = scratch.config(PIN_CONFIGURED);
    let state = scratch.state(PIN_HELD);

    let (text, result) = scratch.run(Command::TrustRotate, &config, &state, false);

    assert!(result.is_ok(), "{result:?}");
    assert!(text.contains(PIN_CONFIGURED), "{text}");
    assert!(
        text.contains(PIN_HELD),
        "the pin it moved away from: {text}"
    );

    let document = scratch.document(&state);
    assert_eq!(pin_in(&document), PIN_CONFIGURED);
    assert_eq!(document["device_id"], serde_json::json!("d_7Hq2Vx9"));
    assert_eq!(document["peers"][0]["name"], serde_json::json!("A"));
    assert_eq!(
        document["sysctl"]["net.ipv4.ip_forward"],
        serde_json::json!("1")
    );
    assert_eq!(document["relay"]["assigned"], serde_json::json!("r_1"));

    // And the device is back in step: the next show succeeds.
    let (text, result) = scratch.run(Command::TrustShow, &config, &state, false);
    assert!(result.is_ok(), "{result:?}");
    assert!(text.contains("the pin matches"), "{text}");
}

#[test]
fn rotating_to_the_pin_already_held_changes_nothing() {
    let scratch = Scratch::new("idempotent");
    let config = scratch.config(PIN_HELD);
    let state = scratch.state(PIN_HELD);
    let before = std::fs::read_to_string(&state).expect("state");

    let (text, result) = scratch.run(Command::TrustRotate, &config, &state, false);

    assert!(result.is_ok(), "{result:?}");
    assert!(text.contains("already"), "{text}");
    assert_eq!(std::fs::read_to_string(&state).expect("state"), before);
}

#[test]
fn rotate_without_a_state_says_to_enrol_first() {
    let scratch = Scratch::new("no-state");
    let config = scratch.config(PIN_CONFIGURED);

    let (_, result) = scratch.run(Command::TrustRotate, &config, &scratch.missing(), false);

    let error = result.expect_err("there is nothing to re-pin").to_string();
    assert!(error.contains("enrol"), "{error}");
}

#[test]
fn a_configuration_without_a_pin_is_refused_rather_than_treated_as_trusted() {
    let scratch = Scratch::new("no-pin");
    let config = scratch.config("");
    let state = scratch.state(PIN_HELD);

    let (_, result) = scratch.run(Command::TrustShow, &config, &state, false);

    let error = result.expect_err("nothing is pinned").to_string();
    assert!(error.contains("nothing is pinned"), "{error}");
}

#[test]
fn a_pin_that_is_not_a_digest_is_refused() {
    let scratch = Scratch::new("bad-pin");
    let config = scratch.config("not-a-pin");
    let state = scratch.state(PIN_HELD);

    let (_, result) = scratch.run(Command::TrustShow, &config, &state, false);

    let error = result.expect_err("a pin is 64 hex digits").to_string();
    assert!(error.contains("SHA-256"), "{error}");
}

#[test]
fn the_trust_commands_parse_with_their_options() {
    let parse = |words: &[&str]| {
        let mut arguments = vec![String::from("wgmesh")];
        arguments.extend(words.iter().map(|word| (*word).to_owned()));
        Args::parse(arguments)
    };

    let args = parse(&["trust", "show", "--json"]).expect("parses");
    assert_eq!(args.command, Command::TrustShow);
    assert!(args.json);

    let args = parse(&[
        "trust",
        "rotate",
        "--config",
        "/tmp/agent.toml",
        "--state",
        "/tmp/s.json",
    ])
    .expect("parses");
    assert_eq!(args.command, Command::TrustRotate);
    assert_eq!(args.config, PathBuf::from("/tmp/agent.toml"));
    assert_eq!(args.state, PathBuf::from("/tmp/s.json"));

    let error = parse(&["trust", "accept"]).expect_err("there is no accept");
    assert!(error.to_string().contains("try show or rotate"), "{error}");
    let error = parse(&["trust"]).expect_err("trust needs a subcommand");
    assert!(error.to_string().contains("needs one of"), "{error}");
}
