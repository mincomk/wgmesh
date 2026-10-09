#![allow(clippy::unwrap_used, clippy::expect_used)]

// The output contract of the `wgmesh` binary, held still.
//
// These assertions are the contract in `docs/cli-contract.md`: if one of them changes, the
// contract changed, and the scripts that read this output broke with it.

use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use assert_cmd::prelude::*;
use predicates::prelude::*;

const GOOD_SPKI: &str = "9f2cbb9d3b5e1d4a0f7c6e5d4c3b2a1908172635445362718091a2b3c4d5e6f7";

/// A 32 byte key, base64, the way `wg genkey` writes one.
const A_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

fn bin() -> Command {
    Command::cargo_bin("wgmesh").expect("the wgmesh binary is built")
}

fn write_config(dir: &Path, body: &str) -> std::path::PathBuf {
    let path = dir.join("agent.toml");
    fs::write(&path, body).expect("config written");
    path
}

fn minimal_config(dir: &Path) -> std::path::PathBuf {
    write_config(
        dir,
        &format!(
            "[coordinator]\nurl = \"https://wgmesh.example.com\"\nspki_sha256 = \"{GOOD_SPKI}\"\n\n\
             [state]\ndir = \"{}\"\n",
            state_dir(dir).display()
        ),
    )
}

fn state_dir(dir: &Path) -> std::path::PathBuf {
    dir.join("state")
}

/// The world the simulated coordination plane hands out: one peer, already reachable.
fn write_world(dir: &Path) {
    let world = format!(
        r#"{{
  "device": 7,
  "network": "prod",
  "tunnel_ip": "10.77.0.7/16",
  "network_bands": ["10.77.0.0/16"],
  "routes": ["10.77.0.0/16"],
  "peers": [
    {{ "id": 8, "name": "B", "public_key": "{A_KEY}",
       "allowed": ["10.77.0.8/32"], "endpoint": "203.0.113.9:41287" }}
  ],
  "version": 1,
  "token": "tok"
}}"#
    );
    let path = state_dir(dir).join("simulated-world.json");
    fs::create_dir_all(state_dir(dir)).expect("state dir");
    fs::write(path, world).expect("world written");
}

#[test]
fn config_defaults_prints_every_default() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = bin()
        .args(["config", "defaults"])
        .current_dir(dir.path())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(out).expect("utf8");
    for expected in [
        "[interface]",
        "name = \"wg0\"",
        "mtu = 1420",
        "[coordinator]",
        "[route]",
        "table = \"main\"",
        "[traversal]",
        "punch_window_secs = 5",
        "[state]",
    ] {
        assert!(
            text.contains(expected),
            "`{expected}` missing from:\n{text}"
        );
    }
}

#[test]
fn config_defaults_json_is_one_document() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = bin()
        .args(["config", "defaults", "--json"])
        .current_dir(dir.path())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value: serde_json::Value = serde_json::from_slice(&out).expect("valid json on stdout");
    assert_eq!(value["schema"], 1);
    assert_eq!(value["settings"]["interface"]["name"], "wg0");
}

#[test]
fn config_show_fills_in_the_defaults() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = minimal_config(dir.path());
    let out = bin()
        .arg("--config")
        .arg(&config)
        .args(["config", "show"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(out).expect("utf8");
    assert!(text.contains("https://wgmesh.example.com"), "{text}");
    assert!(text.contains("name = \"wg0\""), "{text}");
    assert!(text.contains("punch_window_secs = 5"), "{text}");
    assert!(text.contains("interval_secs = 30"), "{text}");
}

#[test]
fn config_check_reports_every_problem_at_once() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = write_config(
        dir.path(),
        "[coordinator]\nurl = \"http://wgmesh.example.com\"\nspki_sha256 = \"nope\"\n\n\
         [traversal]\npunch_window_secs = 90\nkeepalive_secs = 25\nbackoff_secs = [600, 30]\n\n\
         [state]\ndir = \"relative/path\"\n",
    );
    let output = bin()
        .arg("--config")
        .arg(&config)
        .args(["config", "check"])
        .assert()
        .code(3)
        .get_output()
        .clone();
    let text = String::from_utf8_lossy(&output.stdout).to_string()
        + &String::from_utf8_lossy(&output.stderr);
    assert!(
        text.matches("error:").count() >= 4,
        "expected several problems in one run, got:\n{text}"
    );
    for expected in [
        "spki_sha256",
        "https",
        "punch_window_secs",
        "backoff_secs",
        "state.dir",
    ] {
        assert!(
            text.contains(expected),
            "`{expected}` missing from:\n{text}"
        );
    }
}

#[test]
fn config_check_passes_a_valid_configuration() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = minimal_config(dir.path());
    bin()
        .arg("--config")
        .arg(&config)
        .args(["config", "check"])
        .assert()
        .success();
}

#[test]
fn config_check_json_carries_the_problems() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = write_config(
        dir.path(),
        "[coordinator]\nurl = \"http://x.example.com\"\nspki_sha256 = \"nope\"\n",
    );
    let out = bin()
        .arg("--config")
        .arg(&config)
        .args(["config", "check", "--json"])
        .assert()
        .code(3)
        .get_output()
        .stdout
        .clone();
    let value: serde_json::Value = serde_json::from_slice(&out).expect("valid json on stdout");
    assert_eq!(value["schema"], 1);
    assert!(value["errors"].as_array().expect("errors").len() >= 2);
}

#[test]
fn key_show_prints_wg_compatible_base64_keys() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = bin()
        .args(["key", "show"])
        .arg("--state-dir")
        .arg(state_dir(dir.path()))
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(out).expect("utf8");
    let private = field(&text, "private_key:");
    let public = field(&text, "public_key:");
    for key in [&private, &public] {
        assert_eq!(base64_decode(key).len(), 32, "key {key} is not 32 bytes");
    }
    assert_ne!(private, public);
}

#[test]
fn key_show_is_stable_and_persists_the_key() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = state_dir(dir.path());
    let first = key_show_line(&state, "private_key:");
    let second = key_show_line(&state, "private_key:");
    assert_eq!(first, second, "the key must not be minted twice");
    assert!(
        state.join("secrets").join("wg.key").exists(),
        "the key file lives under <state>/secrets"
    );
}

#[test]
fn key_show_json_parses() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = bin()
        .args(["key", "show", "--json"])
        .arg("--state-dir")
        .arg(state_dir(dir.path()))
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value: serde_json::Value = serde_json::from_slice(&out).expect("valid json on stdout");
    assert_eq!(value["schema"], 1);
    assert_eq!(
        base64_decode(value["private_key"].as_str().expect("private key")).len(),
        32
    );
}

#[test]
fn state_show_without_state_fails_cleanly() {
    let dir = tempfile::tempdir().expect("tempdir");
    bin()
        .args(["state", "show"])
        .arg("--state-dir")
        .arg(state_dir(dir.path()))
        .assert()
        .failure()
        .stderr(predicate::str::contains("state"));
}

#[test]
fn state_reset_removes_the_state_and_keeps_the_keys() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = state_dir(dir.path());
    fs::create_dir_all(&state).expect("state dir");
    fs::write(
        state.join("state.json"),
        format!(
            "{{\"schema\":1,\"device_id\":\"7\",\"network\":\"prod\",\"tunnel_ip\":\"10.77.0.7/16\",\
             \"coordinator\":{{\"spki_sha256\":\"{GOOD_SPKI}\",\"last_sync_unix\":1760000000,\
             \"etag\":\"1\"}}}}"
        ),
    )
    .expect("state file");
    let before = key_show_line(&state, "public_key:");

    bin()
        .args(["state", "show"])
        .arg("--state-dir")
        .arg(&state)
        .assert()
        .success();

    bin()
        .args(["state", "reset", "--yes"])
        .arg("--state-dir")
        .arg(&state)
        .assert()
        .success()
        .stdout(predicate::str::contains("re-enrols"));

    assert!(!state.join("state.json").exists(), "state.json is gone");
    assert_eq!(
        before,
        key_show_line(&state, "public_key:"),
        "the keys are not the state's business"
    );
}

#[test]
fn run_refuses_an_invalid_configuration_with_a_nonzero_exit() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = write_config(
        dir.path(),
        "[coordinator]\nurl = \"http://wgmesh.example.com\"\nspki_sha256 = \"nope\"\n",
    );
    let output = bin()
        .arg("--config")
        .arg(&config)
        .arg("run")
        .assert()
        .failure()
        .get_output()
        .clone();
    let code = output.status.code().expect("an exit code");
    assert_ne!(code, 0);
    assert_eq!(code, 3, "an unusable configuration is exit code 3");
    let text = String::from_utf8_lossy(&output.stdout).to_string()
        + &String::from_utf8_lossy(&output.stderr);
    assert!(text.contains("spki_sha256"), "{text}");
    assert!(text.contains("https"), "{text}");
}

#[test]
fn run_check_validates_without_starting() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = minimal_config(dir.path());
    bin()
        .arg("--config")
        .arg(&config)
        .args(["run", "--check"])
        .assert()
        .success()
        .stdout(predicate::str::contains("nothing was started"));
}

#[test]
fn doctor_prints_a_parseable_document() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = minimal_config(dir.path());
    let out = bin()
        .arg("--config")
        .arg(&config)
        .args(["--backend", "simulated", "doctor", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value: serde_json::Value = serde_json::from_slice(&out).expect("valid json on stdout");
    assert_eq!(value["schema"], 1);
    assert!(value["checks"].as_array().expect("checks").len() >= 3);
}

#[test]
fn the_kernel_backend_says_so_rather_than_pretending() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = minimal_config(dir.path());
    // `status` reads the state file and needs no device at all, so it answers on either backend.
    bin()
        .arg("--config")
        .arg(&config)
        .args(["--backend", "kernel", "status"])
        .assert()
        .success();
    // `run` needs the device, and this build does not have one behind the kernel backend: it says
    // so, and points at the backend that does work.
    bin()
        .arg("--config")
        .arg(&config)
        .args(["--backend", "kernel", "run"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("simulated"));
}

#[test]
fn help_lists_every_command_the_contract_names() {
    let out = bin()
        .arg("--help")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(out).expect("utf8");
    for command in [
        "join", "run", "status", "peers", "routes", "relays", "config", "key", "state", "trust",
        "doctor", "pin",
    ] {
        assert!(
            text.contains(command),
            "`{command}` missing from --help:\n{text}"
        );
    }
}

/// The acceptance pipeline: enrol, run, and read one JSON document back out of it.
#[test]
fn the_pipeline_enrols_runs_and_reports_each_peer() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = minimal_config(dir.path());
    write_world(dir.path());
    let state = state_dir(dir.path());

    bin()
        .arg("--config")
        .arg(&config)
        .args(["--backend", "simulated", "join", "--token", "tok"])
        .assert()
        .success()
        .stdout(predicate::str::contains("enrolled as device 7"));

    let mut child = bin()
        .arg("--config")
        .arg(&config)
        .args(["--backend", "simulated", "run"])
        .spawn()
        .expect("the agent starts");

    // The daemon converges on its first pass and writes what it found into the state file.
    let deadline = Instant::now() + Duration::from_secs(30);
    let state_file = state.join("state.json");
    let mut peers_written = false;
    while Instant::now() < deadline {
        if let Ok(text) = fs::read_to_string(&state_file) {
            if text.contains("\"id\": \"8\"") {
                peers_written = true;
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let _ = child.kill();
    let _ = child.wait();
    assert!(
        peers_written,
        "the daemon did not record its peer in the state file"
    );

    let out = bin()
        .arg("--config")
        .arg(&config)
        .args(["--backend", "simulated", "status", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value: serde_json::Value = serde_json::from_slice(&out).expect("valid json on stdout");
    assert_eq!(value["schema"], 1, "{value}");
    assert_eq!(value["device_id"], "7", "{value}");
    let peers = value["peers"].as_array().expect("peers");
    assert_eq!(peers.len(), 1, "{value}");
    let peer = &peers[0];
    assert_eq!(peer["path"], "direct", "{value}");
    assert_eq!(peer["endpoint"], "203.0.113.9:41287", "{value}");
    assert!(peer["handshake_age_secs"].is_number(), "{value}");
}

/// One agent per host: the second refuses to start rather than program the same interface, and a
/// lock left behind by a process that is gone does not keep the next one out.
#[test]
fn a_second_agent_refuses_to_start_and_a_dead_agents_lock_is_taken_over() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = minimal_config(dir.path());
    write_world(dir.path());
    let state = state_dir(dir.path());
    let lock = state.join("run").join("agent.lock");

    bin()
        .arg("--config")
        .arg(&config)
        .args(["--backend", "simulated", "join", "--token", "tok"])
        .assert()
        .success();

    let mut child = bin()
        .arg("--config")
        .arg(&config)
        .args(["--backend", "simulated", "run"])
        .spawn()
        .expect("the agent starts");
    wait_for(&lock, &|_| true, "the running agent to take the lock");
    let holder = fs::read_to_string(&lock).expect("the lock file");

    bin()
        .arg("--config")
        .arg(&config)
        .args(["--backend", "simulated", "run"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("already running"));

    let _ = child.kill();
    let _ = child.wait();

    let mut second = bin()
        .arg("--config")
        .arg(&config)
        .args(["--backend", "simulated", "run"])
        .spawn()
        .expect("the next agent starts");
    wait_for(
        &lock,
        &|text| text != holder,
        "the next agent to take the lock over",
    );
    let _ = second.kill();
    let _ = second.wait();
}

/// Wait until the lock file holds what `done` asks for, or give up.
fn wait_for(lock: &Path, done: &dyn Fn(&str) -> bool, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut last = String::new();
    while Instant::now() < deadline {
        if let Ok(text) = fs::read_to_string(lock) {
            if done(&text) {
                return;
            }
            last = text;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("gave up waiting for {what} (last contents: {last:?})");
}

fn field(text: &str, name: &str) -> String {
    text.lines()
        .find_map(|line| {
            line.trim()
                .strip_prefix(name)
                .map(|rest| rest.trim().to_string())
        })
        .unwrap_or_else(|| panic!("`{name}` not found in:\n{text}"))
}

fn key_show_line(state: &Path, name: &str) -> String {
    let out = bin()
        .args(["key", "show"])
        .arg("--state-dir")
        .arg(state)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    field(&String::from_utf8(out).expect("utf8"), name)
}

fn base64_decode(text: &str) -> Vec<u8> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let mut accumulator: u32 = 0;
    let mut bits = 0;
    for byte in text.bytes() {
        if byte == b'=' {
            break;
        }
        let value = TABLE
            .iter()
            .position(|candidate| *candidate == byte)
            .unwrap_or_else(|| panic!("not base64: {text}")) as u32;
        accumulator = (accumulator << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((accumulator >> bits) as u8);
        }
    }
    out
}
