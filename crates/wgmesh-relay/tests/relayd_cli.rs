#![allow(clippy::unwrap_used, clippy::expect_used)]

// The daemon's own surface: the five subcommands have to exist, `enroll` has to tell the
// truth when there is no coordinator, and `run` has to serve a real assignment and stop
// when systemd asks it to.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_wgmesh-relayd"))
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("wgmesh-relayd-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn run(args: &[&str]) -> Output {
    binary().args(args).output().unwrap()
}

fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// Read a child's stdout until it has said `needle`, and answer everything it has said.
///
/// The daemon keeps running whether or not it has an assignment, so this is the only way to read
/// what it said on the way: a plain `wait_with_output` would wait for a process that is designed
/// to keep going.
fn output_until(child: &mut std::process::Child, needle: &str, seconds: u64) -> String {
    let mut stdout = child.stdout.take().expect("stdout is piped");
    let seen = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let sink = seen.clone();
    std::thread::spawn(move || {
        use std::io::Read as _;
        let mut buffer = [0u8; 1024];
        while let Ok(read) = stdout.read(&mut buffer) {
            if read == 0 {
                break;
            }
            if let Ok(mut text) = sink.lock() {
                text.push_str(&String::from_utf8_lossy(&buffer[..read]));
            }
        }
    });

    let deadline = Instant::now() + Duration::from_secs(seconds);
    loop {
        let text = seen.lock().map(|text| text.clone()).unwrap_or_default();
        if text.contains(needle) {
            return text;
        }
        assert!(
            child.try_wait().unwrap().is_none(),
            "the daemon exited before it said `{needle}`: {text}"
        );
        assert!(
            Instant::now() < deadline,
            "the daemon never said `{needle}`: {text}"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}

#[test]
fn run_says_why_it_has_no_assignment_when_no_coordinator_can_be_reached() {
    let state = scratch("run-no-coordinator");
    let arguments = [
        "run",
        "--coordinator",
        "https://127.0.0.1:1",
        "--pin",
        TEST_PIN,
        "--state-dir",
        state.to_str().unwrap(),
    ];

    // With no identity there is nothing to sign a request with, and the relay names the command
    // that produces one rather than pretending it is waiting for the coordinator.
    let mut child = binary()
        .args(arguments)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let text = output_until(&mut child, "enroll", 20);
    let _ = child.kill();
    let _ = child.wait();
    assert!(text.contains("no assignment was fetched"), "{text}");
    assert!(text.contains("wgmesh-relayd enroll"), "{text}");

    // With one, it asks the coordinator — and says what went wrong when it cannot be reached.
    fs::write(state.join("relay-id"), "relay_1\n").unwrap();
    fs::write(state.join("relay.key"), [7u8; 32]).unwrap();
    let mut child = binary()
        .args(arguments)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let text = output_until(&mut child, "unreachable", 30);
    let _ = child.kill();
    let _ = child.wait();
    assert!(text.contains("no assignment was fetched"), "{text}");
    assert!(text.contains("unreachable"), "{text}");
    assert!(text.contains("127.0.0.1:1"), "{text}");
    let _ = fs::remove_dir_all(&state);
}

#[test]
fn help_lists_every_subcommand() {
    let output = run(&["--help"]);
    assert!(output.status.success());
    let text = text(&output);
    for command in ["enroll", "run", "status", "drain", "keyset"] {
        assert!(
            text.contains(command),
            "help must name `{command}`:\n{text}"
        );
    }
}

#[test]
fn an_unknown_subcommand_is_refused() {
    let output = run(&["teleport"]);
    assert!(!output.status.success());
    assert!(text(&output).contains("unknown command"));
}

/// A pin of the right shape. Nothing in these tests reaches a handshake with it.
const TEST_PIN: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[test]
fn enroll_fails_honestly_without_a_coordinator() {
    let state = scratch("enroll");
    let output = run(&[
        "enroll",
        "--coordinator",
        "https://127.0.0.1:1",
        "--pin",
        TEST_PIN,
        "--token",
        "WGMESH-RELAY-TESTONLY",
        "--endpoint-host",
        "198.51.100.9",
        "--state-dir",
        state.to_str().unwrap(),
    ]);

    assert!(
        !output.status.success(),
        "enroll must not report success with no coordinator: {}",
        text(&output)
    );
    let message = text(&output);
    assert!(
        message.contains("unreachable"),
        "the failure must say what actually went wrong:\n{message}"
    );

    // It did do the part it can do: a private relay key, and nothing else.
    let key = state.join("relay.key");
    assert!(key.exists(), "enroll generates the relay key first");
    let mode = fs::metadata(&key).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "the relay key is never world readable");
    assert!(
        !state.join("relay.toml").exists(),
        "a failed enrollment must not leave a configuration behind"
    );
    // Nor an identity: the coordinator is what assigns a relay id, and this one never answered.
    assert!(!state.join("relay-id").exists());
    let _ = fs::remove_dir_all(&state);
}

#[test]
fn enroll_needs_a_token_and_a_coordinator() {
    let state = scratch("enroll-args");
    let no_token = run(&[
        "enroll",
        "--coordinator",
        "https://127.0.0.1:1",
        "--state-dir",
        state.to_str().unwrap(),
    ]);
    assert!(!no_token.status.success());
    assert!(text(&no_token).contains("--token"));

    let no_coordinator = run(&[
        "enroll",
        "--token",
        "WGMESH-RELAY-TESTONLY",
        "--state-dir",
        state.to_str().unwrap(),
    ]);
    assert!(!no_coordinator.status.success());
    assert!(text(&no_coordinator).contains("--coordinator"));

    // A pin is never learned from the connection that is being pinned.
    let no_pin = run(&[
        "enroll",
        "--coordinator",
        "https://127.0.0.1:1",
        "--token",
        "WGMESH-RELAY-TESTONLY",
        "--state-dir",
        state.to_str().unwrap(),
    ]);
    assert!(!no_pin.status.success());
    assert!(text(&no_pin).contains("--pin"), "{}", text(&no_pin));

    // And the coordinator has to be told where the relay is reachable: it publishes that address
    // to every node that has to reach this relay.
    let no_address = run(&[
        "enroll",
        "--coordinator",
        "https://127.0.0.1:1",
        "--pin",
        TEST_PIN,
        "--token",
        "WGMESH-RELAY-TESTONLY",
        "--state-dir",
        state.to_str().unwrap(),
    ]);
    assert!(!no_address.status.success());
    assert!(
        text(&no_address).contains("--endpoint-host"),
        "{}",
        text(&no_address)
    );
    let _ = fs::remove_dir_all(&state);
}

#[test]
fn status_says_the_relay_is_not_running_when_nothing_has_been_written() {
    let state = scratch("status");
    let output = run(&["status", "--state-dir", state.to_str().unwrap()]);
    assert!(output.status.success());
    assert!(text(&output).contains("not running"));
    let _ = fs::remove_dir_all(&state);
}

#[test]
fn status_reads_a_snapshot_left_by_a_running_relay() {
    let state = scratch("status-snapshot");
    fs::write(
        state.join("status"),
        "relay_id=relay_9f2c\nkeyset_devices=3\nkeyset_age_ms=2000\nforwarded=17\n",
    )
    .unwrap();

    let output = run(&["status", "--state-dir", state.to_str().unwrap()]);
    assert!(output.status.success());
    let text = text(&output);
    assert!(text.contains("relay_9f2c"), "{text}");
    assert!(text.contains("keyset_devices=3"), "{text}");
    assert!(text.contains("forwarded=17"), "{text}");
    let _ = fs::remove_dir_all(&state);
}

#[test]
fn drain_writes_and_clears_the_request_a_running_relay_watches() {
    let state = scratch("drain");
    let flag = state.join("drain");

    let on = run(&["drain", "--state-dir", state.to_str().unwrap()]);
    assert!(on.status.success());
    assert!(flag.exists(), "drain must leave the flag the daemon polls");

    let off = run(&["drain", "--off", "--state-dir", state.to_str().unwrap()]);
    assert!(off.status.success());
    assert!(!flag.exists());

    // Clearing an already clear drain is not an error.
    let again = run(&["drain", "--off", "--state-dir", state.to_str().unwrap()]);
    assert!(again.status.success());
    let _ = fs::remove_dir_all(&state);
}

#[test]
fn keyset_says_what_it_knows_and_can_ask_for_a_refresh() {
    let state = scratch("keyset");
    let unknown = run(&["keyset", "--state-dir", state.to_str().unwrap()]);
    assert!(unknown.status.success());
    assert!(text(&unknown).contains("not running"));

    let refresh = run(&[
        "keyset",
        "--refresh",
        "--state-dir",
        state.to_str().unwrap(),
    ]);
    assert!(refresh.status.success());
    assert!(state.join("refresh-keyset").exists());
    let _ = fs::remove_dir_all(&state);
}

#[test]
fn run_refuses_an_assignment_file_it_cannot_read_or_parse() {
    let state = scratch("run-bad");
    let missing = run(&[
        "run",
        "--state-dir",
        state.to_str().unwrap(),
        "--assignment-file",
        "/nonexistent/assignment",
    ]);
    assert!(!missing.status.success());
    assert!(text(&missing).contains("assignment"));

    let broken = state.join("broken");
    fs::write(&broken, "slot 1 not-a-port\n").unwrap();
    let refused = run(&[
        "run",
        "--state-dir",
        state.to_str().unwrap(),
        "--assignment-file",
        broken.to_str().unwrap(),
    ]);
    assert!(!refused.status.success());
    assert!(
        text(&refused).contains("not a number"),
        "{}",
        text(&refused)
    );
    let _ = fs::remove_dir_all(&state);
}

#[test]
fn the_config_file_names_the_policy_for_a_broken_control_link() {
    let state = scratch("config");
    let config = state.join("relay.toml");

    // The availability-first policy is a config decision, not a code path: an operator
    // who would rather keep a live session through a control-plane outage writes `serve`.
    fs::write(
        &config,
        "relay_id = \"relay_9f2c\"\nkeyset_ttl_secs = 300\nestablished_sessions = \"serve\"\n",
    )
    .unwrap();
    let served = run(&[
        "status",
        "--config",
        config.to_str().unwrap(),
        "--state-dir",
        state.to_str().unwrap(),
    ]);
    assert!(
        served.status.success(),
        "`established_sessions = \"serve\"` must be accepted: {}",
        text(&served)
    );

    // Anything else is refused rather than silently defaulted: the policy is the one
    // thing standing between a stale keyset and a revoked device.
    fs::write(&config, "established_sessions = \"maybe\"\n").unwrap();
    let refused = run(&[
        "status",
        "--config",
        config.to_str().unwrap(),
        "--state-dir",
        state.to_str().unwrap(),
    ]);
    assert!(!refused.status.success());
    assert!(
        text(&refused).contains("not `serve` or `refuse`"),
        "{}",
        text(&refused)
    );
    let _ = fs::remove_dir_all(&state);
}

#[test]
fn run_serves_an_assignment_and_stops_on_sigterm() {
    let state = scratch("run-serve");
    let assignment = state.join("assignment");
    // Port 0 asks the operating system for a free slot port, which keeps the test off
    // every other process's ports.
    fs::write(&assignment, "slot 1 0\nslot 2 0\npair 1 2\nkeyset 1 2\n").unwrap();

    let mut child = binary()
        .args([
            "run",
            "--state-dir",
            state.to_str().unwrap(),
            "--assignment-file",
            assignment.to_str().unwrap(),
        ])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();

    // The daemon writes a status snapshot once a second; wait for the first one.
    let status = state.join("status");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !status.exists() {
        assert!(
            child.try_wait().unwrap().is_none(),
            "the daemon exited before it served anything"
        );
        assert!(
            Instant::now() < deadline,
            "the daemon never wrote a status snapshot"
        );
        std::thread::sleep(Duration::from_millis(50));
    }

    let snapshot = fs::read_to_string(&status).unwrap();
    assert!(snapshot.contains("slots=2"), "{snapshot}");
    assert!(snapshot.contains("pairs=1"), "{snapshot}");
    assert!(snapshot.contains("keyset_devices=2"), "{snapshot}");
    assert!(snapshot.contains("dropped.UnknownIngress=0"), "{snapshot}");

    // A signal, not a kill: the daemon installs handlers for exactly the two systemd
    // sends, and the test checks that it leaves on its own.
    let signalled = Command::new("kill")
        .arg("-TERM")
        .arg(child.id().to_string())
        .status()
        .unwrap();
    assert!(signalled.success());

    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(exit) = child.try_wait().unwrap() {
            assert!(exit.success(), "SIGTERM must be a clean stop: {exit:?}");
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the daemon ignored SIGTERM for twenty seconds"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = fs::remove_dir_all(&state);
}

#[test]
fn the_relay_toml_the_nixos_module_renders_is_understood() {
    let state = scratch("module-config");
    let state_dir = state.join("var-lib-wgmesh-relay");
    let config = state.join("relay.toml");
    // Byte for byte the shape `nix/modules/relay.nix` writes: sectioned, with the
    // coordinator URL and the state directory nested one level down.
    let body = format!(
        "[relay]\nport_range = [51820, 51999]\nendpoint_host = \"198.51.100.9\"\n\n[coordinator]\nurl = \"https://127.0.0.1:1/\"\nspki_sha256 = \"{TEST_PIN}\"\nnetwork = \"default\"\n\n[state]\ndir = \"{}\"\n\n[log]\nlevel = \"debug\"\n",
        state_dir.display()
    );
    fs::write(&config, body).unwrap();

    // Neither --coordinator nor --state-dir is passed: both have to come out of the
    // file, which is exactly how `systemd.services.wgmesh-relayd` invokes the binary.
    let output = run(&[
        "enroll",
        "--token",
        "WGMESH-RELAY-TESTONLY",
        "--config",
        config.to_str().unwrap(),
    ]);
    assert!(!output.status.success());
    let message = text(&output);
    assert!(
        message.contains("coordinator unreachable at https://127.0.0.1:1"),
        "the coordinator URL has to come out of the [coordinator] section:\n{message}"
    );
    assert!(
        !message.contains("--pin"),
        "the pin has to come out of the [coordinator] section too:\n{message}"
    );
    assert!(
        state_dir.join("relay.key").exists(),
        "the relay key has to land in the [state] dir the module points at"
    );
    let _ = fs::remove_dir_all(&state);
}
