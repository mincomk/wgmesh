#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::PathBuf;
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_wgmesh");
const PIN_A: &str = "eef4fe3c04c8f4fb8a918abab36cd3fc76f6274aee0efaeb942e595ac03f3a1c";
const PIN_B: &str = "126305e03335353e8ced874514512ee646fa380247802e061c539b2c7a8a00d5";

fn fixture(name: &str) -> String {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("../wgmesh-client/tests/fixtures");
    path.push(name);
    path.to_string_lossy().into_owned()
}

fn run(args: &[&str]) -> (bool, String) {
    let output = Command::new(BIN).args(args).output().unwrap();
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    (output.status.success(), text)
}

#[test]
fn trust_rotate_updates_the_pin_and_trust_show_reads_it_back() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("agent.toml");
    fs::write(
        &config,
        "network = \"prod\"\ncoordinator = \"https://wgmesh.example.com\"\n",
    )
    .unwrap();
    let config = config.to_string_lossy().into_owned();

    let (ok, text) = run(&["trust", "show", "--config", &config]);
    assert!(ok, "{text}");
    assert!(text.contains("no pin"), "{text}");

    let (ok, text) = run(&[
        "trust",
        "rotate",
        "--config",
        &config,
        "--from-cert",
        &fixture("coordinator-a.pem"),
    ]);
    assert!(ok, "{text}");
    assert!(text.contains(PIN_A), "{text}");

    let written = fs::read_to_string(&config).unwrap();
    assert!(written.contains(PIN_A));
    assert!(written.contains("network = \"prod\""));

    let (ok, text) = run(&["trust", "show", "--config", &config]);
    assert!(ok, "{text}");
    assert!(text.contains(PIN_A), "{text}");

    let (ok, text) = run(&[
        "trust",
        "rotate",
        "--config",
        &config,
        "--from-cert",
        &fixture("coordinator-b.pem"),
    ]);
    assert!(ok, "{text}");
    assert!(text.contains(PIN_B), "{text}");

    let (ok, text) = run(&["trust", "show", "--config", &config]);
    assert!(ok, "{text}");
    assert!(
        text.contains(PIN_B) && !text.contains(PIN_A),
        "the pin moved to the new certificate and the old value is gone: {text}"
    );
    assert_eq!(
        fs::read_to_string(&config)
            .unwrap()
            .matches("coordinator_spki_sha256")
            .count(),
        1
    );
}

#[test]
fn trust_pin_reports_the_pin_of_a_certificate_without_writing_anything() {
    for name in ["coordinator-a.pem", "coordinator-a.der"] {
        let (ok, text) = run(&["trust", "pin", &fixture(name)]);
        assert!(ok, "{text}");
        assert!(text.contains(PIN_A), "{name}: {text}");
    }
    let (ok, text) = run(&["trust", "pin", &fixture("coordinator-b.der")]);
    assert!(ok, "{text}");
    assert!(text.contains(PIN_B), "{text}");
}

#[test]
fn trust_refuses_something_that_is_not_a_certificate() {
    let dir = tempfile::tempdir().unwrap();
    let not_a_cert = dir.path().join("notes.txt");
    fs::write(&not_a_cert, "hello").unwrap();
    let config = dir.path().join("agent.toml");
    fs::write(&config, "network = \"prod\"\n").unwrap();
    let (ok, text) = run(&[
        "trust",
        "rotate",
        "--config",
        &config.to_string_lossy(),
        "--from-cert",
        &not_a_cert.to_string_lossy(),
    ]);
    assert!(!ok, "{text}");
    assert_eq!(fs::read_to_string(&config).unwrap(), "network = \"prod\"\n");
}
