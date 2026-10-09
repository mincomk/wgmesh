#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;

use wgmesh_cli::doctor::{self, Snapshot, Sysctl};
use wgmesh_config::agent::Settings;

/// A sysctl reader a test can set, so the forwarding check does not depend on
/// how the machine running the tests happens to be configured.
struct Fixture(BTreeMap<String, bool>);

impl Sysctl for Fixture {
    fn read(&self, key: &str) -> Option<bool> {
        self.0.get(key).copied()
    }
}

fn sysctl(ipv4: bool, ipv6: bool) -> Fixture {
    Fixture(BTreeMap::from([
        (doctor::IPV4_FORWARD.to_owned(), ipv4),
        (doctor::IPV6_FORWARD.to_owned(), ipv6),
    ]))
}

fn settings(text: &str) -> Settings {
    toml::from_str(text).expect("the settings parse")
}

fn snapshot(peers: &str) -> Snapshot {
    let text = format!(
        r#"{{
            "network": {{ "id": 1, "name": "prod", "cidr": "10.77.0.0/16", "mtu": 1420,
                         "relay_policy": "any" }},
            "me": {{ "device_id": "d_self", "tunnel_ip": "10.77.0.7/16", "state": "active" }},
            "peers": [{peers}]
        }}"#
    );
    serde_json::from_str(&text).expect("the snapshot parses")
}

fn peer(name: &str, last: u8, advertised: &[&str]) -> String {
    let advertised: Vec<String> = advertised
        .iter()
        .map(|band| format!("\"{band}\""))
        .collect();
    format!(
        r#"{{ "device_id": "d_{name}", "name": "{name}", "wg_pubkey": "AAAA",
             "tunnel_ip": "10.77.0.{last}/16", "advertised": [{}], "state": "active" }}"#,
        advertised.join(",")
    )
}

fn codes(report: &doctor::Report) -> Vec<&'static str> {
    report
        .findings
        .iter()
        .map(|finding| finding.code.as_str())
        .collect()
}

#[test]
fn a_healthy_node_comes_back_clean() {
    let settings = settings("");
    let snapshot = snapshot(&format!("{}, {}", peer("b", 8, &[]), peer("c", 9, &[])));
    let report = doctor::run(&settings, Some(&snapshot), &sysctl(true, true));
    assert!(
        report.findings.is_empty(),
        "a healthy node reported {:?}",
        codes(&report)
    );
}

#[test]
fn an_unmanaged_routing_table_while_routes_are_needed_is_caught() {
    let settings = settings("[route]\ntable = \"off\"\n");
    let snapshot = snapshot(&format!("{}, {}", peer("b", 8, &[]), peer("c", 9, &[])));
    let report = doctor::run(&settings, Some(&snapshot), &sysctl(true, true));
    assert!(
        codes(&report).contains(&"routes-needed-but-table-off"),
        "table = \"off\" with routes to install was not reported: {:?}",
        codes(&report)
    );
    assert!(report.findings[0].remedy.contains("route.table"));
}

#[test]
fn an_unmanaged_table_with_no_route_wanted_is_fine() {
    let settings = settings("[route]\ntable = \"off\"\nprefixes = \"none\"\n");
    let report = doctor::run(&settings, None, &sysctl(true, true));
    assert!(report.findings.is_empty(), "{:?}", codes(&report));
}

#[test]
fn a_catch_all_on_two_peers_is_caught() {
    let settings = settings("");
    let snapshot = snapshot(&format!(
        "{}, {}",
        peer("router-a", 8, &["0.0.0.0/0"]),
        peer("router-b", 9, &["0.0.0.0/0"])
    ));
    let report = doctor::run(&settings, Some(&snapshot), &sysctl(true, true));
    assert!(
        codes(&report).contains(&"catch-all-on-multiple-peers"),
        "two peers carrying a catch-all was not reported: {:?}",
        codes(&report)
    );
    assert!(report.findings[0].summary.contains("router-a"));
    assert!(report.findings[0].summary.contains("router-b"));
}

#[test]
fn forwarding_on_while_the_kernel_refuses_to_forward_is_caught() {
    let settings = settings("[forwarding]\nenabled = true\n");
    let snapshot = snapshot(&peer("b", 8, &[]));
    let report = doctor::run(&settings, Some(&snapshot), &sysctl(false, false));
    assert!(
        codes(&report).contains(&"forwarding-enabled-without-ip-forward"),
        "forwarding.enabled with ip_forward off was not reported: {:?}",
        codes(&report)
    );
}

#[test]
fn forwarding_on_with_the_kernel_forwarding_is_fine() {
    let settings = settings("[forwarding]\nenabled = true\n");
    let snapshot = snapshot(&peer("b", 8, &[]));
    let report = doctor::run(&settings, Some(&snapshot), &sysctl(true, true));
    assert!(report.findings.is_empty(), "{:?}", codes(&report));
}

#[test]
fn prefixes_outside_what_the_coordinator_handed_out_are_caught() {
    let settings = settings("[route]\nprefixes = [\"10.77.0.0/16\", \"192.168.5.0/24\"]\n");
    let snapshot = snapshot(&peer("b", 8, &[]));
    let report = doctor::run(&settings, Some(&snapshot), &sysctl(true, true));
    assert!(
        codes(&report).contains(&"prefixes-outside-coordinator-bands"),
        "a prefix outside the coordinator's bands was not reported: {:?}",
        codes(&report)
    );
    assert!(report.findings[0].summary.contains("192.168.5.0/24"));
}

#[test]
fn a_prefix_a_peer_advertises_is_accepted() {
    let settings = settings("[route]\nprefixes = [\"10.77.0.0/16\", \"192.168.5.0/24\"]\n");
    let snapshot = snapshot(&peer("router", 8, &["192.168.5.0/24"]));
    let report = doctor::run(&settings, Some(&snapshot), &sysctl(true, true));
    assert!(
        report.findings.is_empty(),
        "a band a peer advertises was refused: {:?}",
        codes(&report)
    );
}

#[test]
fn the_exit_peer_keeps_the_catch_all_on_its_own() {
    let settings = settings("[peers]\nexit_peer = \"gw\"\n");
    let snapshot = snapshot(&format!("{}, {}", peer("gw", 8, &[]), peer("b", 9, &[])));
    let report = doctor::run(&settings, Some(&snapshot), &sysctl(true, true));
    assert!(
        report.findings.is_empty(),
        "one exit peer carrying the catch-all was reported as a problem: {:?}",
        codes(&report)
    );
}

#[test]
fn without_a_snapshot_the_peer_checks_say_so_instead_of_passing_silently() {
    let settings = settings("");
    let report = doctor::run(&settings, None, &sysctl(true, true));
    assert!(report.findings.is_empty());
    assert!(
        report
            .notes
            .iter()
            .any(|note| note.contains("no --snapshot")),
        "doctor did not admit which checks it skipped: {:?}",
        report.notes
    );
}

#[test]
fn the_json_report_carries_every_finding() {
    let settings = settings("[forwarding]\nenabled = true\n");
    let snapshot = snapshot(&peer("b", 8, &[]));
    let report = doctor::run(&settings, Some(&snapshot), &sysctl(false, false));
    let json = doctor::as_json(&report, None);
    let findings = json["findings"].as_array().expect("an array of findings");
    assert_eq!(findings.len(), 1);
    assert_eq!(
        findings[0]["code"],
        serde_json::Value::String("forwarding-enabled-without-ip-forward".to_owned())
    );
    assert_eq!(
        findings[0]["severity"],
        serde_json::Value::String("error".to_owned())
    );
}

#[test]
fn the_rendered_report_names_the_code_and_the_remedy() {
    let settings = settings("[route]\ntable = \"off\"\n");
    let snapshot = snapshot(&peer("b", 8, &[]));
    let report = doctor::run(&settings, Some(&snapshot), &sysctl(true, true));
    let text = doctor::render(&report, None);
    assert!(text.contains("routes-needed-but-table-off"));
    assert!(text.contains("route.table = \"main\""));
    assert!(text.contains("nat: not probed"));
}
