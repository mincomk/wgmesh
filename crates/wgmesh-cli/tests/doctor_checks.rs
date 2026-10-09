#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;

use wgmesh_config::agent as settings;
use wgmesh_proto::{
    ConfigSnapshot, NetworkView, PeerState, PeerView, RelayState, RelayView, SlotView,
};

use wgmesh_cli::doctor::{self, Sysctl};

/// A sysctl reader a test can set, so the forwarding check does not depend on
/// how the machine running the tests happens to be configured.
fn sysctl(ipv4: bool, ipv6: bool) -> BTreeMap<String, bool> {
    BTreeMap::from([
        ("/proc/sys/net/ipv4/ip_forward".to_owned(), ipv4),
        ("/proc/sys/net/ipv6/conf/all/forwarding".to_owned(), ipv6),
    ])
}

struct Fixture(BTreeMap<String, bool>);

impl Sysctl for Fixture {
    fn read(&self, key: &str) -> Option<bool> {
        self.0.get(key).copied()
    }
}

fn base_settings() -> settings::Settings {
    let mut settings = settings::Settings::default();
    settings.coordinator.url = "https://wgcoord.example.com".to_owned();
    settings.coordinator.spki_sha256 = "9f2c".repeat(16);
    settings
}

fn peer(name: &str, last: u8, advertised: Vec<&str>) -> PeerView {
    PeerView {
        device_id: format!("d_{name}"),
        name: name.to_owned(),
        wg_pubkey: "AAAA".to_owned(),
        tunnel_ip: format!("10.77.0.{last}/16"),
        state: PeerState::Active,
        advertised: advertised.into_iter().map(str::to_owned).collect(),
        endpoint: None,
    }
}

fn snapshot(peers: Vec<PeerView>) -> ConfigSnapshot {
    ConfigSnapshot {
        etag: "cfg-9".to_owned(),
        generation: 9,
        network: NetworkView {
            name: "prod".to_owned(),
            cidr: "10.77.0.0/16".to_owned(),
            mtu: 1420,
        },
        device: PeerView {
            device_id: "d_self".to_owned(),
            name: "self".to_owned(),
            wg_pubkey: "BBBB".to_owned(),
            tunnel_ip: "10.77.0.7/16".to_owned(),
            state: PeerState::Active,
            advertised: vec![],
            endpoint: None,
        },
        peers,
        slots: vec![SlotView {
            relay_id: "relay_1".to_owned(),
            udp_port: 51_901,
        }],
        assignments: vec![],
        relays: vec![RelayView {
            relay_id: "relay_1".to_owned(),
            name: "relay-1".to_owned(),
            endpoint_host: "203.0.113.5".to_owned(),
            region: None,
            state: RelayState::Active,
        }],
    }
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
    let settings = base_settings();
    let snapshot = snapshot(vec![peer("b", 8, vec![]), peer("c", 9, vec![])]);
    let report = doctor::run(&settings, Some(&snapshot), &Fixture(sysctl(true, true)))
        .expect("the configuration is readable");
    assert!(
        report.findings.is_empty(),
        "a healthy node reported {:?}",
        codes(&report)
    );
}

#[test]
fn an_unmanaged_routing_table_while_routes_are_needed_is_caught() {
    let mut settings = base_settings();
    settings.route.table = settings::TableSetting::Named("off".to_owned());
    let snapshot = snapshot(vec![peer("b", 8, vec![]), peer("c", 9, vec![])]);
    let report = doctor::run(&settings, Some(&snapshot), &Fixture(sysctl(true, true)))
        .expect("the configuration is readable");
    assert!(
        codes(&report).contains(&"routes-needed-but-table-off"),
        "table = \"off\" with routes to install was not reported: {:?}",
        codes(&report)
    );
    assert!(report.findings[0].remedy.contains("route.table"));
}

#[test]
fn a_catch_all_on_two_peers_is_caught() {
    let settings = base_settings();
    let snapshot = snapshot(vec![
        peer("router-a", 8, vec!["0.0.0.0/0"]),
        peer("router-b", 9, vec!["0.0.0.0/0"]),
    ]);
    let report = doctor::run(&settings, Some(&snapshot), &Fixture(sysctl(true, true)))
        .expect("the configuration is readable");
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
    let mut settings = base_settings();
    settings.forwarding.enabled = true;
    let snapshot = snapshot(vec![peer("b", 8, vec![])]);
    let report = doctor::run(&settings, Some(&snapshot), &Fixture(sysctl(false, false)))
        .expect("the configuration is readable");
    assert!(
        codes(&report).contains(&"forwarding-enabled-without-ip-forward"),
        "forwarding.enabled with ip_forward off was not reported: {:?}",
        codes(&report)
    );
}

#[test]
fn prefixes_outside_what_the_coordinator_handed_out_are_caught() {
    let mut settings = base_settings();
    settings.route.prefixes = settings::PrefixesSetting::List(vec![
        "10.77.0.0/16".to_owned(),
        "192.168.5.0/24".to_owned(),
    ]);
    let snapshot = snapshot(vec![peer("b", 8, vec![])]);
    let report = doctor::run(&settings, Some(&snapshot), &Fixture(sysctl(true, true)))
        .expect("the configuration is readable");
    assert!(
        codes(&report).contains(&"prefixes-outside-coordinator-bands"),
        "a prefix outside the coordinator's bands was not reported: {:?}",
        codes(&report)
    );
    assert!(report.findings[0].summary.contains("192.168.5.0/24"));
}

#[test]
fn a_prefix_a_peer_advertises_is_accepted() {
    let mut settings = base_settings();
    settings.route.prefixes = settings::PrefixesSetting::List(vec![
        "10.77.0.0/16".to_owned(),
        "192.168.5.0/24".to_owned(),
    ]);
    let snapshot = snapshot(vec![peer("router", 8, vec!["192.168.5.0/24"])]);
    let report = doctor::run(&settings, Some(&snapshot), &Fixture(sysctl(true, true)))
        .expect("the configuration is readable");
    assert!(
        report.findings.is_empty(),
        "a band a peer advertises was refused: {:?}",
        codes(&report)
    );
}

#[test]
fn the_exit_peer_keeps_the_catch_all_on_its_own() {
    let mut settings = base_settings();
    settings.peers.exit_peer = "gw".to_owned();
    let snapshot = snapshot(vec![peer("gw", 8, vec![]), peer("b", 9, vec![])]);
    let report = doctor::run(&settings, Some(&snapshot), &Fixture(sysctl(true, true)))
        .expect("the configuration is readable");
    assert!(
        report.findings.is_empty(),
        "one exit peer carrying the catch-all was reported as a problem: {:?}",
        codes(&report)
    );
}

#[test]
fn without_a_snapshot_the_peer_checks_say_so_instead_of_passing_silently() {
    let settings = base_settings();
    let report = doctor::run(&settings, None, &Fixture(sysctl(true, true)))
        .expect("the configuration is readable");
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
    let mut settings = base_settings();
    settings.forwarding.enabled = true;
    let snapshot = snapshot(vec![peer("b", 8, vec![])]);
    let report = doctor::run(&settings, Some(&snapshot), &Fixture(sysctl(false, false)))
        .expect("the configuration is readable");
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
    let mut settings = base_settings();
    settings.route.table = settings::TableSetting::Named("off".to_owned());
    let snapshot = snapshot(vec![peer("b", 8, vec![])]);
    let report = doctor::run(&settings, Some(&snapshot), &Fixture(sysctl(true, true)))
        .expect("the configuration is readable");
    let text = doctor::render(&report, None);
    assert!(text.contains("routes-needed-but-table-off"));
    assert!(text.contains("route.table = \"main\""));
    assert!(text.contains("nat: not probed"));
}
