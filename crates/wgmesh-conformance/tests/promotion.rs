// The NAT campaign table, reproduced over real UDP sockets on loopback.
//
// The rows are the ones `wgmesh-nat-lab.py` printed:
//
// | A           | B           | path            |
// |-------------|-------------|-----------------|
// | cone        | cone        | direct / direct |
// | restricted  | restricted  | direct / direct |
// | cone        | restricted  | direct / direct |
// | restricted  | cone        | direct / direct |
// | symmetric   | symmetric   | relayed / relayed, after a failed punch |
//
// Each test also asserts the *structural* reason for its row: an
// endpoint-independent mapping is one external port for every destination, and
// a symmetric one is a fresh external port per destination -- which is why the
// address the relay observed is only reachable when the mapping is shared.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::print_stdout)]

use std::time::Duration;

use wgmesh_conformance::lab::default_traversal;
use wgmesh_conformance::{NatMode, Path, campaign};

#[test]
fn the_traversal_timings_are_the_designs_own() {
    let cfg = default_traversal();
    assert_eq!(
        cfg.punch_delay,
        Duration::from_secs(2),
        "the punch must wait for both ends to be observed first"
    );
    assert_eq!(
        cfg.punch_window,
        Duration::from_secs(5),
        "the probe window the acceptance criteria name"
    );
    assert_eq!(
        cfg.backoff.first().copied(),
        Some(Duration::from_secs(30)),
        "the first backoff a failed punch falls back to"
    );
}

#[test]
fn cone_plus_cone_punches_a_direct_path() {
    let out = campaign(NatMode::Cone, NatMode::Cone);
    assert_eq!(out.start_a, Path::Relayed, "both ends start on the relay");
    assert_eq!(out.start_b, Path::Relayed);
    assert_eq!(out.final_a, Path::Direct, "cone + cone must promote");
    assert_eq!(out.final_b, Path::Direct);
    assert_eq!(out.mappings_a, 1, "endpoint-independent mapping: one port");
    assert_eq!(out.mappings_b, 1);
    assert_eq!(out.attempts_a, 0, "a punch that works is not a failed one");
    assert_eq!(out.attempts_b, 0);
}

#[test]
fn restricted_plus_restricted_punches_a_direct_path() {
    let out = campaign(NatMode::Restricted, NatMode::Restricted);
    assert_eq!(out.start_a, Path::Relayed);
    assert_eq!(out.start_b, Path::Relayed);
    assert_eq!(
        out.final_a,
        Path::Direct,
        "simultaneous send opens both filters"
    );
    assert_eq!(out.final_b, Path::Direct);
    assert_eq!(out.mappings_a, 1, "endpoint-independent mapping: one port");
    assert_eq!(out.mappings_b, 1);
}

#[test]
fn cone_plus_restricted_punches_a_direct_path() {
    let out = campaign(NatMode::Cone, NatMode::Restricted);
    assert_eq!(out.start_a, Path::Relayed);
    assert_eq!(out.start_b, Path::Relayed);
    assert_eq!(out.final_a, Path::Direct);
    assert_eq!(out.final_b, Path::Direct);
}

#[test]
fn restricted_plus_cone_punches_a_direct_path() {
    let out = campaign(NatMode::Restricted, NatMode::Cone);
    assert_eq!(out.start_a, Path::Relayed);
    assert_eq!(out.start_b, Path::Relayed);
    assert_eq!(out.final_a, Path::Direct);
    assert_eq!(out.final_b, Path::Direct);
}

#[test]
fn symmetric_plus_symmetric_stays_relayed_and_backs_off() {
    let out = campaign(NatMode::Symmetric, NatMode::Symmetric);
    assert_eq!(out.start_a, Path::Relayed);
    assert_eq!(out.start_b, Path::Relayed);
    assert_eq!(
        out.final_a,
        Path::Relayed,
        "a symmetric NAT cannot be punched"
    );
    assert_eq!(out.final_b, Path::Relayed);

    assert!(
        out.mappings_a >= 2 && out.mappings_b >= 2,
        "a symmetric NAT makes a fresh mapping per destination: A={} B={}",
        out.mappings_a,
        out.mappings_b
    );

    let probe = out.probe_secs.expect("a punch was attempted");
    assert!(
        (4.0..8.0).contains(&probe),
        "the probe must run for punch_window (5s) before falling back, took {probe:.1}s"
    );

    assert!(
        out.attempts_a >= 1 && out.attempts_b >= 1,
        "the punch failed"
    );
    for backoff in [out.backoff_a, out.backoff_b] {
        let backoff = backoff.expect("a failed punch leaves a backoff pending");
        assert!(
            backoff >= Duration::from_secs(25),
            "the backoff must grow to the first table entry (30s), got {backoff:?}"
        );
        assert!(
            backoff <= Duration::from_secs(31),
            "and only to it, got {backoff:?}"
        );
    }

    // The relayed path is live again *after* the fallback: the relay's counter
    // must grow once the punch has given up, not merely be non-zero from the
    // relayed session that preceded it.
    let at_fallback = out
        .forwarded_at_fallback
        .expect("the fallback was observed, so the counter was sampled then");
    assert!(
        out.relay_forwarded > at_fallback,
        "the fallback must put traffic back on the relay: {at_fallback} -> {}",
        out.relay_forwarded
    );
}
