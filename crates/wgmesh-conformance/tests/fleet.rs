// Scenario 4: a relay dies.
//
// Two pairs, each behind a symmetric NAT on both ends, so neither can punch and
// both live on their assigned relay -- which is what makes the relay's liveness
// observable from the outside. Pair (A,B) is homed on relay-1, pair (C,D) on
// relay-2. Killing relay-1 must:
//
// * cut the pair it homed,
// * leave the pair on the surviving relay alone,
// * re-home the cut pair onto the survivor, where it recovers.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::print_stdout)]

use std::thread;
use std::time::{Duration, Instant};

use wgmesh_conformance::lab::{
    CoordinatorProcess, DEVICE_A, DEVICE_B, DEVICE_C, DEVICE_D, relay_forwarded, spawn_fleet,
    start_pair, wait_until,
};
use wgmesh_conformance::{NatMode, relay_of};

#[test]
fn a_dead_relay_costs_its_own_pair_only_and_the_pair_recovers_elsewhere() {
    let coordinator = CoordinatorProcess::start();
    let mut fleet = spawn_fleet(&coordinator, &["relay-1", "relay-2"]);

    let ab = start_pair(
        &coordinator,
        NatMode::Symmetric,
        NatMode::Symmetric,
        DEVICE_A,
        DEVICE_B,
    );
    let cd = start_pair(
        &coordinator,
        NatMode::Symmetric,
        NatMode::Symmetric,
        DEVICE_C,
        DEVICE_D,
    );

    let up = wait_until(Duration::from_secs(20), || {
        ab.a.agent.up() && ab.b.agent.up() && cd.a.agent.up() && cd.b.agent.up()
    });
    assert!(
        up,
        "both pairs must come up relayed: ab {}/{} cd {}/{}",
        ab.a.agent.up(),
        ab.b.agent.up(),
        cd.a.agent.up(),
        cd.b.agent.up()
    );

    let state = coordinator.state();
    assert_eq!(
        relay_of(&state, DEVICE_A).as_deref(),
        Some("relay-1"),
        "the first pair is homed on the first relay"
    );
    assert_eq!(
        relay_of(&state, DEVICE_C).as_deref(),
        Some("relay-2"),
        "the second pair is spread onto the second relay"
    );

    // Let both (doomed) punches expire and both pairs settle back on their relay,
    // so what the kill measures is the relay's liveness and nothing else.
    let settled = wait_until(Duration::from_secs(25), || {
        ab.a.agent.attempts() >= 1
            && ab.b.agent.attempts() >= 1
            && cd.a.agent.attempts() >= 1
            && cd.b.agent.attempts() >= 1
            && ab.a.agent.up()
            && ab.b.agent.up()
            && cd.a.agent.up()
            && cd.b.agent.up()
    });
    assert!(
        settled,
        "the punch window must expire and fall back to the relay: ab {}/{} cd {}/{}",
        ab.a.agent.snapshot().attempts,
        ab.b.agent.snapshot().attempts,
        cd.a.agent.snapshot().attempts,
        cd.b.agent.snapshot().attempts
    );
    let forwarded_before = relay_forwarded(&coordinator.state());

    println!("killing relay-1 (the home of pair {DEVICE_A}/{DEVICE_B})");
    fleet[0].kill();

    let mut ab_down = false;
    let mut ab_recovered = false;
    let mut cd_down = false;
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        let ab_up = ab.a.agent.up() && ab.b.agent.up();
        let cd_up = cd.a.agent.up() && cd.b.agent.up();
        if !ab_up {
            ab_down = true;
        }
        if !cd_up {
            cd_down = true;
        }
        if ab_down && ab_up {
            ab_recovered = true;
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }

    let state = coordinator.state();
    println!(
        "after the kill: pair {DEVICE_A}/{DEVICE_B} on {:?}, pair {DEVICE_C}/{DEVICE_D} on {:?}, \
         relay-1 healthy={:?}",
        relay_of(&state, DEVICE_A),
        relay_of(&state, DEVICE_C),
        state
            .relays
            .iter()
            .find(|relay| relay.id == "relay-1")
            .map(|relay| relay.healthy)
    );

    assert!(
        ab_down,
        "the pair homed on the dead relay must lose its path"
    );
    assert!(
        ab_recovered,
        "and must recover once it is re-homed onto the survivor"
    );
    assert!(
        !cd_down,
        "the pair on the surviving relay must not be disturbed"
    );
    assert_eq!(
        relay_of(&state, DEVICE_A).as_deref(),
        Some("relay-2"),
        "the cut pair is re-homed onto the survivor"
    );
    assert_eq!(
        relay_of(&state, DEVICE_C).as_deref(),
        Some("relay-2"),
        "the surviving pair stays where it was"
    );
    assert!(
        relay_forwarded(&state) > forwarded_before,
        "the survivor keeps forwarding after the re-homing"
    );
}
