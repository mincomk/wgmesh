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
    CoordinatorProcess, DEVICE_A, DEVICE_B, DEVICE_C, DEVICE_D, budget, relay_forwarded,
    spawn_fleet, start_pair, wait_until,
};
use wgmesh_conformance::{NatMode, relay_of};

/// How far apart the outage samples are: this is the unit the gaps below are
/// counted in, so the assertion's meaning ("never down for more than a sample")
/// is the interval, not a number that has to be inferred from a sleep.
const SAMPLE: Duration = Duration::from_millis(100);

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

    let up = wait_until(budget::PAIRS_UP, || {
        ab.a.agent.up() && ab.b.agent.up() && cd.a.agent.up() && cd.b.agent.up()
    });
    assert!(
        up,
        "both pairs must come up relayed, but {} was never seen: ab {}/{} cd {}/{}",
        budget::PAIRS_UP,
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
    //
    // The evidence is each agent's own record of a probe that gave up -- a fact
    // the state machine writes once -- rather than a sampled `up()`. A machine
    // that starves an agent for longer than `UP_WINDOW` makes a live pair read as
    // down, and a wait that needs four such readings at the same instant would be
    // waiting on the scheduler.
    let expired = wait_until(budget::PUNCHES_EXPIRED, || {
        [&ab.a, &ab.b, &cd.a, &cd.b]
            .iter()
            .all(|peer| peer.agent.snapshot().fallback_ms.is_some())
    });
    assert!(
        expired,
        "the punch window must expire and fall back to the relay, but {} was never seen: \
         ab {}/{} cd {}/{} fell back",
        budget::PUNCHES_EXPIRED,
        ab.a.agent.snapshot().fallback_ms.is_some(),
        ab.b.agent.snapshot().fallback_ms.is_some(),
        cd.a.agent.snapshot().fallback_ms.is_some(),
        cd.b.agent.snapshot().fallback_ms.is_some()
    );

    // And the relayed path is carrying traffic on both pairs, which is what the
    // kill is measured against. This one is a reading of `up()`, waited for on
    // its own: below this line the scenario is entitled to assume the relay was
    // live, and above it it is not.
    let carrying = wait_until(budget::RELAYS_CARRYING, || {
        ab.a.agent.up() && ab.b.agent.up() && cd.a.agent.up() && cd.b.agent.up()
    });
    assert!(
        carrying,
        "the relayed path has to be carrying traffic before the kill means anything, but {} \
         was never seen: ab {}/{} cd {}/{}",
        budget::RELAYS_CARRYING,
        ab.a.agent.up(),
        ab.b.agent.up(),
        cd.a.agent.up(),
        cd.b.agent.up()
    );
    let forwarded_before = relay_forwarded(&coordinator.state());

    println!("killing relay-1 (the home of pair {DEVICE_A}/{DEVICE_B})");
    fleet[0].kill();

    // One sample of silence is a scheduling artefact on a loaded machine, not an
    // outage: an outage is *sustained*. The pair that lost its relay is
    // unreachable for the whole re-homing (seconds); the pair on the survivor
    // should never miss more than a sample. Samples are 100ms apart.
    let mut ab_down_run = 0usize;
    let mut ab_longest_gap = 0usize;
    let mut cd_down_run = 0usize;
    let mut cd_longest_gap = 0usize;
    let started = Instant::now();
    let deadline = budget::CUT_PAIR_REHOMED.deadline_from(started);
    let mut rehomed = false;
    while Instant::now() < deadline {
        let ab_up = ab.a.agent.up() && ab.b.agent.up();
        let cd_up = cd.a.agent.up() && cd.b.agent.up();
        if ab_up {
            ab_down_run = 0;
        } else {
            ab_down_run += 1;
            ab_longest_gap = ab_longest_gap.max(ab_down_run);
        }
        if cd_up {
            cd_down_run = 0;
        } else {
            cd_down_run += 1;
            cd_longest_gap = cd_longest_gap.max(cd_down_run);
        }
        // Re-homing is the counter each end keeps, not a sample: an agent that
        // acted on its second assignment has been re-homed, whatever the harness
        // caught it doing at that instant.
        if ab.a.agent.snapshot().assignments >= 2 && ab.b.agent.snapshot().assignments >= 2 {
            rehomed = true;
            break;
        }
        thread::sleep(SAMPLE);
    }
    if !rehomed {
        budget::CUT_PAIR_REHOMED.expired(started.elapsed());
    }

    // Reachability is its own wait rather than a single reading taken at the end:
    // a re-homed pair is up again the moment its next keepalive lands on the
    // survivor, and on a loaded machine that moment is not the moment the
    // assignment was made.
    let ab_recovered = wait_until(budget::CUT_PAIR_REACHABLE, || {
        ab.a.agent.up() && ab.b.agent.up()
    });

    let ab_assignments = ab.a.agent.snapshot().assignments;
    let cd_assignments = cd.a.agent.snapshot().assignments;

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

    println!(
        "longest unreachable run: pair {DEVICE_A}/{DEVICE_B} {ab_longest_gap} samples, \
         pair {DEVICE_C}/{DEVICE_D} {cd_longest_gap} samples"
    );
    // The deterministic evidence that the cut pair was cut and re-homed: it acted
    // on two assignments, the untouched pair on one. (A trailing "heard from
    // within UP_WINDOW" reading hides the first 1.5s of an outage, so the sampled
    // gap below is corroboration, not the proof.)
    assert!(
        ab_assignments >= 2,
        "the pair homed on the dead relay must be re-homed (assignments {ab_assignments})"
    );
    assert!(
        ab_recovered,
        "and must be reachable again once it is re-homed onto the survivor: {} was never seen",
        budget::CUT_PAIR_REACHABLE
    );
    assert_eq!(
        cd_assignments, 1,
        "the pair on the surviving relay must never be re-homed"
    );
    assert!(
        cd_longest_gap <= 1,
        "nor disturbed (longest gap {cd_longest_gap} samples)"
    );
    assert!(
        ab_longest_gap >= cd_longest_gap,
        "the cut pair is the one that went unreachable (runs: {ab_longest_gap} vs {cd_longest_gap})"
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
