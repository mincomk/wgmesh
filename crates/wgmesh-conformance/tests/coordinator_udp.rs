// The structural claim: the coordinator does not carry data.
//
// Behavioural tests can only show that no UDP packet *was seen* on the
// coordinator. This one looks at the running process's own socket table and
// asserts it holds no UDP socket at all -- while the same check, run against
// the harness and against a relay, finds the UDP sockets that certainly do
// exist. Positive and negative controls in one test, so a broken check cannot
// pass as a clean coordinator.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::print_stdout)]

use wgmesh_conformance::lab::{
    CoordinatorProcess, DEVICE_A, DEVICE_B, budget, spawn_fleet, start_pair, wait_until,
};
use wgmesh_conformance::{NatMode, proc};

#[test]
fn the_coordinator_holds_no_udp_socket() {
    let coordinator = CoordinatorProcess::start();
    let fleet = spawn_fleet(&coordinator, &["relay-1", "relay-2"]);
    let duo = start_pair(
        &coordinator,
        NatMode::Cone,
        NatMode::Cone,
        DEVICE_A,
        DEVICE_B,
    );

    let up = wait_until(budget::RELAYED_SESSION_UP, || {
        duo.a.agent.up() && duo.b.agent.up()
    });
    assert!(
        up,
        "the pair has to be talking over the relay before this check means anything, \
         but {} was never seen",
        budget::RELAYED_SESSION_UP
    );

    let coordinator_pid = coordinator.pid();
    let coordinator_udp = proc::process_udp_inodes(coordinator_pid);
    let coordinator_tcp = proc::process_tcp_inodes(coordinator_pid);
    let own_udp = proc::process_udp_inodes(std::process::id());
    let relay_udp: usize = fleet
        .iter()
        .map(|relay| proc::process_udp_inodes(relay.pid()).len())
        .sum();

    println!(
        "UDP sockets: harness={}, relays={}, coordinator={} (TCP on the coordinator: {})",
        own_udp.len(),
        relay_udp,
        coordinator_udp.len(),
        coordinator_tcp.len()
    );

    // Positive controls: the same check finds UDP sockets where they exist.
    assert!(
        own_udp.len() >= 2,
        "the harness holds the two agents' UDP sockets"
    );
    assert!(
        relay_udp >= 2,
        "each relay holds a UDP slot per served device, found {relay_udp}"
    );
    assert!(
        !coordinator_tcp.is_empty(),
        "the coordinator does hold its control-plane TCP socket"
    );

    // The claim.
    assert!(
        coordinator_udp.is_empty(),
        "the coordinator holds UDP sockets: {:?}",
        proc::describe_udp(coordinator_pid)
    );
    assert!(
        proc::describe_udp(coordinator_pid).is_empty(),
        "no /proc/net/udp row belongs to the coordinator"
    );
}
