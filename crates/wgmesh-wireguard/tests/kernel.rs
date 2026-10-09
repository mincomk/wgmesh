// The kernel path, which needs CAP_NET_ADMIN and therefore can not run in the
// pod this adapter was written in.
//
// Measured on that pod:
//
//     $ id
//     uid=1000(attacca) gid=1000(attacca)
//     $ grep Cap /proc/self/status
//     CapEff: 0000000000000000
//     $ sudo ip link add dev wgtest0 type wireguard
//     RTNETLINK answers: Operation not permitted
//
// So every test here is `#[ignore]`d. Run them on a host with CAP_NET_ADMIN:
//
//     sudo -E env "PATH=$PATH" cargo test -p wgmesh-wireguard --test kernel \
//         -- --ignored --test-threads=1

#![allow(clippy::expect_used)]

use std::process::Command;

use wgmesh_core::{
    Allowed, Change, DeviceId, PeerSpec, PublicKey, RouteChange, RouteSpec, RouteTable,
};
use wgmesh_ports::{Routes, WireGuard};
use wgmesh_wireguard::{InterfaceSpec, NetlinkRoutes, NetlinkWireGuard, WG_ROUTE_PROTO};

const IFNAME: &str = "wgmesh-test0";
const TUNNEL: Allowed = Allowed::V4([10, 77, 0, 7], 16);
const BAND: Allowed = Allowed::V4([10, 77, 0, 0], 16);
const PEER_KEY: PublicKey = PublicKey::from_bytes([2u8; 32]);
const DEVICE_KEY: &str = "6LTHiAM4vgKEgi5vm30f/EBIEWFDmySkTc9EWCcIqEs=";

fn peer() -> PeerSpec {
    PeerSpec {
        id: DeviceId(1),
        key: PEER_KEY,
        allowed: vec![Allowed::V4([10, 77, 0, 1], 32)],
        endpoint: None,
        keepalive: Some(std::time::Duration::from_secs(25)),
    }
}

fn cleanup() {
    let _ = Command::new("ip").args(["link", "del", IFNAME]).status();
}

#[test]
#[ignore = "needs CAP_NET_ADMIN to create a WireGuard interface"]
fn the_interface_is_created_configured_and_read_back() {
    cleanup();
    let driver = NetlinkWireGuard::new(IFNAME);

    driver
        .ensure_interface(&InterfaceSpec {
            name: IFNAME.to_string(),
            mtu: Some(1420),
            listen_port: Some(51821),
            private_key: Some(DEVICE_KEY.to_string()),
        })
        .expect("the interface is created");

    assert_eq!(driver.listen_port().expect("a listen port"), 51821);

    driver
        .apply(&[Change::Add(peer())])
        .expect("the peer is written");
    let status = driver.status(&[DeviceId(1)]).expect("status is read");
    assert_eq!(status.len(), 1);
    assert_eq!(status[0].peer, DeviceId(1));

    let counters = driver.counters(&[DeviceId(1)]).expect("counters are read");
    assert_eq!(counters.len(), 1);

    driver
        .apply(&[Change::Remove(DeviceId(1))])
        .expect("the peer is removed");
    assert!(
        driver
            .status(&[DeviceId(1)])
            .expect("status is read")
            .is_empty()
    );

    cleanup();
}

#[test]
#[ignore = "needs CAP_NET_ADMIN to create a WireGuard interface"]
fn only_marked_routes_are_read_back() {
    cleanup();
    let driver = NetlinkWireGuard::new(IFNAME);
    driver
        .ensure_interface(&InterfaceSpec::new(IFNAME))
        .expect("the interface is created");

    let routes = NetlinkRoutes::new(IFNAME);
    routes
        .ensure_address(&TUNNEL)
        .expect("the address is added");
    assert!(
        routes.installed().expect("installed routes").is_empty(),
        "nothing has been installed yet"
    );

    let spec = RouteSpec::new(BAND, RouteTable::Main, None);
    routes
        .apply(&[RouteChange::Add(spec.clone())])
        .expect("the route is added");
    assert_eq!(
        routes.installed().expect("installed routes"),
        vec![spec.clone()]
    );

    // The kernel reports more routes than ours; the marker has to be what
    // decides, and only ours comes back.
    let marked = Command::new("ip")
        .args(["route", "show", "proto", &WG_ROUTE_PROTO.to_string()])
        .output()
        .expect("ip route show runs");
    let marked = String::from_utf8_lossy(&marked.stdout);
    assert!(
        marked.contains("10.77.0.0/16"),
        "the kernel does not show our route: {marked}"
    );

    routes
        .apply(&[RouteChange::Remove(spec)])
        .expect("the route is removed");
    assert!(routes.installed().expect("installed routes").is_empty());

    cleanup();
}
