#![allow(clippy::unwrap_used, clippy::expect_used)]

use wgmesh_app::{
    CatchAllPolicy, RouteConvergence, desired_routes_of, peers_view, route_plan_view,
    unmanaged_plan_view, validate_routing,
};
use wgmesh_core::{Allowed, RouteChange, RoutePrefixes, RouteSpec, RouteTable};
use wgmesh_ports::fake::FakeRoutes;

fn net() -> Allowed {
    Allowed::V4([10, 77, 0, 0], 16)
}

fn lan() -> Allowed {
    Allowed::V4([192, 168, 5, 0], 24)
}

fn v6() -> Allowed {
    Allowed::V6(
        [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        32,
    )
}

fn host(last: u8) -> Allowed {
    Allowed::V4([10, 77, 0, last], 32)
}

fn peers() -> Vec<(String, Vec<Allowed>)> {
    vec![
        (String::from("A"), vec![host(11)]),
        (String::from("gw"), vec![host(12)]),
        (String::from("C"), vec![host(13)]),
    ]
}

#[test]
fn exit_peer_owns_the_catch_all_and_every_other_peer_keeps_its_own_slash_32() {
    let rows =
        peers_view(&CatchAllPolicy::ExitPeer(String::from("gw")), &peers()).expect("resolves");
    let carrying: Vec<&str> = rows
        .iter()
        .filter(|row| row.carries_catch_all)
        .map(|row| row.name.as_str())
        .collect();
    assert_eq!(
        carrying,
        vec!["gw"],
        "the catch-all belongs to exactly one peer"
    );

    let gw = rows.iter().find(|row| row.name == "gw").unwrap();
    assert_eq!(gw.allowed_ips, vec!["0.0.0.0/0", "::/0"]);
    assert_eq!(gw.policy, "exit:gw");
    let other = rows.iter().find(|row| row.name == "A").unwrap();
    assert_eq!(other.allowed_ips, vec!["10.77.0.11/32"]);
    assert!(!other.carries_catch_all);
    let third = rows.iter().find(|row| row.name == "C").unwrap();
    assert_eq!(third.allowed_ips, vec!["10.77.0.13/32"]);
}

#[test]
fn peer_policy_never_programs_a_catch_all() {
    let rows = peers_view(&CatchAllPolicy::Peer, &peers()).expect("resolves");
    assert!(rows.iter().all(|row| !row.carries_catch_all));
    assert_eq!(
        rows.iter().map(|row| row.allowed_ips.len()).sum::<usize>(),
        3
    );
}

#[test]
fn any_policy_is_refused_as_soon_as_there_is_more_than_one_peer() {
    let single = peers_view(&CatchAllPolicy::Any, &peers()[..1]).expect("one peer is enough");
    assert!(single[0].carries_catch_all);

    let error = peers_view(&CatchAllPolicy::Any, &peers()).unwrap_err();
    assert_eq!(error.code(), "any_policy_needs_one_peer");
    assert!(error.to_string().contains("3 peers are configured"));
}

#[test]
fn an_exit_peer_that_names_nobody_is_refused() {
    let error = peers_view(&CatchAllPolicy::ExitPeer(String::from("nope")), &peers()).unwrap_err();
    assert!(error.to_string().contains("`exit_peer = \"nope\"`"));
}

#[test]
fn an_explicit_prefix_list_puts_only_those_bands_on_the_kernel() {
    let routes = FakeRoutes::new();
    let settings = RoutePrefixes::Only(vec![net(), lan()]);
    let convergence = RouteConvergence::new(&routes, RouteTable::Main, settings)
        .network(&[net()])
        .advertised(&[v6(), Allowed::V4([172, 16, 0, 0], 12)]);

    let applied = convergence
        .settle(Some(&Allowed::V4([10, 77, 0, 7], 16)))
        .expect("the kernel accepts the plan");

    assert_eq!(applied.len(), 2);
    assert_eq!(
        routes.installed(),
        vec![
            RouteSpec::new(net(), RouteTable::Main, None),
            RouteSpec::new(lan(), RouteTable::Main, None),
        ],
        "the network band and the advertised bands stay out: only `prefixes` decides"
    );
    assert_eq!(routes.addresses(), vec![Allowed::V4([10, 77, 0, 7], 16)]);
}

#[test]
fn an_off_table_installs_no_route_at_all() {
    let routes = FakeRoutes::new();
    let convergence = RouteConvergence::new(&routes, RouteTable::Unmanaged, RoutePrefixes::Auto)
        .network(&[net()])
        .advertised(&[lan()]);

    let applied = convergence.settle(Some(&net())).expect("off is valid");
    assert!(applied.is_empty());
    assert!(routes.installed().is_empty());
    assert_eq!(routes.addresses(), vec![net()], "the address is still ours");
}

#[test]
fn a_second_settle_changes_nothing() {
    let routes = FakeRoutes::new();
    let convergence =
        RouteConvergence::new(&routes, RouteTable::Main, RoutePrefixes::Auto).network(&[net()]);
    assert_eq!(convergence.settle(None).expect("first run").len(), 1);
    assert!(
        convergence.settle(None).expect("second run").is_empty(),
        "the plan is recomputed from the kernel, so it converges once"
    );
    assert_eq!(routes.applied().len(), 1);
}

#[test]
fn reset_removes_what_the_marker_owns() {
    let routes = FakeRoutes::new();
    routes.seed(RouteSpec::new(lan(), RouteTable::Main, None));
    let convergence =
        RouteConvergence::new(&routes, RouteTable::Main, RoutePrefixes::Auto).network(&[net()]);

    let removed = convergence.reset().expect("reset");
    assert_eq!(removed, vec![RouteSpec::new(lan(), RouteTable::Main, None)]);
    assert!(routes.installed().is_empty());
    assert_eq!(
        routes.applied(),
        vec![RouteChange::Remove(RouteSpec::new(
            lan(),
            RouteTable::Main,
            None
        ))],
        "reset is exactly `installed` turned into removals"
    );
}

#[test]
fn the_default_route_can_never_be_planned() {
    let table = RouteTable::Main;
    let problems = validate_routing(
        &CatchAllPolicy::Peer,
        &peers(),
        &RoutePrefixes::Only(vec![net(), Allowed::V4([0, 0, 0, 0], 0)]),
        table,
        None,
        &[net()],
        &[],
    );
    assert_eq!(problems.len(), 1);
    assert_eq!(problems[0].code(), "catch_all_prefix");
    assert!(problems[0].detail().contains("default route"));

    let problems = validate_routing(
        &CatchAllPolicy::Peer,
        &peers(),
        &RoutePrefixes::Only(vec![v6(), Allowed::V6([0; 16], 0)]),
        table,
        None,
        &[net()],
        &[],
    );
    assert_eq!(problems.len(), 1);
    assert_eq!(
        problems[0].code(),
        "catch_all_prefix",
        "the v6 default is refused too"
    );
}

#[test]
fn an_explicit_prefix_list_with_an_off_table_is_refused() {
    let problems = validate_routing(
        &CatchAllPolicy::Peer,
        &peers(),
        &RoutePrefixes::Only(vec![net(), lan()]),
        RouteTable::Unmanaged,
        None,
        &[net()],
        &[],
    );
    assert_eq!(problems.len(), 1);
    assert_eq!(problems[0].code(), "prefixes_with_unmanaged_table");
    assert!(problems[0].remedy().contains("table = \"main\""));
}

#[test]
fn a_clean_configuration_reports_nothing_and_plans_the_chosen_bands() {
    let problems = validate_routing(
        &CatchAllPolicy::ExitPeer(String::from("gw")),
        &peers(),
        &RoutePrefixes::Only(vec![lan()]),
        RouteTable::Main,
        Some(50),
        &[net()],
        &[],
    );
    assert!(problems.is_empty());

    let desired = desired_routes_of(&RoutePrefixes::Auto, RouteTable::Main, None, &[net()], &[])
        .expect("plan");
    let view = route_plan_view(
        &desired,
        &RoutePrefixes::Auto,
        RouteTable::Main,
        &[RouteSpec::new(lan(), RouteTable::Main, None)],
    );
    assert_eq!(
        view.changes
            .iter()
            .map(|change| (change.action.as_str(), change.prefix.as_str()))
            .collect::<Vec<_>>(),
        vec![("add", "10.77.0.0/16"), ("remove", "192.168.5.0/24")]
    );
    let text = view.text();
    assert!(!text.contains("0.0.0.0/0"));
    assert!(!text.contains("::/0"));
    assert!(!text.contains("default"));
}

#[test]
fn an_off_table_plans_nothing_but_still_answers() {
    let desired = desired_routes_of(
        &RoutePrefixes::Auto,
        RouteTable::Unmanaged,
        None,
        &[net()],
        &[lan()],
    )
    .expect("off is valid");
    assert!(desired.is_empty(), "an unmanaged table desires nothing");

    let view = unmanaged_plan_view(&RoutePrefixes::Auto);
    assert!(view.is_empty());
    assert_eq!(view.table, "off");
    assert!(
        view.installed.is_empty(),
        "nothing is compared either: cleanup is `routes reset`"
    );
}
