// The route adapter: pure message builders, and the rtnetlink calls that carry
// them out.

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use futures_util::StreamExt;
use rtnetlink::RouteMessageBuilder;
use rtnetlink::packet_route::route::{
    RouteAddress, RouteAttribute, RouteHeader, RouteMessage, RouteProtocol,
};
use wgmesh_core::{Allowed, RouteChange, RouteSpec, RouteTable};
use wgmesh_ports::{RouteError, Routes};

use crate::runtime::NetlinkRuntime;

/// The `proto` value every wgmesh route carries.
///
/// `iproute2`'s `rt_protos` table leaves 240 unassigned: the kernel owns 0-23
/// and the routing daemons named there own 186-192. `ip route show proto 240`
/// therefore lists wgmesh's routes and nothing else, which is what lets
/// [`Routes::installed`] be the only source of ownership — a state file can be
/// lost or belong to another machine's history, and neither may cause a foreign
/// route to be deleted.
pub const WG_ROUTE_PROTO: u8 = 240;

/// The `rtnetlink` call one [`RouteChange`] becomes.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum RouteOp {
    /// `handle.route().add(..)`
    Add(RouteMessage),
    /// `handle.route().del(..)`
    Del(RouteMessage),
}

/// The route message that installs `spec` on `ifindex`.
pub fn route_message(spec: &RouteSpec, ifindex: u32) -> RouteMessage {
    match spec.prefix {
        Allowed::V4(bytes, mask) => finish(
            RouteMessageBuilder::<Ipv4Addr>::new().destination_prefix(Ipv4Addr::from(bytes), mask),
            spec,
            ifindex,
        ),
        Allowed::V6(bytes, mask) => finish(
            RouteMessageBuilder::<Ipv6Addr>::new().destination_prefix(Ipv6Addr::from(bytes), mask),
            spec,
            ifindex,
        ),
    }
}

/// The request that dumps one address family, for reading back what we own.
pub fn route_dump_message(ipv6: bool) -> RouteMessage {
    if ipv6 {
        RouteMessageBuilder::<Ipv6Addr>::new().build()
    } else {
        RouteMessageBuilder::<Ipv4Addr>::new().build()
    }
}

/// The ordered `rtnetlink` calls `changes` becomes.
pub fn route_ops(changes: &[RouteChange], ifindex: u32) -> Vec<RouteOp> {
    changes
        .iter()
        .map(|change| match change {
            RouteChange::Add(spec) => RouteOp::Add(route_message(spec, ifindex)),
            RouteChange::Remove(spec) => RouteOp::Del(route_message(spec, ifindex)),
        })
        .collect()
}

/// The specification a kernel route message describes, when it is ours.
///
/// `None` is the answer for every route that does not carry the wgmesh `proto`
/// marker — that filter is what keeps `route reset` from touching a route
/// somebody else installed.
pub fn installed_spec(message: &RouteMessage) -> Option<RouteSpec> {
    if message.header.protocol != RouteProtocol::Other(WG_ROUTE_PROTO) {
        return None;
    }

    let prefix = message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Destination(RouteAddress::Inet(address)) => Some(Allowed::V4(
                address.octets(),
                message.header.destination_prefix_length,
            )),
            RouteAttribute::Destination(RouteAddress::Inet6(address)) => Some(Allowed::V6(
                address.octets(),
                message.header.destination_prefix_length,
            )),
            _ => None,
        })?;

    let metric = message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Priority(metric) => Some(*metric),
            _ => None,
        });

    Some(RouteSpec::new(prefix, table_of(message), metric))
}

/// Every specification in `messages` that carries our marker, in order.
pub fn installed_from(messages: impl IntoIterator<Item = RouteMessage>) -> Vec<RouteSpec> {
    messages
        .into_iter()
        .filter_map(|message| installed_spec(&message))
        .collect()
}

/// The `(address, prefix length)` pair `rtnetlink`'s address request takes.
///
/// # Errors
///
/// A prefix longer than the address family has bits for is
/// [`RouteError::Unsupported`], not a truncation.
pub fn split_address(address: &Allowed) -> Result<(IpAddr, u8), RouteError> {
    match address {
        Allowed::V4(bytes, mask) if *mask <= 32 => Ok((IpAddr::V4(Ipv4Addr::from(*bytes)), *mask)),
        Allowed::V6(bytes, mask) if *mask <= 128 => Ok((IpAddr::V6(Ipv6Addr::from(*bytes)), *mask)),
        Allowed::V4(_, mask) => Err(RouteError::Unsupported(format!(
            "an IPv4 prefix can not be /{mask}"
        ))),
        Allowed::V6(_, mask) => Err(RouteError::Unsupported(format!(
            "an IPv6 prefix can not be /{mask}"
        ))),
    }
}

fn finish<T>(mut builder: RouteMessageBuilder<T>, spec: &RouteSpec, ifindex: u32) -> RouteMessage {
    builder = builder
        .output_interface(ifindex)
        .protocol(RouteProtocol::Other(WG_ROUTE_PROTO))
        .table_id(table_id(spec.table));
    if let Some(metric) = spec.metric {
        builder = builder.priority(metric);
    }
    builder.build()
}

fn table_id(table: RouteTable) -> u32 {
    match table {
        // `Unmanaged` never reaches here: `desired_routes` returns no routes at
        // all for it, and this arm exists only so the function is total.
        RouteTable::Unmanaged | RouteTable::Main => u32::from(RouteHeader::RT_TABLE_MAIN),
        RouteTable::Number(number) => number,
    }
}

fn table_of(message: &RouteMessage) -> RouteTable {
    let table = message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Table(table) => Some(*table),
            _ => None,
        })
        .unwrap_or(u32::from(message.header.table));

    if table == u32::from(RouteHeader::RT_TABLE_MAIN) {
        RouteTable::Main
    } else {
        RouteTable::Number(table)
    }
}

/// The kernel routing table adapter of one interface.
pub struct NetlinkRoutes {
    ifname: String,
    runtime: NetlinkRuntime,
}

impl NetlinkRoutes {
    /// An adapter for `ifname`.
    pub fn new(ifname: impl Into<String>) -> Self {
        Self {
            ifname: ifname.into(),
            runtime: NetlinkRuntime::new(),
        }
    }

    /// The interface this adapter attaches routes to.
    pub fn interface(&self) -> &str {
        &self.ifname
    }

    fn run<T>(&self, future: impl Future<Output = Result<T, RouteError>>) -> Result<T, RouteError> {
        match self.runtime.block_on(future) {
            Ok(result) => result,
            Err(error) => Err(RouteError::Unsupported(error.to_string())),
        }
    }

    /// Read every route one address family reports, keeping ours.
    ///
    /// The dump is the plain one, which the kernel answers for the main table. A
    /// numbered table is read by the policy work in M1, which is what
    /// introduces `table = <number>` in the first place.
    async fn dump(handle: &rtnetlink::Handle, ipv6: bool) -> Result<Vec<RouteSpec>, RouteError> {
        let mut stream = handle.route().get(route_dump_message(ipv6)).execute();
        let mut specs = Vec::new();
        while let Some(entry) = stream.next().await {
            let entry = entry.map_err(|error| RouteError::Netlink(error.to_string()))?;
            if let Some(spec) = installed_spec(&entry) {
                specs.push(spec);
            }
        }
        Ok(specs)
    }

    async fn index(handle: &rtnetlink::Handle, ifname: &str) -> Result<u32, RouteError> {
        let mut links = handle.link().get().match_name(ifname.to_string()).execute();
        match links.next().await {
            Some(Ok(message)) => Ok(message.header.index),
            Some(Err(error)) => Err(RouteError::Netlink(error.to_string())),
            None => Err(RouteError::Interface(ifname.to_string())),
        }
    }
}

impl Routes for NetlinkRoutes {
    fn ensure_address(&self, address: &Allowed) -> Result<(), RouteError> {
        let ifname = self.ifname.clone();
        let address = address.clone();
        self.run(async move {
            let (connection, handle, _) = rtnetlink::new_connection()
                .map_err(|error| RouteError::Netlink(error.to_string()))?;
            tokio::spawn(connection);

            let index = Self::index(&handle, &ifname).await?;
            let (ip, prefix_length) = split_address(&address)?;
            handle
                .address()
                .add(index, ip, prefix_length)
                .execute()
                .await
                .map_err(|error| RouteError::Netlink(error.to_string()))
        })
    }

    fn installed(&self) -> Result<Vec<RouteSpec>, RouteError> {
        self.run(async {
            let (connection, handle, _) = rtnetlink::new_connection()
                .map_err(|error| RouteError::Netlink(error.to_string()))?;
            tokio::spawn(connection);

            let mut specs = Self::dump(&handle, false).await?;
            specs.extend(Self::dump(&handle, true).await?);
            Ok(specs)
        })
    }

    fn apply(&self, changes: &[RouteChange]) -> Result<(), RouteError> {
        if changes.is_empty() {
            return Ok(());
        }
        let ifname = self.ifname.clone();
        let changes = changes.to_vec();
        self.run(async move {
            let (connection, handle, _) = rtnetlink::new_connection()
                .map_err(|error| RouteError::Netlink(error.to_string()))?;
            tokio::spawn(connection);

            let index = Self::index(&handle, &ifname).await?;
            for op in route_ops(&changes, index) {
                match op {
                    RouteOp::Add(message) => {
                        handle
                            .route()
                            .add(message)
                            .execute()
                            .await
                            .map_err(|error| RouteError::Netlink(error.to_string()))?;
                    }
                    RouteOp::Del(message) => {
                        handle
                            .route()
                            .del(message)
                            .execute()
                            .await
                            .map_err(|error| RouteError::Netlink(error.to_string()))?;
                    }
                }
            }
            Ok(())
        })
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use wgmesh_core::{RoutePrefixes, desired_routes, plan_routes};

    const IFINDEX: u32 = 7;

    fn net() -> Allowed {
        Allowed::V4([10, 77, 0, 0], 16)
    }

    fn host(last: u8) -> Allowed {
        Allowed::V4([10, 77, 0, last], 32)
    }

    fn band() -> Allowed {
        Allowed::V6(
            [0x20, 0x01, 0xdb, 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            32,
        )
    }

    /// A route message the way the kernel would report one of ours.
    fn ours(prefix: Allowed, table: RouteTable, metric: Option<u32>) -> RouteMessage {
        route_message(&RouteSpec::new(prefix, table, metric), IFINDEX)
    }

    #[test]
    fn the_marker_is_recorded_in_proto_and_the_link_in_oif() {
        let message = ours(net(), RouteTable::Main, Some(50));

        assert_eq!(
            message.header.protocol,
            RouteProtocol::Other(WG_ROUTE_PROTO)
        );
        assert_eq!(message.header.destination_prefix_length, 16);
        assert!(
            message.attributes.contains(&RouteAttribute::Oif(IFINDEX)),
            "the route is tied to the interface: {:?}",
            message.attributes
        );
        assert!(
            message
                .attributes
                .contains(&RouteAttribute::Destination(RouteAddress::Inet(
                    Ipv4Addr::new(10, 77, 0, 0)
                )))
        );
        assert!(
            message.attributes.contains(&RouteAttribute::Priority(50)),
            "the metric is carried: {:?}",
            message.attributes
        );
    }

    #[test]
    fn the_marker_is_never_the_default_protocol() {
        // `RouteMessageBuilder::new()` defaults to `RouteProtocol::Static`,
        // which would make our routes indistinguishable from anybody else's.
        assert_ne!(
            route_message(&RouteSpec::new(net(), RouteTable::Main, None), IFINDEX)
                .header
                .protocol,
            RouteProtocol::Static
        );
    }

    #[test]
    fn an_address_round_trips_into_the_rtnetlink_pair() {
        assert_eq!(
            split_address(&host(9)).expect("a valid prefix"),
            (IpAddr::V4(Ipv4Addr::new(10, 77, 0, 9)), 32)
        );
        assert_eq!(
            split_address(&band()).expect("a valid prefix"),
            (
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb08, 0, 0, 0, 0, 0, 0)),
                32
            )
        );
        assert!(matches!(
            split_address(&Allowed::V4([10, 0, 0, 0], 33)),
            Err(RouteError::Unsupported(_))
        ));
        assert!(matches!(
            split_address(&Allowed::V6([0; 16], 129)),
            Err(RouteError::Unsupported(_))
        ));
    }

    #[test]
    fn only_the_routes_that_carry_the_marker_are_ours() {
        let mut foreign = ours(net(), RouteTable::Main, None);
        foreign.header.protocol = RouteProtocol::Static;
        let mut kernel = ours(host(1), RouteTable::Main, None);
        kernel.header.protocol = RouteProtocol::Kernel;

        let installed = installed_from(vec![ours(net(), RouteTable::Main, None), foreign, kernel]);

        assert_eq!(
            installed,
            vec![RouteSpec::new(net(), RouteTable::Main, None)]
        );
    }

    #[test]
    fn an_unmarked_route_is_never_read_back() {
        let mut message = ours(net(), RouteTable::Main, None);
        for protocol in [
            RouteProtocol::Unspec,
            RouteProtocol::Boot,
            RouteProtocol::Bgp,
        ] {
            message.header.protocol = protocol;
            assert_eq!(installed_spec(&message), None, "{protocol:?} was claimed");
        }
    }

    #[test]
    fn a_route_without_a_destination_is_not_a_specification() {
        // The dump includes routes this adapter never writes, such as the
        // kernel's own; the ones that do carry our marker still have to name a
        // destination before they mean anything.
        let mut message = RouteMessage::default();
        message.header.protocol = RouteProtocol::Other(WG_ROUTE_PROTO);
        assert_eq!(installed_spec(&message), None);
    }

    #[test]
    fn a_numbered_table_survives_the_round_trip() {
        let spec = RouteSpec::new(net(), RouteTable::Number(51820), None);
        let message = route_message(&spec, IFINDEX);
        assert_eq!(installed_from(vec![message]), vec![spec]);
    }

    #[test]
    fn the_main_table_reads_back_as_main_rather_than_as_254() {
        let spec = RouteSpec::new(net(), RouteTable::Main, None);
        assert_eq!(
            installed_from(vec![route_message(&spec, IFINDEX)]),
            vec![spec]
        );
    }

    #[test]
    fn plan_routes_maps_add_and_remove_onto_rtnetlink_calls() {
        let wide = RouteSpec::new(net(), RouteTable::Main, None);
        let lan = RouteSpec::new(host(0), RouteTable::Main, Some(50));

        let added = plan_routes(&[wide.clone(), lan.clone()], std::slice::from_ref(&wide));
        assert_eq!(
            route_ops(&added, IFINDEX),
            vec![RouteOp::Add(route_message(&lan, IFINDEX))]
        );

        let removed = plan_routes(&[], std::slice::from_ref(&wide));
        assert_eq!(
            route_ops(&removed, IFINDEX),
            vec![RouteOp::Del(route_message(&wide, IFINDEX))]
        );

        let steady = plan_routes(std::slice::from_ref(&wide), std::slice::from_ref(&wide));
        assert!(route_ops(&steady, IFINDEX).is_empty());
    }

    #[test]
    fn the_policy_output_maps_straight_onto_kernel_calls() {
        // The whole chain the agent runs, minus the kernel: the policy picks
        // the bands, the diff picks the changes, and the adapter turns each
        // change into exactly one netlink call.
        let desired = desired_routes(
            &[net()],
            &[host(0)],
            &RoutePrefixes::Auto,
            RouteTable::Main,
            None,
        )
        .expect("the policy accepts these bands");
        assert_eq!(desired.len(), 2);
        assert_eq!(desired[0], RouteSpec::new(net(), RouteTable::Main, None));
        assert_eq!(desired[1], RouteSpec::new(host(0), RouteTable::Main, None));

        let ops = route_ops(&plan_routes(&desired, &[]), IFINDEX);
        assert_eq!(
            ops,
            vec![
                RouteOp::Add(route_message(&desired[0], IFINDEX)),
                RouteOp::Add(route_message(&desired[1], IFINDEX)),
            ]
        );
        // A route the kernel already has is not written twice.
        assert!(route_ops(&plan_routes(&desired, &desired), IFINDEX).is_empty());
    }

    #[test]
    fn an_empty_change_list_makes_no_call() {
        // `apply` returns before it opens a netlink connection, so this runs
        // without a kernel.
        let routes = NetlinkRoutes::new("wgmesh0");
        routes.apply(&[]).expect("nothing to do is not an error");
        assert_eq!(routes.interface(), "wgmesh0");
    }

    #[test]
    fn a_dump_request_names_no_destination() {
        // `RouteGetRequest` switches to `NLM_F_DUMP` exactly when the request
        // carries no destination attribute.
        for ipv6 in [false, true] {
            let message = route_dump_message(ipv6);
            assert!(
                !message
                    .attributes
                    .iter()
                    .any(|attribute| matches!(attribute, RouteAttribute::Destination(_))),
                "a dump request must not name a destination"
            );
        }
    }
}
