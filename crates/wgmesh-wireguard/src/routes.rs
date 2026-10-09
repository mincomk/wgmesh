use wgmesh_core::{Allowed, RouteChange, RouteSpec, RouteTable};
use wgmesh_ports::{
    ChangeAction, MARKER_PROTO, RouteError, Routes, family_flag, format_prefix, parse_prefix,
    reset_routes,
};

use crate::command::CommandRunner;

/// The kernel routing table, driven through `iproute2`.
///
/// Two things keep this adapter away from routes it does not own. Every route it installs
/// carries [`MARKER_PROTO`] as its `proto`, and every question it asks is filtered by that
/// marker: [`Routes::installed`] reads the marked routes out of the kernel, and
/// [`Routes::reset`] deletes exactly what that read returned. A route the host installed
/// with any other `proto` is invisible here, in whatever table it lives.
pub struct IpRoutes<R: CommandRunner> {
    runner: R,
    interface: String,
    table: RouteTable,
}

impl<R: CommandRunner> IpRoutes<R> {
    pub fn new(runner: R, interface: impl Into<String>, table: RouteTable) -> Self {
        Self {
            runner,
            interface: interface.into(),
            table,
        }
    }

    pub fn interface(&self) -> &str {
        &self.interface
    }

    pub fn table(&self) -> RouteTable {
        self.table
    }

    fn table_arg(table: RouteTable) -> Option<String> {
        match table {
            RouteTable::Main => Some(String::from("main")),
            RouteTable::Number(number) => Some(number.to_string()),
            RouteTable::Unmanaged => None,
        }
    }

    /// `ip [-4|-6] route show table <table|all> proto <marker>`.
    fn show_args(&self, family: &str) -> Vec<String> {
        let table = match Self::table_arg(self.table) {
            Some(table) => table,
            // `table = "off"` manages no route, but `wgmesh routes reset` still has to be
            // able to find what an earlier run left behind, wherever it put it.
            None => String::from("all"),
        };
        vec![
            String::from(family),
            String::from("route"),
            String::from("show"),
            String::from("table"),
            table,
            String::from("proto"),
            MARKER_PROTO.to_string(),
        ]
    }

    /// The argv for one change. `replace` rather than `add`, because the same call is also
    /// what fixes a route whose metric drifted, and it never fails on a route that is there.
    pub fn route_args(&self, change: &RouteChange) -> Result<Vec<String>, RouteError> {
        let (action, spec) = match change {
            RouteChange::Add(spec) => (ChangeAction::Add, spec),
            RouteChange::Remove(spec) => (ChangeAction::Remove, spec),
        };
        let table = match Self::table_arg(spec.table) {
            Some(table) => table,
            None => {
                return Err(RouteError::fatal(String::from(
                    "a route with an unmanaged table has no kernel instruction: \
                     `table = \"off\"` means no route is installed",
                )));
            }
        };
        let mut args = vec![
            String::from(family_flag(&spec.prefix)),
            String::from("route"),
            match action {
                ChangeAction::Add => String::from("replace"),
                ChangeAction::Remove => String::from("del"),
            },
            format_prefix(&spec.prefix),
            String::from("dev"),
            self.interface.clone(),
            String::from("table"),
            table,
            String::from("proto"),
            MARKER_PROTO.to_string(),
        ];
        if let Some(metric) = spec.metric {
            args.push(String::from("metric"));
            args.push(metric.to_string());
        }
        Ok(args)
    }

    fn address_args(&self, address: &Allowed) -> Vec<String> {
        vec![
            String::from(family_flag(address)),
            String::from("addr"),
            String::from("replace"),
            format_prefix(address),
            String::from("dev"),
            self.interface.clone(),
        ]
    }

    fn run(&self, args: &[String]) -> Result<(), RouteError> {
        let output = self.runner.run("ip", args)?;
        if output.succeeded() {
            Ok(())
        } else {
            Err(output.into_error())
        }
    }

    /// One line of `ip route show` is one route:
    ///
    /// ```text
    /// 10.77.0.0/16 dev wg0 proto 250 scope link metric 50
    /// ```
    ///
    /// `default` is read rather than skipped: this package never installs a default route,
    /// so a marked one would be a bug worth seeing instead of a line worth hiding.
    fn parse_show(&self, stdout: &str, family: &str) -> Result<Vec<RouteSpec>, RouteError> {
        let mut routes = Vec::new();
        for line in stdout.lines() {
            let tokens: Vec<&str> = line.split_whitespace().collect();
            let Some(first) = tokens.first() else {
                continue;
            };
            let prefix = match parse_prefix(first) {
                Ok(prefix) => prefix,
                Err(_) => continue,
            };
            let prefix = if *first == "default" && family == "-6" {
                Allowed::V6([0; 16], 0)
            } else {
                prefix
            };
            if token_after(&tokens, "dev") != Some(self.interface.as_str()) {
                continue;
            }
            if let Some(proto) = token_after(&tokens, "proto") {
                if proto != MARKER_PROTO.to_string() {
                    continue;
                }
            }
            let metric = token_after(&tokens, "metric").and_then(|value| value.parse::<u32>().ok());
            let table = match token_after(&tokens, "table") {
                Some("main") => RouteTable::Main,
                Some(number) => number
                    .parse::<u32>()
                    .map(RouteTable::Number)
                    .unwrap_or(self.table),
                // `table = "off"` asks across every table, and a line without a table token
                // came from `main`, which is where an unqualified route lives.
                None if self.table == RouteTable::Unmanaged => RouteTable::Main,
                None => self.table,
            };
            routes.push(RouteSpec::new(prefix, table, metric));
        }
        Ok(routes)
    }
}

fn token_after<'a>(tokens: &[&'a str], key: &str) -> Option<&'a str> {
    tokens
        .iter()
        .position(|token| *token == key)
        .and_then(|index| tokens.get(index + 1).copied())
}

impl<R: CommandRunner> IpRoutes<R> {
    /// Delete every route the marker owns, and answer with what was deleted.
    ///
    /// The list comes from `installed`, so what is deleted is exactly what the kernel reported
    /// as ours — never a route by table, and never one by prefix alone.
    pub fn reset(&self) -> Result<Vec<RouteSpec>, RouteError> {
        reset_routes(self)
    }
}

impl<R: CommandRunner> Routes for IpRoutes<R> {
    fn ensure_address(&self, address: &Allowed) -> Result<(), RouteError> {
        self.run(&self.address_args(address))
    }

    fn installed(&self) -> Result<Vec<RouteSpec>, RouteError> {
        let mut routes = Vec::new();
        for family in ["-4", "-6"] {
            let output = self.runner.run("ip", &self.show_args(family))?;
            if !output.succeeded() {
                return Err(output.into_error());
            }
            routes.extend(self.parse_show(&output.stdout, family)?);
        }
        Ok(routes)
    }

    fn apply(&self, changes: &[RouteChange]) -> Result<(), RouteError> {
        for change in changes {
            let args = self.route_args(change)?;
            self.run(&args)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::RecordingRunner;
    use std::sync::Arc;

    fn host(last: u8) -> Allowed {
        Allowed::V4([10, 77, 0, last], 32)
    }

    fn net() -> Allowed {
        Allowed::V4([10, 77, 0, 0], 16)
    }

    fn lan() -> Allowed {
        Allowed::V4([192, 168, 5, 0], 24)
    }

    fn routes(runner: Arc<RecordingRunner>) -> IpRoutes<Arc<RecordingRunner>> {
        IpRoutes::new(runner, "wg0", RouteTable::Main)
    }

    #[test]
    fn an_explicit_prefix_list_becomes_exactly_those_two_routes() {
        let runner = Arc::new(RecordingRunner::new());
        let adapter = routes(runner.clone());
        adapter
            .apply(&[
                RouteChange::Add(RouteSpec::new(net(), RouteTable::Main, None)),
                RouteChange::Add(RouteSpec::new(lan(), RouteTable::Main, None)),
            ])
            .expect("the kernel accepts");

        assert_eq!(
            runner.lines(),
            vec![
                "ip -4 route replace 10.77.0.0/16 dev wg0 table main proto 250",
                "ip -4 route replace 192.168.5.0/24 dev wg0 table main proto 250",
            ]
        );
        assert!(
            runner.lines().iter().all(|line| !line.contains("default")),
            "no change may ever render the default route"
        );
    }

    #[test]
    fn a_listed_band_with_a_metric_carries_it_and_a_numbered_table_is_named() {
        let runner = Arc::new(RecordingRunner::new());
        let adapter = IpRoutes::new(runner.clone(), "wg0", RouteTable::Number(51820));
        adapter
            .apply(&[RouteChange::Add(RouteSpec::new(
                host(9),
                RouteTable::Number(51820),
                Some(50),
            ))])
            .expect("the kernel accepts");
        assert_eq!(
            runner.lines(),
            vec!["ip -4 route replace 10.77.0.9/32 dev wg0 table 51820 proto 250 metric 50"]
        );
    }

    #[test]
    fn an_unmanaged_table_never_renders_a_route_command() {
        let runner = Arc::new(RecordingRunner::new());
        let adapter = IpRoutes::new(runner.clone(), "wg0", RouteTable::Unmanaged);
        let error = adapter
            .apply(&[RouteChange::Add(RouteSpec::new(
                net(),
                RouteTable::Unmanaged,
                None,
            ))])
            .unwrap_err();
        assert!(error.detail().contains("table"), "{}", error.detail());
        assert!(runner.lines().is_empty());
    }

    #[test]
    fn reading_the_kernel_asks_for_our_marker_only() {
        let runner = Arc::new(RecordingRunner::new());
        runner.answer_containing(
            "ip",
            "-4 route show",
            0,
            "10.77.0.0/16 dev wg0 proto 250 scope link metric 50\n\
             192.168.5.0/24 dev wg0 proto 250 scope link\n\
             10.9.9.0/24 dev wg0 proto static\n\
             172.16.0.0/12 dev eth0 proto 250\n\
             default dev wg0 proto 250\n",
            "",
        );
        let installed = routes(runner.clone()).installed().expect("reads");

        assert_eq!(
            installed,
            vec![
                RouteSpec::new(net(), RouteTable::Main, Some(50)),
                RouteSpec::new(lan(), RouteTable::Main, None),
                RouteSpec::new(Allowed::V4([0, 0, 0, 0], 0), RouteTable::Main, None),
            ],
            "a foreign proto and another device are filtered out; a marked default is surfaced"
        );
        assert_eq!(
            runner.lines(),
            vec![
                "ip -4 route show table main proto 250",
                "ip -6 route show table main proto 250",
            ]
        );
    }

    #[test]
    fn the_address_is_replaced_rather_than_added() {
        let runner = Arc::new(RecordingRunner::new());
        routes(runner.clone())
            .ensure_address(&Allowed::V4([10, 77, 0, 7], 16))
            .expect("the kernel accepts");
        assert_eq!(
            runner.lines(),
            vec!["ip -4 addr replace 10.77.0.7/16 dev wg0"]
        );
    }

    #[test]
    fn reset_deletes_the_marked_routes_and_nothing_else() {
        let runner = Arc::new(RecordingRunner::new());
        runner.answer_containing(
            "ip",
            "-4 route show",
            0,
            "10.77.0.0/16 dev wg0 proto 250 scope link\n192.168.5.0/24 dev wg0 proto 250 scope link\n",
            "",
        );
        let removed = routes(runner.clone()).reset().expect("deletes");
        assert_eq!(removed.len(), 2);
        assert_eq!(
            runner.lines(),
            vec![
                "ip -4 route show table main proto 250",
                "ip -6 route show table main proto 250",
                "ip -4 route del 10.77.0.0/16 dev wg0 table main proto 250",
                "ip -4 route del 192.168.5.0/24 dev wg0 table main proto 250",
            ]
        );
    }

    #[test]
    fn a_kernel_that_refuses_is_reported_with_the_command_that_failed() {
        let runner = Arc::new(RecordingRunner::new());
        runner.answer_containing(
            "ip",
            "route replace",
            2,
            "",
            "RTNETLINK answers: Operation not permitted",
        );
        let error = routes(runner)
            .apply(&[RouteChange::Add(RouteSpec::new(
                net(),
                RouteTable::Main,
                None,
            ))])
            .unwrap_err();
        let detail = error.detail();
        assert!(detail.contains("route replace 10.77.0.0/16"), "{detail}");
        assert!(detail.contains("exited with 2"), "{detail}");
        assert!(detail.contains("Operation not permitted"), "{detail}");
    }
}
