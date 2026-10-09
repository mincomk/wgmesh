use wgmesh_ports::{Firewall, RouteError};

use crate::command::CommandRunner;

/// The one nftables table `firewall = "manage"` owns.
pub const FIREWALL_TABLE: &str = "wgmesh";

/// The forwarding chain, declared the way `nft` documents a base chain: a numeric priority
/// (the wiki writes `priority 0`, which is what the `filter` name means) and an accept
/// policy, so the table can never be the reason a packet is dropped.
const CHAIN_SPEC: &str = "{ type filter hook forward priority 0; policy accept; }";

/// The forwarding rules this package is willing to own: one table, named [`FIREWALL_TABLE`],
/// and nothing else.
///
/// No rule of ours is ever added to a chain the host owns — that is what makes
/// `nft delete table inet wgmesh` remove every trace in one line. The other side of that
/// bargain is worth saying out loud: a host chain that drops forwarded traffic still wins,
/// because a verdict in one base chain does not exempt a packet from the next one. Getting
/// forwarding through such a host is the host's business, which is exactly why `wgmesh`
/// never edits the host's rules.
pub struct NftFirewall<R: CommandRunner> {
    runner: R,
    interfaces: Vec<String>,
}

impl<R: CommandRunner> NftFirewall<R> {
    /// `interfaces` are the ones forwarding may cross: the tunnel itself, plus any trusted
    /// interface the operator named.
    pub fn new(runner: R, interfaces: Vec<String>) -> Self {
        Self { runner, interfaces }
    }

    fn nft(&self, args: &[String]) -> Result<(), RouteError> {
        let output = self.runner.run("nft", args)?;
        if output.succeeded() {
            Ok(())
        } else {
            Err(output.into_error())
        }
    }

    fn add_table(&self) -> Result<(), RouteError> {
        match self.nft(&argv(&["add", "table", "inet", FIREWALL_TABLE])) {
            Err(error) if says(&error, "file exists") => Ok(()),
            other => other,
        }
    }

    fn add_chain(&self) -> Result<(), RouteError> {
        match self.nft(&argv(&[
            "add",
            "chain",
            "inet",
            FIREWALL_TABLE,
            "forward",
            CHAIN_SPEC,
        ])) {
            Err(error) if says(&error, "file exists") => Ok(()),
            other => other,
        }
    }
}

/// Whether a failure's own words say the thing we were asking for is already (not) there.
///
/// The ports' error carries a class and a detail rather than a variant per failure mode, so the
/// two failures that are really successes — creating a table that exists, deleting one that does
/// not — are recognised by what the tool said.
fn says(error: &RouteError, needle: &str) -> bool {
    error.detail().to_lowercase().contains(needle)
}

fn argv(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| (*item).to_owned()).collect()
}

impl<R: CommandRunner> Firewall for NftFirewall<R> {
    fn ensure(&self) -> Result<(), RouteError> {
        self.add_table()?;
        self.add_chain()?;
        // Flushing first is what makes a second start equivalent to the first: a rule that
        // is added twice is a rule that exists twice, and this way it never can.
        self.nft(&argv(&[
            "flush",
            "chain",
            "inet",
            FIREWALL_TABLE,
            "forward",
        ]))?;
        for interface in &self.interfaces {
            for direction in ["iifname", "oifname"] {
                self.nft(&argv(&[
                    "add",
                    "rule",
                    "inet",
                    FIREWALL_TABLE,
                    "forward",
                    direction,
                    interface,
                    "accept",
                ]))?;
            }
        }
        Ok(())
    }

    fn remove(&self) -> Result<(), RouteError> {
        match self.nft(&argv(&["delete", "table", "inet", FIREWALL_TABLE])) {
            Err(error) if says(&error, "no such file") => Ok(()),
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::RecordingRunner;
    use std::sync::Arc;

    fn firewall(runner: Arc<RecordingRunner>) -> NftFirewall<Arc<RecordingRunner>> {
        NftFirewall::new(runner, vec![String::from("wg0"), String::from("eth0")])
    }

    #[test]
    fn managing_the_firewall_creates_only_our_own_table() {
        let runner = Arc::new(RecordingRunner::new());
        firewall(runner.clone()).ensure().expect("nft accepts");

        let lines = runner.lines();
        assert_eq!(lines[0], "nft add table inet wgmesh");
        assert_eq!(
            lines[1],
            "nft add chain inet wgmesh forward { type filter hook forward priority 0; policy accept; }"
        );
        assert_eq!(lines[2], "nft flush chain inet wgmesh forward");
        assert_eq!(
            lines[3],
            "nft add rule inet wgmesh forward iifname wg0 accept"
        );
        assert_eq!(
            lines[4],
            "nft add rule inet wgmesh forward oifname wg0 accept"
        );
        assert_eq!(
            lines[5],
            "nft add rule inet wgmesh forward iifname eth0 accept"
        );
        assert_eq!(
            lines[6],
            "nft add rule inet wgmesh forward oifname eth0 accept"
        );

        assert_eq!(runner.programs(), vec!["nft"], "no other tool is invoked");
        for line in &lines {
            assert!(
                line.contains("inet wgmesh"),
                "`{line}` names a table that is not ours"
            );
        }
    }

    #[test]
    fn the_way_back_is_one_delete_of_our_own_table() {
        let runner = Arc::new(RecordingRunner::new());
        let firewall = firewall(runner.clone());
        firewall.ensure().expect("nft accepts");
        runner.clear();
        firewall.remove().expect("nft accepts");
        assert_eq!(runner.lines(), vec!["nft delete table inet wgmesh"]);
    }

    #[test]
    fn a_host_without_the_table_removes_cleanly() {
        let runner = Arc::new(RecordingRunner::new());
        runner.answer_containing(
            "nft",
            "delete table",
            1,
            "",
            "Error: No such file or directory",
        );
        firewall(runner.clone())
            .remove()
            .expect("removing what is not there is not a failure");
    }

    #[test]
    fn an_existing_table_is_not_an_error_but_a_real_failure_is() {
        let runner = Arc::new(RecordingRunner::new());
        runner.answer_containing("nft", "add table inet wgmesh", 1, "", "Error: File exists");
        firewall(runner.clone())
            .ensure()
            .expect("a second start finds its own table");

        let failing = Arc::new(RecordingRunner::new());
        failing.answer_containing("nft", "add rule", 1, "", "Error: Operation not permitted");
        let error = firewall(failing).ensure().unwrap_err();
        assert!(error.to_string().contains("Operation not permitted"));
    }
}
