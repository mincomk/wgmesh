pub mod doctor;
pub mod peers;
pub mod routes;

use std::io::Write;

use wgmesh_app::CatchAllPolicy;
use wgmesh_config::{AllowedIpsSetting, PeersSection};

use crate::CliError;

/// The two configuration switches folded into the one policy the plan speaks: a name in
/// `exit_peer` is more specific than a mode, so it wins.
pub fn catch_all(peers: &PeersSection) -> CatchAllPolicy {
    match peers.exit_peer() {
        Some(name) => CatchAllPolicy::ExitPeer(name.to_owned()),
        None => match peers.allowed_ips {
            AllowedIpsSetting::Peer => CatchAllPolicy::Peer,
            AllowedIpsSetting::Any => CatchAllPolicy::Any,
        },
    }
}

pub fn write_line(out: &mut dyn Write, text: &str) -> Result<(), CliError> {
    writeln!(out, "{text}").map_err(|error| CliError::Output(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_exit_peer_is_more_specific_than_the_mode() {
        let mut peers = PeersSection::default();
        assert_eq!(catch_all(&peers), CatchAllPolicy::Peer);
        peers.allowed_ips = AllowedIpsSetting::Any;
        assert_eq!(catch_all(&peers), CatchAllPolicy::Any);
        peers.exit_peer = String::from("gw");
        assert_eq!(
            catch_all(&peers),
            CatchAllPolicy::ExitPeer(String::from("gw"))
        );
        peers.exit_peer = String::from("  ");
        assert_eq!(
            catch_all(&peers),
            CatchAllPolicy::Any,
            "blank is not a name"
        );
    }
}
