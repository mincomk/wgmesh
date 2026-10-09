pub mod doctor;
pub mod peers;
pub mod routes;
pub mod trust;

use std::io::Write;

use wgmesh_app::CatchAllPolicy;
use wgmesh_config::AllowedIpsSetting;

use crate::CliError;

/// The two configuration switches folded into the one policy the plan speaks: a name in
/// `exit_peer` is more specific than a mode, so it wins.
pub fn catch_all(allowed_ips: AllowedIpsSetting, exit_peer: &str) -> CatchAllPolicy {
    let name = exit_peer.trim();
    if !name.is_empty() {
        return CatchAllPolicy::ExitPeer(name.to_owned());
    }
    match allowed_ips {
        AllowedIpsSetting::Peer => CatchAllPolicy::Peer,
        AllowedIpsSetting::Any => CatchAllPolicy::Any,
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
        assert_eq!(catch_all(AllowedIpsSetting::Peer, ""), CatchAllPolicy::Peer);
        assert_eq!(catch_all(AllowedIpsSetting::Any, ""), CatchAllPolicy::Any);
        assert_eq!(
            catch_all(AllowedIpsSetting::Peer, "gw"),
            CatchAllPolicy::ExitPeer(String::from("gw"))
        );
        assert_eq!(
            catch_all(AllowedIpsSetting::Any, "  "),
            CatchAllPolicy::Any,
            "blank is not a name"
        );
    }
}
