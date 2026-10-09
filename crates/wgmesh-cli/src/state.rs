use std::path::Path;

use serde::Deserialize;
use wgmesh_core::{Allowed, RouteSpec, RouteTable};
use wgmesh_ports::parse_prefix;

use crate::CliError;

/// The two things the routing commands read out of the state file: the peers the last
/// synchronization described, and the routes this device installed.
///
/// `wgmesh-state` owns this schema and will hand it over as a type; until it does, this
/// reader keeps the routing command line working from a state file, and it reads those two
/// fields and nothing else.
#[derive(Clone, PartialEq, Eq, Debug, Default, Deserialize)]
#[serde(default)]
pub struct StateFile {
    pub tunnel_ip: String,
    pub peers: Vec<StatePeer>,
    pub routes: Vec<StateRoute>,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Deserialize)]
#[serde(default)]
pub struct StatePeer {
    pub name: String,
    pub tunnel_ip: String,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Deserialize)]
#[serde(default)]
pub struct StateRoute {
    pub prefix: String,
    pub table: String,
    pub metric: Option<u32>,
}

impl StateFile {
    pub fn load(path: &Path) -> Result<Self, CliError> {
        let text = std::fs::read_to_string(path).map_err(|error| {
            CliError::State(format!(
                "{}: {error}; pass --state to point at the state file",
                path.display()
            ))
        })?;
        serde_json::from_str(&text)
            .map_err(|error| CliError::State(format!("{}: {error}", path.display())))
    }

    /// The peers as a name and the band that peer is reached at.
    ///
    /// The state carries each peer's tunnel address, not the bands it advertised, so what the
    /// policy has to work with here is each peer's own `/32`. That is exactly what the
    /// catch-all question is about: which one peer is allowed to carry everything else.
    pub fn peer_bands(&self) -> Result<Vec<(String, Vec<Allowed>)>, CliError> {
        let mut peers = Vec::new();
        for peer in &self.peers {
            let own = parse_prefix(&peer.tunnel_ip)
                .map_err(|error| CliError::State(format!("peer `{}`: {error}", peer.name)))?;
            let own = match own {
                Allowed::V4(bytes, _) => Allowed::V4(bytes, 32),
                Allowed::V6(bytes, _) => Allowed::V6(bytes, 128),
            };
            peers.push((peer.name.clone(), vec![own]));
        }
        Ok(peers)
    }

    /// The bands `prefixes = "auto"` plans: the network this device is a member of, plus what
    /// the peers advertise.
    ///
    /// The network band comes from this device's own tunnel address, masked to its prefix
    /// length — `10.77.0.7/16` is a member of `10.77.0.0/16`. The state carries each peer's
    /// tunnel address rather than the bands it advertised, so the advertised side is each
    /// peer's own band, which lives inside the network band anyway.
    pub fn advertised_bands(&self) -> Result<(Vec<Allowed>, Vec<Allowed>), CliError> {
        let network = match self.tunnel_ip.trim() {
            "" => Vec::new(),
            text => {
                vec![network_band(&parse_prefix(text).map_err(|error| {
                    CliError::State(format!("tunnel_ip: {error}"))
                })?)]
            }
        };
        let advertised = self
            .peer_bands()?
            .into_iter()
            .flat_map(|(_, bands)| bands)
            .collect();
        Ok((network, advertised))
    }

    /// The routes this device remembers installing. Used as the "installed" side of the plan
    /// when the kernel cannot be asked, so a plan is still answerable on a host without
    /// `iproute2` — with a note saying which side of the comparison it came from.
    pub fn installed(&self) -> Result<Vec<RouteSpec>, CliError> {
        let mut routes = Vec::new();
        for route in &self.routes {
            let prefix = parse_prefix(&route.prefix)
                .map_err(|error| CliError::State(format!("route `{}`: {error}", route.prefix)))?;
            routes.push(RouteSpec::new(
                prefix,
                table_of(&route.table)?,
                route.metric,
            ));
        }
        Ok(routes)
    }
}

/// The band a tunnel address is a member of: the address with everything below the prefix
/// length cleared.
fn network_band(address: &Allowed) -> Allowed {
    match address {
        Allowed::V4(bytes, bits) => {
            let host = u32::from_be_bytes(*bytes);
            let mask = if *bits == 0 {
                0
            } else {
                u32::MAX << (32 - *bits)
            };
            Allowed::V4((host & mask).to_be_bytes(), *bits)
        }
        Allowed::V6(bytes, bits) => {
            let host = u128::from_be_bytes(*bytes);
            let mask = if *bits == 0 {
                0
            } else {
                u128::MAX << (128 - *bits)
            };
            Allowed::V6((host & mask).to_be_bytes(), *bits)
        }
    }
}

fn table_of(label: &str) -> Result<RouteTable, CliError> {
    match label {
        "main" | "" => Ok(RouteTable::Main),
        "off" => Ok(RouteTable::Unmanaged),
        number => number.parse::<u32>().map(RouteTable::Number).map_err(|_| {
            CliError::State(format!(
                "`{number}` is not a routing table this product writes"
            ))
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_state_file_gives_names_bands_and_routes() {
        let state: StateFile = serde_json::from_str(
            r#"{
              "schema": 1,
              "device_id": "d_7Hq2Vx9",
              "peers": [
                { "id": "d_A", "name": "A", "wg_pubkey": "aa", "tunnel_ip": "10.77.0.11/16" },
                { "id": "d_G", "name": "gw", "wg_pubkey": "bb", "tunnel_ip": "10.77.0.12/16" }
              ],
              "routes": [ { "prefix": "192.168.5.0/24", "table": "main", "metric": 50 } ],
              "sysctl": { "net.ipv4.ip_forward": "0" }
            }"#,
        )
        .expect("parses");

        assert_eq!(
            state.peer_bands().expect("bands"),
            vec![
                (String::from("A"), vec![Allowed::V4([10, 77, 0, 11], 32)]),
                (String::from("gw"), vec![Allowed::V4([10, 77, 0, 12], 32)]),
            ]
        );
        assert_eq!(
            state.installed().expect("routes"),
            vec![RouteSpec::new(
                Allowed::V4([192, 168, 5, 0], 24),
                RouteTable::Main,
                Some(50)
            )]
        );
    }

    #[test]
    fn a_missing_state_file_names_the_flag_that_points_at_it() {
        let error = StateFile::load(Path::new("/nonexistent/wgmesh-state.json")).unwrap_err();
        assert!(error.to_string().contains("--state"));
    }
}
