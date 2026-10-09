use wgmesh_core::{DeviceId, Endpoint, RelayId};
use wgmesh_ports::Clock;
use wgmesh_ports::PortError;
use wgmesh_ports::coordinator::{
    Device, DeviceState, Directory, Network, Placement, RelayState, Reports,
};

use super::net::{host_prefix, parse_cidr};
use super::placement::order;
use super::types::{
    ConfigError, ConfigSnapshot, MeView, PeerView, PlacePolicy, RelayPoolEntry, RelayView,
    SelfObservation,
};

/// The design's `persistent-keepalive`, in seconds.
pub const KEEPALIVE_SECS: u32 = 25;

/// The whole of what a node needs to program its interface, in one read.
pub struct BuildConfig<'a> {
    pub directory: &'a dyn Directory,
    pub placement: &'a dyn Placement,
    pub reports: &'a dyn Reports,
    pub clock: &'a dyn Clock,
    pub policy: PlacePolicy,
}

impl BuildConfig<'_> {
    pub async fn execute(&self, device: DeviceId) -> Result<ConfigSnapshot, ConfigError> {
        let record = self
            .directory
            .device_by_id(device)
            .await
            .map_err(ConfigError::Store)?
            .ok_or(ConfigError::UnknownDevice(device))?;
        let network = self
            .directory
            .network_by_id(record.network_id)
            .await
            .map_err(ConfigError::Store)?
            .ok_or(ConfigError::UnknownNetwork(record.network_id))?;

        let slots = relay_slots(self.directory, self.placement, &record)
            .await
            .map_err(ConfigError::Store)?;
        let assigned = assigned_relay(
            self.directory,
            self.placement,
            &record,
            self.clock,
            self.policy,
        )
        .await
        .map_err(ConfigError::Store)?;
        let slot_port = assigned.and_then(|relay| {
            slots
                .iter()
                .find(|entry| entry.id == relay)
                .and_then(|entry| entry.slot_port)
        });

        let observed = match assigned {
            Some(relay) => self
                .reports
                .observation(relay, device)
                .await
                .map_err(ConfigError::Store)?
                .map(|(endpoint, seen_at)| SelfObservation { endpoint, seen_at }),
            None => None,
        };
        let tunnel_ip = with_network_prefix(&record.tunnel_ip, &network);

        // A device still waiting for approval sees no peers: it is not in
        // anyone's list either, and handing it the mesh would undo that.
        let peers = if record.state == DeviceState::Active {
            peer_views(self.directory, self.placement, &record)
                .await
                .map_err(ConfigError::Store)?
        } else {
            Vec::new()
        };

        Ok(ConfigSnapshot {
            network,
            me: MeView {
                id: record.id,
                tunnel_ip,
                state: record.state,
                slot_port,
                observed,
            },
            relay: RelayView { assigned, slots },
            peers,
            keepalive_secs: KEEPALIVE_SECS,
        })
    }
}

/// This device's slot on every relay of its network, so a re-assignment needs
/// no new round trip.
pub(crate) async fn relay_slots(
    directory: &dyn Directory,
    placement: &dyn Placement,
    device: &Device,
) -> Result<Vec<RelayPoolEntry>, PortError> {
    let mut entries = Vec::new();
    for relay in directory.relays_of(device.network_id).await? {
        if relay.state != RelayState::Active {
            continue;
        }
        entries.push(RelayPoolEntry {
            id: relay.id,
            name: relay.name,
            endpoint_host: relay.endpoint_host,
            port_range: relay.port_range,
            region: relay.region,
            state: relay.state,
            slot_port: placement.slot_for(relay.id, device.id).await?,
        });
    }
    Ok(entries)
}

/// The relay this device falls back to when per-pair placement is off: the
/// relay of its lowest-numbered peer, or the first live relay of the pool when
/// it has no peers yet.
pub(crate) async fn assigned_relay(
    directory: &dyn Directory,
    placement: &dyn Placement,
    device: &Device,
    clock: &dyn Clock,
    policy: PlacePolicy,
) -> Result<Option<RelayId>, PortError> {
    let mut peer_relays: Vec<(DeviceId, RelayId)> = Vec::new();
    let mut live: Vec<RelayId> = Vec::new();
    let now = clock.now();
    let stale_after = policy.stale_after();

    for relay in directory.relays_of(device.network_id).await? {
        if relay.state != RelayState::Active {
            continue;
        }
        let fresh = !relay.draining
            && relay
                .last_heartbeat_at
                .is_some_and(|seen| now.0.saturating_sub(seen.0) <= stale_after.0);
        if fresh {
            live.push(relay.id);
        }
        for (left, right) in placement.pairs_of(relay.id).await? {
            if left == device.id {
                peer_relays.push((right, relay.id));
            } else if right == device.id {
                peer_relays.push((left, relay.id));
            }
        }
    }

    peer_relays.sort();
    if let Some((_, relay)) = peer_relays.first() {
        return Ok(Some(*relay));
    }
    live.sort();
    Ok(live.first().copied())
}

/// Every active peer of the device, with the relay its pair uses and the slot
/// it listens on there — phase one routes every peer through its relay.
pub(crate) async fn peer_views(
    directory: &dyn Directory,
    placement: &dyn Placement,
    device: &Device,
) -> Result<Vec<PeerView>, PortError> {
    let mut peers = Vec::new();
    for peer in directory.devices_of(device.network_id).await? {
        if peer.id == device.id || peer.state != DeviceState::Active {
            continue;
        }
        let pair = order(device.id, peer.id);
        let relay = placement.relay_for_pair(pair.0, pair.1).await?;
        let mut endpoint = None;
        if let Some(relay_id) = relay {
            if let Some(record) = directory.relay_by_id(relay_id).await? {
                if let Some(port) = placement.slot_for(relay_id, peer.id).await? {
                    endpoint = socket(&record.endpoint_host, port);
                }
            }
        }
        let mut advertised = peer.advertised.clone();
        if advertised.is_empty() {
            advertised.push(host_prefix(&peer.tunnel_ip));
        }
        peers.push(PeerView {
            id: peer.id,
            name: peer.name,
            wg_pubkey: peer.wg_pubkey,
            tunnel_ip: host_prefix(&peer.tunnel_ip),
            advertised,
            relay,
            endpoint,
            state: peer.state,
        });
    }
    peers.sort_by_key(|peer| peer.id.0);
    Ok(peers)
}

fn with_network_prefix(tunnel_ip: &str, network: &Network) -> String {
    match parse_cidr(&network.cidr) {
        Some((_, length)) => format!(
            "{}/{}",
            tunnel_ip.split('/').next().unwrap_or(tunnel_ip),
            length
        ),
        None => tunnel_ip.to_string(),
    }
}

fn socket(host: &str, port: u16) -> Option<Endpoint> {
    let address: std::net::SocketAddr = format!("{host}:{port}").parse().ok()?;
    Some(Endpoint::new(address))
}
