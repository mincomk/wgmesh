use wgmesh_core::{DeviceId, RelayId};
use wgmesh_ports::Clock;
use wgmesh_ports::coordinator::{Device, Directory, Placement, RelayState};

use super::net::next_free_port;
use super::select_relay::SelectRelay;
use super::types::{PlaceError, PlacePolicy};

/// Pairs are stored under one canonical order so a lookup never has to guess.
pub const fn order(left: DeviceId, right: DeviceId) -> (DeviceId, DeviceId) {
    if left.0 <= right.0 {
        (left, right)
    } else {
        (right, left)
    }
}

/// Give a device a port on every relay of its network. The node opens all of
/// them, so a re-assignment needs no new round trip.
pub async fn ensure_slots(
    directory: &dyn Directory,
    placement: &dyn Placement,
    device: &Device,
) -> Result<Vec<(RelayId, u16)>, PlaceError> {
    let mut assigned = Vec::new();
    for relay in directory
        .relays_of(device.network_id)
        .await
        .map_err(PlaceError::Store)?
    {
        if relay.state != RelayState::Active {
            continue;
        }
        if let Some(port) = placement
            .slot_for(relay.id, device.id)
            .await
            .map_err(PlaceError::Store)?
        {
            assigned.push((relay.id, port));
            continue;
        }
        let used: Vec<u16> = placement
            .slots_of(relay.id)
            .await
            .map_err(PlaceError::Store)?
            .into_iter()
            .map(|(_, port)| port)
            .collect();
        let port = next_free_port(&relay.port_range, &used).ok_or(PlaceError::NoRelayAvailable)?;
        placement
            .assign_slot(relay.id, device.id, port)
            .await
            .map_err(PlaceError::Store)?;
        assigned.push((relay.id, port));
    }
    Ok(assigned)
}

/// Pair a device with every other active device of its network.
pub async fn pair_with_network(
    directory: &dyn Directory,
    placement: &dyn Placement,
    clock: &dyn Clock,
    policy: PlacePolicy,
    device: &Device,
) -> Result<Vec<RelayId>, PlaceError> {
    let mut relays = Vec::new();
    for peer in directory
        .devices_of(device.network_id)
        .await
        .map_err(PlaceError::Store)?
    {
        if peer.id == device.id || peer.state != wgmesh_ports::coordinator::DeviceState::Active {
            continue;
        }
        let assign = AssignPair {
            directory,
            placement,
            clock,
            policy,
        };
        if let Some(relay) = assign.execute(device.id, peer.id).await? {
            relays.push(relay);
        }
    }
    Ok(relays)
}

/// Choose one relay for one pair, keeping a working assignment.
pub struct AssignPair<'a> {
    pub directory: &'a dyn Directory,
    pub placement: &'a dyn Placement,
    pub clock: &'a dyn Clock,
    pub policy: PlacePolicy,
}

impl AssignPair<'_> {
    pub async fn execute(
        &self,
        left: DeviceId,
        right: DeviceId,
    ) -> Result<Option<RelayId>, PlaceError> {
        if left == right {
            return Ok(None);
        }
        let pair = order(left, right);

        if let Some(current) = self
            .placement
            .relay_for_pair(pair.0, pair.1)
            .await
            .map_err(PlaceError::Store)?
        {
            // "Still up" means the coordinator has heard from it recently, not
            // merely that nobody has retired it: a relay that went quiet is the
            // case this whole path exists for, and keeping a pair on one would
            // leave it dead until the next sweep. The reading is the policy's,
            // the same one the sweep moves pairs by.
            let now = self.clock.now();
            let stale_after = self.policy.stale_after();
            let still_up = self
                .directory
                .relay_by_id(current)
                .await
                .map_err(PlaceError::Store)?
                .is_some_and(|relay| {
                    relay.state == RelayState::Active
                        && !relay.draining
                        && relay
                            .last_heartbeat_at
                            .is_some_and(|seen| now.0.saturating_sub(seen.0) <= stale_after.0)
                });
            if still_up {
                return Ok(Some(current));
            }
        }

        let select = SelectRelay {
            directory: self.directory,
            placement: self.placement,
            clock: self.clock,
            policy: self.policy,
        };
        let chosen = select.execute(pair.0, pair.1, None).await?;
        if let Some(relay) = chosen {
            self.placement
                .assign_pair(pair.0, pair.1, relay, self.clock.now())
                .await
                .map_err(PlaceError::Store)?;
        }
        Ok(chosen)
    }
}
