use wgmesh_core::{DeviceId, Millis, RelayId};
use wgmesh_ports::Clock;
use wgmesh_ports::coordinator::{DeviceState, Directory, Placement, Relay, RelayState, Reports};

use super::placement::AssignPair;
use super::select_relay::SelectRelay;
use super::types::{Heartbeat, Observation, PlacePolicy, RehomeReport, ReportError, TrafficSample};

/// Keep what the relays saw. An observation is stored against the relay that
/// saw it, never merged across relays: a mapping learned at relay A says
/// nothing about what relay B will see for the same device. Which observation
/// may be *used* is a separate rule, applied when a punch candidate is built —
/// only the pair's assigned relay counts.
pub struct RecordObservations<'a> {
    pub directory: &'a dyn Directory,
    pub reports: &'a dyn Reports,
}

impl RecordObservations<'_> {
    pub async fn execute(
        &self,
        relay: RelayId,
        observations: &[Observation],
    ) -> Result<usize, ReportError> {
        if self
            .directory
            .relay_by_id(relay)
            .await
            .map_err(ReportError::Store)?
            .is_none()
        {
            return Err(ReportError::UnknownRelay(relay));
        }

        let mut kept = 0;
        for observation in observations {
            let device = self
                .directory
                .device_by_id(observation.device)
                .await
                .map_err(ReportError::Store)?
                .ok_or(ReportError::UnknownDevice(observation.device))?;
            if !serves(self.directory, relay, device.network_id).await? {
                return Err(ReportError::NotLinked(relay, device.network_id));
            }
            self.reports
                .record_observation(
                    relay,
                    observation.device,
                    observation.endpoint,
                    observation.seen_at,
                )
                .await
                .map_err(ReportError::Store)?;
            kept += 1;
        }
        Ok(kept)
    }
}

/// Take a relay's heartbeat and traffic counters, and move pairs off the relays
/// that have gone quiet.
pub struct IngestHeartbeat<'a> {
    pub directory: &'a dyn Directory,
    pub placement: &'a dyn Placement,
    pub reports: &'a dyn Reports,
    pub clock: &'a dyn Clock,
    pub policy: PlacePolicy,
}

impl IngestHeartbeat<'_> {
    pub async fn execute(
        &self,
        relay: RelayId,
        heartbeat: &Heartbeat,
    ) -> Result<usize, ReportError> {
        if self
            .directory
            .relay_by_id(relay)
            .await
            .map_err(ReportError::Store)?
            .is_none()
        {
            return Err(ReportError::UnknownRelay(relay));
        }

        self.directory
            .record_heartbeat(relay, heartbeat.at, heartbeat.agent_version.as_deref())
            .await
            .map_err(ReportError::Store)?;

        let mut samples = 0;
        for TrafficSample {
            device,
            rx_bytes,
            tx_bytes,
            period_start,
        } in &heartbeat.traffic
        {
            let record = self
                .directory
                .device_by_id(*device)
                .await
                .map_err(ReportError::Store)?
                .ok_or(ReportError::UnknownDevice(*device))?;
            if !serves(self.directory, relay, record.network_id).await? {
                return Err(ReportError::NotLinked(relay, record.network_id));
            }
            self.reports
                .record_traffic(relay, *device, *rx_bytes, *tx_bytes, *period_start)
                .await
                .map_err(ReportError::Store)?;
            samples += 1;
        }
        Ok(samples)
    }

    /// Relays that have stopped answering, and the pairs that were moved off
    /// them.
    ///
    /// A relay has no health column: staleness is a reading of
    /// `last_heartbeat_at`, so a relay that comes back needs nothing reset.
    pub async fn sweep(&self, now: Millis) -> Result<Vec<RehomeReport>, ReportError> {
        let quiet_after = self
            .policy
            .heartbeat_timeout
            .0
            .saturating_mul(u64::from(self.policy.reassign_after_misses));
        let mut moved = Vec::new();

        for network in self
            .directory
            .networks()
            .await
            .map_err(ReportError::Store)?
        {
            for relay in self
                .directory
                .relays_of(network.id)
                .await
                .map_err(ReportError::Store)?
            {
                if relay.state != RelayState::Active || !is_quiet(&relay, now, quiet_after) {
                    continue;
                }
                for (left, right) in self
                    .placement
                    .pairs_of(relay.id)
                    .await
                    .map_err(ReportError::Store)?
                {
                    let select = SelectRelay {
                        directory: self.directory,
                        placement: self.placement,
                        clock: self.clock,
                    };
                    let chosen = select
                        .execute(left, right, Some(relay.id))
                        .await
                        .ok()
                        .flatten();
                    if let Some(to) = chosen {
                        let assign = AssignPair {
                            directory: self.directory,
                            placement: self.placement,
                            clock: self.clock,
                        };
                        if assign.execute(left, right).await.is_ok() {
                            moved.push(RehomeReport {
                                from: relay.id,
                                to: Some(to),
                                pair: (left, right),
                            });
                        }
                    } else {
                        moved.push(RehomeReport {
                            from: relay.id,
                            to: None,
                            pair: (left, right),
                        });
                    }
                }
            }
        }
        Ok(moved)
    }

    /// The active devices holding a slot on this relay.
    pub async fn tenants(&self, relay: RelayId) -> Result<Vec<DeviceId>, ReportError> {
        let mut tenants = Vec::new();
        for (device, _) in self
            .placement
            .slots_of(relay)
            .await
            .map_err(ReportError::Store)?
        {
            if let Some(record) = self
                .directory
                .device_by_id(device)
                .await
                .map_err(ReportError::Store)?
            {
                if record.state == DeviceState::Active {
                    tenants.push(device);
                }
            }
        }
        Ok(tenants)
    }
}

fn is_quiet(relay: &Relay, now: Millis, quiet_after: u64) -> bool {
    match relay.last_heartbeat_at {
        Some(last) => now.0.saturating_sub(last.0) > quiet_after,
        None => true,
    }
}

async fn serves(
    directory: &dyn Directory,
    relay: RelayId,
    network_id: u32,
) -> Result<bool, ReportError> {
    Ok(directory
        .relays_of(network_id)
        .await
        .map_err(ReportError::Store)?
        .iter()
        .any(|candidate| candidate.id == relay))
}
