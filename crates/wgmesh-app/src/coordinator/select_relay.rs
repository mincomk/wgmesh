use wgmesh_core::{DeviceId, Millis, RelayId};
use wgmesh_ports::Clock;
use wgmesh_ports::coordinator::{Directory, Placement, RelayState};

use super::types::PlaceError;

/// How stale a relay's last heartbeat may be before it stops being a candidate.
pub const HEARTBEAT_GRACE: Millis = Millis::from_secs(30);

/// Everything the choice is made from. Every field is a fact the caller already
/// holds, so the decision itself is pure and can be replayed in a test.
#[derive(Clone, Debug)]
pub struct RelayCandidate {
    pub relay: RelayId,
    /// Round-trip time each side measured to this relay. `None` means nobody
    /// has measured it yet, which ranks behind a measured relay rather than in
    /// front of one.
    pub rtt_a_ms: Option<u32>,
    pub rtt_b_ms: Option<u32>,
    pub region: Option<String>,
    /// When the coordinator last heard from the relay.
    pub last_seen: Millis,
    /// The relay this pair is already assigned to.
    pub current: bool,
    /// Pairs the relay already carries.
    pub load: u32,
    /// Whether device A already has a pair on another relay of this region.
    /// Picking this one again buys less diversity.
    pub region_already_used: bool,
}

impl RelayCandidate {
    fn is_fresh(&self, now: Millis) -> bool {
        now.0.saturating_sub(self.last_seen.0) <= HEARTBEAT_GRACE.0
    }

    fn rtt_sum(&self) -> Option<u32> {
        match (self.rtt_a_ms, self.rtt_b_ms) {
            (Some(a), Some(b)) => a.checked_add(b),
            _ => None,
        }
    }
}

/// Choose the relay a pair should use.
///
/// The order is the design's: keep an assignment that already works, because
/// re-homing a pair costs a re-punch and a short outage; otherwise take the
/// relay both sides can reach with the lowest combined round-trip time, prefer
/// a region this device is not already on, and spread the load.
pub fn select_relay(candidates: &[RelayCandidate], now: Millis) -> Option<RelayId> {
    let usable: Vec<&RelayCandidate> = candidates
        .iter()
        .filter(|candidate| candidate.is_fresh(now))
        .collect();

    if let Some(sticky) = usable.iter().find(|candidate| candidate.current) {
        return Some(sticky.relay);
    }

    usable
        .into_iter()
        .min_by_key(|candidate| {
            (
                candidate.rtt_sum().unwrap_or(u32::MAX),
                candidate.region_already_used,
                candidate.load,
                candidate.relay.0,
            )
        })
        .map(|candidate| candidate.relay)
}

/// The usecase around [`select_relay`]: read the pool, build the candidates,
/// then let the pure function decide.
pub struct SelectRelay<'a> {
    pub directory: &'a dyn Directory,
    pub placement: &'a dyn Placement,
    pub clock: &'a dyn Clock,
}

impl SelectRelay<'_> {
    pub async fn execute(
        &self,
        device_a: DeviceId,
        device_b: DeviceId,
        exclude: Option<RelayId>,
    ) -> Result<Option<RelayId>, PlaceError> {
        let candidates = self.candidates(device_a, device_b, exclude).await?;
        Ok(select_relay(&candidates, self.clock.now()))
    }

    /// Every relay of the pair's network as a candidate, minus `exclude`.
    pub async fn candidates(
        &self,
        device_a: DeviceId,
        device_b: DeviceId,
        exclude: Option<RelayId>,
    ) -> Result<Vec<RelayCandidate>, PlaceError> {
        let left = self
            .directory
            .device_by_id(device_a)
            .await
            .map_err(PlaceError::Store)?
            .ok_or(PlaceError::UnknownDevice(device_a))?;
        let right = self
            .directory
            .device_by_id(device_b)
            .await
            .map_err(PlaceError::Store)?
            .ok_or(PlaceError::UnknownDevice(device_b))?;
        if left.network_id != right.network_id {
            return Err(PlaceError::NetworkMismatch(device_a, device_b));
        }

        let current = self
            .placement
            .relay_for_pair(device_a, device_b)
            .await
            .map_err(PlaceError::Store)?;

        let mut regions_used = Vec::new();
        let mut candidates = Vec::new();
        for relay in self
            .directory
            .relays_of(left.network_id)
            .await
            .map_err(PlaceError::Store)?
        {
            if relay.state != RelayState::Active || relay.draining || exclude == Some(relay.id) {
                continue;
            }
            let pairs = self
                .placement
                .pairs_of(relay.id)
                .await
                .map_err(PlaceError::Store)?;
            if pairs.iter().any(|(a, b)| {
                (*a == device_a && *b != device_b) || (*b == device_a && *a != device_b)
            }) {
                regions_used.push(relay.region.clone());
            }
            candidates.push(RelayCandidate {
                relay: relay.id,
                rtt_a_ms: None,
                rtt_b_ms: None,
                region: relay.region.clone(),
                last_seen: relay.last_heartbeat_at.unwrap_or(Millis::ZERO),
                current: current == Some(relay.id),
                load: pairs.len() as u32,
                region_already_used: false,
            });
        }

        for candidate in &mut candidates {
            candidate.region_already_used = candidate.region.as_ref().is_some_and(|region| {
                regions_used
                    .iter()
                    .any(|used| used.as_ref() == Some(region))
            });
        }

        Ok(candidates)
    }
}
