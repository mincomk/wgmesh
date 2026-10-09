use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use wgmesh_core::{DeviceId, Endpoint};
use wgmesh_ports::{ApiError, CoordinatorApi, Observation};

/// The control plane as the agent sees it, plus the counters a test wants to
/// assert on.
#[derive(Clone, Debug, Default)]
pub struct FakeCoordinator {
    slot: Arc<Mutex<Option<Endpoint>>>,
    observations: Arc<Mutex<Vec<Observation>>>,
    reported: Arc<Mutex<Vec<Observation>>>,
    observation_calls: Arc<Mutex<u32>>,
}

impl FakeCoordinator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_slot(slot: Endpoint) -> Self {
        let coordinator = Self::default();
        coordinator.set_slot(slot);
        coordinator
    }

    pub fn set_slot(&self, slot: Endpoint) {
        *self.slot.lock().expect("coordinator mutex") = Some(slot);
    }

    /// A relay reported this endpoint for the peer. Called by the harness that
    /// plays the relay, once per step, the way a real relay reports in batches.
    pub fn observe(&self, observation: Observation) {
        let mut observations = self.observations.lock().expect("coordinator mutex");
        observations.retain(|existing| existing.endpoint != observation.endpoint);
        observations.push(observation);
    }

    pub fn observations(&self) -> Vec<Observation> {
        self.observations.lock().expect("coordinator mutex").clone()
    }

    pub fn reported(&self) -> Vec<Observation> {
        self.reported.lock().expect("coordinator mutex").clone()
    }

    pub fn observation_calls(&self) -> u32 {
        *self.observation_calls.lock().expect("coordinator mutex")
    }
}

#[async_trait]
impl CoordinatorApi for FakeCoordinator {
    async fn relay_slot(&self, _peer: DeviceId) -> Result<Option<Endpoint>, ApiError> {
        Ok(*self.slot.lock().expect("coordinator mutex"))
    }

    async fn observations(&self, _peer: DeviceId) -> Result<Vec<Observation>, ApiError> {
        *self.observation_calls.lock().expect("coordinator mutex") += 1;
        Ok(self.observations.lock().expect("coordinator mutex").clone())
    }

    async fn report_observations(
        &self,
        _device: DeviceId,
        observations: &[Observation],
    ) -> Result<(), ApiError> {
        self.reported
            .lock()
            .expect("coordinator mutex")
            .extend_from_slice(observations);
        Ok(())
    }
}
