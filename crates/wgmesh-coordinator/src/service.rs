use std::sync::Arc;

use wgmesh_app::coordinator::Clock;
use wgmesh_app::coordinator::PortError;
use wgmesh_app::coordinator::ports::{AuditEntry, DeviceState, Directory, Placement, Reports};
use wgmesh_app::coordinator::{
    ApproveDevice, AssignPair, BuildConfig, IngestHeartbeat, JoinDevice, JoinPolicy, PlacePolicy,
    PunchReport, RecordObservations, SelectRelay,
};
use wgmesh_core::{DeviceId, Millis, RelayId};

use crate::nonce::NonceCache;
use crate::store::Sqlite;
use wgmesh_proto::api::{
    AssignmentResponse, KeysetNetwork, KeysetPeer, KeysetResponse, PairBody, SlotBody,
};

/// Everything a request needs, wired once at startup.
///
/// The handlers build usecases from this; they never touch the database or the
/// clock themselves.
#[derive(Clone)]
pub struct Services {
    pub store: Arc<Sqlite>,
    pub clock: Arc<dyn Clock>,
    pub nonces: Arc<NonceCache>,
    pub join_policy: JoinPolicy,
    pub place_policy: PlacePolicy,
    pub keyset_ttl_secs: u64,
}

impl Services {
    pub fn new(store: Arc<Sqlite>, clock: Arc<dyn Clock>) -> Self {
        Self {
            store,
            clock,
            nonces: Arc::new(NonceCache::new()),
            join_policy: JoinPolicy::default(),
            place_policy: PlacePolicy::default(),
            keyset_ttl_secs: 300,
        }
    }

    pub fn join_device(&self) -> JoinDevice<'_> {
        JoinDevice {
            tokens: &*self.store,
            directory: &*self.store,
            placement: &*self.store,
            reports: &*self.store,
            clock: &*self.clock,
            policy: self.join_policy,
        }
    }

    pub fn approve_device(&self) -> ApproveDevice<'_> {
        ApproveDevice {
            directory: &*self.store,
            placement: &*self.store,
            reports: &*self.store,
            clock: &*self.clock,
        }
    }

    pub fn build_config(&self) -> BuildConfig<'_> {
        BuildConfig {
            directory: &*self.store,
            placement: &*self.store,
            reports: &*self.store,
            clock: &*self.clock,
        }
    }

    pub fn record_observations(&self) -> RecordObservations<'_> {
        RecordObservations {
            directory: &*self.store,
            reports: &*self.store,
        }
    }

    pub fn ingest_heartbeat(&self) -> IngestHeartbeat<'_> {
        IngestHeartbeat {
            directory: &*self.store,
            placement: &*self.store,
            reports: &*self.store,
            clock: &*self.clock,
            policy: self.place_policy,
        }
    }

    pub fn select_relay(&self) -> SelectRelay<'_> {
        SelectRelay {
            directory: &*self.store,
            placement: &*self.store,
            clock: &*self.clock,
        }
    }

    pub fn assign_pair(&self) -> AssignPair<'_> {
        AssignPair {
            directory: &*self.store,
            placement: &*self.store,
            clock: &*self.clock,
        }
    }

    /// A punch result is a report, not a decision: the agent owns the direct
    /// attempt and its fallback window. What the coordinator keeps is the
    /// record, and the device's liveness.
    pub async fn record_punch(&self, report: PunchReport) -> Result<(), PortError> {
        self.store
            .audit(&AuditEntry {
                at: report.at,
                actor: "device".to_string(),
                action: "punch".to_string(),
                network_id: None,
                device_id: Some(report.peer),
                relay_id: None,
                detail: Some(report.outcome.as_str().to_string()),
            })
            .await
    }

    /// The slot table, the assigned pairs and the network keyset, in one read:
    /// a relay that restarts rebuilds everything from this.
    pub async fn relay_assignment(&self, relay: RelayId) -> Result<AssignmentResponse, PortError> {
        let record = self
            .store
            .relay_by_id(relay)
            .await?
            .ok_or_else(|| PortError::recoverable("no such relay"))?;

        let slots = self
            .store
            .slots_of(relay)
            .await?
            .into_iter()
            .map(|(device, udp_port)| SlotBody {
                device_id: wgmesh_proto::device_id(device),
                udp_port,
            })
            .collect();

        let pairs = self
            .store
            .pairs_of(relay)
            .await?
            .into_iter()
            .map(|(left, right)| PairBody {
                a: wgmesh_proto::device_id(left),
                b: wgmesh_proto::device_id(right),
            })
            .collect();

        Ok(AssignmentResponse {
            relay_id: wgmesh_proto::relay_id(relay),
            endpoint_host: record.endpoint_host,
            slots,
            pairs,
            networks: self.keyset_of(relay).await?,
        })
    }

    pub async fn relay_keyset(&self, relay: RelayId) -> Result<KeysetResponse, PortError> {
        Ok(KeysetResponse {
            fetched_at_ms: self.clock.now().0,
            keyset_ttl_secs: self.keyset_ttl_secs,
            networks: self.keyset_of(relay).await?,
        })
    }

    /// The public keys of every active device on each network this relay
    /// serves. Public keys only: the relay never holds a private one.
    async fn keyset_of(&self, relay: RelayId) -> Result<Vec<KeysetNetwork>, PortError> {
        let mut networks = Vec::new();
        for network in self.store.networks().await? {
            let serves = self
                .store
                .relays_of(network.id)
                .await?
                .iter()
                .any(|candidate| candidate.id == relay);
            if !serves {
                continue;
            }
            let mut peers = Vec::new();
            for device in self.store.devices_of(network.id).await? {
                if device.state != DeviceState::Active {
                    continue;
                }
                peers.push(KeysetPeer {
                    device_id: wgmesh_proto::device_id(device.id),
                    wg_pubkey: wgmesh_proto::encode_key(&device.wg_pubkey),
                });
            }
            networks.push(KeysetNetwork {
                id: network.id,
                name: network.name,
                peers,
            });
        }
        Ok(networks)
    }

    /// The state a principal is in, as the wire shows it.
    pub async fn device_state(&self, device: DeviceId) -> Result<Option<DeviceState>, PortError> {
        Ok(self
            .store
            .device_by_id(device)
            .await?
            .map(|record| record.state))
    }

    pub fn now(&self) -> Millis {
        self.clock.now()
    }
}
