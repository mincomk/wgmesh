use std::sync::Arc;

use tokio::sync::broadcast;

use wgmesh_app::coordinator::Clock;
use wgmesh_app::coordinator::PortError;
use wgmesh_app::coordinator::ports::{AuditEntry, DeviceState, Directory, Placement, Reports};
use wgmesh_app::coordinator::{
    ApproveDevice, AssignPair, BuildConfig, IngestHeartbeat, JoinDevice, JoinPolicy, PlacePolicy,
    PunchReport, RecordObservations, RehomeReport, ReportError, SelectRelay,
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
    /// The allowance `/v1/join` and `/v1/relay/enroll` share, per client
    /// address, per minute. It is a field rather than a constant because the
    /// operator's `[policy] join_rate_limit_per_minute` has to reach the
    /// limiter — a ceiling that is configured and does not apply is worse than
    /// none, because the operator has stopped watching.
    pub join_rate_limit_per_minute: u32,
    /// Announces every configuration change to whoever is streaming. The watch
    /// that feeds it is started explicitly (`http::watch_config`), so a test can
    /// start it too rather than depending on a daemon being up.
    pub updates: broadcast::Sender<u64>,
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
            join_rate_limit_per_minute: crate::http::JOIN_RATE_LIMIT_PER_MINUTE,
            updates: broadcast::channel(64).0,
        }
    }

    /// The same services with a different allowance. A daemon that reads
    /// `[policy] join_rate_limit_per_minute` calls this once at startup.
    pub fn with_join_rate_limit(mut self, per_minute: u32) -> Self {
        self.join_rate_limit_per_minute = per_minute;
        self
    }

    /// The same services with the relay health policy the coordinator's `[relay]`
    /// table states, which is what decides whether a relay is still a place a pair
    /// may be. A daemon that reads `heartbeat_timeout_secs` and
    /// `reassign_after_misses` calls this once at startup; without it the
    /// daemon's own defaults apply and the operator's numbers reach nothing.
    pub fn with_place_policy(mut self, policy: PlacePolicy) -> Self {
        self.place_policy = policy;
        self
    }

    /// The same services with the lifetime the coordinator hands a relay's copy of
    /// the key set. `[relay] keyset_ttl_secs` is what a relay keeps serving for
    /// after the coordinator goes away, so a daemon that reads it calls this.
    pub fn with_keyset_ttl(mut self, secs: u64) -> Self {
        self.keyset_ttl_secs = secs;
        self
    }

    pub fn join_device(&self) -> JoinDevice<'_> {
        JoinDevice {
            tokens: &*self.store,
            directory: &*self.store,
            placement: &*self.store,
            reports: &*self.store,
            clock: &*self.clock,
            policy: self.join_policy,
            place_policy: self.place_policy,
        }
    }

    pub fn approve_device(&self) -> ApproveDevice<'_> {
        ApproveDevice {
            directory: &*self.store,
            placement: &*self.store,
            reports: &*self.store,
            clock: &*self.clock,
            policy: self.place_policy,
        }
    }

    pub fn build_config(&self) -> BuildConfig<'_> {
        BuildConfig {
            directory: &*self.store,
            placement: &*self.store,
            reports: &*self.store,
            clock: &*self.clock,
            policy: self.place_policy,
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
            policy: self.place_policy,
        }
    }

    pub fn assign_pair(&self) -> AssignPair<'_> {
        AssignPair {
            directory: &*self.store,
            placement: &*self.store,
            clock: &*self.clock,
            policy: self.place_policy,
        }
    }

    /// Move the pairs of every relay that has stopped being a place a pair may be
    /// — retired, draining, or gone quiet — onto another relay, and say what moved.
    ///
    /// This is the only thing in the process that ever moves an assignment: a pair
    /// is placed once when it is made and stays where it is until it is swept. So
    /// a relay that dies costs its own pairs only if this is called on a timer, and
    /// the daemon's timer is `http::watch_relays`. The reading of what "gone quiet"
    /// means is `PlacePolicy`'s and is not re-derived here.
    pub async fn sweep(&self, now: Millis) -> Result<Vec<RehomeReport>, ReportError> {
        self.ingest_heartbeat().sweep(now).await
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
