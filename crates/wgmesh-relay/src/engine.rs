use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use wgmesh_core::{DeviceId, DropReason, Endpoint, Millis, RelayTable, Route};

use crate::assignment::{Assignment, Keyset, PairAssignment, SlotAssignment};
use crate::config::RelayConfig;
use crate::error::RelayError;
use crate::limits::SlotLimit;
use crate::report::{Heartbeat, Observation, RelayStatus, Report, SlotStatus, TrafficSample};
use crate::sockets::SlotSockets;

// A datagram that arrives on a slot whose device has no paired counterpart is asked
// about with this device id. Nothing can be assigned against it, so `RelayTable` answers
// `NotAssigned` without the engine second-guessing the core.
pub const UNPAIRED: DeviceId = DeviceId(u32::MAX);

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Drop {
    UnknownIngress,
    UnknownDestination,
    NotAssigned,
    SourceMoved,
    Malformed,
    KeysetStale,
    KeysetUnknown,
    RateLimited,
    Draining,
}

impl Drop {
    pub fn from_core(reason: DropReason) -> Self {
        match reason {
            DropReason::UnknownIngress => Self::UnknownIngress,
            DropReason::UnknownDestination => Self::UnknownDestination,
            DropReason::NotAssigned => Self::NotAssigned,
            DropReason::SourceMoved => Self::SourceMoved,
            DropReason::Malformed => Self::Malformed,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct DropCounters {
    pub unknown_ingress: u64,
    pub unknown_destination: u64,
    pub not_assigned: u64,
    pub source_moved: u64,
    pub malformed: u64,
    pub keyset_stale: u64,
    pub keyset_unknown: u64,
    pub rate_limited: u64,
    pub draining: u64,
}

impl DropCounters {
    fn record(&mut self, drop: Drop) {
        let slot = match drop {
            Drop::UnknownIngress => &mut self.unknown_ingress,
            Drop::UnknownDestination => &mut self.unknown_destination,
            Drop::NotAssigned => &mut self.not_assigned,
            Drop::SourceMoved => &mut self.source_moved,
            Drop::Malformed => &mut self.malformed,
            Drop::KeysetStale => &mut self.keyset_stale,
            Drop::KeysetUnknown => &mut self.keyset_unknown,
            Drop::RateLimited => &mut self.rate_limited,
            Drop::Draining => &mut self.draining,
        };
        *slot += 1;
    }

    pub fn get(&self, drop: Drop) -> u64 {
        match drop {
            Drop::UnknownIngress => self.unknown_ingress,
            Drop::UnknownDestination => self.unknown_destination,
            Drop::NotAssigned => self.not_assigned,
            Drop::SourceMoved => self.source_moved,
            Drop::Malformed => self.malformed,
            Drop::KeysetStale => self.keyset_stale,
            Drop::KeysetUnknown => self.keyset_unknown,
            Drop::RateLimited => self.rate_limited,
            Drop::Draining => self.draining,
        }
    }

    pub fn total(&self) -> u64 {
        self.unknown_ingress
            + self.unknown_destination
            + self.not_assigned
            + self.source_moved
            + self.malformed
            + self.keyset_stale
            + self.keyset_unknown
            + self.rate_limited
            + self.draining
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Counters {
    pub datagrams: u64,
    pub ingress_bytes: u64,
    pub forwarded: u64,
    pub forwarded_bytes: u64,
    pub socket_errors: u64,
    pub drops: DropCounters,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Outcome {
    Forwarded {
        from: DeviceId,
        to: DeviceId,
        bytes: usize,
    },
    Dropped(Drop),
    SendFailed {
        to: DeviceId,
    },
}

#[derive(Clone, Debug, Default)]
struct Traffic {
    rx_packets: u64,
    rx_bytes: u64,
    tx_packets: u64,
    tx_bytes: u64,
}

#[derive(Clone, Debug, Default)]
pub struct Shutdown {
    flag: Arc<AtomicBool>,
}

#[derive(Clone, Debug, Default)]
pub struct ShutdownHandle {
    flag: Arc<AtomicBool>,
}

pub fn shutdown() -> (ShutdownHandle, Shutdown) {
    let flag = Arc::new(AtomicBool::new(false));
    (ShutdownHandle { flag: flag.clone() }, Shutdown { flag })
}

impl ShutdownHandle {
    pub fn trigger(&self) {
        self.flag.store(true, Ordering::SeqCst);
    }
}

impl Shutdown {
    pub fn is_shutdown(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }
}

struct SystemClock {
    start: Instant,
}

impl SystemClock {
    fn start() -> Self {
        Self {
            start: Instant::now(),
        }
    }

    fn now(&self) -> Millis {
        Millis::from_millis(self.start.elapsed().as_millis() as u64)
    }
}

// The relay's data plane. Every routing judgement belongs to `wgmesh_core::RelayTable`;
// what lives here is the socket plumbing, the per-slot abuse controls the coordinator
// cannot enforce from where it sits, and the observation batches the control plane reads.
// The relay holds no database, no private key, and no per-packet state beyond the slot
// table it was handed.
pub struct RelayEngine<S: SlotSockets> {
    sockets: S,
    config: RelayConfig,
    table: RelayTable,
    slot_port: BTreeMap<DeviceId, u16>,
    pair_of: BTreeMap<DeviceId, DeviceId>,
    applied_slots: Vec<SlotAssignment>,
    applied_pairs: Vec<PairAssignment>,
    keyset: Option<Keyset>,
    keyset_loaded_at: Millis,
    observed: BTreeMap<DeviceId, (SocketAddr, Millis)>,
    limits: BTreeMap<DeviceId, SlotLimit>,
    traffic: BTreeMap<DeviceId, Traffic>,
    batch: BTreeMap<DeviceId, Traffic>,
    counters: Counters,
    draining: bool,
    started_at: Millis,
    last_report: Option<Millis>,
    pending: Vec<Report>,
}

impl<S: SlotSockets> RelayEngine<S> {
    pub fn new(sockets: S, config: RelayConfig) -> Self {
        Self {
            sockets,
            config,
            table: RelayTable::default(),
            slot_port: BTreeMap::new(),
            pair_of: BTreeMap::new(),
            applied_slots: Vec::new(),
            applied_pairs: Vec::new(),
            keyset: None,
            keyset_loaded_at: Millis::ZERO,
            observed: BTreeMap::new(),
            limits: BTreeMap::new(),
            traffic: BTreeMap::new(),
            batch: BTreeMap::new(),
            counters: Counters::default(),
            draining: false,
            started_at: Millis::ZERO,
            last_report: None,
            pending: Vec::new(),
        }
    }

    pub fn sockets(&self) -> &S {
        &self.sockets
    }

    // A plain accessor, not a policy hook: it is how a test opens a socket the
    // assignment did not ask for, and so how an unknown-ingress datagram can arrive
    // over a real socket instead of being synthesised.
    pub fn sockets_mut(&mut self) -> &mut S {
        &mut self.sockets
    }

    pub fn config(&self) -> &RelayConfig {
        &self.config
    }

    pub fn counters(&self) -> Counters {
        self.counters
    }

    pub fn slot_port(&self, device: DeviceId) -> Option<u16> {
        self.slot_port.get(&device).copied()
    }

    pub fn pair_of(&self, device: DeviceId) -> Option<DeviceId> {
        self.pair_of.get(&device).copied()
    }

    pub fn slots(&self) -> Vec<DeviceId> {
        self.slot_port.keys().copied().collect()
    }

    pub fn pairs(&self) -> Vec<(DeviceId, DeviceId)> {
        self.applied_pairs
            .iter()
            .map(|pair| (DeviceId(pair.device_a), DeviceId(pair.device_b)))
            .collect()
    }

    pub fn keyset_age(&self, at: Millis) -> Option<Duration> {
        self.keyset
            .as_ref()
            .map(|_| at.elapsed_since(self.keyset_loaded_at))
    }

    pub fn keyset_stale(&self, at: Millis) -> bool {
        match self.keyset {
            None => true,
            Some(_) => at.elapsed_since(self.keyset_loaded_at) > self.config.keyset_ttl,
        }
    }

    pub fn is_draining(&self) -> bool {
        self.draining
    }

    pub fn set_draining(&mut self, draining: bool) {
        self.draining = draining;
    }

    // Applies a fresh slot table, pair set and keyset without a restart. An identical
    // push leaves the routing table alone on purpose: rebuilding it would clear every
    // pinned source address, and the coordinator re-pushes the same assignment on a
    // timer.
    pub fn on_assignment(&mut self, assignment: Assignment, at: Millis) -> Result<(), RelayError> {
        self.keyset = Some(assignment.keyset.clone());
        self.keyset_loaded_at = at;

        let mut slots = assignment.slots.clone();
        slots.sort();
        let mut pairs = assignment.pairs.clone();
        pairs.sort();

        if slots == self.applied_slots && pairs == self.applied_pairs {
            return Ok(());
        }
        self.applied_slots = slots;
        self.applied_pairs = pairs;
        self.rebuild()
    }

    // The keyset-only refresh (`GET /v1/relay/keyset`). Applied on its own so that a
    // revocation reaches the isolation boundary without waiting for a pair change.
    pub fn on_keyset(&mut self, keyset: Keyset, at: Millis) {
        self.keyset = Some(keyset);
        self.keyset_loaded_at = at;
    }

    fn rebuild(&mut self) -> Result<(), RelayError> {
        // A requested port of 0 means an ephemeral slot: the device keeps the port it
        // already holds, so re-applying an assignment never moves a slot out from under
        // a node. A coordinator-assigned port is used verbatim, and a slot whose port
        // changed is closed and rebound.
        let resolved: Vec<(DeviceId, u16)> = self
            .applied_slots
            .iter()
            .map(|slot| {
                let device = DeviceId(slot.device_id);
                let port = if slot.port == 0 {
                    self.slot_port.get(&device).copied().unwrap_or(0)
                } else {
                    slot.port
                };
                (device, port)
            })
            .collect();

        let wanted: BTreeSet<u16> = resolved.iter().map(|(_, port)| *port).collect();
        let mut bound: BTreeSet<u16> = self.sockets.ports().into_iter().collect();
        for port in bound.iter() {
            if !wanted.contains(port) {
                self.sockets.close(*port);
            }
        }

        let mut table = RelayTable::default();
        let mut slot_port = BTreeMap::new();
        for (device, port) in resolved {
            let actual = if port != 0 && bound.contains(&port) {
                port
            } else {
                let actual = self.sockets.bind(port).map_err(RelayError::socket)?;
                bound.insert(actual);
                actual
            };
            table.assign_slot(device, actual);
            slot_port.insert(device, actual);
        }

        let mut pair_of = BTreeMap::new();
        for pair in &self.applied_pairs {
            let (a, b) = (DeviceId(pair.device_a), DeviceId(pair.device_b));
            table.assign_pair(a, b);
            pair_of.insert(a, b);
            pair_of.insert(b, a);
        }

        self.table = table;
        self.slot_port = slot_port;
        self.pair_of = pair_of;
        self.observed
            .retain(|device, _| self.slot_port.contains_key(device));
        self.traffic
            .retain(|device, _| self.slot_port.contains_key(device));
        self.batch
            .retain(|device, _| self.slot_port.contains_key(device));
        self.limits = self
            .slot_port
            .keys()
            .map(|device| {
                (
                    *device,
                    SlotLimit::new(self.config.pps_per_slot, self.config.mbit_per_slot),
                )
            })
            .collect();
        Ok(())
    }

    // Route one datagram that arrived on `port` from `from`. Returning the outcome
    // rather than only acting on it is what lets the tests name the drop reason.
    pub fn handle(&mut self, port: u16, from: SocketAddr, payload: &[u8], at: Millis) -> Outcome {
        self.counters.datagrams += 1;
        self.counters.ingress_bytes += payload.len() as u64;

        let ingress = self.table.ingress(port);
        if let Some(device) = ingress {
            let entry = self.traffic.entry(device).or_default();
            entry.rx_packets += 1;
            entry.rx_bytes += payload.len() as u64;
            let batch = self.batch.entry(device).or_default();
            batch.rx_packets += 1;
            batch.rx_bytes += payload.len() as u64;

            let pps = self.config.pps_per_slot;
            let mbit = self.config.mbit_per_slot;
            let limit = self
                .limits
                .entry(device)
                .or_insert_with(|| SlotLimit::new(pps, mbit));
            if !limit.charge(payload.len(), at) {
                return self.drop_out(Drop::RateLimited);
            }
        }

        let destination = ingress
            .and_then(|device| self.pair_of.get(&device).copied())
            .unwrap_or(UNPAIRED);
        let route = self
            .table
            .route(port, Endpoint::new(from), destination, payload, at);

        if let Some(device) = ingress {
            // `RelayTable` pins the source address exactly when it does not drop for
            // one of these three reasons; the engine mirrors the pin under the same
            // rule so that the address it reports is the one the relay accepted.
            let pinned = !matches!(
                route,
                Route::Drop(
                    DropReason::Malformed | DropReason::UnknownIngress | DropReason::SourceMoved
                )
            );
            if pinned {
                self.observed.insert(device, (from, at));
            }
        }

        let Route::Forward {
            from: origin,
            to,
            destination,
        } = route
        else {
            let Route::Drop(reason) = route else {
                return self.drop_out(Drop::UnknownDestination);
            };
            return self.drop_out(Drop::from_core(reason));
        };

        if self.draining {
            return self.drop_out(Drop::Draining);
        }
        if self.keyset_stale(at) {
            return self.drop_out(Drop::KeysetStale);
        }
        if !self.keyset_allows(to) {
            return self.drop_out(Drop::KeysetUnknown);
        }
        let Some(out_port) = self.slot_port.get(&to).copied() else {
            return self.fail_send(to);
        };

        match self.sockets.send(out_port, destination.addr(), payload) {
            Ok(sent) if sent == payload.len() => {
                self.counters.forwarded += 1;
                self.counters.forwarded_bytes += sent as u64;
                let entry = self.traffic.entry(to).or_default();
                entry.tx_packets += 1;
                entry.tx_bytes += sent as u64;
                let batch = self.batch.entry(to).or_default();
                batch.tx_packets += 1;
                batch.tx_bytes += sent as u64;
                Outcome::Forwarded {
                    from: origin,
                    to,
                    bytes: sent,
                }
            }
            // A short write would mean the relay emitted something other than the
            // datagram it received, which is the one thing that must never happen.
            Ok(_) | Err(_) => self.fail_send(to),
        }
    }

    fn drop_out(&mut self, drop: Drop) -> Outcome {
        self.counters.drops.record(drop);
        Outcome::Dropped(drop)
    }

    fn fail_send(&mut self, to: DeviceId) -> Outcome {
        self.counters.socket_errors += 1;
        Outcome::SendFailed { to }
    }

    fn keyset_allows(&self, device: DeviceId) -> bool {
        match &self.keyset {
            None => false,
            Some(keyset) => keyset.contains(device.0),
        }
    }

    /// Drain every slot socket once, routing each datagram. Returns how many were read.
    pub fn pump(&mut self, at: Millis) -> usize {
        let mut handled = 0;
        for port in self.sockets.ports() {
            loop {
                match self.sockets.recv(port) {
                    Ok(Some(datagram)) => {
                        self.handle(port, datagram.from, &datagram.payload, at);
                        handled += 1;
                    }
                    Ok(None) => break,
                    Err(_) => {
                        self.counters.socket_errors += 1;
                        break;
                    }
                }
            }
        }
        handled
    }

    // The 2-second batch: source observations, the traffic delta since the previous
    // batch, and a heartbeat. Reports leave over the control path, never the data one.
    // The first call establishes the baseline and reports immediately; every later call
    // waits out the interval, so the batch is always exactly one interval of traffic.
    pub fn tick(&mut self, at: Millis) -> Vec<Report> {
        let mut reports = Vec::new();
        if let Some(previous) = self.last_report {
            if at.elapsed_since(previous) < self.config.report_interval {
                return reports;
            }
        }
        self.last_report = Some(at);

        if !self.observed.is_empty() {
            let observations = self
                .observed
                .iter()
                .map(|(device, (address, seen_at))| Observation {
                    device_id: device.0,
                    ip: address.ip(),
                    port: address.port(),
                    seen_at: seen_at.as_millis(),
                })
                .collect();
            reports.push(Report::Observations(observations));
        }

        let batch = std::mem::take(&mut self.batch);
        let samples: Vec<TrafficSample> = batch
            .into_iter()
            .filter(|(_, traffic)| traffic.rx_bytes + traffic.tx_bytes > 0)
            .map(|(device, traffic)| TrafficSample {
                device_id: device.0,
                period_start: at.as_millis(),
                rx_packets: traffic.rx_packets,
                rx_bytes: traffic.rx_bytes,
                tx_packets: traffic.tx_packets,
                tx_bytes: traffic.tx_bytes,
            })
            .collect();
        if !samples.is_empty() {
            reports.push(Report::Traffic(samples));
        }

        reports.push(Report::Heartbeat(Heartbeat {
            relay_id: self.config.relay_id.clone(),
            at: at.as_millis(),
            uptime_ms: at.elapsed_since(self.started_at).as_millis() as u64,
            slots: self.slot_port.len(),
            pairs: self.applied_pairs.len(),
            draining: self.draining,
            keyset_age_ms: self.keyset_age(at).map(|age| age.as_millis() as u64),
            keyset_devices: self.keyset.as_ref().map_or(0, Keyset::len),
            counters: self.counters,
        }));
        reports
    }

    pub fn drain_reports(&mut self) -> Vec<Report> {
        std::mem::take(&mut self.pending)
    }

    pub fn status(&self, at: Millis) -> RelayStatus {
        RelayStatus {
            relay_id: self.config.relay_id.clone(),
            at: at.as_millis(),
            uptime_ms: at.elapsed_since(self.started_at).as_millis() as u64,
            draining: self.draining,
            keyset_devices: self.keyset.as_ref().map_or(0, Keyset::len),
            keyset_age: self.keyset_age(at),
            slots: self
                .slot_port
                .iter()
                .map(|(device, port)| SlotStatus {
                    device_id: device.0,
                    port: *port,
                    observed: self
                        .observed
                        .get(device)
                        .map(|(_, seen_at)| seen_at.as_millis()),
                })
                .collect(),
            pairs: self
                .applied_pairs
                .iter()
                .map(|pair| (pair.device_a, pair.device_b))
                .collect(),
            counters: self.counters,
        }
    }

    // Drive the engine until `shutdown` is triggered. `control` runs once per iteration
    // for the things that are not the data plane: draining, status snapshots, shipping
    // the queued reports. Reports are only queued here, which keeps the HTTPS client out
    // of this crate.
    pub async fn run_with<C>(
        &mut self,
        shutdown: Shutdown,
        mut control: C,
    ) -> Result<(), RelayError>
    where
        C: FnMut(&mut Self, Millis),
    {
        let clock = SystemClock::start();
        loop {
            let now = clock.now();
            self.pump(now);
            let reports = self.tick(now);
            self.pending.extend(reports);
            control(self, now);
            if shutdown.is_shutdown() {
                return Ok(());
            }
            let waited = self
                .last_report
                .map_or(Duration::ZERO, |previous| now.elapsed_since(previous));
            let budget = self
                .config
                .report_interval
                .saturating_sub(waited)
                .min(self.config.poll_budget)
                .max(Duration::from_millis(1));
            self.sockets.wait(budget).await;
        }
    }

    pub async fn run(&mut self, shutdown: Shutdown) -> Result<(), RelayError> {
        self.run_with(shutdown, |_, _| {}).await
    }
}
