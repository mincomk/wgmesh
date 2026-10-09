use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;

use wgmesh_core::rate::Metered;
use wgmesh_core::{
    DeviceId, DropReason, Endpoint, MessageKind, Millis, PublicKey, RelayTable, classify, mac1_key,
    verify_mac1,
};
use wgmesh_metrics::Registry;
use wgmesh_proto::{RelayAssignment, RelayHeartbeat};

/// What became of one packet.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Handling {
    Forward {
        /// The device that sent it, as the ingress port identified it.
        from: String,
        /// The device it is going to.
        to: String,
        /// That device's last known source address.
        destination: SocketAddr,
        /// The slot the reply must leave from. A forwarding relay is not a
        /// black box with one address: the peer's NAT only accepts packets
        /// from the port it sent to.
        via_port: u16,
    },
    /// The slot has spent its packet or byte allowance.
    Throttled,
    /// Refused before it could touch an allowance, because a single packet
    /// must never be able to empty a slot's bucket.
    Oversized,
    Dropped(DropReason),
}

/// Per-slot traffic, which is what a relay's bill is written against.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct SlotCounters {
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub tx_packets: u64,
    pub tx_bytes: u64,
    pub throttled_packets: u64,
    pub throttled_bytes: u64,
    pub dropped_packets: u64,
    /// How many packets were forwarded on behalf of this slot as a
    /// destination, which is what a device actually received.
    pub delivered_packets: u64,
}

impl SlotCounters {
    fn add(&mut self, other: &SlotCounters) {
        self.rx_packets += other.rx_packets;
        self.rx_bytes += other.rx_bytes;
        self.tx_packets += other.tx_packets;
        self.tx_bytes += other.tx_bytes;
        self.throttled_packets += other.throttled_packets;
        self.throttled_bytes += other.throttled_bytes;
        self.dropped_packets += other.dropped_packets;
        self.delivered_packets += other.delivered_packets;
    }
}

/// The per-slot ceilings.
///
/// Both buckets are checked before either is spent, so a packet that is
/// refused for bytes does not also cost its slot a packet token — otherwise a
/// flood of large packets would close the slot to small ones.
#[derive(Debug)]
pub struct SlotLimits {
    packets: Metered<u16>,
    bytes: Metered<u16>,
    max_packet_bytes: usize,
}

impl SlotLimits {
    pub fn new(pps_per_slot: u32, bytes_per_second: f64, max_packet_bytes: usize) -> Self {
        Self {
            packets: Metered::new(f64::from(pps_per_slot), 1_000, 4096),
            bytes: Metered::new(bytes_per_second, 1_000, 4096),
            max_packet_bytes,
        }
    }

    pub fn admit(&mut self, slot: u16, len: usize, now_ms: u64) -> Admission {
        if len > self.max_packet_bytes {
            return Admission::Oversized;
        }
        let size = len as f64;
        if self.packets.projected(slot, now_ms) < 1.0 || self.bytes.projected(slot, now_ms) < size {
            return Admission::Refused {
                packet_allowance_left: self.packets.projected(slot, now_ms),
                byte_allowance_left: self.bytes.projected(slot, now_ms),
            };
        }
        self.packets.take(slot, 1.0, now_ms);
        self.bytes.take(slot, size, now_ms);
        Admission::Admitted
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Admission {
    Admitted,
    Refused {
        packet_allowance_left: f64,
        byte_allowance_left: f64,
    },
    Oversized,
}

/// The relay's whole decision surface. It does no I/O: sockets live in the
/// driver, so every routing, identity and limit decision here can be exercised
/// without a network.
pub struct RelayEngine {
    table: RelayTable,
    limits: SlotLimits,
    /// device id → the numeric handle the core routing table counts with.
    handles: BTreeMap<String, DeviceId>,
    ids: BTreeMap<DeviceId, String>,
    /// relay port → the device that sends from it.
    slots: BTreeMap<u16, String>,
    /// device → the peers it may reach through this relay.
    peers_of: BTreeMap<String, BTreeSet<String>>,
    /// device → its WireGuard public key, for reading a handshake's
    /// destination out of `mac1`.
    keys: BTreeMap<String, PublicKey>,
    counters: BTreeMap<u16, SlotCounters>,
}

impl RelayEngine {
    pub fn new(limits: SlotLimits) -> Self {
        Self {
            table: RelayTable::default(),
            limits,
            handles: BTreeMap::new(),
            ids: BTreeMap::new(),
            slots: BTreeMap::new(),
            peers_of: BTreeMap::new(),
            keys: BTreeMap::new(),
            counters: BTreeMap::new(),
        }
    }

    pub fn from_config(limits: &wgmesh_config::relay::Limits) -> Self {
        Self::new(SlotLimits::new(
            limits.pps_per_slot,
            limits.bytes_per_second(),
            limits.max_packet_bytes as usize,
        ))
    }

    /// Learn what this relay is allowed to carry. Slots and pairs are replaced
    /// wholesale: an assignment is the complete truth, not a delta.
    pub fn apply(&mut self, assignment: &RelayAssignment) {
        self.handles.clear();
        self.ids.clear();
        self.slots.clear();
        self.peers_of.clear();
        self.keys = assignment
            .networks
            .iter()
            .flat_map(|network| network.peers.iter())
            .filter_map(|peer| decode_key(&peer.wg_pubkey).map(|key| (peer.device_id.clone(), key)))
            .collect();

        for slot in &assignment.slots {
            let handle = self.handle_for(&slot.device_id);
            self.table.assign_slot(handle, slot.udp_port);
            self.slots.insert(slot.udp_port, slot.device_id.clone());
            self.counters.entry(slot.udp_port).or_default();
        }
        for pair in &assignment.pairs {
            let a = self.handle_for(&pair.a);
            let b = self.handle_for(&pair.b);
            self.table.assign_pair(a, b);
            self.peers_of
                .entry(pair.a.clone())
                .or_default()
                .insert(pair.b.clone());
            self.peers_of
                .entry(pair.b.clone())
                .or_default()
                .insert(pair.a.clone());
        }
    }

    fn handle_for(&mut self, device: &str) -> DeviceId {
        if let Some(handle) = self.handles.get(device) {
            return *handle;
        }
        let handle = DeviceId(self.handles.len() as u32 + 1);
        self.handles.insert(device.to_owned(), handle);
        self.ids.insert(handle, device.to_owned());
        handle
    }

    /// Decide what to do with one datagram received on `ingress_port`.
    pub fn handle(
        &mut self,
        ingress_port: u16,
        source: SocketAddr,
        packet: &[u8],
        now_ms: u64,
    ) -> Handling {
        let Some(from) = self.slots.get(&ingress_port).cloned() else {
            self.count(ingress_port, |counters| counters.dropped_packets += 1);
            return Handling::Dropped(DropReason::UnknownIngress);
        };
        self.count(ingress_port, |counters| {
            counters.rx_packets += 1;
            counters.rx_bytes += packet.len() as u64;
        });

        let destination_device = match self.destination_for(&from, packet) {
            Some(device) => device,
            None => {
                self.count(ingress_port, |counters| counters.dropped_packets += 1);
                return Handling::Dropped(DropReason::UnknownDestination);
            }
        };

        match self.limits.admit(ingress_port, packet.len(), now_ms) {
            Admission::Admitted => {}
            Admission::Refused { .. } => {
                self.count(ingress_port, |counters| {
                    counters.throttled_packets += 1;
                    counters.throttled_bytes += packet.len() as u64;
                });
                return Handling::Throttled;
            }
            Admission::Oversized => {
                self.count(ingress_port, |counters| counters.dropped_packets += 1);
                return Handling::Oversized;
            }
        }

        let destination = self.handles.get(&destination_device).copied();
        let Some(destination) = destination else {
            self.count(ingress_port, |counters| counters.dropped_packets += 1);
            return Handling::Dropped(DropReason::UnknownDestination);
        };
        let route = self.table.route(
            ingress_port,
            Endpoint::new(source),
            destination,
            packet,
            Millis::from_millis(now_ms),
        );
        match route {
            wgmesh_core::Route::Forward {
                from: _,
                to,
                destination: endpoint,
            } => {
                let to_device = self
                    .ids
                    .get(&to)
                    .cloned()
                    .unwrap_or_else(|| destination_device.clone());
                let via_port = self
                    .slots
                    .iter()
                    .find(|(_, device)| device.as_str() == to_device)
                    .map(|(port, _)| *port);
                self.count(ingress_port, |counters| {
                    counters.tx_packets += 1;
                    counters.tx_bytes += packet.len() as u64;
                });
                if let Some(port) = via_port {
                    self.count(port, |counters| counters.delivered_packets += 1);
                }
                Handling::Forward {
                    from,
                    to: to_device,
                    destination: endpoint.addr(),
                    via_port: via_port.unwrap_or(ingress_port),
                }
            }
            wgmesh_core::Route::Drop(reason) => {
                self.count(ingress_port, |counters| counters.dropped_packets += 1);
                Handling::Dropped(reason)
            }
        }
    }

    /// Which device a packet from `from` is meant for.
    ///
    /// A sender with one peer on this relay is unambiguous. With several, the
    /// destination has to come out of the packet: a handshake carries `mac1`,
    /// which is keyed by the *recipient's* public key, so trying each candidate
    /// peer answers the question. Transport data carries a session index
    /// instead, which is why a node gets one port per relay rather than one
    /// port per pair only in the next milestone.
    fn destination_for(&self, from: &str, packet: &[u8]) -> Option<String> {
        let candidates = self.peers_of.get(from)?;
        match candidates.len() {
            0 => None,
            1 => candidates.iter().next().cloned(),
            _ => {
                let kind = classify(packet)?;
                if !matches!(kind, MessageKind::Initiation | MessageKind::Response) {
                    return None;
                }
                candidates
                    .iter()
                    .find(|candidate| {
                        self.keys
                            .get(*candidate)
                            .is_some_and(|key| verify_mac1(packet, &mac1_key(key)))
                    })
                    .cloned()
            }
        }
    }

    pub fn counters(&self, port: u16) -> SlotCounters {
        self.counters.get(&port).copied().unwrap_or_default()
    }

    pub fn totals(&self) -> SlotCounters {
        let mut total = SlotCounters::default();
        for counters in self.counters.values() {
            total.add(counters);
        }
        total
    }

    pub fn slot_ports(&self) -> Vec<u16> {
        self.slots.keys().copied().collect()
    }

    fn count(&mut self, port: u16, update: impl FnOnce(&mut SlotCounters)) {
        update(self.counters.entry(port).or_default());
    }

    /// The heartbeat this relay reports, so the coordinator can see cost and
    /// congestion without seeing traffic.
    pub fn heartbeat(&self, now: u64) -> RelayHeartbeat {
        let totals = self.totals();
        RelayHeartbeat {
            forwarded_packets: totals.tx_packets,
            forwarded_bytes: totals.tx_bytes,
            throttled_packets: totals.throttled_packets,
            dropped_packets: totals.dropped_packets,
            pairs_active: self
                .peers_of
                .values()
                .map(|peers| peers.len() as u64)
                .sum::<u64>()
                / 2,
            at: now,
        }
    }

    /// Build the scrape text from the counters rather than maintaining a
    /// registry per packet: the numbers are already here, and this way the
    /// exposition cannot drift from them.
    pub fn render_metrics(&self) -> String {
        let mut registry = Registry::new();
        for (port, counters) in &self.counters {
            let slot = port.to_string();
            let labels = [("slot", slot.as_str())];
            registry.add_counter(
                "wgmesh_relay_slot_rx_packets_total",
                "Packets received on a slot.",
                &labels,
                counters.rx_packets as f64,
            );
            registry.add_counter(
                "wgmesh_relay_slot_rx_bytes_total",
                "Bytes received on a slot.",
                &labels,
                counters.rx_bytes as f64,
            );
            registry.add_counter(
                "wgmesh_relay_slot_tx_packets_total",
                "Packets forwarded from a slot.",
                &labels,
                counters.tx_packets as f64,
            );
            registry.add_counter(
                "wgmesh_relay_slot_tx_bytes_total",
                "Bytes forwarded from a slot.",
                &labels,
                counters.tx_bytes as f64,
            );
            registry.add_counter(
                "wgmesh_relay_slot_throttled_packets_total",
                "Packets a slot's rate limit refused.",
                &labels,
                counters.throttled_packets as f64,
            );
            registry.add_counter(
                "wgmesh_relay_slot_dropped_packets_total",
                "Packets a slot dropped.",
                &labels,
                counters.dropped_packets as f64,
            );
        }
        let totals = self.totals();
        registry.add_counter(
            "wgmesh_relay_forwarded_packets_total",
            "Packets this relay has forwarded.",
            &[],
            totals.tx_packets as f64,
        );
        registry.add_counter(
            "wgmesh_relay_forwarded_bytes_total",
            "Bytes this relay has forwarded.",
            &[],
            totals.tx_bytes as f64,
        );
        registry.add_counter(
            "wgmesh_relay_throttled_packets_total",
            "Packets refused by a slot limit.",
            &[],
            totals.throttled_packets as f64,
        );
        registry.set_gauge(
            "wgmesh_relay_slots",
            "Slots this relay is configured for.",
            &[],
            self.counters.len() as f64,
        );
        registry.render()
    }
}

fn decode_key(encoded: &str) -> Option<PublicKey> {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    let bytes: [u8; 32] = bytes.as_slice().try_into().ok()?;
    Some(PublicKey::from_bytes(bytes))
}
