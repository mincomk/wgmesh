// One port per node: the destination comes out of the packet
//
// The MVP relay gives a pair its own two ports, so the ingress port names both ends and the relay
// never reads a byte of the payload. The expanded layout gives each node a single port instead --
// one socket per node, N sockets serving N nodes, N^2 pairs routed through them -- and then the
// ingress port can only say who *sent* a packet. Where it is *going* has to come out of the packet
// itself:
//
//   * a handshake (type 1 or 2) names its recipient through `mac1`, whose MAC key is
//     `HASH(LABEL_MAC1 || responder.static_public)`, so exactly one key in the network verifies it;
//   * a response, a cookie reply or a transport packet (types 2, 3, 4) names its recipient through
//     `receiver_index`, which is the index the *recipient* chose when it last handshook.
//
// A relay holds neither the static keys nor any plaintext; both of these fields are in the clear
// by design, and neither of them reveals the sender. That asymmetry -- destination from the packet,
// sender from the ingress port -- is the whole of this mode.

/// The WireGuard `RekeyAfterTime`: an initiator rekeys about this often and picks a fresh
/// `sender_index`, which is what refreshes the session table with no message of its own.
pub const REKEY_INTERVAL: std::time::Duration = std::time::Duration::from_secs(120);

/// The WireGuard `RejectAfterTime`: past this a session index is worth nothing, because the key
/// behind it has been thrown away.
pub const SESSION_TTL: std::time::Duration = std::time::Duration::from_secs(180);

// WireGuard message layouts, from https://www.wireguard.com/protocol/. The 4-byte header is
// `message_type` plus three reserved zero bytes; every index is a little-endian u32.
//
//   initiation (148)  type(4) sender(4) ephemeral(32) static(48) timestamp(28) mac1(16) mac2(16)
//   response    (92)  type(4) sender(4) receiver(4) ephemeral(32) empty(16) mac1(16) mac2(16)
//   cookie      (64)  type(4) receiver(4) nonce(24) cookie(32)
//   transport  (>=32) type(4) receiver(4) counter(8) encrypted_packet[]
const OFF_RECEIVER_OF_RESPONSE: usize = 8;
const OFF_INDEX: usize = 4;

fn read_index(packet: &[u8], offset: usize) -> Option<u32> {
    let bytes = packet.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// The `sender_index` a handshake attributes to the device that sent it.
///
/// Only handshakes carry one: an initiation names the index the initiator chose, a response names
/// the index the responder chose. A cookie reply and a transport packet carry no sender at all.
pub fn sender_index(packet: &[u8]) -> Option<u32> {
    match crate::classify(packet)? {
        crate::MessageKind::Initiation | crate::MessageKind::Response => {
            read_index(packet, OFF_INDEX)
        }
        crate::MessageKind::CookieReply | crate::MessageKind::Transport => None,
    }
}

/// The `receiver_index` that names the device a packet is addressed to.
///
/// A response addresses the initiator and a cookie reply does the same; a transport packet
/// addresses whoever chose the index in its header.
pub fn receiver_index(packet: &[u8]) -> Option<u32> {
    match crate::classify(packet)? {
        crate::MessageKind::Initiation => None,
        crate::MessageKind::Response => read_index(packet, OFF_RECEIVER_OF_RESPONSE),
        crate::MessageKind::CookieReply | crate::MessageKind::Transport => {
            read_index(packet, OFF_INDEX)
        }
    }
}

/// An entry of the keyset: the device that owns a public key, plus the MAC key derived from it so
/// that verifying a packet does not re-hash the label on every lookup.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct KeysetEntry {
    device: crate::DeviceId,
    mac1_key: crate::Mac1Key,
}

/// The network's public keys, as the coordinator hands them to a relay.
///
/// A public key is all that is needed to verify a `mac1`, and a public key is safe to hold: it
/// proves the sender knows the recipient, and proves nothing at all about the sender.
#[derive(Clone, Debug, Default)]
pub struct Keyset {
    entries: std::collections::BTreeMap<crate::PublicKey, KeysetEntry>,
}

impl Keyset {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add (or replace) a device's public key, returning the device that held it before, if any.
    pub fn insert(
        &mut self,
        device: crate::DeviceId,
        key: crate::PublicKey,
    ) -> Option<crate::DeviceId> {
        let entry = KeysetEntry {
            device,
            mac1_key: crate::mac1_key(&key),
        };
        self.entries
            .insert(key, entry)
            .map(|previous| previous.device)
    }

    /// Forget every key belonging to `device`, returning how many were held.
    pub fn remove(&mut self, device: crate::DeviceId) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, entry| entry.device != device);
        before - self.entries.len()
    }

    pub fn contains(&self, device: crate::DeviceId) -> bool {
        self.entries.values().any(|entry| entry.device == device)
    }

    pub fn device_of(&self, key: &crate::PublicKey) -> Option<crate::DeviceId> {
        self.entries.get(key).map(|entry| entry.device)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Which device a handshake is addressed to, read from its `mac1` alone.
    ///
    /// `None` means no key in the set verifies the packet: it is addressed outside this network,
    /// or its `mac1` is simply wrong. Either way the relay has no destination and must drop it.
    pub fn destination_of(&self, packet: &[u8]) -> Option<crate::DeviceId> {
        if !matches!(
            crate::classify(packet),
            Some(crate::MessageKind::Initiation | crate::MessageKind::Response)
        ) {
            return None;
        }
        self.entries
            .values()
            .find(|entry| crate::verify_mac1(packet, &entry.mac1_key))
            .map(|entry| entry.device)
    }
}

/// One row of the session table: who owns a session index, and when the relay last heard it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct SessionEntry {
    device: crate::DeviceId,
    seen_at: crate::Millis,
}

/// What the relay learned from a handshake it carried.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Observed {
    /// The index is new for this device; the device's own previous index is gone. That is a rekey.
    Recorded,
    /// The same index for the same device, with a fresh timestamp.
    Refreshed,
    /// The index is live and belongs to another device; it is not handed over.
    Refused,
}

/// Which device owns which session index, learned by watching handshakes go past.
///
/// This table holds an index and a device id and nothing else -- no key, no plaintext, not even a
/// digest of either. It exists so that a transport packet's `receiver_index`, which the relay can
/// read but not interpret, becomes a device again. It refreshes itself: WireGuard rekeys roughly
/// every `REKEY_INTERVAL`, a rekey picks a fresh index, and the stale one ages out after
/// `SESSION_TTL`.
#[derive(Clone, Debug, Default)]
pub struct SessionTable {
    by_index: std::collections::BTreeMap<u32, SessionEntry>,
    by_device: std::collections::BTreeMap<crate::DeviceId, u32>,
}

impl SessionTable {
    /// The bytes one entry occupies. Published so a test can assert, structurally, that an entry
    /// is an index and a device id and a timestamp -- it has no room for key material.
    pub const ENTRY_BYTES: usize = std::mem::size_of::<u32>()
        + std::mem::size_of::<crate::DeviceId>()
        + std::mem::size_of::<crate::Millis>();

    fn is_expired(entry: &SessionEntry, at: crate::Millis) -> bool {
        at.elapsed_since(entry.seen_at) > SESSION_TTL
    }

    fn evict_device_index(&mut self, device: crate::DeviceId) {
        if let Some(previous) = self.by_device.remove(&device) {
            if self
                .by_index
                .get(&previous)
                .is_some_and(|entry| entry.device == device)
            {
                self.by_index.remove(&previous);
            }
        }
    }

    /// Attribute an observed `sender_index` to the device the ingress port identified.
    pub fn observe(&mut self, index: u32, device: crate::DeviceId, at: crate::Millis) -> Observed {
        let outcome = match self.by_index.get(&index) {
            Some(existing) if existing.device != device => {
                if !Self::is_expired(existing, at) {
                    return Observed::Refused;
                }
                Observed::Recorded
            }
            Some(_) => Observed::Refreshed,
            None => Observed::Recorded,
        };
        self.evict_device_index(device);
        self.by_index.insert(
            index,
            SessionEntry {
                device,
                seen_at: at,
            },
        );
        self.by_device.insert(device, index);
        outcome
    }

    /// The device a `receiver_index` names, or `None` when no live session claims it.
    pub fn owner(&mut self, index: u32, at: crate::Millis) -> Option<crate::DeviceId> {
        let entry = *self.by_index.get(&index)?;
        if Self::is_expired(&entry, at) {
            self.forget(index);
            return None;
        }
        Some(entry.device)
    }

    /// Drop one index, returning the device that held it.
    pub fn forget(&mut self, index: u32) -> Option<crate::DeviceId> {
        let entry = self.by_index.remove(&index)?;
        if self.by_device.get(&entry.device) == Some(&index) {
            self.by_device.remove(&entry.device);
        }
        Some(entry.device)
    }

    /// Drop every index belonging to a device, returning how many there were.
    pub fn forget_device(&mut self, device: crate::DeviceId) -> usize {
        let stale: Vec<u32> = self
            .by_index
            .iter()
            .filter(|(_, entry)| entry.device == device)
            .map(|(index, _)| *index)
            .collect();
        for index in &stale {
            self.by_index.remove(index);
        }
        self.by_device.remove(&device);
        stale.len()
    }

    /// Drop every entry older than `SESSION_TTL`, returning how many went.
    pub fn sweep(&mut self, at: crate::Millis) -> usize {
        let stale: Vec<u32> = self
            .by_index
            .iter()
            .filter(|(_, entry)| Self::is_expired(entry, at))
            .map(|(index, _)| *index)
            .collect();
        for index in &stale {
            self.forget(*index);
        }
        stale.len()
    }

    /// Every live row, as an index and a device id -- which is the whole of the table.
    pub fn entries(&self) -> impl Iterator<Item = (u32, crate::DeviceId)> + '_ {
        self.by_index
            .iter()
            .map(|(index, entry)| (*index, entry.device))
    }

    pub fn len(&self) -> usize {
        self.by_index.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_index.is_empty()
    }
}

/// What a relay has carried, and what it threw away.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct RelayCounters {
    pub forwarded: u64,
    pub bytes: u64,
    /// Packets dropped because their destination tag named nothing this relay knows: a handshake
    /// whose `mac1` matches no key in the keyset, or an index with no live session behind it.
    pub rejected: u64,
    /// Every packet that was not forwarded, the `rejected` ones included.
    pub dropped: u64,
}

impl crate::RelayTable {
    pub fn keyset(&self) -> &Keyset {
        &self.keyset
    }

    pub fn keyset_mut(&mut self) -> &mut Keyset {
        &mut self.keyset
    }

    pub fn sessions(&self) -> &SessionTable {
        &self.sessions
    }

    pub fn counters(&self) -> RelayCounters {
        self.counters
    }

    fn drop_packet(&mut self, reason: crate::DropReason) -> crate::Route {
        self.counters.dropped += 1;
        crate::Route::Drop(reason)
    }

    fn drop_untagged(&mut self) -> crate::Route {
        self.counters.rejected += 1;
        self.drop_packet(crate::DropReason::UnknownDestination)
    }

    /// Pin the source address of a slot, TOFU, refusing a move while the pin is fresh. The pin is
    /// the only thing the relay knows about a slot's address; the index table is built from the
    /// packets themselves.
    fn pin_source(
        &mut self,
        from: crate::DeviceId,
        source: crate::Endpoint,
        at: crate::Millis,
    ) -> Result<(), crate::DropReason> {
        let Some(entry) = self.slots.get_mut(&from) else {
            return Err(crate::DropReason::UnknownIngress);
        };
        let stale = at.elapsed_since(entry.last_seen) > crate::SOURCE_PIN_WINDOW;
        if let Some(known) = entry.pinned_src {
            if known != source && !stale {
                return Err(crate::DropReason::SourceMoved);
            }
        }
        entry.pinned_src = Some(source);
        entry.last_seen = at;
        Ok(())
    }

    /// Route one inbound packet in the one-port-per-node mode.
    ///
    /// The sender is the slot the packet arrived on; the destination is read from the packet --
    /// `mac1` for a handshake, `receiver_index` for everything else. A packet whose destination
    /// tag names nothing in the keyset or in the session table is dropped and counted `rejected`.
    ///
    /// Nothing is learned from a packet the relay does not carry: the session table is fed by a
    /// handshake that resolved, was between an assigned pair, and had somewhere to go.
    pub fn route_one_port(
        &mut self,
        ingress_port: u16,
        source: crate::Endpoint,
        packet: &[u8],
        at: crate::Millis,
    ) -> crate::Route {
        let Some(kind) = crate::classify(packet) else {
            return self.drop_packet(crate::DropReason::Malformed);
        };
        let Some(from) = self.ingress(ingress_port) else {
            return self.drop_packet(crate::DropReason::UnknownIngress);
        };
        if let Err(reason) = self.pin_source(from, source, at) {
            return self.drop_packet(reason);
        }
        let destination = match kind {
            crate::MessageKind::Initiation | crate::MessageKind::Response => {
                self.keyset.destination_of(packet)
            }
            crate::MessageKind::CookieReply | crate::MessageKind::Transport => {
                receiver_index(packet).and_then(|index| self.sessions.owner(index, at))
            }
        };
        let Some(to) = destination else {
            return self.drop_untagged();
        };
        if !self.assigned.contains(&(from, to)) {
            return self.drop_packet(crate::DropReason::NotAssigned);
        }
        let Some(destination) = self.slots.get(&to).and_then(|entry| entry.pinned_src) else {
            return self.drop_packet(crate::DropReason::UnknownDestination);
        };
        if let Some(index) = sender_index(packet) {
            self.sessions.observe(index, from, at);
        }
        self.counters.forwarded += 1;
        self.counters.bytes += packet.len() as u64;
        crate::Route::Forward {
            from,
            to,
            destination,
        }
    }
}

#[cfg(test)]
mod one_port_routing_tests {
    use super::*;
    use crate::{
        DeviceId, DropReason, Endpoint, MessageKind, Millis, PublicKey, RelayCounters, Route,
    };
    use blake2::digest::{KeyInit, Mac, Update};
    use std::net::{IpAddr, Ipv4Addr};

    const A: DeviceId = DeviceId(1);
    const B: DeviceId = DeviceId(2);
    const C: DeviceId = DeviceId(3);

    const SLOT_A: u16 = 51901;
    const SLOT_B: u16 = 51902;
    const SLOT_C: u16 = 51903;

    fn ep(port: u16) -> Endpoint {
        Endpoint::new(std::net::SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            port,
        ))
    }

    fn key(seed: u8) -> PublicKey {
        PublicKey::from_bytes([seed; 32])
    }

    /// A handshake of `kind` whose `mac1` is keyed by the recipient's public key, carrying
    /// `sender_index` as its sender index.
    fn handshake(kind: MessageKind, recipient: &PublicKey, sender_index: u32) -> Vec<u8> {
        let len = kind.size_floor();
        let mut packet = vec![0u8; len];
        packet[0] = match kind {
            MessageKind::Initiation => 1,
            MessageKind::Response => 2,
            other => panic!("{other:?} is not a handshake"),
        };
        packet[4..8].copy_from_slice(&sender_index.to_le_bytes());
        let derived = crate::mac1_key(recipient);
        let offset = len - 32;
        let mut mac = <crate::Mac1 as KeyInit>::new_from_slice(&derived).unwrap();
        Update::update(&mut mac, &packet[..offset]);
        packet[offset..offset + 16].copy_from_slice(&mac.finalize().into_bytes());
        packet
    }

    fn transport(receiver_index: u32, len: usize) -> Vec<u8> {
        let mut packet = vec![0u8; len];
        packet[0] = 4;
        packet[4..8].copy_from_slice(&receiver_index.to_le_bytes());
        packet
    }

    fn cookie_reply(receiver_index: u32) -> Vec<u8> {
        let mut packet = vec![0u8; 64];
        packet[0] = 3;
        packet[4..8].copy_from_slice(&receiver_index.to_le_bytes());
        packet
    }

    /// A relay serving A and B on one slot each, with A<->B assigned and both keys known.
    fn paired() -> crate::RelayTable {
        let mut table = crate::RelayTable::default();
        table.assign_slot(A, SLOT_A);
        table.assign_slot(B, SLOT_B);
        table.assign_pair(A, B);
        table.keyset_mut().insert(A, key(1));
        table.keyset_mut().insert(B, key(2));
        table
    }

    /// A node opens its slot before there is any session: the real traffic is a keepalive whose
    /// `receiver_index` the relay may not know yet. The source is pinned either way, which is what
    /// lets the first handshake be carried.
    fn open_slot(table: &mut crate::RelayTable, slot: u16, source: Endpoint, at: Millis) {
        assert_eq!(
            table.route_one_port(slot, source, &transport(0xdead_beef, 32), at),
            Route::Drop(DropReason::UnknownDestination)
        );
    }

    fn delta(after: RelayCounters, before: RelayCounters) -> RelayCounters {
        RelayCounters {
            forwarded: after.forwarded - before.forwarded,
            bytes: after.bytes - before.bytes,
            rejected: after.rejected - before.rejected,
            dropped: after.dropped - before.dropped,
        }
    }

    #[test]
    fn mac1_picks_the_destination_out_of_the_keyset() {
        let mut keyset = Keyset::new();
        assert_eq!(keyset.insert(A, key(1)), None);
        assert_eq!(keyset.insert(B, key(2)), None);
        keyset.insert(C, key(3));
        assert_eq!(keyset.device_of(&key(2)), Some(B));
        assert_eq!(keyset.len(), 3);

        assert_eq!(
            keyset.destination_of(&handshake(MessageKind::Initiation, &key(2), 0x11)),
            Some(B)
        );
        assert_eq!(
            keyset.destination_of(&handshake(MessageKind::Response, &key(3), 0x11)),
            Some(C)
        );

        // a handshake addressed to a key the relay does not hold belongs to nobody
        assert_eq!(
            keyset.destination_of(&handshake(MessageKind::Initiation, &key(9), 0x11)),
            None
        );

        // a right-shaped handshake with a corrupted mac1 belongs to nobody either
        let mut corrupted = handshake(MessageKind::Initiation, &key(2), 0x11);
        corrupted[116] ^= 0x01;
        assert_eq!(keyset.destination_of(&corrupted), None);

        // and a transport packet never resolves through mac1
        assert_eq!(keyset.destination_of(&transport(0x11, 64)), None);
        assert_eq!(keyset.destination_of(&[]), None);
    }

    #[test]
    fn mac1_refuses_the_wrong_key_and_the_wrong_shape() {
        let derived = crate::mac1_key(&key(7));
        assert!(crate::verify_mac1(
            &handshake(MessageKind::Initiation, &key(7), 1),
            &derived
        ));
        // a response is verified against the initiator's key, and is 92 bytes, not 148
        assert!(crate::verify_mac1(
            &handshake(MessageKind::Response, &key(7), 1),
            &derived
        ));
        // the same packets against somebody else's key
        assert!(!crate::verify_mac1(
            &handshake(MessageKind::Initiation, &key(7), 1),
            &crate::mac1_key(&key(8))
        ));
        // wrong shape: not a handshake at all, too short for its type, empty
        assert!(!crate::verify_mac1(&transport(1, 64), &derived));
        assert!(!crate::verify_mac1(&cookie_reply(1), &derived));
        assert!(!crate::verify_mac1(&[1u8; 147], &derived));
        assert!(!crate::verify_mac1(&[2u8; 91], &derived));
        assert!(!crate::verify_mac1(&[], &derived));
        // right shape, mac1 nowhere near the key
        assert!(!crate::verify_mac1(&[1u8; 148], &derived));
    }

    #[test]
    fn every_message_type_maps_to_its_destination() {
        let mut table = paired();
        let at = Millis::from_secs(1);
        open_slot(&mut table, SLOT_A, ep(40001), at);
        open_slot(&mut table, SLOT_B, ep(40002), at);
        let base = table.counters();

        // type 1, the initiation: 148 bytes, destination from mac1 -- the responder's key
        assert_eq!(
            table.route_one_port(
                SLOT_A,
                ep(40001),
                &handshake(MessageKind::Initiation, &key(2), 0xaaaa),
                at
            ),
            Route::Forward {
                from: A,
                to: B,
                destination: ep(40002)
            }
        );
        // type 2, the response: 92 bytes, destination from mac1 -- the initiator's key
        assert_eq!(
            table.route_one_port(
                SLOT_B,
                ep(40002),
                &handshake(MessageKind::Response, &key(1), 0xbbbb),
                at
            ),
            Route::Forward {
                from: B,
                to: A,
                destination: ep(40001)
            }
        );
        // type 4, transport: destination from receiver_index -- B's index, going to B
        assert_eq!(
            table.route_one_port(SLOT_A, ep(40001), &transport(0xbbbb, 96), at),
            Route::Forward {
                from: A,
                to: B,
                destination: ep(40002)
            }
        );
        // ... and A's index, going back to A
        assert_eq!(
            table.route_one_port(SLOT_B, ep(40002), &transport(0xaaaa, 96), at),
            Route::Forward {
                from: B,
                to: A,
                destination: ep(40001)
            }
        );
        // type 3, a cookie reply, is addressed the way a transport packet is
        assert_eq!(
            table.route_one_port(SLOT_B, ep(40002), &cookie_reply(0xaaaa), at),
            Route::Forward {
                from: B,
                to: A,
                destination: ep(40001)
            }
        );

        // the smallest transport packet the spec allows still carries a full-length header
        assert_eq!(
            table.route_one_port(SLOT_A, ep(40001), &transport(0xbbbb, 32), at),
            Route::Forward {
                from: A,
                to: B,
                destination: ep(40002)
            }
        );

        let moved = delta(table.counters(), base);
        assert_eq!(moved.forwarded, 6);
        assert_eq!(moved.rejected, 0, "nothing was unaddressed");
    }

    #[test]
    fn a_session_index_is_learned_from_the_handshake_that_carries_it() {
        let mut table = paired();
        let at = Millis::from_secs(1);
        open_slot(&mut table, SLOT_A, ep(40001), at);
        open_slot(&mut table, SLOT_B, ep(40002), at);

        // before any handshake the relay knows no index at all
        assert!(table.sessions().is_empty());
        assert_eq!(
            table.route_one_port(SLOT_A, ep(40001), &transport(0xaaaa, 64), at),
            Route::Drop(DropReason::UnknownDestination)
        );

        table.route_one_port(
            SLOT_A,
            ep(40001),
            &handshake(MessageKind::Initiation, &key(2), 0xaaaa),
            at,
        );
        // the initiation taught the relay A's index, and says nothing about B's yet
        assert_eq!(
            table.sessions().entries().collect::<Vec<_>>(),
            vec![(0xaaaa, A)]
        );

        table.route_one_port(
            SLOT_B,
            ep(40002),
            &handshake(MessageKind::Response, &key(1), 0xbbbb),
            at,
        );
        assert_eq!(table.sessions().len(), 2);
        assert!(
            table
                .sessions()
                .entries()
                .any(|(index, device)| index == 0xbbbb && device == B)
        );
    }

    #[test]
    fn the_session_table_refreshes_itself_when_the_initiator_rekeys() {
        let mut table = SessionTable::default();
        let start = Millis::ZERO;
        assert_eq!(table.observe(0xaaaa, A, start), Observed::Recorded);

        // a rekey picks a fresh sender index; the old one stops naming anything
        let rekey = start.plus(REKEY_INTERVAL);
        assert_eq!(table.observe(0xbbbb, A, rekey), Observed::Recorded);
        assert_eq!(table.owner(0xaaaa, rekey), None);
        assert_eq!(table.owner(0xbbbb, rekey), Some(A));
        assert_eq!(table.len(), 1, "one device holds one index, not two");

        // and an index nobody refreshes ages out on its own
        let expiry = rekey.plus(SESSION_TTL);
        assert_eq!(
            table.owner(0xbbbb, expiry),
            Some(A),
            "still inside the window"
        );
        assert_eq!(
            table.owner(0xbbbb, expiry.plus(std::time::Duration::from_millis(1))),
            None
        );
        assert_eq!(table.len(), 0);
        assert_eq!(table.sweep(expiry), 0);
    }

    #[test]
    fn an_index_is_never_stolen_from_its_live_owner_but_may_be_reused_once_stale() {
        let mut table = SessionTable::default();
        assert_eq!(table.observe(0x1111, A, Millis::ZERO), Observed::Recorded);
        assert_eq!(
            table.observe(0x1111, B, Millis::from_secs(1)),
            Observed::Refused
        );
        assert_eq!(table.owner(0x1111, Millis::from_secs(2)), Some(A));

        let after_ttl = Millis::ZERO.plus(SESSION_TTL + std::time::Duration::from_secs(1));
        assert_eq!(table.observe(0x1111, B, after_ttl), Observed::Recorded);
        assert_eq!(
            table.owner(0x1111, after_ttl.plus(std::time::Duration::from_secs(1))),
            Some(B)
        );
    }

    #[test]
    fn the_session_table_holds_indices_and_device_ids_and_nothing_else() {
        let mut table = SessionTable::default();
        let at = Millis::from_secs(3);
        table.observe(0xdead_beef, A, at);
        table.observe(0xfeed_face, B, at);

        // Structural: an entry is an index, a device id and a timestamp. There is no field for a
        // key, and no room for one in the struct, so no key or plaintext can be stored here.
        assert_eq!(
            std::mem::size_of::<SessionEntry>(),
            std::mem::size_of::<u32>()
                + std::mem::size_of::<DeviceId>()
                + std::mem::size_of::<Millis>()
        );
        assert_eq!(
            SessionTable::ENTRY_BYTES,
            std::mem::size_of::<SessionEntry>()
        );
        const {
            assert!(
                SessionTable::ENTRY_BYTES < 32,
                "a 32-byte key could not fit in an entry"
            )
        };

        // Content: the whole table is expressible as (index, device) pairs, handed out by an API
        // that has no other shape to give.
        assert_eq!(
            table.entries().collect::<Vec<_>>(),
            vec![(0xdead_beef, A), (0xfeed_face, B)]
        );
        assert_eq!(table.len(), 2);
        assert_eq!(table.forget_device(A), 1);
        assert_eq!(table.entries().collect::<Vec<_>>(), vec![(0xfeed_face, B)]);
    }

    #[test]
    fn a_destination_outside_the_keyset_is_rejected_and_counted() {
        let mut table = paired();
        let at = Millis::from_secs(1);
        open_slot(&mut table, SLOT_A, ep(40001), at);
        open_slot(&mut table, SLOT_B, ep(40002), at);
        let base = table.counters();

        // a handshake whose mac1 matches no key in the keyset: no destination, dropped
        let outsider = handshake(MessageKind::Initiation, &key(9), 0x11);
        assert_eq!(
            table.route_one_port(SLOT_A, ep(40001), &outsider, at),
            Route::Drop(DropReason::UnknownDestination)
        );
        assert_eq!(delta(table.counters(), base).rejected, 1);

        // a transport packet naming an index nobody owns: dropped exactly the same way
        assert_eq!(
            table.route_one_port(SLOT_A, ep(40001), &transport(0xfeed, 64), at),
            Route::Drop(DropReason::UnknownDestination)
        );
        let moved = delta(table.counters(), base);
        assert_eq!(moved.rejected, 2);
        assert_eq!(moved.dropped, 2, "rejected packets are dropped packets too");
        assert_eq!(moved.forwarded, 0);
    }

    #[test]
    fn one_port_mode_still_forwards_only_assigned_pairs() {
        let mut table = paired();
        table.assign_slot(C, SLOT_C);
        table.keyset_mut().insert(C, key(3));
        let at = Millis::from_secs(1);
        open_slot(&mut table, SLOT_A, ep(40001), at);
        open_slot(&mut table, SLOT_B, ep(40002), at);
        open_slot(&mut table, SLOT_C, ep(40003), at);
        let base = table.counters();

        // the mac1 resolves perfectly well -- C is in the keyset -- and the packet still does not
        // move, because (A, C) is not an assigned pair
        assert_eq!(
            table.route_one_port(
                SLOT_A,
                ep(40001),
                &handshake(MessageKind::Initiation, &key(3), 0x11),
                at
            ),
            Route::Drop(DropReason::NotAssigned)
        );
        assert_eq!(delta(table.counters(), base).rejected, 0);
        assert_eq!(delta(table.counters(), base).dropped, 1);

        // and a packet that is not WireGuard-shaped never reaches the routing decision
        assert_eq!(
            table.route_one_port(SLOT_A, ep(40001), &[0u8; 64], at),
            Route::Drop(DropReason::Malformed)
        );
        assert_eq!(
            table.route_one_port(51999, ep(40001), &transport(0x22, 64), at),
            Route::Drop(DropReason::UnknownIngress)
        );
        let moved = delta(table.counters(), base);
        assert_eq!(moved.forwarded, 0);
        assert_eq!(moved.dropped, 3);
        assert_eq!(
            moved.rejected, 0,
            "none of these was an unknown destination tag"
        );
        assert!(table.sessions().is_empty(), "nothing learned from a drop");
    }

    #[test]
    fn nothing_is_learned_from_a_packet_that_is_not_carried() {
        let mut table = paired();
        table.assign_slot(C, SLOT_C);
        let at = Millis::from_secs(1);
        open_slot(&mut table, SLOT_A, ep(40001), at);
        open_slot(&mut table, SLOT_B, ep(40002), at);
        open_slot(&mut table, SLOT_C, ep(40003), at);
        assert!(table.sessions().is_empty());

        // C's handshake is addressed to A, which resolves -- and is still not carried, because
        // (C, A) is not an assigned pair. It leaves no index behind.
        let init = handshake(MessageKind::Initiation, &key(1), 0x33);
        assert_eq!(
            table.route_one_port(SLOT_C, ep(40003), &init, at),
            Route::Drop(DropReason::NotAssigned)
        );
        assert!(table.sessions().is_empty());
    }

    #[test]
    fn one_port_mode_refuses_a_slot_whose_source_moved() {
        let mut table = paired();
        let at = Millis::from_secs(1);
        open_slot(&mut table, SLOT_A, ep(40001), at);
        open_slot(&mut table, SLOT_B, ep(40002), at);
        let init = handshake(MessageKind::Initiation, &key(2), 0xaaaa);
        assert!(matches!(
            table.route_one_port(SLOT_A, ep(40001), &init, at),
            Route::Forward { .. }
        ));
        assert_eq!(
            table.route_one_port(SLOT_A, ep(40099), &init, Millis::from_secs(2)),
            Route::Drop(DropReason::SourceMoved)
        );
        // once the pin has gone stale the slot may be taken over by wherever it now comes from
        let revived = Millis::from_secs(2)
            .plus(crate::SOURCE_PIN_WINDOW + std::time::Duration::from_millis(1));
        assert_eq!(
            table.route_one_port(SLOT_A, ep(40099), &init, revived),
            Route::Forward {
                from: A,
                to: B,
                destination: ep(40002)
            }
        );
    }

    #[test]
    fn the_relay_decides_on_the_header_alone_and_never_adds_a_byte() {
        // The relay can read a packet's type and its two index fields and nothing else: past the
        // header is WireGuard ciphertext it has no key for. Two packets that differ only beyond
        // the header must therefore route identically, and what leaves must be exactly what
        // arrived -- no destination tag added, nothing stripped, no amplification.
        let mut table = paired();
        let at = Millis::from_secs(1);
        open_slot(&mut table, SLOT_A, ep(40001), at);
        open_slot(&mut table, SLOT_B, ep(40002), at);
        table.route_one_port(
            SLOT_B,
            ep(40002),
            &handshake(MessageKind::Response, &key(1), 0xbbbb),
            at,
        );
        let base = table.counters();

        let smallest = transport(0xbbbb, 32);
        let largest = transport(0xbbbb, 1400);
        assert_eq!(
            table.route_one_port(SLOT_A, ep(40001), &smallest, at),
            table.route_one_port(SLOT_A, ep(40001), &largest, at),
            "the decision must not depend on anything past the header"
        );

        let moved = delta(table.counters(), base);
        assert_eq!(moved.forwarded, 2);
        assert_eq!(moved.bytes, (32 + 1400) as u64, "byte for byte");
        assert_eq!(moved.rejected, 0);
    }
}
