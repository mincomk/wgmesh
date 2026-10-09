#![allow(clippy::unwrap_used, clippy::expect_used)]

// Replay a **real** WireGuard capture through the one-port routing.
//
// `crates/wgmesh-relay/tests/one_port_udp.rs` drives the routing with buffers that carry a
// genuine `mac1` and zeros everywhere else: it proves the path a deployed relay runs, but it
// does not prove that the offsets and the `mac1` derivation are the ones WireGuard actually
// uses. This test closes that gap with bytes nobody in this repository produced.
//
// `tests/data/wg-handshake.pcap` was captured with `tcpdump` on this Computer while two
// WireGuard peers running boringtun 0.7.1 -- an independent implementation -- performed a
// genuine Noise_IKpsk2 handshake over loopback UDP and then sent traffic through it. Every
// datagram in that file is a real WireGuard message: type 1, 2, 3 and 4 are all present, and
// the last two are a separate exchange in which the responder, deliberately under load,
// answers an initiation whose `mac2` does not verify with a cookie reply.
//
// What is asserted here, all of it against those bytes:
//
// * the offsets the router reads: `sender_index` at 4, a response's `receiver_index` at 8,
//   a cookie reply's and a transport packet's `receiver_index` at 4, `mac1` in the first 16
//   bytes of the packet's last 32;
// * the direction of `mac1`: a handshake is keyed by the *recipient's* static public key,
//   whichever way round the handshake runs;
// * that `RelayTable::route_one_port` resolves the initiation through `mac1` and the traffic
//   that follows through an index learned from the handshake the relay carried.
//
// See `tests/data/README.md` for how the capture was taken and what it is not.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use wgmesh_relay::wgmesh_core::{
    DeviceId, DropReason, Endpoint, MessageKind, Millis, PublicKey, RelayTable, Route, classify,
    mac1_key, verify_mac1,
};

/// The capture. See `tests/data/README.md`.
const CAPTURE: &[u8] = include_bytes!("data/wg-handshake.pcap");

/// The static public keys of the two peers that produced the capture. A static public key is
/// never on the wire, so it cannot be read out of the file; both come from the run that wrote
/// it and are recorded in `tests/data/README.md`.
const INITIATOR_KEY: &str = "7b4e909bbe7ffe44c465a220037d608ee35897d31ef972f07f74892cb0f73f13";
const RESPONDER_KEY: &str = "0faa684ed28867b97f4a6a2dee5df8ce974e76b7018e3f22a1c4cf2678570f20";

/// The four slice ports the capture ran on: the first pair is the handshake that completes,
/// the second the exchange that produced a cookie reply.
const INITIATOR_PORT: u16 = 51901;
const RESPONDER_PORT: u16 = 51902;
const COOKIE_INITIATOR_PORT: u16 = 51903;
const COOKIE_RESPONDER_PORT: u16 = 51904;

const A: DeviceId = DeviceId(1);
const B: DeviceId = DeviceId(2);
const C: DeviceId = DeviceId(3);
const D: DeviceId = DeviceId(4);

const SLOT_A: u16 = 51901;
const SLOT_B: u16 = 51902;
const SLOT_C: u16 = 51903;
const SLOT_D: u16 = 51904;

// ---------------------------------------------------------------------------------------------
// The capture, and the little pcap reader this test needs.
//
// Deliberately not a dependency: a pcap file is a 24-byte header followed by
// `(16-byte record header, frame)` pairs, and the frames here are IPv4/UDP on a link layer this
// test knows how to step over. Thirty lines of it keep the repository's dependency list -- and
// so `cargo xtask check-deps` -- untouched.
// ---------------------------------------------------------------------------------------------

fn link_header_length(link_type: u32) -> usize {
    match link_type {
        1 => 14,   // LINKTYPE_ETHERNET
        101 => 0,  // LINKTYPE_RAW
        113 => 16, // LINKTYPE_LINUX_SLL
        other => panic!("unexpected link type {other}; the capture needs re-taking"),
    }
}

/// Every UDP payload in `capture`, in capture order.
fn udp_payloads(capture: &[u8]) -> Vec<Vec<u8>> {
    assert!(capture.len() > 24, "truncated pcap header");
    let magic = u32::from_le_bytes(capture[0..4].try_into().unwrap());
    assert!(
        magic == 0xa1b2_c3d4 || magic == 0xa1b2_3c4d,
        "not a little-endian pcap (magic {magic:#010x})"
    );
    let link_header = link_header_length(u32::from_le_bytes(capture[20..24].try_into().unwrap()));

    let mut payloads = Vec::new();
    let mut at = 24;
    while at + 16 <= capture.len() {
        let included = u32::from_le_bytes(capture[at + 8..at + 12].try_into().unwrap()) as usize;
        at += 16;
        let frame = &capture[at..at + included];
        at += included;

        let Some(ip) = frame.get(link_header..) else {
            continue;
        };
        if ip.len() < 20 || ip[0] >> 4 != 4 || ip[9] != 17 {
            continue; // not IPv4, or not UDP
        }
        let header = (ip[0] as usize & 0x0f) * 4;
        let total = u16::from_be_bytes([ip[2], ip[3]]) as usize;
        let Some(payload) = ip.get(header + 8..total.min(ip.len())) else {
            continue;
        };
        payloads.push(payload.to_vec());
    }
    payloads
}

fn public_key(hex: &str) -> PublicKey {
    let mut bytes = [0_u8; 32];
    for (slot, pair) in bytes.iter_mut().zip(hex.as_bytes().chunks(2)) {
        *slot = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap();
    }
    PublicKey::from_bytes(bytes)
}

fn initiator() -> PublicKey {
    public_key(INITIATOR_KEY)
}

fn responder() -> PublicKey {
    public_key(RESPONDER_KEY)
}

fn index_at(packet: &[u8], offset: usize) -> u32 {
    let bytes = &packet[offset..offset + 4];
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

/// The datagrams of the capture, in order, as WireGuard messages.
fn capture() -> Vec<Vec<u8>> {
    let datagrams = udp_payloads(CAPTURE);
    assert!(!datagrams.is_empty(), "the capture holds no UDP payload");
    datagrams
}

/// Every message of `kind` (the message type byte: 1, 2, 3 or 4).
fn of_kind(datagrams: &[Vec<u8>], kind: MessageKind) -> Vec<&Vec<u8>> {
    datagrams
        .iter()
        .filter(|packet| classify(packet) == Some(kind))
        .collect()
}

fn first_of_kind(datagrams: &[Vec<u8>], kind: MessageKind) -> Vec<u8> {
    of_kind(datagrams, kind)
        .first()
        .unwrap_or_else(|| panic!("the capture holds no {kind:?}"))
        .to_vec()
}

/// A 32-byte transport packet naming an index nobody owns. It is used only to let the relay
/// learn a slot's source address, which is as much as the relay requires before it will carry
/// anything from that slot -- every real packet in this test was captured, this one only opens
/// the session-table-less path the way an arrival from that peer would.
fn open_slot(table: &mut RelayTable, slot: u16, source: Endpoint, at: Millis) {
    let mut packet = vec![0_u8; 32];
    packet[0] = 4;
    packet[4..8].copy_from_slice(&0xdead_beef_u32.to_le_bytes());
    assert_eq!(
        table.route_one_port(slot, source, &packet, at),
        Route::Drop(DropReason::UnknownDestination)
    );
}

fn endpoint(port: u16) -> Endpoint {
    Endpoint::new(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port))
}

// ---------------------------------------------------------------------------------------------

/// The capture holds a whole exchange: both handshake messages, the traffic after them, and a
/// cookie reply.
#[test]
fn the_capture_holds_a_real_handshake_and_the_traffic_after_it() {
    let datagrams = capture();
    let kinds: Vec<MessageKind> = datagrams.iter().map(|p| classify(p).unwrap()).collect();

    assert_eq!(
        kinds,
        vec![
            MessageKind::Initiation,
            MessageKind::Response,
            MessageKind::Transport,
            MessageKind::Transport,
            MessageKind::Transport,
            MessageKind::Initiation,
            MessageKind::CookieReply,
        ],
        "the capture is not the exchange this test describes; re-read tests/data/README.md"
    );
    assert_eq!(datagrams[0].len(), 148, "an initiation is 148 bytes");
    assert_eq!(datagrams[1].len(), 92, "a response is 92 bytes");
    assert_eq!(datagrams[6].len(), 64, "a cookie reply is 64 bytes");
}

/// The offsets, read out of the capture's own bytes, are the ones `router.rs` reads: a sender
/// index at 4, a response's receiver index at 8, every other index at 4.
#[test]
fn the_offsets_read_out_of_the_capture_are_the_ones_the_router_reads() {
    let datagrams = capture();
    let initiation = first_of_kind(&datagrams, MessageKind::Initiation);
    let response = first_of_kind(&datagrams, MessageKind::Response);
    let cookie = first_of_kind(&datagrams, MessageKind::CookieReply);
    let transport = first_of_kind(&datagrams, MessageKind::Transport);

    // The header is a 4-byte type (little-endian, so the type byte first) followed by three
    // reserved zero bytes -- on every message type.
    for packet in [&initiation, &response, &cookie, &transport] {
        assert_eq!(
            &packet[1..4],
            &[0, 0, 0],
            "the reserved bytes of the header are zero"
        );
    }

    // Type 1: an initiation carries the index the initiator chose, at offset 4, and no
    // receiver index anywhere.
    let initiator_index = index_at(&initiation, 4);

    // Type 2: a response carries the responder's own index at offset 4 and the *initiator's*
    // index -- the one it is answering -- at offset 8.
    let responder_index = index_at(&response, 4);
    assert_ne!(
        responder_index, initiator_index,
        "the two peers must not have landed on the same index, or this proves nothing"
    );
    assert_eq!(
        index_at(&response, 8),
        initiator_index,
        "a response names the initiator it answers at offset 8"
    );

    // Type 4: traffic addresses the responder by the index the response named at offset 4.
    assert_eq!(
        index_at(&transport, 4),
        responder_index,
        "a transport packet names its recipient at offset 4"
    );
    assert!(
        transport.len() >= 32,
        "a transport packet is at least 32 bytes"
    );

    // Type 3: the cookie reply is addressed to the initiator of the *second* initiation, so
    // the index it carries at offset 4 is that second handshake's, not the first one's.
    let second_initiation = of_kind(&datagrams, MessageKind::Initiation)[1].clone();
    assert_eq!(
        index_at(&cookie, 4),
        index_at(&second_initiation, 4),
        "a cookie reply names the initiator it is for at offset 4"
    );
    assert_ne!(
        index_at(&cookie, 4),
        initiator_index,
        "the two exchanges used different indices, which is why the cookie proves nothing about \
         the first handshake"
    );
}

/// `mac1` is keyed by the **recipient's** static public key, in both directions, and it is the
/// 16 bytes at the start of the packet's last 32 -- the same derivation `wgmesh-core` verifies
/// with. Nothing but a real implementation's output can settle this.
#[test]
fn the_real_mac1_is_keyed_by_the_recipient() {
    let datagrams = capture();
    let initiation = first_of_kind(&datagrams, MessageKind::Initiation);
    let response = first_of_kind(&datagrams, MessageKind::Response);

    // An initiation goes to the responder, so its mac1 answers to the responder's key.
    assert!(
        verify_mac1(&initiation, &mac1_key(&responder())),
        "the captured initiation's mac1 is not the responder's"
    );
    assert!(
        !verify_mac1(&initiation, &mac1_key(&initiator())),
        "the captured initiation's mac1 must not answer to the initiator's key"
    );

    // A response goes back to the initiator, so its mac1 answers to the initiator's key.
    assert!(
        verify_mac1(&response, &mac1_key(&initiator())),
        "the captured response's mac1 is not the initiator's"
    );
    assert!(
        !verify_mac1(&response, &mac1_key(&responder())),
        "the captured response's mac1 must not answer to the responder's key"
    );

    // mac1 covers everything before the packet's last 32 bytes, and it is the first 16 of
    // those 32: the byte just before it is covered, and its own first byte is not.
    let mut covered = initiation.clone();
    let before_mac1 = covered.len() - 33;
    covered[before_mac1] ^= 0x01;
    assert!(
        !verify_mac1(&covered, &mac1_key(&responder())),
        "mac1 must cover the byte before it"
    );
    let mut mac2 = initiation.clone();
    let first_byte_of_mac2 = mac2.len() - 16;
    mac2[first_byte_of_mac2] ^= 0x01; // the first byte of mac2, past mac1
    assert!(
        verify_mac1(&mac2, &mac1_key(&responder())),
        "mac1 must not cover mac2"
    );
}

/// Every datagram of the first exchange routes to the right peer: the initiation by `mac1`, the
/// response by `mac1`, and the traffic after them by the index the response taught the relay.
#[test]
fn the_captured_packets_route_to_the_right_peer() {
    let datagrams = capture();
    let at = Millis(0);

    let mut table = RelayTable::default();
    table.assign_slot(A, SLOT_A);
    table.assign_slot(B, SLOT_B);
    table.assign_pair(A, B);
    table.keyset_mut().insert(A, initiator());
    table.keyset_mut().insert(B, responder());

    // Both peers have been heard from, so the relay knows where each slot lives.
    open_slot(&mut table, SLOT_A, endpoint(INITIATOR_PORT), at);
    open_slot(&mut table, SLOT_B, endpoint(RESPONDER_PORT), at);
    assert!(
        table.sessions().is_empty(),
        "opening a slot teaches nothing"
    );

    // 1. The initiation, from the initiator's slot: its destination is the responder, and the
    //    only thing that says so is the mac1 the responder's key verifies.
    assert_eq!(
        table.route_one_port(SLOT_A, endpoint(INITIATOR_PORT), &datagrams[0], at),
        Route::Forward {
            from: A,
            to: B,
            destination: endpoint(RESPONDER_PORT),
        },
        "a real initiation must route on its mac1"
    );
    assert_eq!(
        table.sessions().len(),
        1,
        "carrying the initiation taught the relay the initiator's index"
    );

    // 2. The response, back the other way, also on mac1 -- keyed by the initiator this time.
    //    Carrying it is what teaches the relay the responder's own index.
    assert_eq!(
        table.route_one_port(SLOT_B, endpoint(RESPONDER_PORT), &datagrams[1], at),
        Route::Forward {
            from: B,
            to: A,
            destination: endpoint(INITIATOR_PORT),
        },
        "a real response must route on its mac1"
    );
    assert_eq!(
        table.sessions().len(),
        2,
        "the relay learned an index from each handshake it carried -- the initiator's from the \
         initiation and the responder's from the response -- and it is the second of those that \
         the traffic below is resolved through"
    );

    // 3. The traffic after the handshake: no mac1, no key -- the receiver_index the response
    //    named, read by the relay and resolved through what it learned in step 2.
    for transport in &datagrams[2..5] {
        assert_eq!(
            table.route_one_port(SLOT_A, endpoint(INITIATOR_PORT), transport, at),
            Route::Forward {
                from: A,
                to: B,
                destination: endpoint(RESPONDER_PORT),
            },
            "real transport traffic must route on the receiver_index the handshake taught"
        );
    }
    assert_eq!(table.counters().forwarded, 5);
    assert_eq!(table.counters().rejected, 2, "the two slot-opening packets");
}

/// The second exchange: under load the responder answered with a cookie reply, and that cookie
/// reply routes too -- through the same `receiver_index` path, learned from the initiation the
/// relay carried a moment earlier.
#[test]
fn the_captured_cookie_reply_routes_on_the_initiation_that_came_before_it() {
    let datagrams = capture();
    let at = Millis(0);
    let initiation = &datagrams[5];
    let cookie = &datagrams[6];

    let mut table = RelayTable::default();
    table.assign_slot(C, SLOT_C);
    table.assign_slot(D, SLOT_D);
    table.assign_pair(C, D);
    table.keyset_mut().insert(C, initiator());
    table.keyset_mut().insert(D, responder());

    open_slot(&mut table, SLOT_C, endpoint(COOKIE_INITIATOR_PORT), at);
    open_slot(&mut table, SLOT_D, endpoint(COOKIE_RESPONDER_PORT), at);

    assert_eq!(
        table.route_one_port(SLOT_C, endpoint(COOKIE_INITIATOR_PORT), initiation, at),
        Route::Forward {
            from: C,
            to: D,
            destination: endpoint(COOKIE_RESPONDER_PORT),
        },
        "the second real initiation routes on its mac1 as well"
    );
    assert_eq!(
        table.route_one_port(SLOT_D, endpoint(COOKIE_RESPONDER_PORT), cookie, at),
        Route::Forward {
            from: D,
            to: C,
            destination: endpoint(COOKIE_INITIATOR_PORT),
        },
        "a real cookie reply routes on the receiver_index of the initiation it answers"
    );
}

/// The routing is not indifferent to the bytes: corrupting one bit of a real initiation's mac1
/// makes the same table drop it, which is what says the checks above are reading the field and
/// not just agreeing with themselves.
#[test]
fn a_real_packet_with_one_bit_changed_in_its_mac1_is_dropped() {
    let datagrams = capture();
    let at = Millis(0);

    let mut table = RelayTable::default();
    table.assign_slot(A, SLOT_A);
    table.assign_slot(B, SLOT_B);
    table.assign_pair(A, B);
    table.keyset_mut().insert(A, initiator());
    table.keyset_mut().insert(B, responder());
    open_slot(&mut table, SLOT_A, endpoint(INITIATOR_PORT), at);
    open_slot(&mut table, SLOT_B, endpoint(RESPONDER_PORT), at);

    let mut initiation = datagrams[0].clone();
    let first_byte_of_mac1 = initiation.len() - 32;
    initiation[first_byte_of_mac1] ^= 0x80; // the top bit of mac1's first byte

    assert_eq!(
        table.route_one_port(SLOT_A, endpoint(INITIATOR_PORT), &initiation, at),
        Route::Drop(DropReason::UnknownDestination)
    );
    assert_eq!(table.counters().forwarded, 0);
}
