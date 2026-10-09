// WireGuard-shaped packets for the lab.
//
// The lab's stand-in devices speak packets that have WireGuard's *shape*
// (type byte, minimum length, `mac1` in the last 32 bytes where the real
// message has it) so that `wgmesh-core`'s `classify` and `verify_mac1` -- the
// functions the relay and the agent both run -- are exercised for real. The
// bytes in between are a nonce and a pattern, not a Noise handshake.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use blake2::Blake2sMac;
use blake2::digest::consts::U16;
use blake2::digest::{KeyInit, Mac, Update};
use wgmesh_core::{MessageKind, PublicKey, mac1_key};

/// Same construction as `wgmesh-core`, reused here so the lab can *sign* what
/// the relay and the agents *verify*.
pub type Mac1 = Blake2sMac<U16>;

pub fn loopback(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port)
}

pub fn packet_len(kind: MessageKind) -> usize {
    match kind {
        MessageKind::Initiation => 148,
        MessageKind::Response => 92,
        MessageKind::CookieReply => 64,
        MessageKind::Transport => 64,
    }
}

fn type_byte(kind: MessageKind) -> u8 {
    match kind {
        MessageKind::Initiation => 1,
        MessageKind::Response => 2,
        MessageKind::CookieReply => 3,
        MessageKind::Transport => 4,
    }
}

/// Build a packet addressed to whoever holds `signer`'s public key.
///
/// `mac1` is keyed by the *recipient*: the responder's key for an initiation and
/// the initiator's key for a response. Both cases are "the public key of the
/// device this packet is for", which is what the relay verifies against.
pub fn build(kind: MessageKind, signer: &PublicKey, nonce: u64, seed: u8) -> Vec<u8> {
    let len = packet_len(kind);
    let mut packet = vec![0u8; len];
    packet[0] = type_byte(kind);
    for (index, byte) in packet[1..len - 32].iter_mut().enumerate() {
        *byte = seed.wrapping_add(index as u8);
    }
    packet[1..9].copy_from_slice(&nonce.to_be_bytes());
    if matches!(kind, MessageKind::Initiation | MessageKind::Response) {
        let key = mac1_key(signer);
        let mut mac = <Mac1 as KeyInit>::new_from_slice(&key).expect("mac1 key is 32 bytes");
        Update::update(&mut mac, &packet[..len - 32]);
        packet[len - 32..len - 16].copy_from_slice(&mac.finalize().into_bytes());
    }
    packet
}
