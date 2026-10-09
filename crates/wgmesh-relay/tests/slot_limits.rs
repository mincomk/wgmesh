#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use tokio::net::UdpSocket;

use wgmesh_proto::api::{AssignmentResponse, KeysetNetwork, PairBody, SlotBody};
use wgmesh_relay::{RelayEngine, RelayNode, SlotLimits};

const A: &str = "d_alpha";
const B: &str = "d_beta";

/// A relay carrying one pair over real loopback sockets, exactly as the
/// daemon does — so the limits are exercised on the path packets actually
/// take, not on a call that stands in for it.
struct Harness {
    node: Arc<RelayNode>,
    client_a: UdpSocket,
    client_b: UdpSocket,
    port_a: u16,
    port_b: u16,
    shutdown: Arc<AtomicBool>,
}

fn assignment(port_a: u16, port_b: u16) -> AssignmentResponse {
    AssignmentResponse {
        relay_id: "relay_test".to_owned(),
        endpoint_host: "127.0.0.1".to_owned(),
        slots: vec![
            SlotBody {
                device_id: A.to_owned(),
                udp_port: port_a,
            },
            SlotBody {
                device_id: B.to_owned(),
                udp_port: port_b,
            },
        ],
        pairs: vec![PairBody {
            a: A.to_owned(),
            b: B.to_owned(),
        }],
        networks: vec![KeysetNetwork {
            id: 1,
            name: "prod".to_owned(),
            peers: vec![],
        }],
    }
}

/// A packet of the shape a relay forwards: a WireGuard transport message.
fn packet(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    bytes[0] = 4;
    bytes
}

async fn start(limits: SlotLimits) -> Harness {
    let mut node = RelayNode::new(RelayEngine::new(limits));
    let ports = node
        .bind_ephemeral(IpAddr::V4(Ipv4Addr::LOCALHOST), 2)
        .await
        .expect("two slot sockets bind on loopback");
    let (port_a, port_b) = (ports[0], ports[1]);
    node.engine().apply(&assignment(port_a, port_b));
    let node = Arc::new(node);
    let shutdown = Arc::new(AtomicBool::new(false));
    tokio::spawn(Arc::clone(&node).serve(Arc::clone(&shutdown)));
    let client_a = UdpSocket::bind("127.0.0.1:0").await.expect("client A");
    let client_b = UdpSocket::bind("127.0.0.1:0").await.expect("client B");
    Harness {
        node,
        client_a,
        client_b,
        port_a,
        port_b,
        shutdown,
    }
}

impl Harness {
    /// Let the relay learn where each peer is, the way a keepalive does.
    ///
    /// It waits for evidence rather than for a duration: on a loaded machine
    /// the relay's tasks may not have run for a while, and a fixed sleep would
    /// make every test below fail for a reason that has nothing to do with what
    /// it is testing.
    async fn greet(&self) {
        let hello = packet(64);
        for _ in 0..100 {
            let _ = self
                .client_a
                .send_to(&hello, ("127.0.0.1", self.port_a))
                .await;
            let _ = self
                .client_b
                .send_to(&hello, ("127.0.0.1", self.port_b))
                .await;
            tokio::time::sleep(Duration::from_millis(50)).await;
            let pinned = {
                let engine = self.node.engine();
                engine.counters(self.port_a).tx_packets > 0
                    && engine.counters(self.port_b).tx_packets > 0
            };
            if pinned {
                break;
            }
        }
        let mut sink = [0u8; 2048];
        while self.client_b.try_recv_from(&mut sink).is_ok() {}
        while self.client_a.try_recv_from(&mut sink).is_ok() {}
    }

    /// Drain everything B receives within `window`.
    async fn collect_b(&self, window: Duration) -> usize {
        let deadline = tokio::time::Instant::now() + window;
        let mut buffer = [0u8; 2048];
        let mut received = 0;
        while tokio::time::Instant::now() < deadline {
            match tokio::time::timeout(
                Duration::from_millis(50),
                self.client_b.recv_from(&mut buffer),
            )
            .await
            {
                Ok(Ok(_)) => received += 1,
                Ok(Err(_)) => break,
                Err(_) => {}
            }
        }
        received
    }

    fn stop(&self) {
        self.shutdown
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_slots_packet_allowance_limits_delivery_and_the_overflow_is_counted() {
    let harness = start(SlotLimits::new(50, 10_000_000.0, 65_535)).await;
    harness.greet().await;

    let burst = packet(64);
    for _ in 0..400 {
        let _ = harness
            .client_a
            .send_to(&burst, ("127.0.0.1", harness.port_a))
            .await;
    }
    let received = harness.collect_b(Duration::from_secs(2)).await;

    let counters = harness.node.engine().counters(harness.port_a);
    assert!(
        received > 0,
        "the allowance should have let a burst through, not none of it"
    );
    assert!(
        received < 400,
        "the packet ceiling did not limit delivery: {received} of 400 arrived"
    );
    assert!(
        counters.throttled_packets > 0,
        "nothing was counted as throttled on a slot that was flooded"
    );
    assert!(
        counters.rx_packets >= 200,
        "the flood barely reached the relay: {} packets read on the slot",
        counters.rx_packets
    );
    // Every packet the relay read is accounted for exactly once. (Packets the
    // kernel dropped on the way in were never read, and are not the relay's to
    // count.)
    assert_eq!(
        counters.rx_packets,
        counters.tx_packets + counters.throttled_packets + counters.dropped_packets,
        "traffic is not accounted for: {} read, {} forwarded, {} throttled, {} dropped",
        counters.rx_packets,
        counters.tx_packets,
        counters.throttled_packets,
        counters.dropped_packets
    );
    assert!(
        received as u64 <= counters.tx_packets,
        "more packets arrived at the peer than the slot forwarded"
    );

    let metrics = harness.node.engine().render_metrics();
    let slot_label = format!("slot=\"{}\"", harness.port_a);
    assert!(
        metrics.contains(&slot_label),
        "the exposure does not mention the slot that was flooded"
    );
    assert!(metrics.contains("wgmesh_relay_slot_throttled_packets_total"));
    harness.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_slots_byte_allowance_limits_delivery_independently_of_the_packet_rate() {
    // A generous packet ceiling and a mean byte ceiling: 8 kB a second with
    // 1 kB packets means about eight get through, however many are sent.
    let harness = start(SlotLimits::new(100_000, 8_000.0, 65_535)).await;
    harness.greet().await;

    let burst = packet(1_000);
    for _ in 0..100 {
        let _ = harness
            .client_a
            .send_to(&burst, ("127.0.0.1", harness.port_a))
            .await;
    }
    let received = harness.collect_b(Duration::from_secs(2)).await;

    let counters = harness.node.engine().counters(harness.port_a);
    assert!(received > 0, "the byte allowance let nothing through");
    assert!(
        received < 40,
        "the byte ceiling did not limit delivery: {received} of 100 one-kilobyte packets arrived"
    );
    assert!(
        counters.throttled_packets > 0,
        "the byte ceiling refused packets without counting them"
    );
    assert!(
        counters.throttled_bytes >= 1_000,
        "throttled bytes should be reported, not just packets"
    );
    harness.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_oversized_packet_is_refused_without_spending_the_slots_allowance() {
    let harness = start(SlotLimits::new(50, 10_000_000.0, 1_500)).await;
    harness.greet().await;

    let before = harness.node.engine().counters(harness.port_a);
    let huge = packet(4_000);
    let _ = harness
        .client_a
        .send_to(&huge, ("127.0.0.1", harness.port_a))
        .await;
    tokio::time::sleep(Duration::from_millis(150)).await;
    let counting = harness.node.engine().counters(harness.port_a);
    assert_eq!(
        counting.dropped_packets,
        before.dropped_packets + 1,
        "an oversized packet should be dropped, and counted once"
    );
    assert_eq!(
        counting.throttled_packets, before.throttled_packets,
        "an oversized packet must not be charged to the rate limiter"
    );

    // The allowance is untouched, so a normal packet still gets through.
    let normal = packet(64);
    for _ in 0..10 {
        let _ = harness
            .client_a
            .send_to(&normal, ("127.0.0.1", harness.port_a))
            .await;
    }
    let received = harness.collect_b(Duration::from_secs(2)).await;
    assert_eq!(
        received, 10,
        "an oversized packet cost the slot its allowance"
    );
    harness.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_packet_from_an_unassigned_port_is_dropped_rather_than_forwarded() {
    let harness = start(SlotLimits::new(50, 10_000_000.0, 65_535)).await;
    harness.greet().await;

    let stranger = UdpSocket::bind("127.0.0.1:0").await.expect("stranger");
    let packet = packet(64);
    // A port that belongs to no slot at all.
    let _ = stranger
        .send_to(&packet, ("127.0.0.1", harness.port_a + 1))
        .await;
    // And a real slot, but in the wrong direction: the relay has no pair for
    // this source, so there is nowhere for it to go.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let received = harness.collect_b(Duration::from_secs(1)).await;
    assert_eq!(received, 0);
    harness.stop();
}
