// # wgmesh-relay
//
// The relay's data plane. A relay is a UDP forwarder that never decrypts
// anything: a packet arriving on a device's **slot** is a packet *from* that
// device, and it is re-sent from the **destination's** slot socket, so every
// node always sees its peer at exactly the address it is configured to send
// to.
//
// Two checks decide whether a packet is forwarded, and both are the M0
// versions of the real ones:
//
// * the 2-byte destination tag in front of the packet stands in for the
//   destination the real relay derives from an initiation's `mac1` (or a
//   transport packet's `receiver_index`);
// * the packet's `mac1` is verified against the destination's public key --
//   the relay's keyset. A packet whose mac1 does not belong to the device it
//   claims is dropped. Transport packets carry no mac1 and are covered by the
//   slot's own source pinning instead.
//
// Every accepted packet also teaches the relay the source address of the
// device that sent it, which is what the coordinator distributes as the
// candidate the two ends punch at.

use std::collections::BTreeMap;
use std::io::Write;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::control::{
    DeviceKey, Observation, RelayDirective, RelayHeartbeat, RelayStats, SlotReport,
};
use wgmesh_core::{
    DeviceId, Endpoint, MessageKind, Millis, PublicKey, RelayTable, Route, classify, mac1_key,
    verify_mac1,
};

/// WireGuard's smallest legal message (a transport packet).
const MIN_WG_PACKET: usize = 32;

struct Slot {
    socket: Arc<UdpSocket>,
    port: u16,
}

pub struct RelayEngine {
    id: String,
    started: Instant,
    table: Mutex<RelayTable>,
    slots: Mutex<BTreeMap<u32, Arc<Slot>>>,
    keys: Mutex<BTreeMap<u32, [u8; 32]>>,
    observations: Mutex<BTreeMap<u32, SocketAddr>>,
    forwarded: AtomicU64,
    dropped: AtomicU64,
    running: Mutex<bool>,
}

impl RelayEngine {
    pub fn new(id: impl Into<String>) -> Arc<Self> {
        Arc::new(Self {
            id: id.into(),
            started: Instant::now(),
            table: Mutex::new(RelayTable::default()),
            slots: Mutex::new(BTreeMap::new()),
            keys: Mutex::new(BTreeMap::new()),
            observations: Mutex::new(BTreeMap::new()),
            forwarded: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            running: Mutex::new(true),
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    /// Take on the devices and pairs the coordinator says are ours. A slot is
    /// opened for each device the first time we hear about it.
    pub fn apply_directive(self: &Arc<Self>, directive: &RelayDirective) {
        for DeviceKey { device, public_key } in &directive.devices {
            let key = crate::control::decode32(public_key).unwrap_or([0u8; 32]);
            self.ensure_slot(*device, key);
        }
        let mut table = self.table.lock().unwrap();
        for pair in &directive.pairs {
            table.assign_pair(DeviceId(pair.a), DeviceId(pair.b));
        }
    }

    fn ensure_slot(self: &Arc<Self>, device: u32, public_key: [u8; 32]) {
        self.keys.lock().unwrap().insert(device, public_key);
        let mut slots = self.slots.lock().unwrap();
        if slots.contains_key(&device) {
            return;
        }
        let socket = match UdpSocket::bind("127.0.0.1:0") {
            Ok(socket) => socket,
            Err(error) => {
                eprintln!("relayd {}: slot for device {device}: {error}", self.id);
                return;
            }
        };
        socket
            .set_read_timeout(Some(Duration::from_millis(200)))
            .ok();
        let port = socket.local_addr().map(|addr| addr.port()).unwrap_or(0);
        let socket = Arc::new(socket);
        slots.insert(
            device,
            Arc::new(Slot {
                socket: Arc::clone(&socket),
                port,
            }),
        );
        drop(slots);
        self.table
            .lock()
            .unwrap()
            .assign_slot(DeviceId(device), port);
        let engine = Arc::clone(self);
        thread::spawn(move || engine.slot_loop(device, port, socket));
    }

    fn slot_loop(self: Arc<Self>, device: u32, port: u16, socket: Arc<UdpSocket>) {
        let mut buffer = vec![0u8; 2048];
        loop {
            if !*self.running.lock().unwrap() {
                return;
            }
            match socket.recv_from(&mut buffer) {
                Ok((len, source)) => self.handle(device, port, &buffer[..len], source),
                Err(error) => match error.kind() {
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => continue,
                    _ => return,
                },
            }
        }
    }

    fn handle(self: &Arc<Self>, ingress: u32, ingress_port: u16, frame: &[u8], source: SocketAddr) {
        if frame.len() < 2 + MIN_WG_PACKET {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let destination = u16::from_be_bytes([frame[0], frame[1]]) as u32;
        let body = &frame[2..];
        let Some(kind) = classify(body) else {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        };

        // Every accepted packet teaches the relay where this device currently is.
        {
            let mut observations = self.observations.lock().unwrap();
            if observations.get(&ingress) != Some(&source) {
                observations.insert(ingress, source);
            }
        }

        let at = Millis::from_millis(self.started.elapsed().as_millis() as u64);
        let route = self.table.lock().unwrap().route(
            ingress_port,
            Endpoint::new(source),
            DeviceId(destination),
            body,
            at,
        );
        let Route::Forward {
            destination: target,
            ..
        } = route
        else {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        };

        // The keyset check: an initiation or response must be signed for the
        // device it claims to be going to.
        if !matches!(kind, MessageKind::Transport) {
            let key = self.keys.lock().unwrap().get(&destination).copied();
            let ok = key
                .map(|key| verify_mac1(body, &mac1_key(&PublicKey::from_bytes(key))))
                .unwrap_or(false);
            if !ok {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }

        let slot = self.slots.lock().unwrap().get(&destination).map(Arc::clone);
        let Some(slot) = slot else {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        };
        if slot.socket.send_to(body, target.addr()).is_ok() {
            self.forwarded.fetch_add(1, Ordering::Relaxed);
        } else {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn slot_reports(&self) -> Vec<SlotReport> {
        self.slots
            .lock()
            .unwrap()
            .iter()
            .map(|(device, slot)| SlotReport {
                device: *device,
                port: slot.port,
            })
            .collect()
    }

    pub fn observation_reports(&self) -> Vec<Observation> {
        self.observations
            .lock()
            .unwrap()
            .iter()
            .map(|(device, addr)| Observation {
                device: *device,
                addr: addr.to_string(),
            })
            .collect()
    }

    pub fn stats(&self) -> RelayStats {
        RelayStats {
            forwarded: self.forwarded.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
        }
    }

    pub fn shutdown(&self) {
        *self.running.lock().unwrap() = false;
    }
}

// ------------------------------------------------------------------ process --

// The relay as a process: open slots as the coordinator hands out devices, poll
// it with a heartbeat, and forward.
pub fn run() {
    let mut id = "relay".to_string();
    let mut coordinator = "http://127.0.0.1:8080".to_string();
    let mut heartbeat = Duration::from_millis(300);
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--id" => {
                if let Some(value) = args.next() {
                    id = value;
                }
            }
            "--coordinator" => {
                if let Some(value) = args.next() {
                    coordinator = value;
                }
            }
            "--heartbeat-ms" => {
                if let Some(value) = args.next().and_then(|value| value.parse::<u64>().ok()) {
                    heartbeat = Duration::from_millis(value.max(20));
                }
            }
            _ => {}
        }
    }

    let url = format!("{coordinator}/v1/relays/heartbeat");
    let engine = RelayEngine::new(id.clone());
    let mut announced = false;
    let mut failures = 0u32;

    loop {
        let message = RelayHeartbeat {
            id: id.clone(),
            slots: engine.slot_reports(),
            observations: engine.observation_reports(),
            stats: engine.stats(),
        };
        match crate::control::post_json::<_, RelayDirective>(&url, &message) {
            Ok(directive) => {
                engine.apply_directive(&directive);
                if !announced {
                    println!("lab-relayd ready id={id}");
                    std::io::stdout().flush().ok();
                    announced = true;
                }
                failures = 0;
            }
            Err(error) => {
                failures += 1;
                if failures == 1 || failures % 20 == 0 {
                    eprintln!("lab-relayd {id}: coordinator {url}: {error}");
                }
            }
        }
        thread::sleep(heartbeat);
    }
}
