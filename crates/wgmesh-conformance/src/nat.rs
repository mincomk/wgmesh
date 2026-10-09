// A simulated NAPT.
//
// The behaviour that matters for hole punching is specified, not incidental, so
// it is implemented explicitly rather than approximated:
//
// * **mapping**: endpoint-independent (one external port per internal port, for
//   every destination -- `cone`, `restricted`) or endpoint-dependent (a fresh
//   external port per destination -- `symmetric`);
// * **filtering**: endpoint-independent (`cone`) or address/port-dependent
//   (`restricted`, `symmetric`), so an inbound packet is admitted only if the
//   internal host has already sent to that source port through this mapping;
// * a mapping idle timeout, so keep-alives matter.
//
// The host<->NAT links carry a 2-byte destination/source port header, exactly
// as the Python labs did: the inner host says where a datagram is going, and the
// NAT tells it which external port an arriving datagram came from.

use std::collections::{HashMap, HashSet};
use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::wire::loopback;

const POLL: Duration = Duration::from_millis(200);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NatMode {
    /// Endpoint-independent mapping, endpoint-independent filtering.
    Cone,
    /// Endpoint-independent mapping, address/port-dependent filtering.
    Restricted,
    /// Endpoint-dependent mapping (and filtering).
    Symmetric,
}

impl NatMode {
    pub fn label(self) -> &'static str {
        match self {
            Self::Cone => "cone",
            Self::Restricted => "restricted",
            Self::Symmetric => "symmetric",
        }
    }

    fn endpoint_independent_mapping(self) -> bool {
        !matches!(self, Self::Symmetric)
    }

    fn endpoint_independent_filtering(self) -> bool {
        matches!(self, Self::Cone)
    }
}

struct Mapping {
    /// The external-facing socket; its port is this mapping's public port.
    ext: UdpSocket,
    /// The internal host port this mapping belongs to.
    internal_port: u16,
    /// Destination ports the internal host has sent to through this mapping.
    allowed: Mutex<HashSet<u16>>,
    last: Mutex<Instant>,
    dead: AtomicBool,
}

type Mappings = Arc<Mutex<HashMap<(u16, u16), Arc<Mapping>>>>;

pub struct Nat {
    pub mode: NatMode,
    pub inner_port: u16,
    name: String,
    inner: Arc<UdpSocket>,
    mappings: Mappings,
    created: Arc<AtomicU64>,
    running: Arc<AtomicBool>,
    ttl: Duration,
}

impl Nat {
    pub fn start(name: impl Into<String>, mode: NatMode, ttl: Duration) -> Arc<Self> {
        let inner = Arc::new(UdpSocket::bind("127.0.0.1:0").expect("nat: bind inner socket"));
        inner
            .set_read_timeout(Some(POLL))
            .expect("nat: read timeout");
        let nat = Arc::new(Self {
            mode,
            inner_port: inner.local_addr().expect("nat: addr").port(),
            name: name.into(),
            inner,
            mappings: Arc::new(Mutex::new(HashMap::new())),
            created: Arc::new(AtomicU64::new(0)),
            running: Arc::new(AtomicBool::new(true)),
            ttl,
        });
        {
            let nat = Arc::clone(&nat);
            thread::spawn(move || nat.inner_loop());
        }
        {
            let nat = Arc::clone(&nat);
            thread::spawn(move || nat.sweeper());
        }
        nat
    }

    /// How many external mappings this NAT has had to create. One per internal
    /// port for an endpoint-independent mapping; one per destination for a
    /// symmetric one -- which is the structural reason a symmetric NAT cannot be
    /// punched.
    pub fn mappings_created(&self) -> u64 {
        self.created.load(Ordering::Relaxed)
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn shutdown(&self) {
        self.running.store(false, Ordering::Relaxed);
    }

    fn inner_loop(self: Arc<Self>) {
        let mut buffer = vec![0u8; 2048];
        while self.running.load(Ordering::Relaxed) {
            let (len, source) = match self.inner.recv_from(&mut buffer) {
                Ok(value) => value,
                Err(error) => match error.kind() {
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => continue,
                    _ => return,
                },
            };
            if len < 2 {
                continue;
            }
            let destination_port = u16::from_be_bytes([buffer[0], buffer[1]]);
            let payload = &buffer[2..len];
            let internal_port = source.port();
            let key = (
                internal_port,
                if self.mode.endpoint_independent_mapping() {
                    0
                } else {
                    destination_port
                },
            );

            let mapping = {
                let mut mappings = self.mappings.lock().unwrap();
                match mappings.get(&key) {
                    Some(existing) => Arc::clone(existing),
                    None => {
                        let ext = match UdpSocket::bind("127.0.0.1:0") {
                            Ok(socket) => socket,
                            Err(_) => continue,
                        };
                        ext.set_read_timeout(Some(POLL)).ok();
                        let mapping = Arc::new(Mapping {
                            ext,
                            internal_port,
                            allowed: Mutex::new(HashSet::new()),
                            last: Mutex::new(Instant::now()),
                            dead: AtomicBool::new(false),
                        });
                        mappings.insert(key, Arc::clone(&mapping));
                        self.created.fetch_add(1, Ordering::Relaxed);
                        let nat = Arc::clone(&self);
                        let outer = Arc::clone(&mapping);
                        thread::spawn(move || nat.outer_loop(outer));
                        mapping
                    }
                }
            };

            mapping.allowed.lock().unwrap().insert(destination_port);
            *mapping.last.lock().unwrap() = Instant::now();
            let _ = mapping.ext.send_to(payload, loopback(destination_port));
        }
    }

    fn outer_loop(self: Arc<Self>, mapping: Arc<Mapping>) {
        let mut buffer = vec![0u8; 2048];
        while self.running.load(Ordering::Relaxed) && !mapping.dead.load(Ordering::Relaxed) {
            let (len, source) = match mapping.ext.recv_from(&mut buffer) {
                Ok(value) => value,
                Err(error) => match error.kind() {
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => continue,
                    _ => return,
                },
            };
            let admitted = mapping.allowed.lock().unwrap().contains(&source.port());
            if !(self.mode.endpoint_independent_filtering() || admitted) {
                continue;
            }
            *mapping.last.lock().unwrap() = Instant::now();
            let mut frame = Vec::with_capacity(len + 2);
            frame.extend_from_slice(&source.port().to_be_bytes());
            frame.extend_from_slice(&buffer[..len]);
            let _ = self.inner.send_to(&frame, loopback(mapping.internal_port));
        }
    }

    fn sweeper(self: Arc<Self>) {
        while self.running.load(Ordering::Relaxed) {
            thread::sleep(POLL);
            let mut mappings = self.mappings.lock().unwrap();
            let ttl = self.ttl;
            mappings.retain(|_, mapping| {
                if mapping.last.lock().unwrap().elapsed() <= ttl {
                    return true;
                }
                mapping.dead.store(true, Ordering::Relaxed);
                false
            });
        }
    }
}

impl Drop for Nat {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
    }
}
