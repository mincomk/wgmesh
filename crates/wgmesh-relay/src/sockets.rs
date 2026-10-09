use std::collections::BTreeMap;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket as StdUdpSocket};
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};

// The largest datagram a slot socket will read. Anything the kernel hands us beyond
// this is truncated, so the buffer is one datagram of headroom above any offload size.
pub const MAX_DATAGRAM: usize = 65_535;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Datagram {
    pub from: SocketAddr,
    pub payload: Vec<u8>,
}

// The one port that separates the engine's decision from the operating system's
// sockets. Tests bind 127.0.0.1; a deployed relay binds the real listen address. The
// engine never sees a file descriptor, so the whole forwarding path is testable
// without privileges.
pub trait SlotSockets: Send {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Bind a slot socket. A requested port of 0 asks the operating system to pick a
    /// free port; the port that actually got bound is returned either way and is the
    /// one the engine must use.
    fn bind(&mut self, port: u16) -> Result<u16, Self::Error>;
    fn close(&mut self, port: u16);
    fn ports(&self) -> Vec<u16>;
    fn recv(&mut self, port: u16) -> Result<Option<Datagram>, Self::Error>;
    fn send(&mut self, port: u16, to: SocketAddr, payload: &[u8]) -> Result<usize, Self::Error>;
    /// Wait until a slot may have a datagram ready, or `budget` elapses. This is the
    /// one place readiness lives, so an event-driven wait can replace it without the
    /// engine noticing.
    fn wait(&self, budget: Duration) -> impl Future<Output = ()> + Send;
}

pub struct UdpSlotSockets {
    listen: IpAddr,
    sockets: BTreeMap<u16, StdUdpSocket>,
    buffer: Vec<u8>,
}

impl UdpSlotSockets {
    pub fn new(listen: IpAddr) -> Self {
        Self {
            listen,
            sockets: BTreeMap::new(),
            buffer: vec![0_u8; MAX_DATAGRAM],
        }
    }

    pub fn listen(&self) -> IpAddr {
        self.listen
    }

    pub fn bound_ports(&self) -> Vec<u16> {
        self.sockets.keys().copied().collect()
    }
}

impl SlotSockets for UdpSlotSockets {
    type Error = io::Error;

    fn bind(&mut self, port: u16) -> Result<u16, Self::Error> {
        if port != 0 && self.sockets.contains_key(&port) {
            return Ok(port);
        }
        let domain = if self.listen.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
        // SO_REUSEADDR is never set on purpose: a slot port belongs to exactly one
        // device, so a second bind must fail loudly instead of silently sharing.
        socket.bind(&SocketAddr::new(self.listen, port).into())?;
        if self.listen.is_ipv6() {
            socket.set_only_v6(true)?;
        }
        socket.set_nonblocking(true)?;
        let socket: StdUdpSocket = socket.into();
        let bound = socket.local_addr()?.port();
        self.sockets.insert(bound, socket);
        Ok(bound)
    }

    fn close(&mut self, port: u16) {
        self.sockets.remove(&port);
    }

    fn ports(&self) -> Vec<u16> {
        self.sockets.keys().copied().collect()
    }

    fn recv(&mut self, port: u16) -> Result<Option<Datagram>, Self::Error> {
        let Some(socket) = self.sockets.get(&port) else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("port {port} is not bound"),
            ));
        };
        match socket.recv_from(&mut self.buffer) {
            Ok((length, from)) => Ok(Some(Datagram {
                from,
                payload: self.buffer[..length].to_vec(),
            })),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn send(&mut self, port: u16, to: SocketAddr, payload: &[u8]) -> Result<usize, Self::Error> {
        let Some(socket) = self.sockets.get(&port) else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("port {port} is not bound"),
            ));
        };
        socket.send_to(payload, to)
    }

    // The readiness seam. This build waits out the budget and re-reads the slots, which
    // costs one wake-up per `poll_budget` and needs nothing beyond tokio. An
    // `AsyncFd`/epoll wait replaces this body and nothing else when the relay is tuned.
    fn wait(&self, budget: Duration) -> impl Future<Output = ()> + Send {
        tokio::time::sleep(budget)
    }
}
