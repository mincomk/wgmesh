use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use tokio::net::UdpSocket;

use crate::engine::{Handling, RelayEngine};

#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    #[error("binding a slot: {0}")]
    Bind(#[source] std::io::Error),
    #[error("the relay has no slot for port {0}")]
    UnknownSlot(u16),
}

/// A relay's sockets and the loop that drives them.
///
/// One socket per slot, because the port a packet arrives on is the sender's
/// identity and the port a reply leaves from is the one the peer's NAT will
/// accept. The decisions themselves live in `RelayEngine`; this layer only
/// moves bytes.
pub struct RelayNode {
    engine: Arc<Mutex<RelayEngine>>,
    sockets: BTreeMap<u16, Arc<UdpSocket>>,
}

impl RelayNode {
    pub fn new(engine: RelayEngine) -> Self {
        Self {
            engine: Arc::new(Mutex::new(engine)),
            sockets: BTreeMap::new(),
        }
    }

    pub fn engine(&self) -> MutexGuard<'_, RelayEngine> {
        self.engine
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn shared_engine(&self) -> Arc<Mutex<RelayEngine>> {
        Arc::clone(&self.engine)
    }

    pub fn ports(&self) -> Vec<u16> {
        self.sockets.keys().copied().collect()
    }

    /// Bind one slot socket per port on `listen`.
    pub async fn bind(
        &mut self,
        listen: IpAddr,
        ports: impl IntoIterator<Item = u16>,
    ) -> Result<(), RelayError> {
        for port in ports {
            let socket = UdpSocket::bind(SocketAddr::new(listen, port))
                .await
                .map_err(RelayError::Bind)?;
            self.sockets.insert(port, Arc::new(socket));
        }
        Ok(())
    }

    /// Bind `count` slot sockets to whatever free ports the kernel hands out,
    /// which is what a test wants; the ports come back so an assignment can be
    /// built around them.
    pub async fn bind_ephemeral(
        &mut self,
        listen: IpAddr,
        count: usize,
    ) -> Result<Vec<u16>, RelayError> {
        let mut ports = Vec::with_capacity(count);
        for _ in 0..count {
            let socket = UdpSocket::bind(SocketAddr::new(listen, 0))
                .await
                .map_err(RelayError::Bind)?;
            let port = socket.local_addr().map_err(RelayError::Bind)?.port();
            self.sockets.insert(port, Arc::new(socket));
            ports.push(port);
        }
        Ok(ports)
    }

    /// Read every slot socket until told to stop. A short read timeout keeps
    /// the shutdown flag meaningful without a cancellation token.
    pub async fn serve(self: Arc<Self>, shutdown: Arc<AtomicBool>) {
        let ports: Vec<u16> = self.sockets.keys().copied().collect();
        let mut tasks = Vec::with_capacity(ports.len());
        for port in ports {
            let node = Arc::clone(&self);
            let shutdown = Arc::clone(&shutdown);
            tasks.push(tokio::spawn(async move {
                let Some(socket) = node.sockets.get(&port).map(Arc::clone) else {
                    return;
                };
                let mut buffer = vec![0u8; 65_536];
                while !shutdown.load(Ordering::Relaxed) {
                    match tokio::time::timeout(
                        Duration::from_millis(200),
                        socket.recv_from(&mut buffer),
                    )
                    .await
                    {
                        Ok(Ok((len, source))) => {
                            let now = crate::now_ms();
                            let handling = node.engine().handle(port, source, &buffer[..len], now);
                            if let Handling::Forward {
                                destination,
                                via_port,
                                ..
                            } = handling
                            {
                                if let Some(out) = node.sockets.get(&via_port) {
                                    let _ = out.send_to(&buffer[..len], destination).await;
                                }
                            }
                        }
                        Ok(Err(error)) => {
                            tracing::warn!(port, %error, "slot socket read failed");
                        }
                        Err(_) => {}
                    }
                }
            }));
        }
        for task in tasks {
            let _ = task.await;
        }
    }
}
