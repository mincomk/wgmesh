// The kernel WireGuard driver: rtnetlink brings the link up, the generic
// netlink `wireguard` family carries the peer configuration.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::sync::{Mutex, MutexGuard};

use futures_util::StreamExt;
use nl_wireguard::WireguardParsed;
use rtnetlink::{LinkUnspec, LinkWireguard};
use wgmesh_core::{Change, DeviceId, Endpoint, Millis, PublicKey};
use wgmesh_ports::{PeerStatus, WireGuard, WireGuardError};

use crate::InterfaceSpec;
use crate::attrs::{device_config, device_properties, peer_op};
use crate::base64;
use crate::runtime::NetlinkRuntime;

/// The byte counters the kernel keeps per peer.
///
/// `wgmesh_ports::PeerStatus` carries the liveness signal the traversal needs
/// and nothing else, so the counters — which are diagnostics rather than state
/// — are read through this type instead of widening the shared port.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PeerCounters {
    /// The device this counter belongs to.
    pub peer: DeviceId,
    /// Bytes received from the peer since the interface came up.
    pub rx_bytes: u64,
    /// Bytes sent to the peer since the interface came up.
    pub tx_bytes: u64,
}

/// The driver of one WireGuard interface.
///
/// The interface is created with `rtnetlink` first — `nl-wireguard` only
/// configures an interface that already exists — and the WireGuard properties
/// are then written through the generic netlink `wireguard` family.
pub struct NetlinkWireGuard {
    ifname: String,
    runtime: NetlinkRuntime,
    /// The device ids this driver has written, and the public key each one was
    /// written under. `Change::Remove` carries only the id, so the driver has
    /// to remember the key that names the peer to the kernel.
    known: Mutex<BTreeMap<DeviceId, PublicKey>>,
}

impl NetlinkWireGuard {
    /// A driver for `ifname`.
    pub fn new(ifname: impl Into<String>) -> Self {
        Self {
            ifname: ifname.into(),
            runtime: NetlinkRuntime::new(),
            known: Mutex::new(BTreeMap::new()),
        }
    }

    /// The interface this driver programs.
    pub fn interface(&self) -> &str {
        &self.ifname
    }

    /// The device ids this driver can still resolve to a public key.
    pub fn known_peers(&self) -> BTreeMap<DeviceId, PublicKey> {
        self.known().clone()
    }

    /// Create the interface when it is missing, then set its MTU and the device
    /// level WireGuard properties.
    ///
    /// Calling it on an interface that already exists is not an error, so the
    /// agent can call it on every start.
    ///
    /// # Errors
    ///
    /// Returns [`WireGuardError::Netlink`] when the kernel refuses. On a host
    /// where the caller lacks `CAP_NET_ADMIN` every path here fails with
    /// `Operation not permitted`, which is the honest answer rather than a
    /// silent no-op.
    pub fn ensure_interface(&self, spec: &InterfaceSpec) -> Result<(), WireGuardError> {
        let spec = spec.clone();
        self.run(async move {
            let (connection, handle, _) = rtnetlink::new_connection()
                .map_err(|error| WireGuardError::Netlink(error.to_string()))?;
            tokio::spawn(connection);

            match link_index(&handle, &spec.name)
                .await
                .map_err(|error| WireGuardError::Netlink(error.to_string()))?
            {
                Some(index) => {
                    if let Some(mtu) = spec.mtu {
                        let message = LinkUnspec::new_with_index(index).mtu(mtu).build();
                        handle
                            .link()
                            .change(message)
                            .execute()
                            .await
                            .map_err(|error| WireGuardError::Netlink(error.to_string()))?;
                    }
                }
                None => {
                    let mut builder = LinkWireguard::new(&spec.name).up();
                    if let Some(mtu) = spec.mtu {
                        builder = builder.mtu(mtu);
                    }
                    handle
                        .link()
                        .add(builder.build())
                        .execute()
                        .await
                        .map_err(|error| WireGuardError::Netlink(error.to_string()))?;
                }
            }

            if spec.private_key.is_some() || spec.listen_port.is_some() {
                let config =
                    device_properties(&spec.name, spec.private_key.clone(), spec.listen_port);
                let (connection, mut handle, _) = nl_wireguard::new_connection()
                    .map_err(|error| WireGuardError::Netlink(error.to_string()))?;
                tokio::spawn(connection);
                handle
                    .set(config)
                    .await
                    .map_err(|error| WireGuardError::Netlink(error.to_string()))?;
            }
            Ok(())
        })
    }

    /// The byte counters of the named peers.
    ///
    /// # Errors
    ///
    /// The same failures as [`WireGuard::status`].
    pub fn counters(&self, peers: &[DeviceId]) -> Result<Vec<PeerCounters>, WireGuardError> {
        let device = self.device()?;
        let resolved = self.resolve(&device, peers);

        Ok(resolved
            .into_iter()
            .map(|(id, peer)| PeerCounters {
                peer: id,
                rx_bytes: peer.rx_bytes.unwrap_or(0),
                tx_bytes: peer.tx_bytes.unwrap_or(0),
            })
            .collect())
    }

    fn known(&self) -> MutexGuard<'_, BTreeMap<DeviceId, PublicKey>> {
        self.known
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn run<T>(
        &self,
        future: impl Future<Output = Result<T, WireGuardError>>,
    ) -> Result<T, WireGuardError> {
        match self.runtime.block_on(future) {
            Ok(result) => result,
            Err(error) => Err(WireGuardError::Unsupported(error.to_string())),
        }
    }

    /// Read the whole device back out of the kernel.
    fn device(&self) -> Result<WireguardParsed, WireGuardError> {
        let ifname = self.ifname.clone();
        self.run(async move {
            let (connection, mut handle, _) = nl_wireguard::new_connection()
                .map_err(|error| WireGuardError::Netlink(error.to_string()))?;
            tokio::spawn(connection);
            handle
                .get_by_name(&ifname)
                .await
                .map_err(|error| WireGuardError::Netlink(error.to_string()))
        })
    }

    /// The peers the kernel reports that this driver knows and the caller asked
    /// for, paired with their device id.
    fn resolve<'a>(
        &self,
        device: &'a WireguardParsed,
        peers: &[DeviceId],
    ) -> Vec<(DeviceId, &'a nl_wireguard::WireguardPeerParsed)> {
        let known = self.known();
        let by_key: BTreeMap<Vec<u8>, DeviceId> = known
            .iter()
            .map(|(id, key)| (key.as_bytes().to_vec(), *id))
            .collect();
        let wanted: BTreeSet<DeviceId> = peers.iter().copied().collect();

        let mut resolved = Vec::new();
        for peer in device.peers.as_deref().unwrap_or_default() {
            let Some(encoded) = peer.public_key.as_deref() else {
                continue;
            };
            let Some(bytes) = base64::decode(encoded) else {
                continue;
            };
            let Some(id) = by_key.get(&bytes).copied() else {
                continue;
            };
            if !wanted.contains(&id) {
                continue;
            }
            resolved.push((id, peer));
        }
        resolved
    }
}

impl WireGuard for NetlinkWireGuard {
    fn apply(&self, changes: &[Change]) -> Result<(), WireGuardError> {
        let ops = {
            let known = self.known();
            let mut ops = Vec::with_capacity(changes.len());
            for change in changes {
                match peer_op(change, &known) {
                    Some(op) => ops.push(op),
                    None => {
                        if let Change::Remove(id) = change {
                            return Err(WireGuardError::Interface(format!(
                                "peer {id:?} has no public key: this driver never wrote it, \
                                 so it can not name it to the kernel"
                            )));
                        }
                    }
                }
            }
            ops
        };

        if !ops.is_empty() {
            let config = device_config(&self.ifname, &ops);
            self.run(async move {
                let (connection, mut handle, _) = nl_wireguard::new_connection()
                    .map_err(|error| WireGuardError::Netlink(error.to_string()))?;
                tokio::spawn(connection);
                handle
                    .set(config)
                    .await
                    .map_err(|error| WireGuardError::Netlink(error.to_string()))
            })?;
        }

        let mut known = self.known();
        for change in changes {
            match change {
                Change::Add(spec) | Change::Update(spec) => {
                    known.insert(spec.id, spec.key);
                }
                Change::Remove(id) => {
                    known.remove(id);
                }
            }
        }
        Ok(())
    }

    fn status(&self, peers: &[DeviceId]) -> Result<Vec<PeerStatus>, WireGuardError> {
        let device = self.device()?;
        Ok(self
            .resolve(&device, peers)
            .into_iter()
            .map(|(peer, reported)| PeerStatus {
                peer,
                endpoint: reported.endpoint.map(Endpoint::new),
                last_handshake: reported.last_handshake.map(|since_epoch| {
                    Millis(u64::try_from(since_epoch.as_millis()).unwrap_or(u64::MAX))
                }),
            })
            .collect())
    }

    fn listen_port(&self) -> Result<u16, WireGuardError> {
        let device = self.device()?;
        device.listen_port.ok_or_else(|| {
            WireGuardError::Interface(format!("{} reports no listen port", self.ifname))
        })
    }
}

/// The interface index of `name`, or `None` when there is no such link.
async fn link_index(
    handle: &rtnetlink::Handle,
    name: &str,
) -> Result<Option<u32>, rtnetlink::Error> {
    let mut links = handle.link().get().match_name(name.to_string()).execute();
    match links.next().await {
        Some(Ok(message)) => Ok(Some(message.header.index)),
        Some(Err(error)) => Err(error),
        None => Ok(None),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn a_driver_starts_without_touching_the_kernel() {
        // The driver is built during startup, before the interface necessarily
        // exists, so nothing in the constructor may talk to netlink.
        let driver = NetlinkWireGuard::new("wgmesh0");
        assert_eq!(driver.interface(), "wgmesh0");
        assert!(driver.known_peers().is_empty());
    }

    #[test]
    fn removing_a_peer_we_never_wrote_is_refused_before_the_kernel() {
        // The driver can not name a peer it has never written to the kernel, so
        // the message is refused instead of being applied as "remove nothing".
        let driver = NetlinkWireGuard::new("wgmesh0");
        let error = driver
            .apply(&[Change::Remove(DeviceId(9))])
            .expect_err("an unknown peer is refused");
        assert!(
            matches!(error, WireGuardError::Interface(_)),
            "unexpected error: {error:?}"
        );
    }

    #[test]
    fn an_empty_batch_touches_nothing() {
        let driver = NetlinkWireGuard::new("wgmesh0");
        driver.apply(&[]).expect("nothing to do is not an error");
        assert!(driver.known_peers().is_empty());
    }
}
