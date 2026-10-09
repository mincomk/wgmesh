use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use wgmesh_core::Endpoint;
use wgmesh_ports::{
    AddressScope, DiscoveryError, InterfaceInventory, LocalAddress, MappedPort, PortMapper,
};

#[derive(Clone, Debug)]
pub struct FakeInventory {
    addresses: Vec<LocalAddress>,
    listen_port: u16,
}

impl FakeInventory {
    pub fn new(addresses: Vec<LocalAddress>, listen_port: u16) -> Self {
        Self {
            addresses,
            listen_port,
        }
    }

    pub fn lan(ip: std::net::IpAddr) -> LocalAddress {
        LocalAddress::new(ip, AddressScope::Lan)
    }

    pub fn ipv6(ip: std::net::IpAddr) -> LocalAddress {
        LocalAddress::new(ip, AddressScope::Ipv6Global)
    }
}

impl InterfaceInventory for FakeInventory {
    fn addresses(&self) -> Result<Vec<LocalAddress>, DiscoveryError> {
        Ok(self.addresses.clone())
    }

    fn listen_port(&self) -> Result<u16, DiscoveryError> {
        Ok(self.listen_port)
    }
}

/// Records every call, so a test can state "with `upnp = false` the router is
/// never spoken to" as an assertion rather than as a reading of the code.
#[derive(Clone, Debug)]
pub struct RecordingPortMapper {
    calls: Arc<Mutex<Vec<(u16, Duration)>>>,
    mapped: Option<Endpoint>,
}

impl RecordingPortMapper {
    pub fn new(mapped: Option<Endpoint>) -> Self {
        Self {
            calls: Arc::new(Mutex::new(Vec::new())),
            mapped,
        }
    }

    pub fn calls(&self) -> usize {
        self.calls.lock().expect("mapper mutex").len()
    }

    pub fn call_log(&self) -> Vec<(u16, Duration)> {
        self.calls.lock().expect("mapper mutex").clone()
    }
}

#[async_trait]
impl PortMapper for RecordingPortMapper {
    async fn map(&self, local_port: u16, lifetime: Duration) -> Result<MappedPort, DiscoveryError> {
        self.calls
            .lock()
            .expect("mapper mutex")
            .push((local_port, lifetime));
        match self.mapped {
            Some(endpoint) => Ok(MappedPort::new(endpoint)),
            None => Err(DiscoveryError::Unsupported(
                "no gateway answered".to_string(),
            )),
        }
    }
}
