//! The daemon: the lock, the startup sequence, and the loop that keeps the mesh converged.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::time::Duration;

use wgmesh_app::AppError;
use wgmesh_core::{DeviceId, Event, Millis, Path as TrafficPath, PeerSpec};
use wgmesh_ports::{Clock, StateStore, WireGuard};

use crate::container::{Container, Traversal};
use crate::error::CliError;

/// The lock a running agent holds.
///
/// Two agents programming one interface is not a crash: the kernel would accept both, and the
/// result would be a peer table that flickers between two opinions. The lock is what makes that
/// impossible.
pub struct Lock {
    file: File,
    path: PathBuf,
}

impl Lock {
    /// Take the lock at `dir/name`, creating the directory when it is missing.
    pub fn acquire(dir: &Path, name: &str) -> Result<Self, CliError> {
        std::fs::create_dir_all(dir)
            .map_err(|error| CliError::runtime(format!("{}: {error}", dir.display())))?;
        let path = dir.join(name);
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&path)
            .map_err(|error| CliError::runtime(format!("{}: {error}", path.display())))?;
        match file.try_lock() {
            Ok(()) => Ok(Self { file, path }),
            Err(std::fs::TryLockError::WouldBlock) => Err(CliError::runtime(format!(
                "another wgmesh agent is already running on this host ({} is locked)",
                path.display()
            ))),
            Err(std::fs::TryLockError::Error(error)) => {
                Err(CliError::runtime(format!("{}: {error}", path.display())))
            }
        }
    }

    /// The lock file.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

/// What a run did before it settled into the loop.
#[derive(Clone, Debug)]
pub struct Started {
    /// The device the coordinator assigned.
    pub device: DeviceId,
    /// How many peers were converged.
    pub peers: usize,
    /// How many route changes were written.
    pub routes: usize,
    /// The interface name.
    pub interface: String,
}

/// Run the agent until it is told to stop.
pub async fn run(container: &Container) -> Result<Started, CliError> {
    let lock = Lock::acquire(container.run_dir(), "agent.lock")?;
    let settings = container.agent_settings()?;
    let interval = Duration::from_secs(container.settings().sync.interval_secs.max(1));

    let agent = container.agent(settings)?;
    let startup = agent.start().await.map_err(app_error)?;

    let started = Started {
        device: startup.state.device,
        peers: startup.convergence.snapshot.peers.len(),
        routes: startup.convergence.route_changes.len(),
        interface: container.settings().interface.name.clone(),
    };

    let mut state = startup.state;
    let mut traversals: BTreeMap<DeviceId, Traversal<'_>> = BTreeMap::new();

    loop {
        refresh(container, &mut state)?;
        save(container, &state)?;

        let device = state.device;
        let peers: Vec<PeerSpec> = state
            .peers
            .iter()
            .map(|peer| PeerSpec {
                id: peer.device,
                key: peer.public_key,
                allowed: peer.tunnel_ip.iter().cloned().collect(),
                endpoint: peer.endpoint,
                keepalive: None,
            })
            .collect();

        for peer in peers {
            let traversal = traversals
                .entry(peer.id)
                .or_insert_with(|| agent.traverse(device, peer.clone()));
            let at = container.clock().now();
            let event = match traversal.path() {
                TrafficPath::Direct => Event::Tick { at },
                _ => Event::Tick { at },
            };
            if let Err(error) = traversal.handle(event).await {
                // A peer this device cannot reach is reported, not fatal: the loop keeps
                // converging the rest of the mesh.
                tracing::debug!(?error, peer = peer.id.0, "traversal event failed");
            }
        }

        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            _ = tokio::time::sleep(interval) => {}
        }

        state = agent
            .converge(&state, container.clock().now())
            .await
            .map_err(app_error)?
            .state;
    }

    drop(lock);
    Ok(started)
}

/// Fold what the device knows about the peers into the state the commands read.
///
/// The state file is this device's memory of the mesh — endpoints, paths, handshakes — and the
/// device is the only thing that knows them after the fact.
fn refresh(container: &Container, state: &mut wgmesh_ports::PersistedState) -> Result<(), CliError> {
    let devices: Vec<DeviceId> = state.peers.iter().map(|peer| peer.device).collect();
    let statuses = container
        .ports()?
        .wireguard
        .status(&devices)
        .map_err(|error| CliError::runtime(error.to_string()))?;
    let now = container.clock().now();
    for status in statuses {
        if let Some(record) = state
            .peers
            .iter_mut()
            .find(|record| record.device == status.device)
        {
            record.endpoint = status.endpoint;
            record.last_handshake = status.last_handshake;
            record.path = live_path(status.last_handshake, now);
        }
    }
    Ok(())
}

/// Which way traffic is going, from how long ago the last handshake was.
pub fn live_path(handshake: Option<Millis>, now: Millis) -> TrafficPath {
    match handshake {
        Some(at) if now.as_millis().saturating_sub(at.as_millis()) < 180_000 => TrafficPath::Direct,
        Some(_) => TrafficPath::Relayed,
        None => TrafficPath::Unknown,
    }
}

fn save(container: &Container, state: &wgmesh_ports::PersistedState) -> Result<(), CliError> {
    container
        .state()
        .save(state)
        .map_err(|error| CliError::runtime(error.to_string()))
}

/// Turn an agent failure into something a person can act on.
pub fn app_error(error: AppError) -> CliError {
    CliError::runtime(format!("{}: {error}", error.class().as_str()))
}
