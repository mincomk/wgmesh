// The glue: what turns a store that speaks files into a store that speaks `wgmesh-ports`.
//
// Nothing above this module knows how a key is written or what the state file looks like. The
// two wrappers here are the whole of the translation, and they are deliberately the only place a
// key is read and the only place a state document is turned into the state the use cases hold.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use wgmesh_core::{Allowed, DeviceId, Endpoint, Millis, PublicKey, RelayId, RouteSpec};
use wgmesh_ports::{
    Observation, PeerRecord, PersistedState, RelayState, SecretError, Signature, Spki, StateError,
    StateStore,
};
use wgmesh_secrets::{FileSecretStore, KeyKind, SecretSource};
use wgmesh_state::FileStateStore;

use crate::simulated::{parse_prefix, write_prefix};

/// The device's key material, as the ports want it.
///
/// A device has two keys and they are not interchangeable: the WireGuard key is what the kernel
/// uses and what peers see, and the API key is the identity that signs requests. Both live here,
/// and neither is ever handed out — the ports ask for a public half or for a signature.
pub struct FileSecrets {
    identity: FileSecretStore,
    tunnel: FileSecretStore,
}

impl FileSecrets {
    /// Open both key files, minting what is missing where the path is ours to own.
    ///
    /// A path the configuration names explicitly is read-only: it belongs to whatever provisioned
    /// it, and writing it would break the declarative setup that put it there.
    pub fn new(
        dir: &Path,
        private_key_file: Option<PathBuf>,
        api_key_file: Option<PathBuf>,
    ) -> Self {
        let tunnel = match private_key_file {
            Some(path) => FileSecretStore::at(path, KeyKind::X25519, SecretSource::RequireExisting),
            None => FileSecretStore::wireguard(dir, SecretSource::LoadOrGenerate),
        };
        let identity = match api_key_file {
            Some(path) => {
                FileSecretStore::at(path, KeyKind::Ed25519, SecretSource::RequireExisting)
            }
            None => FileSecretStore::api(dir, SecretSource::LoadOrGenerate),
        };
        Self { identity, tunnel }
    }

    /// The tunnel key pair, in the encoding `wg(8)` writes: base64 private, base64 public.
    pub fn tunnel_pair(&self) -> Result<(String, String), String> {
        let private = self
            .tunnel
            .reveal()
            .map_err(|error| format!("{}: {error}", self.tunnel.path().display()))?;
        let public = self
            .tunnel
            .public_key()
            .map_err(|error| format!("{}: {error}", self.tunnel.path().display()))?;
        Ok((
            wgmesh_secrets::encode_key(&private).trim().to_string(),
            wgmesh_secrets::encode_key(&public).trim().to_string(),
        ))
    }

    /// The identity key pair, in the encoding `wg(8)` writes.
    pub fn identity_pair(&self) -> Result<(String, String), String> {
        let private = self
            .identity
            .reveal()
            .map_err(|error| format!("{}: {error}", self.identity.path().display()))?;
        let public = self
            .identity
            .public_key()
            .map_err(|error| format!("{}: {error}", self.identity.path().display()))?;
        Ok((
            wgmesh_secrets::encode_key(&private).trim().to_string(),
            wgmesh_secrets::encode_key(&public).trim().to_string(),
        ))
    }

    /// Replace the tunnel key with a fresh one.
    ///
    /// A device that rotates its tunnel key is a device every peer has to be told about, which is
    /// why this is an explicit command and never something the daemon does on its own.
    pub fn rotate_tunnel(&self) -> Result<String, String> {
        let path = self.tunnel.path().to_path_buf();
        let mut key = wgmesh_secrets::generate::random_key()
            .map_err(|error| format!("{}: {error}", path.display()))?;
        wgmesh_secrets::write_atomic(&path, &key, wgmesh_secrets::SECRET_FILE_MODE)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        key.fill(0);
        let (_private, public) = self.tunnel_pair()?;
        Ok(public)
    }

    /// Where the tunnel key lives.
    pub fn tunnel_path(&self) -> &Path {
        self.tunnel.path()
    }
}

impl wgmesh_ports::SecretStore for FileSecrets {
    fn wireguard_public_key(&self) -> Result<PublicKey, SecretError> {
        let bytes = self
            .tunnel
            .public_key()
            .map_err(|error| SecretError::fatal(error.to_string()))?;
        Ok(PublicKey::from_bytes(bytes))
    }

    fn public_key(&self) -> Result<PublicKey, SecretError> {
        let bytes = self
            .identity
            .public_key()
            .map_err(|error| SecretError::fatal(error.to_string()))?;
        Ok(PublicKey::from_bytes(bytes))
    }

    fn sign(&self, message: &[u8]) -> Result<Signature, SecretError> {
        let signature = self
            .identity
            .sign(message)
            .map_err(|error| SecretError::fatal(error.to_string()))?;
        Ok(Signature::from_bytes(signature))
    }
}

/// The state file, as the ports want it.
pub struct FileState {
    store: FileStateStore,
}

impl FileState {
    /// A state store rooted at `dir`.
    pub fn new(dir: &Path) -> Self {
        Self {
            store: FileStateStore::new(dir),
        }
    }

    /// Where the state file is.
    pub fn path(&self) -> &Path {
        self.store.path()
    }

    /// Whether there is a state file.
    pub fn exists(&self) -> bool {
        self.store.exists()
    }

    /// The state document, as the store holds it.
    pub fn document(&self) -> Result<Option<wgmesh_state::PersistedState>, StateError> {
        let load = self
            .store
            .load()
            .map_err(|error| StateError::fatal(error.to_string()))?;
        Ok(load.state().cloned())
    }

    /// Write a state document back, without going through the ports' type.
    pub fn save_document(&self, document: &wgmesh_state::PersistedState) -> Result<(), StateError> {
        self.store
            .save(document)
            .map_err(|error| StateError::fatal(error.to_string()))
    }
}

impl StateStore for FileState {
    fn load(&self) -> Result<Option<PersistedState>, StateError> {
        let load = self
            .store
            .load()
            .map_err(|error| StateError::fatal(error.to_string()))?;
        // A state file that was reset is a state file that is gone: the device enrols again with
        // the keys it always had, which is exactly what starting over means here.
        let Some(document) = load.state() else {
            return Ok(None);
        };
        document
            .to_ports()
            .map(Some)
            .map_err(StateError::recoverable)
    }

    fn save(&self, state: &PersistedState) -> Result<(), StateError> {
        let document = wgmesh_state::PersistedState::from_ports(state);
        self.store
            .save(&document)
            .map_err(|error| StateError::fatal(error.to_string()))
    }

    fn clear(&self) -> Result<(), StateError> {
        self.store
            .clear()
            .map_err(|error| StateError::fatal(error.to_string()))
    }
}

/// The state document, with the conversion both ways.
///
/// The file is the operator-readable document the blueprint describes; the ports' state is what
/// the use cases hold. The conversion is the only place either shape is known.
pub trait StateDocument {
    /// Lift the document into the ports' state.
    fn to_ports(&self) -> Result<PersistedState, String>;

    /// Lower the ports' state into the document.
    fn from_ports(state: &PersistedState) -> wgmesh_state::PersistedState;
}

impl StateDocument for wgmesh_state::PersistedState {
    fn to_ports(&self) -> Result<PersistedState, String> {
        let device = DeviceId(
            self.device_id
                .parse()
                .map_err(|_| format!("device id is not a number: {}", self.device_id))?,
        );
        let spki = crate::container::parse_spki(&self.coordinator.spki_sha256)
            .map_err(|error| format!("state pin: {error}"))?;
        let peers = self
            .peers
            .iter()
            .map(|peer| {
                let id: u32 = peer
                    .id
                    .parse()
                    .map_err(|_| format!("peer id is not a number: {}", peer.id))?;
                Ok(PeerRecord {
                    device: DeviceId(id),
                    name: (!peer.name.is_empty()).then(|| peer.name.clone()),
                    public_key: decode_public_key(&peer.wg_pubkey)
                        .ok_or_else(|| format!("peer {} has an unusable public key", peer.id))?,
                    tunnel_ip: if peer.tunnel_ip.is_empty() {
                        None
                    } else {
                        Some(parse_prefix(&peer.tunnel_ip)?)
                    },
                    endpoint: peer
                        .endpoint
                        .as_deref()
                        .and_then(|text| text.parse().ok())
                        .map(Endpoint::new),
                    path: match peer.path {
                        wgmesh_state::PeerPath::Unknown => wgmesh_core::Path::Unknown,
                        wgmesh_state::PeerPath::Relayed => wgmesh_core::Path::Relayed,
                        wgmesh_state::PeerPath::Direct => wgmesh_core::Path::Direct,
                    },
                    last_handshake: (peer.last_handshake_unix > 0)
                        .then(|| Millis::from_secs(peer.last_handshake_unix)),
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        let observations = self
            .observations
            .iter()
            .filter_map(|(relay, observation)| {
                let relay: u16 = relay.parse().ok()?;
                let endpoint: std::net::SocketAddr =
                    format!("{}:{}", observation.ip, observation.port)
                        .parse()
                        .ok()?;
                Some((
                    RelayId(relay),
                    Observation {
                        device,
                        endpoint: Endpoint::new(endpoint),
                        kind: wgmesh_core::CandidateKind::Observed,
                        at: Millis::from_secs(observation.seen_unix),
                    },
                ))
            })
            .collect();
        let routes = self
            .routes
            .iter()
            .map(|route| {
                Ok(RouteSpec::new(
                    parse_prefix(&route.prefix)?,
                    parse_table(&route.table),
                    route.metric,
                ))
            })
            .collect::<Result<Vec<_>, String>>()?;
        Ok(PersistedState {
            schema: self.schema,
            device,
            network: self.network.clone(),
            tunnel_ip: parse_prefix(&self.tunnel_ip)?,
            coordinator: wgmesh_ports::CoordinatorLink {
                spki,
                last_sync: Millis::from_secs(self.coordinator.last_sync_unix),
                etag: (!self.coordinator.etag.is_empty()).then(|| self.coordinator.etag.clone()),
            },
            relay: RelayState {
                assigned: self.relay.assigned.parse().ok().map(RelayId),
                slot_port: (self.relay.slot_port > 0).then_some(self.relay.slot_port),
                slots: self
                    .relay
                    .slots
                    .iter()
                    .filter_map(|(relay, port)| Some((RelayId(relay.parse().ok()?), *port)))
                    .collect(),
            },
            peers,
            observations,
            routes,
            sysctl: self.sysctl.clone(),
        })
    }

    fn from_ports(state: &PersistedState) -> wgmesh_state::PersistedState {
        let mut document =
            wgmesh_state::PersistedState::new(state.device.0.to_string(), state.network.clone());
        document.schema = state.schema;
        document.tunnel_ip = write_prefix(&state.tunnel_ip);
        document.coordinator = wgmesh_state::CoordinatorState {
            spki_sha256: crate::container::hex_of(state.coordinator.spki.as_bytes()),
            last_sync_unix: state.coordinator.last_sync.as_millis() / 1000,
            etag: state.coordinator.etag.clone().unwrap_or_default(),
        };
        document.relay = wgmesh_state::RelayState {
            assigned: state
                .relay
                .assigned
                .map(|relay| relay.0.to_string())
                .unwrap_or_default(),
            slot_port: state.relay.slot_port.unwrap_or(0),
            slots: state
                .relay
                .slots
                .iter()
                .map(|(relay, port)| (relay.0.to_string(), *port))
                .collect(),
        };
        document.peers = state
            .peers
            .iter()
            .map(|peer| wgmesh_state::PeerState {
                id: peer.device.0.to_string(),
                name: peer.name.clone().unwrap_or_default(),
                wg_pubkey: encode_public_key(&peer.public_key),
                tunnel_ip: peer
                    .tunnel_ip
                    .as_ref()
                    .map(write_prefix)
                    .unwrap_or_default(),
                endpoint: peer.endpoint.map(|endpoint| endpoint.addr().to_string()),
                path: match peer.path {
                    wgmesh_core::Path::Unknown => wgmesh_state::PeerPath::Unknown,
                    wgmesh_core::Path::Relayed => wgmesh_state::PeerPath::Relayed,
                    wgmesh_core::Path::Direct => wgmesh_state::PeerPath::Direct,
                },
                last_handshake_unix: peer
                    .last_handshake
                    .map(|at| at.as_millis() / 1000)
                    .unwrap_or(0),
            })
            .collect();
        document.observations = state
            .observations
            .iter()
            .map(|(relay, observation)| {
                let addr = observation.endpoint.addr();
                (
                    relay.0.to_string(),
                    wgmesh_state::Observation {
                        ip: addr.ip().to_string(),
                        port: addr.port(),
                        seen_unix: observation.at.as_millis() / 1000,
                    },
                )
            })
            .collect();
        document.routes = state
            .routes
            .iter()
            .map(|route| wgmesh_state::RouteRecord {
                prefix: write_prefix(&route.prefix),
                table: write_table(route.table),
                metric: route.metric,
            })
            .collect();
        document.sysctl = state.sysctl.clone();
        document
    }
}

/// A public key in the encoding `wg(8)` writes.
pub fn encode_public_key(key: &PublicKey) -> String {
    // `encode_key` writes the trailing newline `wg(8)` writes for a whole file, which is not
    // wanted in a field of a document.
    wgmesh_secrets::encode_key(key.as_bytes())
        .trim()
        .to_string()
}

/// A public key from the encoding `wg(8)` writes.
pub fn decode_public_key(text: &str) -> Option<PublicKey> {
    wgmesh_secrets::parse_key(text.trim().as_bytes())
        .ok()
        .map(|(bytes, _format)| PublicKey::from_bytes(bytes))
}

fn parse_table(text: &str) -> wgmesh_core::RouteTable {
    match text {
        "" | "main" => wgmesh_core::RouteTable::Main,
        "off" | "unmanaged" => wgmesh_core::RouteTable::Unmanaged,
        other => other
            .parse()
            .map(wgmesh_core::RouteTable::Number)
            .unwrap_or(wgmesh_core::RouteTable::Main),
    }
}

fn write_table(table: wgmesh_core::RouteTable) -> String {
    match table {
        wgmesh_core::RouteTable::Unmanaged => "off".to_string(),
        wgmesh_core::RouteTable::Main => "main".to_string(),
        wgmesh_core::RouteTable::Number(number) => number.to_string(),
    }
}

/// The pin, as the state file holds it.
pub fn spki_of(state: &PersistedState) -> String {
    crate::container::hex_of(state.coordinator.spki.as_bytes())
}

/// The addresses of a state, as text.
pub fn addresses_of(state: &PersistedState) -> Vec<String> {
    let mut addresses = vec![write_prefix(&state.tunnel_ip)];
    addresses.retain(|text| !text.is_empty());
    addresses
}

/// A relay id, as text.
pub fn relay_text(relay: Option<RelayId>) -> Option<String> {
    relay.map(|relay| relay.0.to_string())
}

/// A BTreeMap of slots, as text.
pub fn slots_text(slots: &BTreeMap<RelayId, u16>) -> BTreeMap<String, u16> {
    slots
        .iter()
        .map(|(relay, port)| (relay.0.to_string(), *port))
        .collect()
}

/// An address, when it parses.
pub fn endpoint_of(text: &str) -> Option<Endpoint> {
    text.parse().ok().map(Endpoint::new)
}

/// The SPKI of a state's coordinator link.
pub fn pin_of(state: &PersistedState) -> Spki {
    state.coordinator.spki
}

/// A tunnel address as a prefix.
pub fn tunnel_ip_of(state: &PersistedState) -> Allowed {
    state.tunnel_ip.clone()
}
