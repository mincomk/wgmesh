// The client itself: one HTTPS connection to the coordinator, and the port's five calls on it.
//
// The shape is the port's, and the port is asynchronous, so every method here is a network round
// trip in the order the agent needs it: enroll once, then read the world and report what happened.
// What this module adds to the port is what the port cannot express — the version of a
// configuration that did not change, and the raw body a diagnostic command wants to read.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use base64ct::{Base64, Encoding};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, ETAG, IF_NONE_MATCH};
use reqwest::{Method, StatusCode};

use wgmesh_core::{Allowed, Endpoint, PeerSpec, PublicKey};
use wgmesh_ports::{
    ApiError, Class, Clock, ConfigSnapshot, CoordinatorApi, EnrollRequest, Enrollment, Observation,
    PortError, PunchOutcome, PunchReport, RelayAssignment, SecretStore, Spki,
};
use wgmesh_proto as naming;
use wgmesh_proto::api::{
    AssignmentResponse, ConfigResponse, EndpointBody, ErrorBody, JoinBody, JoinResponse,
    ObservedIn, PeerBody, PunchBody, RelayEnrollBody, RelayEnrollResponse, RotateBody,
};

use crate::pin::{PinnedVerifier, client_config};

const JOIN_PATH: &str = "/v1/join";
const CONFIG_PATH: &str = "/v1/config";
const ENDPOINT_PATH: &str = "/v1/endpoint";
const PUNCH_PATH: &str = "/v1/punch";
const ROTATE_PATH: &str = "/v1/rotate";
const RELAY_ENROLL_PATH: &str = "/v1/relay/enroll";
const RELAY_ASSIGNMENT_PATH: &str = "/v1/relay/assignment";

/// How long one request may take before it is a failure. A coordinator that has not answered in
/// half a minute is one this device should ask again, not one it should wait on.
pub const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// What came back from `GET /v1/config`.
///
/// The port has one word for "here is the world" and none for "you already have it", and the
/// coordinator answers a device that names the version it holds with a `304` and no body at all.
/// Carrying both cases here — and the raw body with them, because `wgmesh doctor` reads more of it
/// than the port's snapshot keeps — is what keeps that difference out of the use cases.
#[derive(Clone, Debug)]
pub enum ConfigExchange {
    /// `200`: the world, and the version it carries.
    Fresh {
        /// The version this answer is.
        etag: String,
        /// The world, as the use cases want it.
        snapshot: ConfigSnapshot,
        /// The body as the coordinator wrote it, for callers that read more than the snapshot.
        body: Vec<u8>,
    },
    /// `304`: the version the caller named is the current one, and no body was sent.
    NotModified {
        /// The version, when the coordinator repeated it in the header.
        etag: Option<String>,
    },
}

/// Whether a call is an enrollment or an ordinary signed request.
///
/// The distinction exists for one status code. Everywhere else a `403` means "not allowed yet":
/// a device waiting for approval, a relay that is not serving a network — all of them keep working
/// once something else has happened. At enrollment a `403` means the join token was refused, and no
/// amount of waiting mints another one; that is a person's decision, so it is `Fatal` there.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Call {
    /// An unauthenticated call that spends a join token.
    Enroll,
    /// A signed call by a principal the coordinator already knows.
    Signed,
}

/// What the client remembers between calls, so a `304` can be answered.
struct Cached {
    etag: String,
    snapshot: ConfigSnapshot,
}

/// The coordination plane, over HTTPS, pinned to one key.
///
/// The pin and the origin are fixed for the client's life; the identity is not, because a device
/// learns its own id from the answer to its first call. A client built for a device that has
/// already enrolled is given that id with `with_identity`, which is what lets `wgmesh doctor`
/// or a restarted relay sign a request without enrolling again.
pub struct Coordinator<'a, S, K>
where
    S: SecretStore,
    K: Clock,
{
    http: reqwest::Client,
    origin: String,
    pin: Spki,
    verifier: Arc<PinnedVerifier>,
    secrets: &'a S,
    clock: &'a K,
    identity: Mutex<Option<String>>,
    name: String,
    advertised: Vec<String>,
    agent_version: String,
    cached: Mutex<Option<Cached>>,
}

impl<'a, S, K> Coordinator<'a, S, K>
where
    S: SecretStore,
    K: Clock,
{
    /// A client for one coordinator, pinned to one key.
    ///
    /// The origin must be an `https://` URL with no user information and no path: a pin is only
    /// worth anything on a connection whose host is the one the operator wrote down. Everything
    /// else the client needs — the key it signs with, the time it stamps requests with — is a port.
    pub fn new(
        origin: impl Into<String>,
        pin: Spki,
        secrets: &'a S,
        clock: &'a K,
    ) -> Result<Self, PortError> {
        let origin = normalize_origin(&origin.into())?;
        let verifier = Arc::new(PinnedVerifier::new(pin));
        let tls = client_config(&verifier)?;
        let http = reqwest::Client::builder()
            .use_preconfigured_tls(tls)
            // The pin is checked on the connection to this one origin, so nothing may move the
            // request to another one: a redirect to a plain http target would be a request with
            // no TLS and therefore no pin at all, and its body would be read as the world.
            .redirect(reqwest::redirect::Policy::none())
            .https_only(true)
            .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
            .build()
            .map_err(|error| {
                PortError::fatal(format!("the HTTPS client did not build: {error}"))
            })?;
        Ok(Self {
            http,
            origin,
            pin,
            verifier,
            secrets,
            clock,
            identity: Mutex::new(None),
            name: "wgmesh".to_string(),
            advertised: Vec::new(),
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            cached: Mutex::new(None),
        })
    }

    /// The identity this client already has, from a state file or a previous call.
    pub fn with_identity(self, identity: impl Into<String>) -> Self {
        self.remember(identity);
        self
    }

    /// What this device calls itself when it enrolls.
    pub fn with_name(self, name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ..self
        }
    }

    /// The bands this device routes for others, reported at enrollment.
    pub fn with_advertised(self, advertised: Vec<String>) -> Self {
        Self { advertised, ..self }
    }

    /// The version this build reports to the coordinator.
    pub fn with_agent_version(self, version: impl Into<String>) -> Self {
        Self {
            agent_version: version.into(),
            ..self
        }
    }

    /// The origin every request goes to.
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// The key this client pins.
    pub const fn pin(&self) -> Spki {
        self.pin
    }

    /// The identity this client signs with, if it has one yet.
    pub fn identity(&self) -> Option<String> {
        self.identity
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// `POST /v1/join`, the unauthenticated enrollment exchange.
    pub async fn join(&self, body: &JoinBody) -> Result<JoinResponse, PortError> {
        let bytes = serialize(JOIN_PATH, body)?;
        let response = self.send(Method::POST, JOIN_PATH, bytes, None).await?;
        let answer = ok_bytes(JOIN_PATH, response, Call::Enroll).await?;
        deserialize(JOIN_PATH, &answer)
    }

    /// `GET /v1/config`, naming the version the caller already holds.
    ///
    /// A `200` remembers the world, so the `304` that answers the next call with the same version
    /// can be turned back into it without a body: the caller wants the world either way, and
    /// `wgmesh_core::diff` against an unchanged world is what makes the second sync free.
    pub async fn exchange_config(&self, etag: Option<&str>) -> Result<ConfigExchange, PortError> {
        let identity = self.signed_identity()?;
        let authorization = self.authorization("GET", CONFIG_PATH, b"", &identity)?;
        let mut request = self
            .http
            .request(Method::GET, format!("{}{}", self.origin, CONFIG_PATH))
            .header(AUTHORIZATION, authorization);
        if let Some(etag) = etag {
            request = request.header(IF_NONE_MATCH, etag);
        }
        let response = request
            .send()
            .await
            .map_err(|error| self.transport_error("GET", CONFIG_PATH, &error))?;
        let version = header(&response, ETAG);
        if response.status() == StatusCode::NOT_MODIFIED {
            return Ok(ConfigExchange::NotModified { etag: version });
        }
        let body = ok_bytes(CONFIG_PATH, response, Call::Signed).await?;
        let answer: ConfigResponse = deserialize(CONFIG_PATH, &body)?;
        let snapshot = snapshot_of(&answer)?;
        *self
            .cached
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(Cached {
            etag: answer.etag.clone(),
            snapshot: snapshot.clone(),
        });
        Ok(ConfigExchange::Fresh {
            etag: answer.etag,
            snapshot,
            body,
        })
    }

    /// `POST /v1/relay/enroll`, which registers a relay rather than a device.
    ///
    /// The relay id that comes back becomes this client's identity, because that is what signs the
    /// assignment the relay asks for next.
    pub async fn relay_enroll(
        &self,
        body: &RelayEnrollBody,
    ) -> Result<RelayEnrollResponse, PortError> {
        let bytes = serialize(RELAY_ENROLL_PATH, body)?;
        let response = self
            .send(Method::POST, RELAY_ENROLL_PATH, bytes, None)
            .await?;
        let answer = ok_bytes(RELAY_ENROLL_PATH, response, Call::Enroll).await?;
        let enrolled: RelayEnrollResponse = deserialize(RELAY_ENROLL_PATH, &answer)?;
        self.remember(enrolled.relay_id.clone());
        Ok(enrolled)
    }

    /// `GET /v1/relay/assignment`: the slot table, the pairs and the keyset of this relay.
    pub async fn relay_assignment(&self) -> Result<AssignmentResponse, PortError> {
        let identity = self.signed_identity()?;
        let response = self
            .send(
                Method::GET,
                RELAY_ASSIGNMENT_PATH,
                Vec::new(),
                Some(&identity),
            )
            .await?;
        let answer = ok_bytes(RELAY_ASSIGNMENT_PATH, response, Call::Signed).await?;
        deserialize(RELAY_ASSIGNMENT_PATH, &answer)
    }

    /// A signed `POST` that is answered with a status and nothing this client reads.
    async fn post_signed(&self, path: &str, body: &[u8]) -> Result<(), PortError> {
        let identity = self.signed_identity()?;
        let response = self
            .send(Method::POST, path, body.to_vec(), Some(&identity))
            .await?;
        ok_bytes(path, response, Call::Signed).await.map(|_| ())
    }

    /// The version this client holds, when it is the one being asked about.
    fn cached_snapshot(&self, etag: &str) -> Option<ConfigSnapshot> {
        self.cached
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .filter(|cached| cached.etag == etag)
            .map(|cached| cached.snapshot.clone())
    }

    fn remember(&self, identity: impl Into<String>) {
        *self
            .identity
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(identity.into());
    }

    fn signed_identity(&self) -> Result<String, PortError> {
        self.identity().ok_or_else(|| {
            PortError::fatal(
                "this client has no identity yet: enroll first, or hand it the id this device \
                 already has",
            )
        })
    }

    /// The `Authorization` header for one request.
    ///
    /// A fresh nonce and the current time go into the signature with the method, the path and the
    /// digest of exactly the bytes being sent, so a captured request is worth nothing: it carries
    /// a nonce the coordinator has already spent and a timestamp that has moved on.
    fn authorization(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
        identity: &str,
    ) -> Result<String, PortError> {
        let timestamp = i64::try_from(self.clock.now().0 / 1000).unwrap_or(i64::MAX);
        let mut seed = [0u8; 16];
        getrandom::fill(&mut seed).map_err(|error| {
            PortError::fatal(format!("no randomness for a request nonce: {error}"))
        })?;
        let nonce = Base64::encode_string(&seed);
        let message = naming::sign::canonical(method, path, body, timestamp, &nonce);
        let signature = self.secrets.sign(&message)?;
        Ok(format!(
            "{} {identity} {timestamp} {nonce} {}",
            naming::sign::SCHEME,
            Base64::encode_string(signature.as_bytes())
        ))
    }

    async fn send(
        &self,
        method: Method,
        path: &str,
        body: Vec<u8>,
        identity: Option<&str>,
    ) -> Result<reqwest::Response, PortError> {
        let mut request = self
            .http
            .request(method.clone(), format!("{}{}", self.origin, path));
        if let Some(identity) = identity {
            request = request.header(
                AUTHORIZATION,
                self.authorization(method.as_str(), path, &body, identity)?,
            );
        }
        if !body.is_empty() {
            request = request.header(CONTENT_TYPE, "application/json");
        }
        request
            .body(body)
            .send()
            .await
            .map_err(|error| self.transport_error(method.as_str(), path, &error))
    }

    /// Which class a connection that did not produce an answer is.
    ///
    /// A refusal by the pin is checked first, because it is the one failure that must never be
    /// retried and the one a plain "the connection was reset" detail would hide: the TLS alert the
    /// server sends back says nothing about which key it presented, and this device holds the
    /// answer to that.
    fn transport_error(&self, method: &str, path: &str, error: &reqwest::Error) -> PortError {
        if let Some(refusal) = self.verifier.take_refusal() {
            return PortError::trust(format!("{method} {path}: {refusal}"));
        }
        let detail = format!("{method} {path}: {error}");
        if error.is_timeout() || error.is_connect() || error.is_request() || error.is_body() {
            PortError::transient(detail)
        } else {
            PortError::fatal(detail)
        }
    }
}

#[async_trait]
impl<S, K> CoordinatorApi for Coordinator<'_, S, K>
where
    S: SecretStore,
    K: Clock,
{
    /// Enroll: trade a token and two public keys for an identity.
    ///
    /// This is the one call that is not signed — nobody can sign for an identity before they have
    /// one — and the one that teaches the client its own name. The device id the coordinator hands
    /// back becomes this client's identity for every later request.
    async fn enroll(&self, request: EnrollRequest) -> Result<Enrollment, ApiError> {
        let body = JoinBody {
            token: request.token.as_str().to_string(),
            name: request
                .hostname
                .clone()
                .unwrap_or_else(|| self.name.clone()),
            wg_pubkey: naming::encode_key(&request.wireguard),
            api_pubkey: naming::encode_key(&request.signer),
            os: None,
            agent_version: Some(self.agent_version.clone()),
            advertised: self.advertised.clone(),
        };
        let answer = self.join(&body).await?;
        let device = naming::parse_device_id(&answer.device_id).ok_or_else(|| {
            PortError::fatal(format!(
                "{JOIN_PATH}: the coordinator named this device `{}`, which is not a device id",
                answer.device_id
            ))
        })?;
        let tunnel_ip =
            tunnel_prefix(&answer.tunnel_ip, &answer.network.cidr).ok_or_else(|| {
                PortError::fatal(format!(
                    "{JOIN_PATH}: the tunnel address `{}` is not an address in `{}`",
                    answer.tunnel_ip, answer.network.cidr
                ))
            })?;
        let assignment = answer.relay_pool.iter().find_map(|relay| {
            Some(RelayAssignment {
                relay: naming::parse_relay_id(&relay.relay_id)?,
                slot_port: relay.slot_port?,
            })
        });
        self.remember(answer.device_id.clone());
        Ok(Enrollment {
            device,
            network: answer.network.name,
            tunnel_ip,
            assignment,
            etag: None,
        })
    }

    async fn config(&self, etag: Option<&str>) -> Result<ConfigSnapshot, ApiError> {
        match self.exchange_config(etag).await? {
            ConfigExchange::Fresh { snapshot, .. } => Ok(snapshot),
            // A device that has just restarted hands over the version it remembered, and this
            // process has never held that world. The coordinator keeps no history to send it, so
            // the answer is to ask again without a version rather than to fail the sync.
            ConfigExchange::NotModified { etag } => {
                if let Some(cached) = etag.as_deref().and_then(|etag| self.cached_snapshot(etag)) {
                    return Ok(cached);
                }
                match self.exchange_config(None).await? {
                    ConfigExchange::Fresh { snapshot, .. } => Ok(snapshot),
                    ConfigExchange::NotModified { .. } => Err(PortError::fatal(
                        "the coordinator answered 304 to a request that carried no version",
                    )),
                }
            }
        }
    }

    /// `POST /v1/endpoint`, which is how a device reports where it was seen.
    ///
    /// The coordinator's route carries this device's *own* observation: a peer is observed by the
    /// relay that carries its traffic, and that is a relay's report rather than a device's. An
    /// observation naming another device is therefore refused here rather than quietly dropped.
    async fn report_observations(&self, observations: &[Observation]) -> Result<(), ApiError> {
        let identity = self.signed_identity()?;
        let mut mine = None;
        for observation in observations {
            let named = naming::device_id(observation.device);
            if named != identity {
                return Err(PortError::fatal(format!(
                    "{ENDPOINT_PATH} carries this device's own observation, and this report names \
                     {named}"
                )));
            }
            mine = Some(observation);
        }
        let Some(observation) = mine else {
            return Ok(());
        };
        let address = observation.endpoint.addr();
        let body = EndpointBody {
            observed: Some(ObservedIn {
                ip: address.ip().to_string(),
                port: address.port(),
                seen_at_ms: Some(observation.at.0),
            }),
            advertised: None,
        };
        self.post_signed(ENDPOINT_PATH, &serialize(ENDPOINT_PATH, &body)?)
            .await
    }

    /// `POST /v1/punch`, how a traversal ended.
    async fn report_punch(&self, report: PunchReport) -> Result<(), ApiError> {
        let body = PunchBody {
            peer: naming::device_id(report.peer),
            outcome: match report.outcome {
                PunchOutcome::Direct => "direct",
                PunchOutcome::Relayed => "relayed",
                PunchOutcome::Failed => "failed",
            }
            .to_string(),
        };
        self.post_signed(PUNCH_PATH, &serialize(PUNCH_PATH, &body)?)
            .await
    }

    /// `POST /v1/rotate`, telling the coordinator this device's new tunnel key.
    async fn rotate(&self, key: PublicKey) -> Result<(), ApiError> {
        let body = RotateBody {
            wg_pubkey: naming::encode_key(&key),
        };
        self.post_signed(ROTATE_PATH, &serialize(ROTATE_PATH, &body)?)
            .await
    }
}

/// The pin a coordinator presents, learned by completing a handshake with nothing pinned.
///
/// This is `wgmesh pin`: the value it answers is the one a person writes into
/// `coordinator.spki_sha256`, and they have to see it before they can write it. Nothing else in
/// this crate reaches a coordinator without a pin — the request that follows this handshake is
/// answered with `401` and that answer is not read, because the handshake is the whole point of it.
pub async fn learn_pin(origin: &str) -> Result<Spki, PortError> {
    let origin = normalize_origin(origin)?;
    let verifier = Arc::new(PinnedVerifier::learn());
    let tls = client_config(&verifier)?;
    let http = reqwest::Client::builder()
        .use_preconfigured_tls(tls)
        .redirect(reqwest::redirect::Policy::none())
        .https_only(true)
        .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
        .build()
        .map_err(|error| PortError::fatal(format!("the HTTPS client did not build: {error}")))?;
    let _ = http.get(format!("{origin}{CONFIG_PATH}")).send().await;
    verifier.presented().map(Spki::from_bytes).ok_or_else(|| {
        PortError::transient(format!(
            "{origin} completed no handshake, so it presented no key to pin"
        ))
    })
}

/// One address out of the wire, or the failure that names the peer and the text.
///
/// `allowed` is the ACL the interface is handed, so an address that does not parse is refused
/// rather than dropped: a band quietly left out is a peer silently shrunk, and a peer whose own
/// address was dropped is a peer the kernel has no key for.
fn address_of(peer: &PeerBody, field: &str, text: &str) -> Result<Allowed, PortError> {
    parse_prefix(text).ok_or_else(|| {
        PortError::fatal(format!(
            "{CONFIG_PATH}: the peer {} {field} `{text}`, which is not an address with a prefix",
            peer.device_id
        ))
    })
}

/// The world, as the port wants it, out of the wire's own answer.
fn snapshot_of(answer: &ConfigResponse) -> Result<ConfigSnapshot, PortError> {
    let network = parse_prefix(&answer.network.cidr).ok_or_else(|| {
        PortError::fatal(format!(
            "{CONFIG_PATH}: the network cidr `{}` is not an address with a prefix",
            answer.network.cidr
        ))
    })?;
    let mut advertised = BTreeSet::new();
    for peer in &answer.peers {
        for band in &peer.advertised {
            advertised.insert(address_of(peer, "advertises", band)?);
        }
    }
    Ok(ConfigSnapshot {
        etag: answer.etag.clone(),
        network: vec![network],
        advertised: advertised.into_iter().collect(),
        peers: answer
            .peers
            .iter()
            .map(|peer| peer_spec(peer, answer.keepalive_secs))
            .collect::<Result<Vec<_>, _>>()?,
    })
}

/// One peer, as the interface should hold it.
///
/// `allowed` is the peer's own bands — the address it holds in the tunnel and everything it says
/// it routes for — because that list *is* the ACL: `wgmesh_core` hands it straight to the policy,
/// and a peer missing from it is a peer whose packets the kernel has no key for.
fn peer_spec(peer: &PeerBody, keepalive_secs: u32) -> Result<PeerSpec, PortError> {
    let id = naming::parse_device_id(&peer.device_id).ok_or_else(|| {
        PortError::fatal(format!(
            "{CONFIG_PATH}: the peer `{}` is not a device id",
            peer.device_id
        ))
    })?;
    let key = naming::decode_key(&peer.wg_pubkey).ok_or_else(|| {
        PortError::fatal(format!(
            "{CONFIG_PATH}: the peer {} has a key that is not a 32-byte public key",
            peer.device_id
        ))
    })?;
    let mut allowed = BTreeSet::new();
    allowed.insert(address_of(peer, "holds the address", &peer.tunnel_ip)?);
    for band in &peer.advertised {
        allowed.insert(address_of(peer, "advertises", band)?);
    }
    Ok(PeerSpec {
        id,
        key,
        allowed: allowed.into_iter().collect(),
        endpoint: peer
            .endpoint
            .as_deref()
            .and_then(|text| text.parse().ok())
            .map(Endpoint::new),
        keepalive: (keepalive_secs > 0).then(|| Duration::from_secs(u64::from(keepalive_secs))),
    })
}

/// Which `Class` a status becomes.
///
/// | the coordinator said | what a caller may do | why |
/// |---|---|---|
/// | `400`, anything else unexpected | `Fatal` | this build sent something the coordinator cannot read, and sending it again changes nothing |
/// | `401` | `Recoverable` | the identity, the clock or the replay window: something has to change first, and that something may be a fresh enrollment |
/// | `403` | `Recoverable`, except at enrollment where it is `Fatal` | a device waiting for approval keeps working once a person approves it; a refused join token never becomes valid |
/// | `404`, `409` | `Recoverable` | the coordinator does not know this device or network yet, or the address is taken |
/// | `429` | `Transient` | the limiter asks for a wait |
/// | `5xx` | `Transient` | the coordinator is briefly unwell |
///
/// A wrong pin never reaches this function: it fails the handshake, and `transport_error` is what
/// turns it into `Class::Trust`.
fn status_error(path: &str, status: StatusCode, body: &[u8], call: Call) -> PortError {
    let detail = match serde_json::from_slice::<ErrorBody>(body) {
        Ok(error) => format!(
            "{status} {path}: {} ({})",
            error.error.message, error.error.code
        ),
        Err(_) => {
            let text = String::from_utf8_lossy(body);
            let text = text.trim();
            if text.is_empty() {
                format!("{status} {path}: no detail")
            } else {
                format!("{status} {path}: {text}")
            }
        }
    };
    let class = match status {
        StatusCode::BAD_REQUEST => Class::Fatal,
        StatusCode::UNAUTHORIZED => Class::Recoverable,
        StatusCode::FORBIDDEN => match call {
            Call::Enroll => Class::Fatal,
            Call::Signed => Class::Recoverable,
        },
        StatusCode::NOT_FOUND | StatusCode::CONFLICT => Class::Recoverable,
        StatusCode::TOO_MANY_REQUESTS => Class::Transient,
        _ if status.is_server_error() => Class::Transient,
        _ => Class::Fatal,
    };
    PortError::new(class, detail)
}

async fn ok_bytes(
    path: &str,
    response: reqwest::Response,
    call: Call,
) -> Result<Vec<u8>, PortError> {
    let status = response.status();
    let bytes = response.bytes().await.map_err(|error| {
        PortError::transient(format!("{path}: the answer could not be read: {error}"))
    })?;
    if status.is_success() {
        return Ok(bytes.to_vec());
    }
    Err(status_error(path, status, &bytes, call))
}

fn serialize<T: serde::Serialize>(path: &str, value: &T) -> Result<Vec<u8>, PortError> {
    serde_json::to_vec(value).map_err(|error| {
        PortError::fatal(format!("{path}: the request did not serialize: {error}"))
    })
}

fn deserialize<T: serde::de::DeserializeOwned>(path: &str, body: &[u8]) -> Result<T, PortError> {
    serde_json::from_slice(body).map_err(|error| {
        PortError::fatal(format!(
            "{path}: the answer is not the JSON this build expects: {error}"
        ))
    })
}

fn header(response: &reqwest::Response, name: reqwest::header::HeaderName) -> Option<String> {
    response
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
}

/// The origin every request goes to, with nothing a URL can hide behind it.
fn normalize_origin(origin: &str) -> Result<String, PortError> {
    let origin = origin.trim().trim_end_matches('/');
    let Some(rest) = origin.strip_prefix("https://") else {
        return Err(PortError::fatal(format!(
            "{origin}: a coordinator is reached over https, and this address is not one"
        )));
    };
    if rest.is_empty()
        || rest.contains('@')
        || rest.contains('/')
        || rest.contains('?')
        || rest.contains('#')
    {
        return Err(PortError::fatal(format!(
            "{origin}: a coordinator's origin is a host and an optional port, with no user \
             information, no path and no query"
        )));
    }
    Ok(origin.to_string())
}

/// `10.77.0.0/16` or `fd00::/64`, as the core prefix type.
fn parse_prefix(text: &str) -> Option<Allowed> {
    let (address, bits) = text.split_once('/')?;
    let bits: u8 = bits.parse().ok()?;
    match address.parse::<std::net::IpAddr>().ok()? {
        std::net::IpAddr::V4(address) => {
            (bits <= 32).then_some(Allowed::V4(address.octets(), bits))
        }
        std::net::IpAddr::V6(address) => {
            (bits <= 128).then_some(Allowed::V6(address.octets(), bits))
        }
    }
}

/// The address a device holds in the tunnel, out of either shape the API uses.
///
/// Enrollment answers with the bare address and the network separately — the prefix belongs to the
/// network rather than to the device — while a configuration snapshot carries the two joined, as
/// the coordinator's `with_network_prefix` writes it. Both reach this function and both come out
/// as one prefix, because that is what the interface is given.
fn tunnel_prefix(address: &str, network_cidr: &str) -> Option<Allowed> {
    if let Some(prefix) = parse_prefix(address) {
        return Some(prefix);
    }
    let address: std::net::IpAddr = address.parse().ok()?;
    let network = parse_prefix(network_cidr)?;
    // A bare address only borrows the length of a network of its own family: a `10.77.0.2` in a
    // `fd00::/64` is a disagreement about the world, not a prefix to carry.
    match (address, network) {
        (std::net::IpAddr::V4(address), Allowed::V4(_, bits)) => {
            Some(Allowed::V4(address.octets(), bits))
        }
        (std::net::IpAddr::V6(address), Allowed::V6(_, bits)) => {
            Some(Allowed::V6(address.octets(), bits))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_origin_is_https_and_nothing_else() {
        assert_eq!(
            normalize_origin("https://coordinator.example/").expect("valid"),
            "https://coordinator.example"
        );
        assert_eq!(
            normalize_origin("https://127.0.0.1:8443").expect("valid"),
            "https://127.0.0.1:8443"
        );
        for bad in [
            "http://coordinator.example",
            "https://user@coordinator.example",
            "https://coordinator.example/v1",
            "https://",
            "coordinator.example",
        ] {
            assert!(normalize_origin(bad).is_err(), "{bad} was accepted");
        }
    }

    #[test]
    fn a_prefix_is_read_the_way_the_core_writes_it() {
        assert_eq!(
            parse_prefix("10.77.0.7/16"),
            Some(Allowed::V4([10, 77, 0, 7], 16))
        );
        assert_eq!(parse_prefix("10.77.0.7/33"), None);
        assert_eq!(parse_prefix("10.77.0.7"), None);
        assert_eq!(parse_prefix("not an address/8"), None);
    }

    #[test]
    fn a_bare_address_borrows_the_networks_length() {
        // What enrollment answers: the address alone, and the network beside it.
        assert_eq!(
            tunnel_prefix("10.77.0.7", "10.77.0.0/16"),
            Some(Allowed::V4([10, 77, 0, 7], 16))
        );
        // And what a snapshot answers: the two already joined.
        assert_eq!(
            tunnel_prefix("10.77.0.7/16", "10.77.0.0/16"),
            Some(Allowed::V4([10, 77, 0, 7], 16))
        );
        assert_eq!(
            tunnel_prefix("fd00::7", "fd00::/64"),
            Some(Allowed::V6(
                [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7],
                64
            ))
        );
        assert_eq!(tunnel_prefix("10.77.0.7", "not a cidr"), None);
        assert_eq!(tunnel_prefix("10.77.0.7", "fd00::/64"), None);
    }

    #[test]
    fn a_band_that_is_not_an_address_is_refused_rather_than_dropped() {
        let other = naming::device_id(wgmesh_core::DeviceId(2));
        // `allowed` is the ACL the interface is handed, so a peer whose own address does not parse
        // must not become a peer with nothing allowed: it is a disagreement about the world.
        let peer = PeerBody {
            device_id: other.clone(),
            name: "peer".to_string(),
            wg_pubkey: naming::encode_key(&PublicKey::from_bytes([6u8; 32])),
            tunnel_ip: "not an address".to_string(),
            advertised: Vec::new(),
            relay: None,
            endpoint: None,
            state: "active".to_string(),
        };
        let error = peer_spec(&peer, 25).expect_err("a peer without an address is not a peer");
        assert_eq!(error.class(), Class::Fatal, "{error}");
        assert!(error.detail().contains(&other), "{error}");

        let mut peer = peer;
        peer.tunnel_ip = "10.77.0.2/32".to_string();
        peer.advertised = vec!["10.9.0.0/24".to_string(), "192.168.0.0/33".to_string()];
        let error = peer_spec(&peer, 25).expect_err("a band that is not a prefix is not a band");
        assert!(error.detail().contains("192.168.0.0/33"), "{error}");

        peer.advertised = vec!["10.9.0.0/24".to_string()];
        let spec = peer_spec(&peer, 25).expect("both addresses parse");
        assert_eq!(
            spec.allowed,
            vec![
                Allowed::V4([10, 9, 0, 0], 24),
                Allowed::V4([10, 77, 0, 2], 32)
            ]
        );
    }

    #[test]
    fn a_status_carries_the_class_a_caller_needs() {
        let error = status_error(
            CONFIG_PATH,
            StatusCode::UNAUTHORIZED,
            b"{\"error\":{\"code\":\"unauthorized\",\"message\":\"the request was not authenticated\"}}",
            Call::Signed,
        );
        assert_eq!(error.class(), Class::Recoverable);
        assert!(error.detail().contains("not authenticated"), "{error}");

        let refused = status_error(JOIN_PATH, StatusCode::FORBIDDEN, b"", Call::Enroll);
        assert_eq!(
            refused.class(),
            Class::Fatal,
            "a refused token is not a wait"
        );
        let waiting = status_error(ENDPOINT_PATH, StatusCode::FORBIDDEN, b"", Call::Signed);
        assert_eq!(waiting.class(), Class::Recoverable, "approval is a wait");

        assert_eq!(
            status_error(
                CONFIG_PATH,
                StatusCode::TOO_MANY_REQUESTS,
                b"",
                Call::Signed
            )
            .class(),
            Class::Transient
        );
        assert_eq!(
            status_error(CONFIG_PATH, StatusCode::BAD_REQUEST, b"", Call::Signed).class(),
            Class::Fatal
        );
    }
}
