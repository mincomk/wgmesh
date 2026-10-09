use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, UNIX_EPOCH};

use axum::body::Body;
use axum::extract::{ConnectInfo, Extension, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use tokio_stream::StreamExt as _;
use tokio_stream::wrappers::BroadcastStream;

use wgmesh_config::coordinator as settings;
use wgmesh_core::rate::{Admission, Metered};
use wgmesh_metrics::Registry;
use wgmesh_proto::{
    ConfigEvent, JoinRequest, JoinResponse, ObservationBatch, RelayAssignment, RelayEnrollRequest,
    RelayEnrollResponse, RelayHeartbeat, canonical, parse_authorization,
};

use crate::store::{JoinError, Store, now_unix};

/// The largest request body a signature is verified over. Anything bigger is
/// refused before the body is buffered.
const MAX_BODY_BYTES: usize = 256 * 1024;

/// One refusal, in the shape every handler returns it.
#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub message: String,
    pub retry_after_secs: Option<u64>,
}

impl ApiError {
    pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
            retry_after_secs: None,
        }
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }

    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, message)
    }

    pub fn too_many_requests(retry_after_secs: u64) -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            message: "rate limit exceeded".to_owned(),
            retry_after_secs: Some(retry_after_secs),
        }
    }

    pub fn unavailable(message: impl Into<String>) -> Self {
        Self::new(StatusCode::SERVICE_UNAVAILABLE, message)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = Json(serde_json::json!({ "error": self.message }));
        let mut response = (self.status, body).into_response();
        if let Some(seconds) = self.retry_after_secs {
            if let Ok(value) = HeaderValue::from_str(&seconds.to_string()) {
                response.headers_mut().insert(header::RETRY_AFTER, value);
            }
        }
        response
    }
}

/// The identity a middleware established for this request.
#[derive(Clone, Debug)]
pub struct Authed {
    pub id: String,
}

/// Signature identity, with the skew and replay checks the design calls for.
///
/// This is state the store does not own: a request that fails verification
/// must leave no trace in the world.
#[derive(Debug, Default)]
pub struct NonceCache {
    seen: HashMap<(String, String), u64>,
}

impl NonceCache {
    pub fn accept(&mut self, id: &str, nonce: &[u8], now: u64, ttl_secs: u64) -> bool {
        self.prune(now);
        let key = (id.to_owned(), STANDARD.encode(nonce));
        if self.seen.contains_key(&key) {
            return false;
        }
        self.seen.insert(key, now + ttl_secs);
        true
    }

    fn prune(&mut self, now: u64) {
        if self.seen.len() < 4096 {
            return;
        }
        self.seen.retain(|_, expires_at| *expires_at > now);
    }
}

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<Mutex<Store>>,
    pub metrics: Arc<Mutex<Registry>>,
    pub limiter: Arc<Mutex<Metered<IpAddr>>>,
    pub nonces: Arc<Mutex<NonceCache>>,
    pub settings: Arc<settings::Settings>,
}

impl AppState {
    pub fn new(settings: settings::Settings) -> Self {
        let store = Store::new(&settings);
        let limiter = Metered::new(
            f64::from(settings.policy.join_rate_limit_per_minute),
            60_000,
            settings.policy.rate_limit_tracked_ips,
        );
        Self {
            store: Arc::new(Mutex::new(store)),
            metrics: Arc::new(Mutex::new(Registry::new())),
            limiter: Arc::new(Mutex::new(limiter)),
            nonces: Arc::new(Mutex::new(NonceCache::default())),
            settings: Arc::new(settings),
        }
    }

    fn store(&self) -> MutexGuard<'_, Store> {
        self.store
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn metrics(&self) -> MutexGuard<'_, Registry> {
        self.metrics
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Count one request outcome. `endpoint` is the route, `outcome` is what
    /// became of it.
    fn count(&self, endpoint: &str, outcome: &str) {
        self.metrics().add_counter(
            "wgmesh_requests_total",
            "Requests by endpoint and outcome.",
            &[("endpoint", endpoint), ("outcome", outcome)],
            1.0,
        );
    }

    /// Admit one unauthenticated request from `client`, or refuse it with the
    /// wait the caller should observe.
    fn admit(&self, endpoint: &str, client: IpAddr, now_ms: u64) -> Result<(), ApiError> {
        let mut limiter = self
            .limiter
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match limiter.take(client, 1.0, now_ms) {
            Admission::Allow => Ok(()),
            Admission::Deny { retry_after_secs } => {
                drop(limiter);
                self.metrics().add_counter(
                    "wgmesh_rate_limited_total",
                    "Requests refused by the per-address limiter.",
                    &[("endpoint", endpoint)],
                    1.0,
                );
                self.count(endpoint, "rate_limited");
                Err(ApiError::too_many_requests(retry_after_secs))
            }
        }
    }
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

/// The whole HTTP surface. `/v1/join` and `/v1/relay/enroll` are the only
/// routes a stranger can reach.
pub fn router(state: AppState) -> Router {
    let devices = Router::new()
        .route("/v1/config", get(config))
        .route("/v1/events", get(events))
        .route("/v1/endpoint", post(report_endpoint))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_device,
        ));

    let relays = Router::new()
        .route("/v1/relay/assignment", get(relay_assignment))
        .route("/v1/relay/observations", post(relay_observations))
        .route("/v1/relay/heartbeat", post(relay_heartbeat))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_relay));

    let public = Router::new()
        .route("/v1/join", post(join))
        .route("/v1/relay/enroll", post(relay_enroll))
        .route("/metrics", get(scrape_metrics));

    devices.merge(relays).merge(public).with_state(state)
}

async fn join(
    State(state): State<AppState>,
    ConnectInfo(client): ConnectInfo<SocketAddr>,
    Json(request): Json<JoinRequest>,
) -> Result<Json<JoinResponse>, ApiError> {
    state.admit("/v1/join", client.ip(), now_ms())?;
    let now = now_unix();
    let device = {
        let mut store = state.store();
        match store.join(&request, now) {
            Ok(device) => device,
            Err(error) => {
                drop(store);
                state.count("/v1/join", "refused");
                return Err(match error {
                    JoinError::UnknownToken => {
                        // "not found" and "expired" are deliberately the same
                        // answer, so a token cannot be probed for existence.
                        ApiError::new(StatusCode::FORBIDDEN, "the join token is not usable")
                    }
                    other => ApiError::bad_request(other.to_string()),
                });
            }
        }
    };
    let snapshot = state
        .store()
        .snapshot_for(&device.id)
        .ok_or_else(|| ApiError::unavailable("the device vanished while joining"))?;
    state.count("/v1/join", "joined");
    Ok(Json(JoinResponse {
        device_id: device.id,
        state: device.state,
        snapshot,
    }))
}

async fn relay_enroll(
    State(state): State<AppState>,
    ConnectInfo(client): ConnectInfo<SocketAddr>,
    Json(request): Json<RelayEnrollRequest>,
) -> Result<Json<RelayEnrollResponse>, ApiError> {
    state.admit("/v1/relay/enroll", client.ip(), now_ms())?;
    let now = now_unix();
    let mut store = state.store();
    match store.enroll_relay(&request, now) {
        Ok(relay) => {
            let networks = vec![store.network.name.clone()];
            drop(store);
            state.count("/v1/relay/enroll", "enrolled");
            Ok(Json(RelayEnrollResponse {
                relay_id: relay.id,
                state: relay.state,
                networks,
            }))
        }
        Err(error) => {
            drop(store);
            state.count("/v1/relay/enroll", "refused");
            Err(match error {
                JoinError::UnknownToken => {
                    ApiError::new(StatusCode::FORBIDDEN, "the join token is not usable")
                }
                other => ApiError::bad_request(other.to_string()),
            })
        }
    }
}

async fn config(
    State(state): State<AppState>,
    Extension(auth): Extension<Authed>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let snapshot = {
        let store = state.store();
        store
            .snapshot_for(&auth.id)
            .ok_or_else(|| ApiError::unauthorized("unknown device"))?
    };
    let etag = snapshot.etag.clone();
    if let Some(presented) = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
    {
        if presented.trim_matches('"') == etag {
            state.count("/v1/config", "not_modified");
            let mut response = StatusCode::NOT_MODIFIED.into_response();
            insert_etag(&mut response, &etag);
            return Ok(response);
        }
    }
    state.count("/v1/config", "served");
    let mut response = Json(snapshot).into_response();
    insert_etag(&mut response, &etag);
    Ok(response)
}

fn insert_etag(response: &mut Response, etag: &str) {
    if let Ok(value) = HeaderValue::from_str(&format!("\"{etag}\"")) {
        response.headers_mut().insert(header::ETAG, value);
    }
}

/// The push side of config delivery. It opens with the current generation so a
/// client can tell how far behind its last poll it is, then carries every
/// change as it happens.
async fn events(State(state): State<AppState>, Extension(auth): Extension<Authed>) -> Response {
    let (receiver, opening) = {
        let store = state.store();
        let opening = ConfigEvent {
            kind: "snapshot".to_owned(),
            generation: store.generation,
            etag: store.etag.clone(),
            peer_id: Some(auth.id.clone()),
            relay_id: None,
            message: format!("stream opened at generation {}", store.generation),
        };
        (store.subscribe(), opening)
    };
    state.count("/v1/events", "streamed");

    let opening = tokio_stream::once(Ok::<Event, std::convert::Infallible>(to_sse(&opening)));
    let live = BroadcastStream::new(receiver).filter_map(|message| match message {
        Ok(event) => Some(Ok(to_sse(&event))),
        Err(tokio_stream::wrappers::errors::BroadcastStreamRecvError::Lagged(missed)) => {
            let event = ConfigEvent {
                kind: "lagged".to_owned(),
                generation: 0,
                etag: String::new(),
                peer_id: None,
                relay_id: None,
                message: format!("{missed} events missed — re-read the snapshot"),
            };
            Some(Ok(to_sse(&event)))
        }
    });
    Sse::new(opening.chain(live))
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
        .into_response()
}

fn to_sse(event: &ConfigEvent) -> Event {
    let data = serde_json::to_string(event).unwrap_or_else(|_| "{}".to_owned());
    Event::default().event("config").data(data)
}

async fn report_endpoint(
    State(state): State<AppState>,
    Extension(auth): Extension<Authed>,
    Json(batch): Json<ObservationBatch>,
) -> Result<StatusCode, ApiError> {
    let now = now_unix();
    let mut store = state.store();
    if let Some(device) = store.devices.get_mut(&auth.id) {
        device.last_seen_at = Some(now);
    }
    let reported = batch.observations.len();
    state.count("/v1/endpoint", "reported");
    Ok(if reported == 0 {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::ACCEPTED
    })
}

async fn relay_assignment(
    State(state): State<AppState>,
    Extension(auth): Extension<Authed>,
) -> Result<Json<RelayAssignment>, ApiError> {
    let assignment = state
        .store()
        .relay_assignment(&auth.id)
        .ok_or_else(|| ApiError::unauthorized("unknown relay"))?;
    state.count("/v1/relay/assignment", "served");
    Ok(Json(assignment))
}

async fn relay_observations(
    State(state): State<AppState>,
    Extension(auth): Extension<Authed>,
    Json(batch): Json<ObservationBatch>,
) -> Result<StatusCode, ApiError> {
    let mut store = state.store();
    let mut accepted = 0usize;
    for observation in &batch.observations {
        store.observe(
            &auth.id,
            &observation.device_id,
            &observation.ip,
            observation.port,
            observation.seen_at,
        );
        accepted += 1;
    }
    drop(store);
    state.count("/v1/relay/observations", "reported");
    Ok(if accepted == 0 {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::ACCEPTED
    })
}

async fn relay_heartbeat(
    State(state): State<AppState>,
    Extension(auth): Extension<Authed>,
    Json(heartbeat): Json<RelayHeartbeat>,
) -> Result<StatusCode, ApiError> {
    let now = now_unix();
    state.store().heartbeat(&auth.id, &heartbeat, now);
    state.count("/v1/relay/heartbeat", "reported");
    Ok(StatusCode::NO_CONTENT)
}

/// The scrape endpoint. Counters come from the registry the handlers write to;
/// the gauges are read out of the store at scrape time, because a stale
/// summary of the world is worse than no summary.
async fn scrape_metrics(State(state): State<AppState>) -> Response {
    let mut registry = state.metrics().clone();
    {
        let store = state.store();
        registry.set_gauge(
            "wgmesh_config_generation",
            "The generation of the config currently being served.",
            &[],
            store.generation as f64,
        );
        registry.set_gauge(
            "wgmesh_devices",
            "Devices by state.",
            &[("state", "active")],
            store
                .devices
                .values()
                .filter(|device| device.state == wgmesh_proto::PeerState::Active)
                .count() as f64,
        );
        registry.set_gauge(
            "wgmesh_devices",
            "Devices by state.",
            &[("state", "pending")],
            store
                .devices
                .values()
                .filter(|device| device.state == wgmesh_proto::PeerState::Pending)
                .count() as f64,
        );
        registry.set_gauge(
            "wgmesh_devices",
            "Devices by state.",
            &[("state", "revoked")],
            store
                .devices
                .values()
                .filter(|device| device.state == wgmesh_proto::PeerState::Revoked)
                .count() as f64,
        );
        for relay in store.relays.values() {
            let labels = [("relay", relay.name.as_str())];
            let age = relay
                .last_heartbeat_at
                .map(|last| now_unix().saturating_sub(last) as f64)
                .unwrap_or(f64::INFINITY);
            registry.set_gauge(
                "wgmesh_relay_last_heartbeat_age_seconds",
                "Seconds since this relay last reported.",
                &labels,
                age,
            );
            registry.add_counter(
                "wgmesh_relay_forwarded_bytes_total",
                "Bytes this relay has forwarded.",
                &labels,
                relay.forwarded_bytes as f64,
            );
            registry.add_counter(
                "wgmesh_relay_forwarded_packets_total",
                "Packets this relay has forwarded.",
                &labels,
                relay.forwarded_packets as f64,
            );
            registry.add_counter(
                "wgmesh_relay_throttled_packets_total",
                "Packets a slot's rate limit refused.",
                &labels,
                relay.throttled_packets as f64,
            );
            registry.set_gauge(
                "wgmesh_relay_misses",
                "Heartbeats missed in a row.",
                &labels,
                f64::from(relay.misses),
            );
        }
        registry.set_gauge(
            "wgmesh_relays",
            "Relays known to this coordinator.",
            &[],
            store.relays.len() as f64,
        );
        registry.set_gauge(
            "wgmesh_pair_assignments",
            "Pairs with a relay assigned.",
            &[],
            store.assignments.len() as f64,
        );
    }
    let body = registry.render();
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
        .into_response()
}

async fn require_device(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state, &mut request, Identity::Device).await?;
    request.extensions_mut().insert(identity);
    Ok(next.run(request).await)
}

async fn require_relay(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let identity = authenticate(&state, &mut request, Identity::Relay).await?;
    request.extensions_mut().insert(identity);
    Ok(next.run(request).await)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Identity {
    Device,
    Relay,
}

async fn authenticate(
    state: &AppState,
    request: &mut Request,
    identity: Identity,
) -> Result<Authed, ApiError> {
    let header = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| ApiError::unauthorized("no authorization header"))?;
    let credentials =
        parse_authorization(header).map_err(|error| ApiError::unauthorized(error.to_string()))?;

    let method = request.method().as_str().to_owned();
    let path = request.uri().path().to_owned();
    let (parts, body) = std::mem::replace(request, Request::new(Body::empty())).into_parts();
    let bytes = axum::body::to_bytes(body, MAX_BODY_BYTES)
        .await
        .map_err(|_| ApiError::bad_request("the request body could not be read"))?;
    *request = Request::from_parts(parts, Body::from(bytes.clone()));

    let now = now_unix() as i64;
    let skew = state.settings.policy.signature_skew_secs;
    if (now - credentials.timestamp).abs() > skew {
        return Err(ApiError::unauthorized(
            "the request timestamp is outside the accepted window",
        ));
    }

    let (public_key, allowed) = {
        let store = state.store();
        match identity {
            Identity::Device => {
                let (key, device_state) = store
                    .api_pubkey_of_device(&credentials.id)
                    .ok_or_else(|| ApiError::unauthorized("unknown device"))?;
                (
                    key,
                    matches!(
                        device_state,
                        wgmesh_proto::PeerState::Active | wgmesh_proto::PeerState::Pending
                    ),
                )
            }
            Identity::Relay => {
                let (key, relay_state) = store
                    .api_pubkey_of_relay(&credentials.id)
                    .ok_or_else(|| ApiError::unauthorized("unknown relay"))?;
                (
                    key,
                    matches!(
                        relay_state,
                        wgmesh_proto::RelayState::Active | wgmesh_proto::RelayState::Draining
                    ),
                )
            }
        }
    };
    if !allowed {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "this identity has been revoked",
        ));
    }

    let key_bytes = STANDARD
        .decode(&public_key)
        .map_err(|_| ApiError::unauthorized("the stored public key is not base64"))?;
    let key_bytes: [u8; 32] = key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| ApiError::unauthorized("the stored public key is not 32 bytes"))?;
    let verifying = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|_| ApiError::unauthorized("the stored public key is not ed25519"))?;
    let signature_bytes: [u8; 64] = credentials
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| ApiError::unauthorized("the signature is not 64 bytes"))?;
    let signature = Signature::from_bytes(&signature_bytes);
    let message = canonical(
        &method,
        &path,
        &bytes,
        credentials.timestamp,
        &credentials.nonce,
    );
    verifying
        .verify(&message, &signature)
        .map_err(|_| ApiError::unauthorized("the signature does not verify"))?;

    {
        let mut nonces = state
            .nonces
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !nonces.accept(
            &credentials.id,
            &credentials.nonce,
            now_unix(),
            state.settings.policy.nonce_ttl_secs,
        ) {
            return Err(ApiError::unauthorized("this nonce has already been used"));
        }
    }

    Ok(Authed { id: credentials.id })
}
