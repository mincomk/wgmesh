pub mod handlers;

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};

use tokio_stream::StreamExt as _;
use tokio_stream::wrappers::BroadcastStream;
use wgmesh_app::coordinator::PortError;
use wgmesh_app::coordinator::ports::{DeviceState, Directory, RelayState};
use wgmesh_core::rate::{Admission, Metered};
use wgmesh_core::{DeviceId, RelayId};
use wgmesh_metrics::Registry;

use crate::service::Services;
use wgmesh_proto as naming;
use wgmesh_proto::sign as auth;

pub const MAX_BODY_BYTES: usize = 256 * 1024;

/// The allowance `/v1/join` and `/v1/relay/enroll` share, per client address,
/// per minute. Both routes are reachable without a signature, so this is the
/// only thing standing between a stranger and an unbounded number of tries.
pub const JOIN_RATE_LIMIT_PER_MINUTE: u32 = 30;

/// How many client addresses the limiter tracks before it forgets the ones
/// that have gone quiet.
const RATE_LIMIT_TRACKED_IPS: usize = 4096;

#[derive(Clone)]
pub struct AppState {
    pub services: Services,
    /// One bucket per client address, shared by the two unauthenticated
    /// routes.
    pub limiter: Arc<Mutex<Metered<IpAddr>>>,
    /// What `/metrics` renders.
    pub metrics: Arc<Mutex<Registry>>,
}

/// `/v1/join` and `/v1/relay/enroll` are the only two routes reachable without a
/// signature — they are the ones a principal cannot sign for yet. Everything
/// else sits behind one of the two extractors below.
pub fn router(services: Services) -> Router {
    // The allowance is the services' — which is `JOIN_RATE_LIMIT_PER_MINUTE`
    // unless a daemon has read a larger or smaller one from its configuration.
    let allowance = services.join_rate_limit_per_minute;
    let state = AppState {
        services,
        limiter: Arc::new(Mutex::new(Metered::new(
            f64::from(allowance),
            60_000,
            RATE_LIMIT_TRACKED_IPS,
        ))),
        metrics: Arc::new(Mutex::new(Registry::new())),
    };

    // The two routes a principal cannot sign for yet. They are the only ones
    // that carry the per-address allowance, so it sits on their own router.
    let unauthenticated = Router::new()
        .route("/v1/join", post(handlers::join))
        .route("/v1/relay/enroll", post(handlers::relay_enroll))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            limit_unauthenticated,
        ));

    let rest = Router::new()
        .route("/metrics", get(metrics))
        .route(
            "/v1/config",
            get(handlers::config).layer(axum::middleware::from_fn_with_state(
                state.clone(),
                require_device,
            )),
        )
        .route(
            "/v1/endpoint",
            post(handlers::endpoint).layer(axum::middleware::from_fn_with_state(
                state.clone(),
                require_active_device,
            )),
        )
        .route(
            "/v1/punch",
            post(handlers::punch).layer(axum::middleware::from_fn_with_state(
                state.clone(),
                require_active_device,
            )),
        )
        .route(
            "/v1/rotate",
            post(handlers::rotate).layer(axum::middleware::from_fn_with_state(
                state.clone(),
                require_active_device,
            )),
        )
        .route(
            "/v1/relay/assignment",
            get(handlers::relay_assignment).layer(axum::middleware::from_fn_with_state(
                state.clone(),
                require_relay,
            )),
        )
        .route(
            "/v1/relay/observations",
            post(handlers::relay_observations).layer(axum::middleware::from_fn_with_state(
                state.clone(),
                require_relay,
            )),
        )
        .route(
            "/v1/relay/heartbeat",
            post(handlers::relay_heartbeat).layer(axum::middleware::from_fn_with_state(
                state.clone(),
                require_relay,
            )),
        )
        .route(
            "/v1/events",
            get(events).layer(axum::middleware::from_fn_with_state(
                state.clone(),
                require_device,
            )),
        )
        .route(
            "/v1/relay/keyset",
            get(handlers::relay_keyset).layer(axum::middleware::from_fn_with_state(
                state.clone(),
                require_relay,
            )),
        );

    unauthenticated
        .merge(rest)
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            count_requests,
        ))
        .with_state(state)
}

/// Watch the configuration and announce every change on the services'
/// channel, which is what `/v1/events` streams.
///
/// The daemon starts this once; a test starts it itself, which is why it is a
/// function rather than something the router does quietly. The interval is
/// short because the whole point is to beat the thirty-second poll by a wide
/// margin, and the query behind it is a handful of counts.
pub fn watch_config(services: Services) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_millis(500));
        let mut last: Option<u64> = None;
        loop {
            ticker.tick().await;
            let Ok(version) = services.store.config_version().await else {
                continue;
            };
            if last != Some(version) {
                last = Some(version);
                // No subscribers is not an error: it means nobody is streaming.
                let _ = services.updates.send(version);
            }
        }
    })
}

/// Watch the relays and move the pairs of the ones that have stopped being a
/// place a pair may be onto another relay.
///
/// The daemon starts this once, alongside `watch_config`, because nothing else
/// moves an assignment: a relay that dies, an operator's `retire`, and a relay
/// that says it is draining all leave their pairs where they are until a sweep
/// runs, and this is the timer that runs it. A sweep reads the relays of each
/// network and the pairs of the ones that are leaving, and writes only what it
/// moves, so the cadence is set by how quickly a pair should be re-homed after
/// the deadline passes rather than by cost. `main` derives it from the window one
/// heartbeat is given.
pub fn watch_relays(services: Services, interval: Duration) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // Not immediately, unlike `watch_config`, which has something to announce
        // the moment it starts. A relay that has not reported since the daemon came
        // up reads as quiet — that is what "never heard from" means — so a sweep at
        // that instant would call every pair of the pool homeless before a single
        // heartbeat had arrived. Waiting one interval lets the relays that are up
        // say so first.
        let start = tokio::time::Instant::now() + interval;
        let mut ticker = tokio::time::interval_at(start, interval);
        // A pair with nowhere to go stays stranded for as long as the pool has no
        // fresh relay, so it is reported when it becomes stranded rather than on
        // every tick that finds it so: a line per interval about a condition that
        // has not changed is noise, and it would bury the moves that did happen.
        let mut stranded: BTreeSet<(RelayId, DeviceId, DeviceId)> = BTreeSet::new();
        loop {
            ticker.tick().await;
            let moved = match services.sweep(services.now()).await {
                Ok(moved) => moved,
                // A sweep that could not read the store is worth saying out loud:
                // it means pairs are staying on relays that have gone.
                Err(error) => {
                    eprintln!("wgmeshd: the relay sweep failed: {error}");
                    continue;
                }
            };
            for report in &moved {
                if let Some(to) = report.to {
                    eprintln!(
                        "wgmeshd: pair {} {} moved from relay {} to relay {}",
                        naming::device_id(report.pair.0),
                        naming::device_id(report.pair.1),
                        naming::relay_id(report.from),
                        naming::relay_id(to),
                    );
                }
            }
            let orphaned: BTreeSet<(RelayId, DeviceId, DeviceId)> = moved
                .iter()
                .filter(|report| report.to.is_none())
                .map(|report| (report.from, report.pair.0, report.pair.1))
                .collect();
            for (from, left, right) in orphaned.difference(&stranded) {
                eprintln!(
                    "wgmeshd: pair {} {} has nowhere to go: relay {} is not a place any more and no other relay is fresh",
                    naming::device_id(*left),
                    naming::device_id(*right),
                    naming::relay_id(*from),
                );
            }
            stranded = orphaned;
        }
    })
}

/// The push side of config delivery: the current version first, so a client
/// knows where it stands without a poll, then every change as it happens.
async fn events(State(state): State<AppState>) -> Response {
    let current = state.services.store.config_version().await.unwrap_or(0);
    let receiver = state.services.updates.subscribe();
    let opening = tokio_stream::once(Ok::<Event, std::convert::Infallible>(event_of(current)));
    let live = BroadcastStream::new(receiver).filter_map(|message| match message {
        Ok(version) => Some(Ok(event_of(version))),
        // A client that fell behind is told to re-read the snapshot rather
        // than handed a silent gap.
        Err(_) => Some(Ok(Event::default().event("lagged").data("{}"))),
    });
    Sse::new(opening.chain(live))
        .keep_alive(KeepAlive::new().interval(std::time::Duration::from_secs(15)))
        .into_response()
}

fn event_of(version: u64) -> Event {
    Event::default()
        .event("config")
        .data(serde_json::json!({ "generation": version }).to_string())
}

/// Admit one unauthenticated request, or answer `429` with the wait the caller
/// should observe.
///
/// A request with no peer address in its extensions is attributed to one
/// unnamed bucket rather than waved through: an unattributable request is
/// still a request, and a limiter that silently stops applying is worse than
/// one that is merely coarse.
async fn limit_unauthenticated(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let client = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(address)| address.ip())
        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    let now_ms = state.services.now().as_millis();
    let decision = {
        let mut limiter = state
            .limiter
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        limiter.take(client, 1.0, now_ms)
    };
    match decision {
        Admission::Allow => Ok(next.run(request).await),
        // The refusal is counted once, by the layer that wraps the whole
        // surface: it sees the 429 on the way out and would otherwise count it
        // a second time.
        Admission::Deny { retry_after_secs } => Err(ApiError::rate_limited(retry_after_secs)),
    }
}

/// Count every answer by route and status class, which is what `/metrics`
/// renders. It wraps the whole surface, so a route added later is counted
/// without anyone remembering to count it.
async fn count_requests(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let path = request.uri().path().to_owned();
    let response = next.run(request).await;
    let status = response.status().as_u16();
    let outcome = if status == StatusCode::TOO_MANY_REQUESTS.as_u16() {
        "rate_limited"
    } else {
        status_class(status)
    };
    state.count(&path, outcome, status);
    response
}

const fn status_class(status: u16) -> &'static str {
    match status / 100 {
        1 => "1xx",
        2 => "2xx",
        3 => "3xx",
        4 => "4xx",
        _ => "5xx",
    }
}

/// The scrape endpoint: the counters this process has kept, as the text a
/// Prometheus scraper reads.
async fn metrics(State(state): State<AppState>) -> Response {
    let body = state
        .metrics
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .render();
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

impl AppState {
    /// Count one answer. `outcome` is a status class for an ordinary answer,
    /// or `rate_limited` for one the limiter refused.
    fn count(&self, endpoint: &str, outcome: &str, status: u16) {
        self.metrics
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .add_counter(
                "wgmesh_requests_total",
                "Answers by route and outcome.",
                &[("endpoint", endpoint), ("outcome", outcome)],
                1.0,
            );
        if status == StatusCode::TOO_MANY_REQUESTS.as_u16() {
            self.metrics
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .add_counter(
                    "wgmesh_rate_limited_total",
                    "Requests the per-address limiter refused.",
                    &[("endpoint", endpoint)],
                    1.0,
                );
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Principal {
    Device,
    Relay,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Gate {
    /// A device still waiting for approval may read its own config, so it can
    /// report that it is waiting.
    PendingOrActive,
    ActiveOnly,
}

async fn require_device(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    authenticate(
        &state,
        request,
        next,
        Principal::Device,
        Gate::PendingOrActive,
    )
    .await
}

async fn require_active_device(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    authenticate(&state, request, next, Principal::Device, Gate::ActiveOnly).await
}

async fn require_relay(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    authenticate(&state, request, next, Principal::Relay, Gate::ActiveOnly).await
}

/// Verify a signed request and put the principal's id in the request
/// extensions. Handlers read the extension and never see the header.
///
/// The order is the design's — identity, state, skew, signature, nonce — with
/// the signature checked before the nonce is spent, so an unsigned request
/// cannot burn a nonce on its way to being rejected.
async fn authenticate(
    state: &AppState,
    request: Request,
    next: Next,
    principal: Principal,
    gate: Gate,
) -> Result<Response, ApiError> {
    let (mut parts, body) = request.into_parts();
    let bytes = axum::body::to_bytes(body, MAX_BODY_BYTES)
        .await
        .map_err(|_| ApiError::unauthorized())?;

    let header = parts
        .headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(ApiError::unauthorized)?;
    let signed = auth::parse_authorization(header).ok_or_else(ApiError::unauthorized)?;

    let now = state.services.now();
    if !auth::within_skew(signed.timestamp, now) {
        return Err(ApiError::unauthorized());
    }

    let message = auth::canonical(
        parts.method.as_str(),
        parts.uri.path(),
        &bytes,
        signed.timestamp,
        &signed.nonce,
    );

    match principal {
        Principal::Device => {
            let id =
                naming::parse_device_id(&signed.identity).ok_or_else(ApiError::unauthorized)?;
            let record = state
                .services
                .store
                .device_by_id(id)
                .await
                .map_err(ApiError::from)?
                .ok_or_else(ApiError::unauthorized)?;
            if record.state == DeviceState::Revoked {
                return Err(ApiError::unauthorized());
            }
            if gate == Gate::ActiveOnly && record.state != DeviceState::Active {
                return Err(ApiError::forbidden("device is not active"));
            }
            if !wgmesh_secrets::verify(&record.api_pubkey, &message, &signed.signature) {
                return Err(ApiError::unauthorized());
            }
            if !state.services.nonces.accept(&signed.nonce, now) {
                return Err(ApiError::unauthorized());
            }
            parts.extensions.insert(id);
        }
        Principal::Relay => {
            let id = naming::parse_relay_id(&signed.identity).ok_or_else(ApiError::unauthorized)?;
            let record = state
                .services
                .store
                .relay_by_id(id)
                .await
                .map_err(ApiError::from)?
                .ok_or_else(ApiError::unauthorized)?;
            if record.state == RelayState::Retired {
                return Err(ApiError::unauthorized());
            }
            if gate == Gate::ActiveOnly && record.state != RelayState::Active {
                return Err(ApiError::forbidden("relay is not active"));
            }
            if !wgmesh_secrets::verify(&record.api_pubkey, &message, &signed.signature) {
                return Err(ApiError::unauthorized());
            }
            if !state.services.nonces.accept(&signed.nonce, now) {
                return Err(ApiError::unauthorized());
            }
            parts.extensions.insert(id);
        }
    }

    Ok(next
        .run(Request::from_parts(parts, Body::from(bytes)))
        .await)
}

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
    /// Set only by the limiter, so a refused client can back off instead of
    /// hammering.
    retry_after_secs: Option<u64>,
}

impl ApiError {
    fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            retry_after_secs: None,
        }
    }

    pub fn rate_limited(retry_after_secs: u64) -> Self {
        let mut error = Self::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "rate limit exceeded",
        );
        error.retry_after_secs = Some(retry_after_secs);
        error
    }

    /// One answer for every way authentication can fail, so a caller cannot
    /// tell an unknown identity from a bad signature.
    pub fn unauthorized() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "the request was not authenticated",
        )
    }

    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, "forbidden", message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", message)
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "bad_request", message)
    }

    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, "conflict", message)
    }

    pub fn unavailable(message: impl Into<String>) -> Self {
        Self::new(StatusCode::SERVICE_UNAVAILABLE, "unavailable", message)
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", message)
    }
}

impl From<PortError> for ApiError {
    fn from(error: PortError) -> Self {
        let detail = error.detail().to_string();
        match error.class() {
            wgmesh_app::coordinator::Class::Transient => Self::unavailable(detail),
            wgmesh_app::coordinator::Class::Recoverable => Self::not_found(detail),
            wgmesh_app::coordinator::Class::Fatal => Self::internal(detail),
            wgmesh_app::coordinator::Class::Trust => Self::forbidden(detail),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = wgmesh_proto::api::ErrorBody::new(self.code, self.message);
        let mut response = (self.status, axum::Json(body)).into_response();
        if let Some(seconds) = self.retry_after_secs {
            if let Ok(value) = HeaderValue::from_str(&seconds.to_string()) {
                response.headers_mut().insert(header::RETRY_AFTER, value);
            }
        }
        response
    }
}

/// The two ids a handler may find in the request extensions.
pub type DevicePrincipal = DeviceId;
pub type RelayPrincipal = RelayId;
