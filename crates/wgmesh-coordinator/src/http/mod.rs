pub mod handlers;

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use wgmesh_app::coordinator::PortError;
use wgmesh_app::coordinator::ports::{DeviceState, Directory, RelayState};
use wgmesh_core::{DeviceId, RelayId};

use crate::service::Services;
use wgmesh_proto as naming;
use wgmesh_proto::sign as auth;

pub const MAX_BODY_BYTES: usize = 256 * 1024;

#[derive(Clone)]
pub struct AppState {
    pub services: Services,
}

/// `/v1/join` and `/v1/relay/enroll` are the only two routes reachable without a
/// signature — they are the ones a principal cannot sign for yet. Everything
/// else sits behind one of the two extractors below.
pub fn router(services: Services) -> Router {
    let state = AppState { services };

    Router::new()
        .route("/v1/join", post(handlers::join))
        .route("/v1/relay/enroll", post(handlers::relay_enroll))
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
            "/v1/relay/keyset",
            get(handlers::relay_keyset).layer(axum::middleware::from_fn_with_state(
                state.clone(),
                require_relay,
            )),
        )
        .with_state(state)
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
}

impl ApiError {
    fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
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
        (self.status, axum::Json(body)).into_response()
    }
}

/// The two ids a handler may find in the request extensions.
pub type DevicePrincipal = DeviceId;
pub type RelayPrincipal = RelayId;
