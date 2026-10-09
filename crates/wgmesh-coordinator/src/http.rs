use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::json;

use wgmesh_proto::signed::{SignedRequest, decode_base64, encode_base64, sha256_hex};

use crate::auth::{self, AuthError, Credential, DeviceState, NonceCache, OneRow};
use crate::store::{AuditEntry, NewDevice, Store, StoreError};

pub const ADMIN_HEADER: &str = "x-wgmesh-admin";

pub trait Clock: Send + Sync {
    fn now_secs(&self) -> i64;
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now_secs(&self) -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|since| since.as_secs() as i64)
            .unwrap_or(0)
    }
}

// The operator's bootstrap credential is not a shared secret between the server
// and its clients, and it is never written to the database: the process holds it
// in memory for as long as it runs, and nothing else on disk knows it. Only its
// SHA-256 is kept here, so a memory dump of the comparison is not a token.
pub struct AdminAuth {
    token_hash: String,
}

impl AdminAuth {
    pub fn from_token(token: &str) -> Self {
        Self {
            token_hash: sha256_hex(token.as_bytes()),
        }
    }

    pub fn verify(&self, token: &str) -> bool {
        self.token_hash
            .eq_ignore_ascii_case(&sha256_hex(token.as_bytes()))
    }
}

#[derive(Clone)]
pub struct AppState {
    pub store: Store,
    pub nonces: Arc<NonceCache>,
    pub admin: Arc<AdminAuth>,
    pub clock: Arc<dyn Clock>,
}

impl AppState {
    pub fn new(store: Store, admin: AdminAuth, clock: Arc<dyn Clock>) -> Self {
        Self {
            store,
            nonces: Arc::new(NonceCache::default()),
            admin: Arc::new(admin),
            clock,
        }
    }
}

#[derive(Debug)]
pub enum ApiError {
    Unauthorized { code: &'static str, detail: String },
    Forbidden { code: &'static str, detail: String },
    BadRequest { code: &'static str, detail: String },
    NotFound { code: &'static str, detail: String },
    Conflict { code: &'static str, detail: String },
    Internal(String),
}

impl ApiError {
    fn unauthorized(code: &'static str, detail: impl Into<String>) -> Self {
        Self::Unauthorized {
            code,
            detail: detail.into(),
        }
    }

    fn forbidden(code: &'static str, detail: impl Into<String>) -> Self {
        Self::Forbidden {
            code,
            detail: detail.into(),
        }
    }

    fn bad_request(code: &'static str, detail: impl Into<String>) -> Self {
        Self::BadRequest {
            code,
            detail: detail.into(),
        }
    }

    fn conflict(code: &'static str, detail: impl Into<String>) -> Self {
        Self::Conflict {
            code,
            detail: detail.into(),
        }
    }

    fn store(error: StoreError) -> Self {
        Self::Internal(error.to_string())
    }
}

impl From<AuthError> for ApiError {
    fn from(error: AuthError) -> Self {
        let detail = error.to_string();
        let code = error.code();
        match error {
            AuthError::NotActive { .. } => Self::Forbidden { code, detail },
            _ => Self::Unauthorized { code, detail },
        }
    }
}

impl From<StoreError> for ApiError {
    fn from(error: StoreError) -> Self {
        Self::store(error)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, detail) = match self {
            Self::Unauthorized { code, detail } => (StatusCode::UNAUTHORIZED, code, detail),
            Self::Forbidden { code, detail } => (StatusCode::FORBIDDEN, code, detail),
            Self::BadRequest { code, detail } => (StatusCode::BAD_REQUEST, code, detail),
            Self::NotFound { code, detail } => (StatusCode::NOT_FOUND, code, detail),
            Self::Conflict { code, detail } => (StatusCode::CONFLICT, code, detail),
            Self::Internal(detail) => (StatusCode::INTERNAL_SERVER_ERROR, "internal", detail),
        };
        (status, Json(json!({ "error": code, "detail": detail }))).into_response()
    }
}

#[derive(Debug, Deserialize)]
pub struct JoinRequest {
    pub token: String,
    pub wg_pubkey: String,
    pub api_pubkey: String,
    pub name: String,
}

#[derive(Debug, Serialize)]
pub struct JoinResponse {
    pub device_id: String,
    pub tunnel_ip: String,
    pub state: &'static str,
}

#[derive(Debug, Serialize)]
pub struct PeerEntry {
    pub device_id: String,
    pub name: String,
    pub wg_pubkey: String,
    pub tunnel_ip: String,
}

#[derive(Debug, Serialize)]
pub struct NetworkInfo {
    pub id: i64,
    pub name: String,
    pub cidr: String,
    pub mtu: i64,
}

#[derive(Debug, Serialize)]
pub struct ConfigSnapshot {
    pub etag: String,
    pub network: NetworkInfo,
    pub peers: Vec<PeerEntry>,
    pub keyset: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct RotateRequest {
    pub wg_pubkey: String,
}

#[derive(Debug, Serialize)]
pub struct AuditView {
    pub ts: i64,
    pub actor: String,
    pub action: String,
    pub detail: String,
}

fn parse_body<T: for<'de> Deserialize<'de>>(body: &[u8]) -> Result<T, ApiError> {
    serde_json::from_slice(body)
        .map_err(|error| ApiError::bad_request("malformed_body", error.to_string()))
}

fn decode_key(text: &str) -> Result<Vec<u8>, ApiError> {
    let bytes = decode_base64(text)
        .ok_or_else(|| ApiError::bad_request("malformed_key", "a public key is not base64"))?;
    if bytes.len() != 32 {
        return Err(ApiError::bad_request(
            "malformed_key",
            "a public key must be 32 bytes",
        ));
    }
    Ok(bytes)
}

fn admin_actor(state: &AppState, headers: &HeaderMap) -> Result<String, ApiError> {
    let token = headers
        .get(ADMIN_HEADER)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| ApiError::unauthorized("missing_admin_credential", "no admin credential"))?;
    if !state.admin.verify(token) {
        return Err(ApiError::unauthorized(
            "bad_admin_credential",
            "the admin credential is wrong",
        ));
    }
    Ok(String::from("admin"))
}

async fn authorize(
    state: &AppState,
    headers: &HeaderMap,
    method: &str,
    path: &str,
    body: &[u8],
) -> Result<Credential, ApiError> {
    let header = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or(ApiError::from(AuthError::Missing))?;
    let request = SignedRequest::parse(header).map_err(AuthError::Malformed)?;
    let credential = state
        .store
        .credential(&request.device_id)
        .await
        .map_err(ApiError::store)?;
    let directory = OneRow(credential);
    let now = state.clock.now_secs();
    auth::authenticate_signed(&request, method, path, body, now, &state.nonces, &directory)
        .map_err(ApiError::from)
}

async fn join(State(state): State<AppState>, body: Bytes) -> Result<Json<JoinResponse>, ApiError> {
    let request: JoinRequest = parse_body(&body)?;
    let now = state.clock.now_secs();

    let redeemed = state
        .store
        .redeem_join_token(&request.token, now)
        .await
        .map_err(ApiError::store)?
        .ok_or_else(|| {
            ApiError::unauthorized(
                "invalid_join_token",
                "the join token is unknown, expired or already used",
            )
        })?;

    if redeemed.kind != "device" {
        return Err(ApiError::forbidden(
            "wrong_token_kind",
            "this token enrolls a relay, not a device",
        ));
    }

    let wg_pubkey = decode_key(&request.wg_pubkey)?;
    let api_pubkey = decode_key(&request.api_pubkey)?;
    let device_key = format!("d_{}", &sha256_hex(&api_pubkey)[..10]);
    let tunnel_ip = state
        .store
        .next_tunnel_ip(redeemed.network_id)
        .await
        .map_err(ApiError::store)?;
    let device_state = if redeemed.auto_approve {
        DeviceState::Active
    } else {
        DeviceState::Pending
    };

    let id = state
        .store
        .insert_device(&NewDevice {
            device_key: device_key.clone(),
            network_id: redeemed.network_id,
            name: request.name.clone(),
            wg_pubkey,
            api_pubkey,
            tunnel_ip: tunnel_ip.clone(),
            state: device_state,
            created_at: now,
        })
        .await
        .map_err(|error| match error {
            StoreError::Sql(sqlx::Error::Database(database))
                if database.is_unique_violation() =>
            {
                ApiError::conflict("already_enrolled", "this public key is already enrolled")
            }
            other => ApiError::store(other),
        })?;

    state
        .store
        .record_audit(&AuditEntry {
            ts: now,
            actor: device_key.clone(),
            action: String::from("join"),
            device_id: Some(id),
            detail: format!("name={} state={}", request.name, device_state.as_str()),
        })
        .await?;

    Ok(Json(JoinResponse {
        device_id: device_key,
        tunnel_ip,
        state: device_state.as_str(),
    }))
}

async fn config(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<ConfigSnapshot>, ApiError> {
    let credential = authorize(&state, &headers, "GET", "/v1/config", &body).await?;
    let now = state.clock.now_secs();
    let device = state
        .store
        .device(&credential.device_id)
        .await
        .map_err(ApiError::store)?
        .ok_or_else(|| ApiError::unauthorized("unknown_identity", "the device is gone"))?;
    let network = state
        .store
        .network(device.network_id)
        .await
        .map_err(ApiError::store)?
        .ok_or_else(|| ApiError::NotFound {
            code: "unknown_network",
            detail: String::from("the network is gone"),
        })?;

    // The peer list is the ACL: a device that is not `active` is simply not in
    // it, and a peer that is missing from here is removed from the kernel on the
    // next convergence, which drops every packet it sends.
    let peers: Vec<PeerEntry> = state
        .store
        .devices_in_state(device.network_id, DeviceState::Active)
        .await?
        .into_iter()
        .filter(|peer| peer.device_key != device.device_key)
        .map(|peer| PeerEntry {
            device_id: peer.device_key,
            name: peer.name,
            wg_pubkey: encode_base64(&peer.wg_pubkey),
            tunnel_ip: peer.tunnel_ip,
        })
        .collect();
    let keyset: Vec<String> = peers.iter().map(|peer| peer.wg_pubkey.clone()).collect();

    state
        .store
        .touch_device(&credential.device_id, now)
        .await?;

    let etag = format!("cfg-{}-{}", peers.len(), sha256_hex(keyset.join(",").as_bytes()).get(..12).unwrap_or("000000000000"));

    Ok(Json(ConfigSnapshot {
        etag,
        network: NetworkInfo {
            id: network.id,
            name: network.name,
            cidr: network.cidr,
            mtu: network.mtu,
        },
        peers,
        keyset,
    }))
}

async fn rotate(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<serde_json::Value>, ApiError> {
    let credential = authorize(&state, &headers, "POST", "/v1/rotate", &body).await?;
    let request: RotateRequest = parse_body(&body)?;
    let wg_pubkey = decode_key(&request.wg_pubkey)?;
    let now = state.clock.now_secs();
    let rotated = state
        .store
        .rotate_wg_key(&credential.device_id, &wg_pubkey, now)
        .await
        .map_err(ApiError::store)?;
    if !rotated {
        return Err(ApiError::Forbidden {
            code: "identity_not_active",
            detail: String::from("only an active device may rotate its tunnel key"),
        });
    }
    state
        .store
        .record_audit(&AuditEntry {
            ts: now,
            actor: credential.device_id.clone(),
            action: String::from("rotate"),
            device_id: None,
            detail: String::from("wg_pubkey"),
        })
        .await?;
    Ok(Json(json!({ "rotated": true })))
}

async fn approve(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(device_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    set_state(state, headers, device_id, DeviceState::Active, "approve").await
}

async fn revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(device_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    set_state(state, headers, device_id, DeviceState::Revoked, "revoke").await
}

async fn set_state(
    state: AppState,
    headers: HeaderMap,
    device_id: String,
    target: DeviceState,
    action: &'static str,
) -> Result<Json<serde_json::Value>, ApiError> {
    let actor = admin_actor(&state, &headers)?;
    let now = state.clock.now_secs();
    let device = state
        .store
        .device(&device_id)
        .await
        .map_err(ApiError::store)?
        .ok_or_else(|| ApiError::NotFound {
            code: "unknown_identity",
            detail: format!("no device is enrolled under {device_id}"),
        })?;
    state
        .store
        .set_device_state(&device_id, target, now)
        .await
        .map_err(ApiError::store)?;
    state
        .store
        .record_audit(&AuditEntry {
            ts: now,
            actor,
            action: String::from(action),
            device_id: Some(device.id),
            detail: format!("{} -> {}", device.state.as_str(), target.as_str()),
        })
        .await?;
    Ok(Json(
        json!({ "device_id": device_id, "state": target.as_str() }),
    ))
}

async fn audit(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<AuditView>>, ApiError> {
    admin_actor(&state, &headers)?;
    let entries = state.store.audit_entries().await.map_err(ApiError::store)?;
    Ok(Json(
        entries
            .into_iter()
            .map(|entry| AuditView {
                ts: entry.ts,
                actor: entry.actor,
                action: entry.action,
                detail: entry.detail,
            })
            .collect(),
    ))
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/join", post(join))
        .route("/v1/config", get(config))
        .route("/v1/rotate", post(rotate))
        .route("/v1/devices/{device_id}/approve", post(approve))
        .route("/v1/devices/{device_id}/revoke", post(revoke))
        .route("/v1/audit", get(audit))
        .with_state(state)
}
