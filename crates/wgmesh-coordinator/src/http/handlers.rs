use std::net::SocketAddr;

use axum::Json;
use axum::extract::{Extension, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use wgmesh_app::coordinator::net::{host_prefix, parse_port_range};
use wgmesh_app::coordinator::ports::{
    AuditEntry, DeviceState, Directory, Network, NewRelay, Relay, RelayState, Reports, TokenKind,
    TokenStore,
};
use wgmesh_app::coordinator::{
    ApproveError, ConfigError, ConfigSnapshot, Heartbeat, JoinError, JoinRequest, Observation,
    PlaceError, PunchOutcome, PunchReport, ReportError, TrafficSample,
};
use wgmesh_core::{DeviceId, Endpoint, Millis, RelayId};

use super::{ApiError, AppState};
use wgmesh_proto as naming;
use wgmesh_proto::api::{
    Ack, AssignmentResponse, ConfigResponse, EndpointBody, HeartbeatBody, JoinBody, JoinResponse,
    KeysetNetwork, KeysetResponse, MeBody, NetworkBody, ObservationIn, ObservationsBody, PairBody,
    PeerBody, PunchBody, RelayBody, RelayEnrollBody, RelayEnrollResponse, RelayViewBody,
    RotateBody, SelfObservationBody, SlotBody, TrafficIn,
};
use wgmesh_proto::sign::etag;
use wgmesh_proto::token;
use wgmesh_proto::{decode_key, encode_key};

pub async fn join(
    State(state): State<AppState>,
    Json(body): Json<JoinBody>,
) -> Result<Json<JoinResponse>, ApiError> {
    let wg_pubkey = decode_key(&body.wg_pubkey)
        .ok_or_else(|| ApiError::bad_request("wg_pubkey must be a 32-byte base64 key"))?;
    let api_pubkey = decode_key(&body.api_pubkey)
        .ok_or_else(|| ApiError::bad_request("api_pubkey must be a 32-byte base64 key"))?;

    let outcome = state
        .services
        .join_device()
        .execute(JoinRequest {
            // A token that does not decode becomes `None` and is refused on the
            // same path as one that was already spent.
            token_hash: token::hash_token_text(&body.token),
            name: body.name.trim().to_string(),
            wg_pubkey,
            api_pubkey,
            advertised: body.advertised,
        })
        .await
        .map_err(join_error)?;

    Ok(Json(JoinResponse {
        device_id: naming::device_id(outcome.device_id),
        state: outcome.state.as_str().to_string(),
        network: network_body(&outcome.network),
        tunnel_ip: outcome.tunnel_ip,
        peers: outcome.peers.iter().map(peer_body).collect(),
        relay_pool: outcome.relay_pool.iter().map(relay_body).collect(),
    }))
}

/// The snapshot, with an ETag over its own body so a node that is already in
/// step gets a 304 and no work.
pub async fn config(
    State(state): State<AppState>,
    Extension(device): Extension<DeviceId>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let snapshot = state
        .services
        .build_config()
        .execute(device)
        .await
        .map_err(config_error)?;

    let mut body = config_body(&snapshot);
    body.etag = String::new();
    let tag = etag(&body).ok_or_else(|| ApiError::internal("the snapshot did not serialize"))?;
    body.etag = tag.clone();

    if headers
        .get(header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        == Some(tag.as_str())
    {
        return Ok((StatusCode::NOT_MODIFIED, [(header::ETAG, tag)]).into_response());
    }

    Ok((StatusCode::OK, [(header::ETAG, tag)], axum::Json(body)).into_response())
}

/// A device's own report: the bands it routes for others, and where it believes
/// it is. Relay-sourced observations stay relay-sourced — the coordinator never
/// mixes the two, because a mapping depends on which relay saw it.
pub async fn endpoint(
    State(state): State<AppState>,
    Extension(device): Extension<DeviceId>,
    Json(body): Json<EndpointBody>,
) -> Result<Json<Ack>, ApiError> {
    let now = state.services.now();

    if let Some(bands) = body.advertised {
        let record = state
            .services
            .store
            .device_by_id(device)
            .await
            .map_err(ApiError::from)?
            .ok_or_else(|| ApiError::not_found("no such device"))?;
        let mut advertised = vec![host_prefix(&record.tunnel_ip)];
        for band in bands {
            if !advertised.contains(&band) {
                advertised.push(band);
            }
        }
        state
            .services
            .store
            .set_device_advertised(device, &advertised)
            .await
            .map_err(ApiError::from)?;
    }

    if let Some(observed) = body.observed {
        let address = address_of(&observed.ip, observed.port)?;
        state
            .services
            .store
            .audit(&AuditEntry {
                at: observed.seen_at_ms.map(Millis::from_millis).unwrap_or(now),
                actor: "device".to_string(),
                action: "endpoint.observed".to_string(),
                network_id: None,
                device_id: Some(device),
                relay_id: None,
                detail: Some(address.to_string()),
            })
            .await
            .map_err(ApiError::from)?;
    }

    state
        .services
        .store
        .touch_device(device, now)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(Ack::new()))
}

pub async fn punch(
    State(state): State<AppState>,
    Extension(device): Extension<DeviceId>,
    Json(body): Json<PunchBody>,
) -> Result<Json<Ack>, ApiError> {
    let peer = naming::parse_device_id(&body.peer)
        .ok_or_else(|| ApiError::bad_request("peer must be a device id"))?;
    let outcome = match body.outcome.as_str() {
        "direct" => PunchOutcome::Direct,
        "relayed" => PunchOutcome::Relayed,
        "failed" => PunchOutcome::Failed,
        _ => {
            return Err(ApiError::bad_request(
                "outcome must be direct, relayed or failed",
            ));
        }
    };
    let at = state.services.now();
    state
        .services
        .record_punch(PunchReport { peer, outcome, at })
        .await
        .map_err(ApiError::from)?;
    state
        .services
        .store
        .touch_device(device, at)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(Ack::new()))
}

pub async fn rotate(
    State(state): State<AppState>,
    Extension(device): Extension<DeviceId>,
    Json(body): Json<RotateBody>,
) -> Result<Json<Ack>, ApiError> {
    let key = decode_key(&body.wg_pubkey)
        .ok_or_else(|| ApiError::bad_request("wg_pubkey must be a 32-byte base64 key"))?;
    state
        .services
        .store
        .set_device_wg_pubkey(device, &key)
        .await
        .map_err(ApiError::from)?;
    state
        .services
        .store
        .audit(&AuditEntry {
            at: state.services.now(),
            actor: format!("device:{}", naming::device_id(device)),
            action: "device.rotate".to_string(),
            network_id: None,
            device_id: Some(device),
            relay_id: None,
            detail: None,
        })
        .await
        .map_err(ApiError::from)?;
    Ok(Json(Ack::new()))
}

pub async fn relay_enroll(
    State(state): State<AppState>,
    Json(body): Json<RelayEnrollBody>,
) -> Result<Json<RelayEnrollResponse>, ApiError> {
    let api_pubkey = decode_key(&body.api_pubkey)
        .ok_or_else(|| ApiError::bad_request("api_pubkey must be a 32-byte base64 key"))?;
    if parse_port_range(&body.port_range).is_none() {
        return Err(ApiError::bad_request(
            "port_range must look like 51820-51999",
        ));
    }

    let now = state.services.now();
    let grant = match token::hash_token_text(&body.token) {
        Some(hash) => state
            .services
            .store
            .consume_join_token(&hash, TokenKind::Relay, now)
            .await
            .map_err(ApiError::from)?,
        None => None,
    };
    let grant = grant.ok_or_else(|| ApiError::forbidden("the join token was refused"))?;

    let relay = state
        .services
        .store
        .insert_relay(&NewRelay {
            name: body.name.trim().to_string(),
            api_pubkey,
            state: if grant.auto_approve {
                RelayState::Active
            } else {
                RelayState::Pending
            },
            endpoint_host: body.endpoint_host,
            port_range: body.port_range,
            region: body.region,
            provider: body.provider,
            operator: body.operator,
            created_at: now,
        })
        .await
        .map_err(ApiError::from)?;

    let offered = state
        .services
        .store
        .networks()
        .await
        .map_err(ApiError::from)?;
    let serving: Vec<Network> = if body.networks.is_empty() {
        offered
    } else {
        offered
            .into_iter()
            .filter(|network| body.networks.contains(&network.name))
            .collect()
    };
    for network in &serving {
        state
            .services
            .store
            .link_relay_network(relay.id, network.id)
            .await
            .map_err(ApiError::from)?;
    }

    state
        .services
        .store
        .audit(&AuditEntry {
            at: now,
            actor: "relay".to_string(),
            action: "relay.enroll".to_string(),
            network_id: None,
            device_id: None,
            relay_id: Some(relay.id),
            detail: Some(format!(
                "host={} state={}",
                relay.endpoint_host,
                relay.state.as_str()
            )),
        })
        .await
        .map_err(ApiError::from)?;

    Ok(Json(RelayEnrollResponse {
        relay_id: naming::relay_id(relay.id),
        name: relay.name,
        endpoint_host: relay.endpoint_host,
        port_range: relay.port_range,
        state: relay.state.as_str().to_string(),
        networks: serving.iter().map(network_body).collect(),
    }))
}

pub async fn relay_assignment(
    State(state): State<AppState>,
    Extension(relay): Extension<RelayId>,
) -> Result<Json<AssignmentResponse>, ApiError> {
    let assignment = state
        .services
        .relay_assignment(relay)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(assignment))
}

pub async fn relay_keyset(
    State(state): State<AppState>,
    Extension(relay): Extension<RelayId>,
) -> Result<Json<KeysetResponse>, ApiError> {
    let keyset = state
        .services
        .relay_keyset(relay)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(keyset))
}

pub async fn relay_observations(
    State(state): State<AppState>,
    Extension(relay): Extension<RelayId>,
    Json(body): Json<ObservationsBody>,
) -> Result<Json<Ack>, ApiError> {
    let now = state.services.now();
    let observations: Vec<Observation> = body
        .observations
        .iter()
        .map(|entry| observation_of(entry, now))
        .collect::<Result<_, ApiError>>()?;

    state
        .services
        .record_observations()
        .execute(relay, &observations)
        .await
        .map_err(report_error)?;
    Ok(Json(Ack::new()))
}

pub async fn relay_heartbeat(
    State(state): State<AppState>,
    Extension(relay): Extension<RelayId>,
    Json(body): Json<HeartbeatBody>,
) -> Result<Json<Ack>, ApiError> {
    let now = state.services.now();
    let traffic: Vec<TrafficSample> = body
        .traffic
        .iter()
        .map(|entry| traffic_of(entry, now))
        .collect::<Result<_, ApiError>>()?;

    state
        .services
        .ingest_heartbeat()
        .execute(
            relay,
            &Heartbeat {
                at: now,
                agent_version: body.agent_version,
                traffic,
                draining: body.draining,
            },
        )
        .await
        .map_err(report_error)?;

    // The same reading that moves pairs off a quiet relay.
    state
        .services
        .ingest_heartbeat()
        .sweep(now)
        .await
        .map_err(report_error)?;

    Ok(Json(Ack::new()))
}

fn observation_of(entry: &ObservationIn, now: Millis) -> Result<Observation, ApiError> {
    let device = naming::parse_device_id(&entry.device_id)
        .ok_or_else(|| ApiError::bad_request("device_id must be a device id"))?;
    let address = address_of(&entry.ip, entry.port)?;
    Ok(Observation {
        device,
        endpoint: Endpoint::new(address),
        seen_at: entry.seen_at_ms.map(Millis::from_millis).unwrap_or(now),
    })
}

fn traffic_of(entry: &TrafficIn, now: Millis) -> Result<TrafficSample, ApiError> {
    let device = naming::parse_device_id(&entry.device_id)
        .ok_or_else(|| ApiError::bad_request("device_id must be a device id"))?;
    Ok(TrafficSample {
        device,
        rx_bytes: entry.rx_bytes,
        tx_bytes: entry.tx_bytes,
        period_start: entry
            .period_start_ms
            .map(Millis::from_millis)
            .unwrap_or(now),
    })
}

fn address_of(host: &str, port: u16) -> Result<SocketAddr, ApiError> {
    format!("{host}:{port}")
        .parse()
        .map_err(|_| ApiError::bad_request("not an address"))
}

fn network_body(network: &Network) -> NetworkBody {
    NetworkBody {
        id: network.id,
        name: network.name.clone(),
        cidr: network.cidr.clone(),
        mtu: network.mtu,
        relay_policy: network.relay_policy.clone(),
    }
}

fn peer_body(peer: &wgmesh_app::coordinator::PeerView) -> PeerBody {
    PeerBody {
        device_id: naming::device_id(peer.id),
        name: peer.name.clone(),
        wg_pubkey: encode_key(&peer.wg_pubkey),
        tunnel_ip: peer.tunnel_ip.clone(),
        advertised: peer.advertised.clone(),
        relay: peer.relay.map(naming::relay_id),
        endpoint: peer.endpoint.map(|endpoint| endpoint.addr().to_string()),
        state: peer.state.as_str().to_string(),
    }
}

fn relay_body(entry: &wgmesh_app::coordinator::RelayPoolEntry) -> RelayBody {
    RelayBody {
        relay_id: naming::relay_id(entry.id),
        name: entry.name.clone(),
        endpoint_host: entry.endpoint_host.clone(),
        port_range: entry.port_range.clone(),
        region: entry.region.clone(),
        state: entry.state.as_str().to_string(),
        slot_port: entry.slot_port,
    }
}

fn config_body(snapshot: &ConfigSnapshot) -> ConfigResponse {
    ConfigResponse {
        etag: String::new(),
        network: network_body(&snapshot.network),
        me: MeBody {
            device_id: naming::device_id(snapshot.me.id),
            tunnel_ip: snapshot.me.tunnel_ip.clone(),
            state: snapshot.me.state.as_str().to_string(),
            slot_port: snapshot.me.slot_port,
            observed: snapshot.me.observed.map(|observed| SelfObservationBody {
                endpoint: observed.endpoint.addr().to_string(),
                seen_at_ms: observed.seen_at.0,
            }),
        },
        relay: RelayViewBody {
            assigned: snapshot.relay.assigned.map(naming::relay_id),
            slots: snapshot.relay.slots.iter().map(relay_body).collect(),
        },
        peers: snapshot.peers.iter().map(peer_body).collect(),
        keepalive_secs: snapshot.keepalive_secs,
    }
}

fn join_error(error: JoinError) -> ApiError {
    match error {
        // Deliberately one answer: unknown, expired, revoked and exhausted all
        // look the same from outside.
        JoinError::TokenRefused => ApiError::forbidden("the join token was refused"),
        JoinError::NetworkUnknown(id) => ApiError::not_found(format!("no network {id}")),
        JoinError::NetworkFull { limit } => {
            ApiError::forbidden(format!("the network holds its limit of {limit} devices"))
        }
        JoinError::AddressExhausted => ApiError::conflict("no free tunnel address"),
        JoinError::Duplicate(what) => {
            ApiError::conflict(format!("a device with that {what} already exists"))
        }
        JoinError::Placement(inner) => ApiError::internal(format!("placement failed: {inner}")),
        JoinError::Store(inner) => ApiError::from(inner),
    }
}

fn config_error(error: ConfigError) -> ApiError {
    match error {
        ConfigError::UnknownDevice(id) => ApiError::not_found(format!("no device {}", id.0)),
        ConfigError::UnknownNetwork(id) => ApiError::not_found(format!("no network {id}")),
        ConfigError::Store(inner) => ApiError::from(inner),
    }
}

fn report_error(error: ReportError) -> ApiError {
    match error {
        ReportError::UnknownRelay(id) => ApiError::not_found(format!("no relay {}", id.0)),
        ReportError::UnknownDevice(id) => ApiError::not_found(format!("no device {}", id.0)),
        ReportError::NotLinked(relay, network) => ApiError::forbidden(format!(
            "relay {} does not serve network {network}",
            relay.0
        )),
        ReportError::Store(inner) => ApiError::from(inner),
    }
}

pub fn approve_error(error: ApproveError) -> ApiError {
    match error {
        ApproveError::UnknownDevice(id) => ApiError::not_found(format!("no device {}", id.0)),
        ApproveError::NotApprovable(state) => {
            ApiError::forbidden(format!("a {} device cannot be approved", state.as_str()))
        }
        ApproveError::Placement(inner) => ApiError::internal(format!("placement failed: {inner}")),
        ApproveError::Store(inner) => ApiError::from(inner),
    }
}

pub fn place_error(error: PlaceError) -> ApiError {
    match error {
        PlaceError::UnknownDevice(id) => ApiError::not_found(format!("no device {}", id.0)),
        PlaceError::NotActive(id) => ApiError::forbidden(format!("device {} is not active", id.0)),
        PlaceError::NetworkMismatch(left, right) => ApiError::bad_request(format!(
            "devices {} and {} are on different networks",
            left.0, right.0
        )),
        PlaceError::NoRelayAvailable => ApiError::conflict("no relay is available"),
        PlaceError::Store(inner) => ApiError::from(inner),
    }
}

pub fn device_state_name(state: DeviceState) -> &'static str {
    state.as_str()
}

pub fn relay_state_name(state: RelayState) -> &'static str {
    state.as_str()
}

pub fn relay_record_body(record: &Relay) -> RelayBody {
    RelayBody {
        relay_id: naming::relay_id(record.id),
        name: record.name.clone(),
        endpoint_host: record.endpoint_host.clone(),
        port_range: record.port_range.clone(),
        region: record.region.clone(),
        state: record.state.as_str().to_string(),
        slot_port: None,
    }
}

pub fn slot_body(device: DeviceId, udp_port: u16) -> SlotBody {
    SlotBody {
        device_id: naming::device_id(device),
        udp_port,
    }
}

pub fn pair_body(pair: (DeviceId, DeviceId)) -> PairBody {
    PairBody {
        a: naming::device_id(pair.0),
        b: naming::device_id(pair.1),
    }
}

pub fn keyset_body(network: &Network, peers: Vec<(DeviceId, String)>) -> KeysetNetwork {
    KeysetNetwork {
        id: network.id,
        name: network.name.clone(),
        peers: peers
            .into_iter()
            .map(|(device, wg_pubkey)| wgmesh_proto::api::KeysetPeer {
                device_id: naming::device_id(device),
                wg_pubkey,
            })
            .collect(),
    }
}
