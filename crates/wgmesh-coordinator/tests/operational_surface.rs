#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signer as _, SigningKey};
use http_body_util::BodyExt as _;
use tower::ServiceExt as _;

use wgmesh_config::coordinator as settings;
use wgmesh_coordinator::store::{TokenKind, now_unix};
use wgmesh_coordinator::{AppState, router};
use wgmesh_proto::{
    ConfigEvent, JoinRequest, JoinResponse, RelayEnrollRequest, RelayEnrollResponse, canonical,
};

fn address(last: u8) -> SocketAddr {
    SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, last)),
        40_000 + u16::from(last),
    )
}

fn settings_with(limit: u32) -> settings::Settings {
    let mut settings = settings::Settings::default();
    settings.policy.join_rate_limit_per_minute = limit;
    settings.policy.default_auto_approve = true;
    settings.api.listen = "127.0.0.1:0".to_owned();
    settings
}

fn body_bytes(value: &impl serde::Serialize) -> Vec<u8> {
    serde_json::to_vec(value).expect("the request body serialises")
}

/// Issue one join token of the given kind straight from the store, which is
/// how an operator would.
fn issue(state: &AppState, kind: TokenKind, uses: u32) -> String {
    let mut store = state.store.lock().expect("the store lock is not poisoned");
    store.issue_token(kind, true, uses, 3_600, "test")
}

async fn call(state: &AppState, request: Request<Body>) -> (StatusCode, Vec<u8>) {
    let response = router(state.clone())
        .oneshot(request)
        .await
        .expect("the router answers");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("the body reads")
        .to_bytes();
    (status, bytes.to_vec())
}

fn signature_key() -> SigningKey {
    SigningKey::generate(&mut rand::thread_rng())
}

/// Join a device the way the CLI does: a token, then a signature identity.
async fn join_device(state: &AppState, name: &str, client: SocketAddr) -> (String, SigningKey) {
    let key = signature_key();
    let token = issue(state, TokenKind::Device, 4);
    let request = JoinRequest {
        token,
        wg_pubkey: STANDARD.encode(rand::random::<[u8; 32]>()),
        api_pubkey: STANDARD.encode(key.verifying_key().to_bytes()),
        name: name.to_owned(),
        os: "linux".to_owned(),
        agent_version: "0.1.0".to_owned(),
        advertised: vec![],
    };
    let http = Request::builder()
        .method("POST")
        .uri("/v1/join")
        .header("content-type", "application/json")
        .extension(ConnectInfo(client))
        .body(Body::from(body_bytes(&request)))
        .expect("a well-formed request");
    let (status, bytes) = call(state, http).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "join: {}",
        String::from_utf8_lossy(&bytes)
    );
    let joined: JoinResponse = serde_json::from_slice(&bytes).expect("a join response");
    (joined.device_id, key)
}

async fn enroll_relay(state: &AppState, name: &str, client: SocketAddr) -> (String, SigningKey) {
    let key = signature_key();
    let token = issue(state, TokenKind::Relay, 2);
    let request = RelayEnrollRequest {
        token,
        api_pubkey: STANDARD.encode(key.verifying_key().to_bytes()),
        name: name.to_owned(),
        endpoint_host: "203.0.113.1".to_owned(),
        port_range: [51_820, 51_999],
        region: None,
        provider: None,
    };
    let http = Request::builder()
        .method("POST")
        .uri("/v1/relay/enroll")
        .header("content-type", "application/json")
        .extension(ConnectInfo(client))
        .body(Body::from(body_bytes(&request)))
        .expect("a well-formed request");
    let (status, bytes) = call(state, http).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "enroll: {}",
        String::from_utf8_lossy(&bytes)
    );
    let enrolled: RelayEnrollResponse = serde_json::from_slice(&bytes).expect("an enroll response");
    (enrolled.relay_id, key)
}

/// A request signed the way the design specifies.
fn signed(
    method: &str,
    path: &str,
    body: &[u8],
    id: &str,
    key: &SigningKey,
    client: SocketAddr,
) -> Request<Body> {
    let timestamp = now_unix() as i64;
    let nonce: [u8; 16] = rand::random();
    let message = canonical(method, path, body, timestamp, &nonce);
    let signature = key.sign(&message);
    let header =
        wgmesh_proto::auth::format_authorization(id, timestamp, &nonce, &signature.to_bytes());
    Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", header)
        .header("content-type", "application/json")
        .extension(ConnectInfo(client))
        .body(Body::from(body.to_vec()))
        .expect("a well-formed request")
}

fn unsigned(method: &str, path: &str, body: Vec<u8>, client: SocketAddr) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json")
        .extension(ConnectInfo(client))
        .body(Body::from(body))
        .expect("a well-formed request")
}

fn join_body(state: &AppState, name: &str) -> Vec<u8> {
    let request = JoinRequest {
        token: issue(state, TokenKind::Device, 4),
        wg_pubkey: STANDARD.encode(rand::random::<[u8; 32]>()),
        api_pubkey: STANDARD.encode(rand::random::<[u8; 32]>()),
        name: name.to_owned(),
        os: String::new(),
        agent_version: String::new(),
        advertised: vec![],
    };
    body_bytes(&request)
}

fn enroll_body(state: &AppState, name: &str) -> Vec<u8> {
    let request = RelayEnrollRequest {
        token: issue(state, TokenKind::Relay, 2),
        api_pubkey: STANDARD.encode(rand::random::<[u8; 32]>()),
        name: name.to_owned(),
        endpoint_host: "203.0.113.1".to_owned(),
        port_range: [51_820, 51_999],
        region: None,
        provider: None,
    };
    body_bytes(&request)
}

/// A deliberately small reader for the Prometheus text format: it understands
/// `name{label="value",...} value` and the `#` comments, which is all the
/// exposition has.
fn parse_exposition(text: &str) -> BTreeMap<String, f64> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((series, value)) = line.rsplit_once(' ') else {
            continue;
        };
        let value: f64 = value
            .parse()
            .unwrap_or_else(|_| panic!("not a number: {line}"));
        out.insert(series.to_owned(), value);
    }
    out
}

#[tokio::test]
async fn a_flood_is_refused_with_429_while_other_addresses_are_untouched() {
    let state = AppState::new(settings_with(5));
    let flooder = address(1);

    for index in 0..5 {
        let (status, bytes) = call(
            &state,
            unsigned("POST", "/v1/join", join_body(&state, "flood"), flooder),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "request {index} inside the allowance was refused: {}",
            String::from_utf8_lossy(&bytes)
        );
    }

    let (status, bytes) = call(
        &state,
        unsigned("POST", "/v1/join", join_body(&state, "flood"), flooder),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    let body = String::from_utf8_lossy(&bytes);
    assert!(body.contains("rate limit"), "{body}");

    // The relay enrollment endpoint shares the same per-address allowance, so
    // the flooder is refused there too without spending anything.
    let (status, _) = call(
        &state,
        unsigned(
            "POST",
            "/v1/relay/enroll",
            enroll_body(&state, "r"),
            flooder,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);

    // A different address is not affected by the flooder at all.
    let (status, bytes) = call(
        &state,
        unsigned("POST", "/v1/join", join_body(&state, "quiet"), address(2)),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an ordinary client was caught by another address's flood: {}",
        String::from_utf8_lossy(&bytes)
    );

    let (status, bytes) = call(
        &state,
        unsigned(
            "POST",
            "/v1/relay/enroll",
            enroll_body(&state, "r"),
            address(3),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "relay enrollment from a clean address was refused: {}",
        String::from_utf8_lossy(&bytes)
    );

    // A 429 says how long to wait, so a client can back off instead of
    // hammering.
    let response = router(state.clone())
        .oneshot(unsigned(
            "POST",
            "/v1/join",
            join_body(&state, "flood"),
            flooder,
        ))
        .await
        .expect("the router answers");
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(response.headers().contains_key("retry-after"));

    let (_, metrics) = call(
        &state,
        Request::builder()
            .uri("/metrics")
            .extension(ConnectInfo(address(9)))
            .body(Body::empty())
            .expect("a metrics request"),
    )
    .await;
    let parsed = parse_exposition(&String::from_utf8_lossy(&metrics));
    assert!(
        parsed
            .get("wgmesh_rate_limited_total{endpoint=\"/v1/join\"}")
            .copied()
            .unwrap_or(0.0)
            >= 1.0
    );
}

#[tokio::test]
async fn an_ordinary_client_is_never_refused_at_the_default_allowance() {
    // 12 joins a minute against the documented default of 30: a client that
    // is merely using the service must not see a single 429.
    let state = AppState::new(settings_with(30));
    let client = address(4);
    for _ in 0..12 {
        let (status, _) = call(
            &state,
            unsigned("POST", "/v1/join", join_body(&state, "ordinary"), client),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn a_revocation_reaches_a_streaming_node_long_before_a_poll_would() {
    let state = AppState::new(settings_with(30));
    let (alpha, alpha_key) = join_device(&state, "alpha", address(10)).await;
    let (beta, beta_key) = join_device(&state, "beta", address(11)).await;

    // A node that polls every 30 seconds, as `sync.interval_secs` defaults to.
    let poll_interval = Duration::from_secs(30);

    let request = signed("GET", "/v1/events", b"", &alpha, &alpha_key, address(10));
    let response = router(state.clone())
        .oneshot(request)
        .await
        .expect("the router answers");
    assert_eq!(response.status(), StatusCode::OK);
    let mut stream = response.into_body();

    // The stream opens with the current generation, so a client knows where it
    // stands without a poll.
    let opening = next_event(&mut stream).await;
    assert_eq!(opening.kind, "snapshot");

    let before = Instant::now();
    {
        let mut store = state.store.lock().expect("the store lock is not poisoned");
        assert!(store.revoke_device(&beta), "beta should have been revoked");
    }
    let pushed = next_event(&mut stream).await;
    let elapsed = before.elapsed();

    assert_eq!(pushed.kind, "revoked");
    assert_eq!(pushed.peer_id.as_deref(), Some(beta.as_str()));
    assert!(
        elapsed < Duration::from_secs(1),
        "the push took {elapsed:?}, which a 30-second poll ({poll_interval:?}) could have beaten"
    );

    // And the polled snapshot agrees, so a node that missed the event is not
    // left with a stale peer list.
    let (status, bytes) = call(
        &state,
        signed("GET", "/v1/config", b"", &alpha, &alpha_key, address(10)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let snapshot: wgmesh_proto::ConfigSnapshot =
        serde_json::from_slice(&bytes).expect("a snapshot");
    assert!(
        snapshot.peers.is_empty(),
        "the revoked peer is still listed"
    );

    // A revoked device is refused, which is the other half of revocation.
    let (status, _) = call(
        &state,
        signed("GET", "/v1/config", b"", &beta, &beta_key, address(11)),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a revoked device is still being served"
    );
}

#[tokio::test]
async fn a_relay_reassignment_is_pushed_as_well() {
    let state = AppState::new(settings_with(30));
    let (alpha, alpha_key) = join_device(&state, "alpha", address(20)).await;
    let (beta, _) = join_device(&state, "beta", address(21)).await;
    let (relay_one, _) = enroll_relay(&state, "relay-1", address(22)).await;
    let (relay_two, _) = enroll_relay(&state, "relay-2", address(23)).await;

    let assigned = {
        let store = state.store.lock().expect("the store lock is not poisoned");
        store
            .relay_of_pair(&alpha, &beta)
            .cloned()
            .expect("the pair has a relay")
    };
    assert!(assigned == relay_one || assigned == relay_two);

    let request = signed("GET", "/v1/events", b"", &alpha, &alpha_key, address(20));
    let response = router(state.clone())
        .oneshot(request)
        .await
        .expect("the router answers");
    let mut stream = response.into_body();
    let opening = next_event(&mut stream).await;
    assert_eq!(opening.kind, "snapshot");

    let survivor = if assigned == relay_one {
        relay_two.clone()
    } else {
        relay_one.clone()
    };
    let before = Instant::now();
    let moved = {
        let mut store = state.store.lock().expect("the store lock is not poisoned");
        store.rehome_pairs(&assigned)
    };
    let pushed = next_event(&mut stream).await;
    let elapsed = before.elapsed();

    assert!(!moved.is_empty(), "no pair was moved off the relay");
    assert_eq!(pushed.kind, "reassigned");
    assert_eq!(pushed.relay_id.as_deref(), Some(survivor.as_str()));
    assert!(
        elapsed < Duration::from_secs(1),
        "the reassignment push took {elapsed:?}"
    );
}

#[tokio::test]
async fn the_metrics_endpoint_renders_prose_that_parses() {
    let state = AppState::new(settings_with(30));
    let (_, _) = join_device(&state, "alpha", address(30)).await;
    let (relay_id, relay_key) = enroll_relay(&state, "relay-1", address(31)).await;

    // A heartbeat, so the relay-side counters have something to report.
    let heartbeat = wgmesh_proto::RelayHeartbeat {
        forwarded_packets: 120,
        forwarded_bytes: 900_000,
        throttled_packets: 7,
        dropped_packets: 2,
        pairs_active: 1,
        at: now_unix(),
    };
    let (status, _) = call(
        &state,
        signed(
            "POST",
            "/v1/relay/heartbeat",
            &body_bytes(&heartbeat),
            &relay_id,
            &relay_key,
            address(31),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, bytes) = call(
        &state,
        Request::builder()
            .uri("/metrics")
            .extension(ConnectInfo(address(32)))
            .body(Body::empty())
            .expect("a metrics request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let text = String::from_utf8_lossy(&bytes).to_string();
    let parsed = parse_exposition(&text);

    assert!(
        parsed.contains_key("wgmesh_config_generation"),
        "the exposition has no generation gauge:\n{text}"
    );
    assert_eq!(
        parsed.get("wgmesh_relay_forwarded_bytes_total{relay=\"relay-1\"}"),
        Some(&900_000.0)
    );
    assert_eq!(
        parsed
            .get("wgmesh_relay_throttled_packets_total{relay=\"relay-1\"}")
            .copied(),
        Some(7.0)
    );
    assert_eq!(
        parsed.get("wgmesh_devices{state=\"active\"}").copied(),
        Some(1.0)
    );
    assert!(parsed.contains_key("wgmesh_requests_total{endpoint=\"/v1/join\",outcome=\"joined\"}"));

    // The exposition must be well-formed: every value a number, every series
    // named, and a TYPE line for each family it mentions.
    for name in ["wgmesh_config_generation", "wgmesh_requests_total"] {
        assert!(
            text.contains(&format!("# TYPE {name} ")),
            "{name} has no TYPE line"
        );
    }
}

/// Read one server-sent event off the stream.
async fn next_event(body: &mut Body) -> ConfigEvent {
    let frame = tokio::time::timeout(Duration::from_secs(5), body.frame())
        .await
        .expect("an event arrives")
        .expect("the stream is still open")
        .expect("a frame");
    let data = frame.into_data().expect("a data frame");
    let text = String::from_utf8_lossy(&data).to_string();
    let payload = text
        .lines()
        .find_map(|line| line.strip_prefix("data: "))
        .unwrap_or_else(|| panic!("no data line in {text:?}"));
    serde_json::from_str(payload).expect("an event payload")
}
