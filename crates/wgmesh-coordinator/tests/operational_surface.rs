#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode, header};
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use http_body_util::BodyExt as _;
use tower::ServiceExt;

use wgmesh_app::coordinator::ports::{Directory, NewJoinToken, NewNetwork, TokenKind, TokenStore};
use wgmesh_coordinator::clock::FixedClock;
use wgmesh_coordinator::http::watch_config;
use wgmesh_coordinator::router;
use wgmesh_coordinator::service::Services;
use wgmesh_coordinator::store::Sqlite;
use wgmesh_core::{Millis, PublicKey};
use wgmesh_proto::encode_key;
use wgmesh_proto::sign as auth;
use wgmesh_proto::token as join_token;

const NOW_SECS: u64 = 1_760_000_000;

/// A coordinator with an empty store: the two unauthenticated routes refuse
/// every request here, which is exactly what a flood looks like from the
/// limiter's side — it counts before any handler runs.
async fn harness() -> (Router, Arc<Sqlite>, Services, u32, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("coordinator.db");
    let url = format!("sqlite://{}?mode=rwc", path.display());
    let store = Arc::new(Sqlite::open(&url, 4).await.expect("open"));
    store.migrate().await.expect("migrate");
    let network = insert_network(&store, "prod", "10.77.0.0/16").await;
    let clock = Arc::new(FixedClock::new(Millis::from_secs(NOW_SECS)));
    let services = Services::new(Arc::clone(&store), clock);
    (router(services.clone()), store, services, network, dir)
}

async fn insert_network(store: &Sqlite, name: &str, cidr: &str) -> u32 {
    let network = store
        .insert_network(&NewNetwork {
            name: name.to_owned(),
            cidr: cidr.to_owned(),
            mtu: 1420,
            relay_policy: "any".to_owned(),
            created_at: Millis::from_secs(NOW_SECS),
        })
        .await
        .expect("network");
    network.id
}

/// Mint a join token and enrol a device, exactly as a node does: a token, then
/// the two public keys it will be known by.
async fn enrol(app: &Router, store: &Sqlite, network_id: u32, name: &str) -> (String, SigningKey) {
    let signing = SigningKey::from_bytes(&[7u8; 32]);
    let mut secret = [0u8; 20];
    secret[0] = name.as_bytes()[0];
    secret[19] = 0xa5;
    store
        .insert_join_token(&NewJoinToken {
            network_id,
            kind: TokenKind::Device,
            token_hash: join_token::hash_secret(&secret),
            max_uses: 1,
            auto_approve: true,
            expires_at: Millis::from_secs(NOW_SECS + 3_600),
            created_by: "ops:token".to_owned(),
            created_at: Millis::from_secs(NOW_SECS),
        })
        .await
        .expect("token");
    let body = serde_json::json!({
        "token": join_token::format_token(&secret),
        "name": name,
        "wg_pubkey": encode_key(&PublicKey::from_bytes(signing.verifying_key().to_bytes())),
        "api_pubkey": encode_key(&PublicKey::from_bytes(signing.verifying_key().to_bytes())),
        "os": "linux",
        "agent_version": "0.1.0",
        "advertised": [],
    })
    .to_string();
    let request = Request::builder()
        .method("POST")
        .uri("/v1/join")
        .header(header::CONTENT_TYPE, "application/json")
        .extension(ConnectInfo(address(30)))
        .body(Body::from(body))
        .expect("a well-formed request");
    let (status, body) = call(app, request).await;
    assert_eq!(status, StatusCode::OK, "join: {body}");
    let joined: serde_json::Value = serde_json::from_str(&body).expect("a join response");
    let identity = joined["device_id"].as_str().expect("device id").to_owned();
    (identity, signing)
}

/// A `GET` signed the way the design specifies — what a node sends.
fn signed_get(path: &str, signing: &SigningKey, identity: &str, nonce: &str) -> Request<Body> {
    let timestamp = NOW_SECS as i64;
    let message = auth::canonical("GET", path, b"", timestamp, nonce);
    let signature = signing.sign(&message).to_bytes();
    let header_value = format!(
        "WGMESH {identity} {timestamp} {nonce} {}",
        base64::engine::general_purpose::STANDARD.encode(signature)
    );
    Request::builder()
        .method("GET")
        .uri(path)
        .header(header::AUTHORIZATION, header_value)
        .extension(ConnectInfo(address(30)))
        .body(Body::empty())
        .expect("a well-formed request")
}

/// Read one server-sent event off a response body.
async fn next_frame(body: &mut Body) -> String {
    let frame = tokio::time::timeout(Duration::from_secs(5), body.frame())
        .await
        .expect("an event arrives")
        .expect("the stream is still open")
        .expect("a frame");
    String::from_utf8_lossy(&frame.into_data().expect("a data frame")).into_owned()
}

fn address(last: u8) -> SocketAddr {
    SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, last)),
        40_000 + u16::from(last),
    )
}

fn join_request(client: SocketAddr) -> Request<Body> {
    let body = serde_json::json!({
        "token": "WGMESH-NOPE-NOPE-NOPE",
        "name": "flood",
        "wg_pubkey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "api_pubkey": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
    })
    .to_string();
    Request::builder()
        .method("POST")
        .uri("/v1/join")
        .header("content-type", "application/json")
        .extension(ConnectInfo(client))
        .body(Body::from(body))
        .expect("a well-formed request")
}

async fn call(app: &Router, request: Request<Body>) -> (StatusCode, String) {
    let response = app
        .clone()
        .oneshot(request)
        .await
        .expect("the router answers");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("the body reads");
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// A deliberately small reader for the Prometheus text format: `name{labels} value`
/// plus the `#` comments, which is the whole of the exposition.
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
async fn a_flood_is_refused_with_429_while_another_address_is_untouched() {
    let (app, _store, _services, _network, _dir) = harness().await;
    let flooder = address(1);

    for index in 0..30 {
        let (status, body) = call(&app, join_request(flooder)).await;
        assert_ne!(
            status,
            StatusCode::TOO_MANY_REQUESTS,
            "request {index} inside the allowance was refused: {body}"
        );
    }

    let response = app
        .clone()
        .oneshot(join_request(flooder))
        .await
        .expect("the router answers");
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(
        response.headers().contains_key("retry-after"),
        "a refusal must say how long to wait"
    );

    // Another address is not affected by the flooder at all.
    let (status, body) = call(&app, join_request(address(2))).await;
    assert_ne!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "an ordinary client was caught by another address's flood: {body}"
    );
}

#[tokio::test]
async fn the_metrics_endpoint_renders_text_that_parses() {
    let (app, _store, _services, _network, _dir) = harness().await;
    let flooder = address(3);
    for _ in 0..31 {
        let _ = call(&app, join_request(flooder)).await;
    }

    let request = Request::builder()
        .uri("/metrics")
        .extension(ConnectInfo(address(9)))
        .body(Body::empty())
        .expect("a metrics request");
    let (status, body) = call(&app, request).await;
    assert_eq!(status, StatusCode::OK);

    // Every sample line must parse: this is the check that the exposition is
    // well-formed, not merely present.
    let parsed = parse_exposition(&body);
    assert!(
        parsed.contains_key("wgmesh_requests_total{endpoint=\"/v1/join\",outcome=\"4xx\"}"),
        "the unauthenticated route is not counted:\n{body}"
    );
    assert_eq!(
        parsed
            .get("wgmesh_requests_total{endpoint=\"/v1/join\",outcome=\"rate_limited\"}")
            .copied(),
        Some(1.0),
        "the refusal is not counted once:\n{body}"
    );
    assert_eq!(
        parsed
            .get("wgmesh_rate_limited_total{endpoint=\"/v1/join\"}")
            .copied()
            .unwrap_or(0.0),
        1.0,
        "the refusal was not counted as a rate limit:\n{body}"
    );
    assert!(body.contains("# TYPE wgmesh_requests_total counter"));
}

#[tokio::test]
async fn a_configuration_change_is_announced_within_a_second() {
    let (app, store, services, network, _dir) = harness().await;
    let mut updates = services.updates.subscribe();
    let watcher = watch_config(services.clone());

    // The watch announces where the configuration stands, so a stream that
    // opens has something to send immediately.
    let first = tokio::time::timeout(Duration::from_secs(5), updates.recv())
        .await
        .expect("the watch announces the current version")
        .expect("a version");

    // An operator's change — `wgmeshd bootstrap`, in production — made in
    // another connection, which is exactly the case an in-process broadcast
    // would miss.
    insert_network(&store, "other", "10.78.0.0/16").await;

    let before = std::time::Instant::now();
    let changed = tokio::time::timeout(Duration::from_secs(5), updates.recv())
        .await
        .expect("the change is announced")
        .expect("a version");
    let elapsed = before.elapsed();

    assert_ne!(first, changed, "the version did not change");
    assert!(
        elapsed < Duration::from_secs(30),
        "the change took {elapsed:?}, which a 30-second poll could have beaten"
    );
    watcher.abort();

    // And the stream is a route on the device-authenticated surface: without a
    // signature it is refused like every other device route.
    let request = Request::builder()
        .uri("/v1/events")
        .extension(ConnectInfo(address(7)))
        .body(Body::empty())
        .expect("a well-formed request");
    let (status, _) = call(&app, request).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// The push, over the wire, to a signed-in device: the framing, the opening
/// version, and a change made through another connection arriving after it.
#[tokio::test]
async fn a_streaming_device_receives_the_change_over_the_wire() {
    let (app, store, services, network, _dir) = harness().await;
    let watcher = watch_config(services.clone());
    let (identity, signing) = enrol(&app, &store, network, "alpha").await;

    let response = app
        .clone()
        .oneshot(signed_get("/v1/events", &signing, &identity, "nonce-1"))
        .await
        .expect("the router answers");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default(),
        "text/event-stream"
    );
    let mut body = response.into_body();

    let opening = next_frame(&mut body).await;
    assert!(
        opening.contains("event: config") && opening.contains("generation"),
        "the stream does not open with the current version: {opening:?}"
    );

    insert_network(&store, "other", "10.78.0.0/16").await;
    let pushed = next_frame(&mut body).await;
    assert!(
        pushed.contains("event: config") && pushed.contains("generation"),
        "the change was not pushed: {pushed:?}"
    );
    watcher.abort();
}
