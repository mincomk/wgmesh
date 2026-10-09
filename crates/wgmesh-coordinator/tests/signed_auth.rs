#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use serde_json::Value;
use tower::ServiceExt;

use wgmesh_coordinator::{AdminAuth, AppState, Clock, Store, router};
use wgmesh_proto::{canonical, encode_base64, sha256_hex};

struct FixedClock(AtomicI64);

impl Clock for FixedClock {
    fn now_secs(&self) -> i64 {
        self.0.load(Ordering::Relaxed)
    }
}

struct Harness {
    app: Router,
    store: Store,
    clock: Arc<FixedClock>,
    admin: String,
    network: i64,
}

struct Device {
    key: String,
    secret: [u8; 32],
}

impl Device {
    fn signed(&self, method: &str, path: &str, body: &str, ts: i64, nonce: [u8; 16]) -> Request<Body> {
        let message = canonical(method, path, body.as_bytes(), ts, &nonce);
        let signature = wgmesh_secrets::sign(&self.secret, &message);
        let header = format!(
            "WGMESH {} {ts} {} {}",
            self.key,
            encode_base64(&nonce),
            encode_base64(&signature)
        );
        Request::builder()
            .method(method)
            .uri(path)
            .header("authorization", header)
            .body(Body::from(body.to_owned()))
            .unwrap()
    }
}

async fn harness() -> Harness {
    let store = Store::open_in_memory().await.unwrap();
    let network = store
        .create_network("prod", "10.77.0.0/16", 1420, 1_000_000)
        .await
        .unwrap();
    let clock = Arc::new(FixedClock(AtomicI64::new(1_000_000)));
    let admin = String::from("admin-secret");
    let state = AppState::new(
        store.clone(),
        AdminAuth::from_token(&admin),
        Arc::clone(&clock) as Arc<dyn Clock>,
    );
    Harness {
        app: router(state),
        store,
        clock,
        admin,
        network,
    }
}

async fn body_json(response: axum::response::Response) -> Value {
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

async fn error_code(response: axum::response::Response) -> String {
    body_json(response).await["error"]
        .as_str()
        .unwrap()
        .to_owned()
}

async fn join(harness: &Harness, name: &str, auto_approve: bool, seed: u8) -> Device {
    let token = format!("WGMESH-TEST-TOKEN-{name}");
    harness
        .store
        .create_join_token(harness.network, "device", &token, 1, auto_approve, 2_000_000, "admin", 1_000_000)
        .await
        .unwrap();
    let secret = [seed; 32];
    let api_pubkey = wgmesh_secrets::public_key(&secret);
    let body = serde_json::json!({
        "token": token,
        "wg_pubkey": encode_base64(&[seed; 32]),
        "api_pubkey": encode_base64(&api_pubkey),
        "name": name,
    })
    .to_string();
    let response = harness
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/join")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "join must succeed");
    let value = body_json(response).await;
    Device {
        key: value["device_id"].as_str().unwrap().to_owned(),
        secret,
    }
}

async fn admin(harness: &Harness, path: &str) -> axum::response::Response {
    harness
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header(wgmesh_coordinator::ADMIN_HEADER, &harness.admin)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn config(harness: &Harness, device: &Device) -> axum::response::Response {
    harness
        .app
        .clone()
        .oneshot(device.signed("GET", "/v1/config", "", harness.clock.0.load(Ordering::Relaxed), [42u8; 16]))
        .await
        .unwrap()
}

fn peers_of(value: &Value) -> Vec<String> {
    value["peers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|peer| peer["device_id"].as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test]
async fn a_request_without_an_authorization_header_is_refused() {
    let harness = harness().await;
    let response = harness
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/config")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(error_code(response).await, "missing_authorization");
}

#[tokio::test]
async fn a_request_with_a_wrong_signature_is_refused() {
    let harness = harness().await;
    let device = join(&harness, "alpha", true, 11).await;
    let mut request = device.signed("GET", "/v1/config", "", 1_000_000, [1u8; 16]);
    let tampered = {
        let mut secret = device.secret;
        secret[0] ^= 0xff;
        let message = canonical("GET", "/v1/config", b"", 1_000_000, &[1u8; 16]);
        let signature = wgmesh_secrets::sign(&secret, &message);
        format!(
            "WGMESH {} 1000000 {} {}",
            device.key,
            encode_base64(&[1u8; 16]),
            encode_base64(&signature)
        )
    };
    request.headers_mut().insert(
        "authorization",
        tampered.parse().unwrap(),
    );
    let response = harness.app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(error_code(response).await, "bad_signature");
}

#[tokio::test]
async fn a_replayed_nonce_is_refused_inside_the_window() {
    let harness = harness().await;
    let device = join(&harness, "alpha", true, 12).await;
    let first = config(&harness, &device).await;
    assert_eq!(first.status(), StatusCode::OK);

    let replay = harness
        .app
        .clone()
        .oneshot(device.signed("GET", "/v1/config", "", 1_000_000, [42u8; 16]))
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(error_code(replay).await, "nonce_reused");

    harness.clock.0.store(1_000_000 + 121, Ordering::Relaxed);
    let after_the_window = config(&harness, &device).await;
    assert_eq!(
        after_the_window.status(),
        StatusCode::OK,
        "the same nonce is accepted once the entry has aged out of the 120 second cache"
    );
}

#[tokio::test]
async fn a_timestamp_further_than_sixty_seconds_from_now_is_refused() {
    let harness = harness().await;
    let device = join(&harness, "alpha", true, 13).await;
    for ts in [1_000_061, 999_939] {
        let response = harness
            .app
            .clone()
            .oneshot(device.signed("GET", "/v1/config", "", ts, [ts as u8; 16]))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(error_code(response).await, "clock_skew");
    }
    let inside = harness
        .app
        .clone()
        .oneshot(device.signed("GET", "/v1/config", "", 1_000_060, [7u8; 16]))
        .await
        .unwrap();
    assert_eq!(inside.status(), StatusCode::OK);
}

#[tokio::test]
async fn a_pending_device_signature_is_refused() {
    let harness = harness().await;
    let device = join(&harness, "pending-device", false, 14).await;
    let response = config(&harness, &device).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(error_code(response).await, "identity_not_active");
}

#[tokio::test]
async fn a_revoked_device_signature_is_refused() {
    let harness = harness().await;
    let device = join(&harness, "alpha", true, 15).await;
    assert_eq!(config(&harness, &device).await.status(), StatusCode::OK);

    let revoked = admin(&harness, &format!("/v1/devices/{}/revoke", device.key)).await;
    assert_eq!(revoked.status(), StatusCode::OK);

    let response = config(&harness, &device).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(error_code(response).await, "identity_not_active");
}

#[tokio::test]
async fn a_device_enrolled_without_auto_approve_stays_pending_and_is_not_in_the_peer_list() {
    let harness = harness().await;
    let approved = join(&harness, "alpha", true, 21).await;
    let waiting = join(&harness, "beta", false, 22).await;

    let snapshot = body_json(config(&harness, &approved).await).await;
    assert_eq!(peers_of(&snapshot), Vec::<String>::new());

    let row = harness.store.device(&waiting.key).await.unwrap().unwrap();
    assert_eq!(row.state.as_str(), "pending");

    let snapshot = body_json(config(&harness, &approved).await).await;
    assert_eq!(snapshot["keyset"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn approving_a_device_puts_it_in_the_peer_list() {
    let harness = harness().await;
    let alpha = join(&harness, "alpha", true, 31).await;
    let beta = join(&harness, "beta", false, 32).await;

    let approved = admin(&harness, &format!("/v1/devices/{}/approve", beta.key)).await;
    assert_eq!(approved.status(), StatusCode::OK);

    let snapshot = body_json(config(&harness, &beta).await).await;
    assert_eq!(peers_of(&snapshot), vec![alpha.key.clone()]);
    assert_eq!(snapshot["keyset"].as_array().unwrap().len(), 1);
    assert_eq!(
        snapshot["peers"].as_array().unwrap()[0]["wg_pubkey"],
        encode_base64(&[31u8; 32])
    );
}

#[tokio::test]
async fn revoking_a_device_removes_it_from_peers_and_keyset_on_the_next_sync() {
    let harness = harness().await;
    let alpha = join(&harness, "alpha", true, 41).await;
    let beta = join(&harness, "beta", true, 42).await;
    let gamma = join(&harness, "gamma", true, 43).await;

    let before = body_json(config(&harness, &alpha).await).await;
    assert_eq!(peers_of(&before), vec![beta.key.clone(), gamma.key.clone()]);
    assert_eq!(before["keyset"].as_array().unwrap().len(), 2);

    let revoked = admin(&harness, &format!("/v1/devices/{}/revoke", beta.key)).await;
    assert_eq!(revoked.status(), StatusCode::OK);

    let after = body_json(config(&harness, &alpha).await).await;
    assert_eq!(peers_of(&after), vec![gamma.key.clone()]);
    assert_eq!(after["keyset"].as_array().unwrap().len(), 1);
    assert!(
        !after["keyset"]
            .as_array()
            .unwrap()
            .iter()
            .any(|key| key == &Value::String(encode_base64(&[42u8; 32]))),
        "the revoked device's tunnel key must be gone from the keyset"
    );
    assert_ne!(before["etag"], after["etag"]);
}

#[tokio::test]
async fn the_database_stores_only_hashes_and_public_keys() {
    let harness = harness().await;
    let device = join(&harness, "alpha", true, 51).await;

    let tables = harness.store.tables().await.unwrap();
    for expected in [
        "networks",
        "join_tokens",
        "devices",
        "relays",
        "relay_networks",
        "relay_slots",
        "pair_assignments",
        "relay_observations",
        "relay_traffic",
        "audit_log",
    ] {
        assert!(tables.iter().any(|table| table == expected), "{expected} is missing");
    }

    let mut columns = harness.store.columns("devices").await.unwrap();
    columns.sort();
    assert_eq!(
        columns,
        vec![
            "api_pubkey",
            "created_at",
            "device_key",
            "id",
            "last_seen_at",
            "name",
            "network_id",
            "state",
            "tunnel_ip",
            "wg_pubkey",
        ],
        "the device table holds public keys and a state, and no private key"
    );

    let token_columns = harness.store.columns("join_tokens").await.unwrap();
    assert!(token_columns.iter().any(|column| column == "token_hash"));
    assert!(
        !token_columns.iter().any(|column| column == "token"),
        "the join token itself must never have a column"
    );

    let forbidden = ["token", "secret", "password", "private_key", "api_secret", "psk"];
    for table in &tables {
        if table == "_sqlx_migrations" {
            continue;
        }
        for column in harness.store.columns(table).await.unwrap() {
            assert!(
                !forbidden.contains(&column.as_str()),
                "{table}.{column} looks like a stored shared secret"
            );
        }
    }

    let stored = harness.store.join_token_hashes().await.unwrap();
    assert_eq!(stored.len(), 1);
    let token = String::from("WGMESH-TEST-TOKEN-alpha");
    assert_eq!(stored[0], sha256_hex(token.as_bytes()));
    assert_ne!(stored[0], token);
    assert_eq!(stored[0].len(), 64);

    let devices = harness.store.devices_in_state(harness.network, wgmesh_coordinator::DeviceState::Active).await.unwrap();
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].api_pubkey.len(), 32);
    assert_eq!(devices[0].api_pubkey, wgmesh_secrets::public_key(&device.secret));
}

#[tokio::test]
async fn join_approve_revoke_and_rotate_are_audited_with_the_actor() {
    let harness = harness().await;
    let alpha = join(&harness, "alpha", false, 61).await;
    let beta = join(&harness, "beta", true, 62).await;

    admin(&harness, &format!("/v1/devices/{}/approve", alpha.key)).await;

    let body = serde_json::json!({ "wg_pubkey": encode_base64(&[99u8; 32]) }).to_string();
    let rotated = harness
        .app
        .clone()
        .oneshot(alpha.signed("POST", "/v1/rotate", &body, 1_000_000, [3u8; 16]))
        .await
        .unwrap();
    assert_eq!(rotated.status(), StatusCode::OK);

    admin(&harness, &format!("/v1/devices/{}/revoke", beta.key)).await;

    let entries = harness.store.audit_entries().await.unwrap();
    let find = |action: &str| {
        entries
            .iter()
            .find(|entry| entry.action == action)
            .unwrap_or_else(|| panic!("no audit entry for {action}"))
            .clone()
    };
    assert_eq!(find("join").actor, alpha.key);
    assert_eq!(find("approve").actor, "admin");
    assert_eq!(find("rotate").actor, alpha.key);
    assert_eq!(find("revoke").actor, "admin");
    assert!(entries.iter().all(|entry| !entry.actor.is_empty()));

    let listed = harness
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/audit")
                .header(wgmesh_coordinator::ADMIN_HEADER, &harness.admin)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(listed.status(), StatusCode::OK);
    let listed = body_json(listed).await;
    assert!(listed.as_array().unwrap().len() >= 4);
}

#[tokio::test]
async fn a_revoked_device_cannot_rotate_its_tunnel_key() {
    let harness = harness().await;
    let alpha = join(&harness, "alpha", true, 71).await;
    admin(&harness, &format!("/v1/devices/{}/revoke", alpha.key)).await;
    let body = serde_json::json!({ "wg_pubkey": encode_base64(&[9u8; 32]) }).to_string();
    let response = harness
        .app
        .clone()
        .oneshot(alpha.signed("POST", "/v1/rotate", &body, 1_000_000, [4u8; 16]))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn the_admin_surface_needs_the_admin_credential() {
    let harness = harness().await;
    let alpha = join(&harness, "alpha", false, 81).await;
    let response = harness
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/devices/{}/approve", alpha.key))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let wrong = harness
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/devices/{}/approve", alpha.key))
                .header(wgmesh_coordinator::ADMIN_HEADER, "not-the-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(error_code(wrong).await, "bad_admin_credential");
}
