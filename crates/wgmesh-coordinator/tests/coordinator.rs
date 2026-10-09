#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};
use tower::ServiceExt;
use wgmesh_app::coordinator::Clock;
use wgmesh_app::coordinator::ports::{
    Directory, NewJoinToken, NewNetwork, NewRelay, RelayState, TokenKind, TokenStore,
};
use wgmesh_coordinator::clock::FixedClock;
use wgmesh_coordinator::router;
use wgmesh_coordinator::service::Services;
use wgmesh_coordinator::store::Sqlite;
use wgmesh_core::{DeviceId, Millis, PublicKey, RelayId};
use wgmesh_proto as naming;
use wgmesh_proto::encode_key;
use wgmesh_proto::sign as auth;
use wgmesh_proto::token as join_token;

const NOW_SECS: u64 = 1_760_000_000;

struct Harness {
    router: Router,
    store: Arc<Sqlite>,
    clock: Arc<FixedClock>,
    network_id: u32,
    relay_id: RelayId,
    minted: std::sync::atomic::AtomicU8,
    _dir: tempfile::TempDir,
}

impl Harness {
    async fn new() -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("coordinator.db");
        let url = format!("sqlite://{}?mode=rwc", path.display());
        let store = Arc::new(Sqlite::open(&url, 8).await.expect("open"));
        store.migrate().await.expect("migrate");

        let now = Millis::from_secs(NOW_SECS);
        let network = store
            .insert_network(&NewNetwork {
                name: "prod".to_string(),
                cidr: "10.77.0.0/16".to_string(),
                mtu: 1420,
                relay_policy: "any".to_string(),
                created_at: now,
            })
            .await
            .expect("network");

        let relay_signing = SigningKey::from_bytes(&[9u8; 32]);
        let relay = store
            .insert_relay(&NewRelay {
                name: "relay-1".to_string(),
                api_pubkey: PublicKey::from_bytes(relay_signing.verifying_key().to_bytes()),
                state: RelayState::Active,
                endpoint_host: "198.51.100.4".to_string(),
                port_range: "51900-51999".to_string(),
                region: Some("ap-northeast-2".to_string()),
                provider: Some("vultr".to_string()),
                operator: None,
                created_at: now,
            })
            .await
            .expect("relay");
        store
            .link_relay_network(relay.id, network.id)
            .await
            .expect("link");
        store
            .record_heartbeat(relay.id, now, Some("0.1.0"))
            .await
            .expect("heartbeat");

        let clock = Arc::new(FixedClock::new(now));
        let services = Services::new(store.clone(), clock.clone());
        Self {
            router: router(services),
            store,
            clock,
            network_id: network.id,
            relay_id: relay.id,
            minted: std::sync::atomic::AtomicU8::new(0),
            _dir: dir,
        }
    }

    async fn mint_token(&self, auto_approve: bool, max_uses: u32, expires_at: Millis) -> String {
        // A counter, not a random source: a test wants a fresh token, not an
        // unpredictable one.
        let mut secret = [0u8; 20];
        secret[0] = self
            .minted
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            .wrapping_add(1);
        secret[19] = 0xa5;
        let text = join_token::format_token(&secret);
        self.store
            .insert_join_token(&NewJoinToken {
                network_id: self.network_id,
                kind: TokenKind::Device,
                token_hash: join_token::hash_secret(&secret),
                max_uses,
                auto_approve,
                expires_at,
                created_by: "test".to_string(),
                created_at: self.clock.now(),
            })
            .await
            .expect("token");
        text
    }

    async fn send(&self, request: Request<Body>) -> (StatusCode, Value, Option<String>) {
        let response = self.router.clone().oneshot(request).await.expect("route");
        let status = response.status();
        let etag = response
            .headers()
            .get(header::ETAG)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .expect("body");
        let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, value, etag)
    }
}

fn keypair(seed: u8) -> SigningKey {
    let mut bytes = [0u8; 32];
    bytes[0] = seed.max(1);
    bytes[31] = seed.max(1);
    SigningKey::from_bytes(&bytes)
}

fn api_key(signing: &SigningKey) -> PublicKey {
    PublicKey::from_bytes(signing.verifying_key().to_bytes())
}

fn signed(
    method: &str,
    path: &str,
    body: &[u8],
    signing: &SigningKey,
    identity: &str,
    nonce: &str,
) -> String {
    let timestamp = NOW_SECS as i64;
    let message = auth::canonical(method, path, body, timestamp, nonce);
    let signature = signing.sign(&message).to_bytes();
    format!(
        "WGMESH {identity} {timestamp} {nonce} {}",
        base64::engine::general_purpose::STANDARD.encode(signature)
    )
}

fn post(path: &str, body: &Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(body).expect("json")))
        .expect("request")
}

fn post_signed(
    path: &str,
    body: &Value,
    signing: &SigningKey,
    identity: &str,
    nonce: &str,
) -> Request<Body> {
    let bytes = serde_json::to_vec(body).expect("json");
    Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json")
        .header(
            header::AUTHORIZATION,
            signed("POST", path, &bytes, signing, identity, nonce),
        )
        .body(Body::from(bytes))
        .expect("request")
}

fn get_signed(path: &str, signing: &SigningKey, identity: &str, nonce: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(path)
        .header(
            header::AUTHORIZATION,
            signed("GET", path, b"", signing, identity, nonce),
        )
        .body(Body::empty())
        .expect("request")
}

async fn join(
    harness: &Harness,
    token: &str,
    name: &str,
    signing: &SigningKey,
    advertised: Vec<String>,
) -> (StatusCode, Value) {
    let body = json!({
        "token": token,
        "name": name,
        "wg_pubkey": encode_key(&api_key(signing)),
        "api_pubkey": encode_key(&api_key(signing)),
        "os": "linux",
        "agent_version": "0.1.0",
        "advertised": advertised,
    });
    let (status, value, _) = harness.send(post("/v1/join", &body)).await;
    (status, value)
}

fn identity_of(joined: &Value) -> String {
    joined["device_id"].as_str().expect("device id").to_string()
}

// --- join tokens -----------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_single_use_token_is_spent_exactly_once_under_concurrency() {
    let harness = Harness::new().await;
    let token = harness
        .mint_token(true, 1, Millis::from_secs(NOW_SECS + 3_600))
        .await;
    let hash = join_token::hash_token_text(&token).expect("hash");
    let at = Millis::from_secs(NOW_SECS);

    let mut set = tokio::task::JoinSet::new();
    for _ in 0..24 {
        let store = harness.store.clone();
        set.spawn(async move {
            store
                .consume_join_token(&hash, TokenKind::Device, at)
                .await
                .expect("consume")
                .is_some()
        });
    }

    let mut winners = 0;
    while let Some(result) = set.join_next().await {
        if result.expect("task") {
            winners += 1;
        }
    }
    assert_eq!(winners, 1, "a one-use token must admit exactly one device");
}

#[tokio::test]
async fn an_expired_revoked_or_exhausted_token_is_refused() {
    let harness = Harness::new().await;
    let at = Millis::from_secs(NOW_SECS);

    let expired = harness
        .mint_token(true, 1, Millis::from_secs(NOW_SECS - 1))
        .await;
    let expired_hash = join_token::hash_token_text(&expired).expect("hash");
    assert!(
        harness
            .store
            .consume_join_token(&expired_hash, TokenKind::Device, at)
            .await
            .expect("consume")
            .is_none()
    );

    let revoked = harness
        .mint_token(true, 1, Millis::from_secs(NOW_SECS + 600))
        .await;
    let revoked_hash = join_token::hash_token_text(&revoked).expect("hash");
    assert!(
        harness
            .store
            .revoke_join_token(&revoked_hash, at)
            .await
            .expect("revoke")
    );
    assert!(
        harness
            .store
            .consume_join_token(&revoked_hash, TokenKind::Device, at)
            .await
            .expect("consume")
            .is_none()
    );

    let once = harness
        .mint_token(true, 1, Millis::from_secs(NOW_SECS + 600))
        .await;
    let once_hash = join_token::hash_token_text(&once).expect("hash");
    assert!(
        harness
            .store
            .consume_join_token(&once_hash, TokenKind::Device, at)
            .await
            .expect("consume")
            .is_some()
    );
    assert!(
        harness
            .store
            .consume_join_token(&once_hash, TokenKind::Device, at)
            .await
            .expect("consume")
            .is_none()
    );
}

#[tokio::test]
async fn the_ways_a_token_can_fail_are_indistinguishable_on_the_wire() {
    let harness = Harness::new().await;

    let spent = harness
        .mint_token(true, 1, Millis::from_secs(NOW_SECS + 600))
        .await;
    let (status, first) = join(&harness, &spent, "a", &keypair(1), vec![]).await;
    assert_eq!(status, StatusCode::OK, "{first}");

    let expired = harness
        .mint_token(true, 1, Millis::from_secs(NOW_SECS - 1))
        .await;
    let revoked = harness
        .mint_token(true, 1, Millis::from_secs(NOW_SECS + 600))
        .await;
    let revoked_hash = join_token::hash_token_text(&revoked).expect("hash");
    harness
        .store
        .revoke_join_token(&revoked_hash, Millis::from_secs(NOW_SECS))
        .await
        .expect("revoke");

    let cases = [
        ("unknown", "WGMESH-0000-0000-0000-0000-0000-0000-0000-0000"),
        ("malformed", "not-a-token"),
        ("expired", expired.as_str()),
        ("revoked", revoked.as_str()),
        ("exhausted", spent.as_str()),
    ];

    let mut seen: Vec<(String, StatusCode, Value)> = Vec::new();
    for (label, token) in cases {
        let (status, value) = join(&harness, token, "b", &keypair(9), vec![]).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{label}: {value}");
        assert_eq!(
            value["error"]["code"],
            json!("forbidden"),
            "{label}: {value}"
        );
        seen.push((label.to_string(), status, value));
    }

    let reference = seen[0].clone();
    for entry in &seen[1..] {
        assert_eq!(
            entry.1, reference.1,
            "{} differs from {} in status",
            entry.0, reference.0
        );
        assert_eq!(
            entry.2, reference.2,
            "{} differs from {} in body",
            entry.0, reference.0
        );
    }
}

// --- approval and the config snapshot --------------------------------------

#[tokio::test]
async fn a_device_without_auto_approval_is_pending_and_out_of_the_peer_list() {
    let harness = Harness::new().await;
    let open = keypair(1);
    let held = keypair(2);

    let open_token = harness
        .mint_token(true, 1, Millis::from_secs(NOW_SECS + 600))
        .await;
    let (status, approved) = join(&harness, &open_token, "open", &open, vec![]).await;
    assert_eq!(status, StatusCode::OK, "{approved}");
    assert_eq!(approved["state"], json!("active"));

    let held_token = harness
        .mint_token(false, 1, Millis::from_secs(NOW_SECS + 600))
        .await;
    let (status, pending) = join(&harness, &held_token, "held", &held, vec![]).await;
    assert_eq!(status, StatusCode::OK, "{pending}");
    assert_eq!(pending["state"], json!("pending"));

    let open_identity = identity_of(&approved);
    let pending_identity = identity_of(&pending);
    assert_ne!(open_identity, pending_identity);

    let (status, config, _) = harness
        .send(get_signed("/v1/config", &open, &open_identity, "n1"))
        .await;
    assert_eq!(status, StatusCode::OK, "{config}");
    assert_eq!(
        config["peers"].as_array().map(Vec::len),
        Some(0),
        "a pending device must not appear in a peer list: {config}"
    );

    // The pending device may still read its own snapshot; it sees nobody.
    let (status, own, _) = harness
        .send(get_signed("/v1/config", &held, &pending_identity, "n2"))
        .await;
    assert_eq!(status, StatusCode::OK, "{own}");
    assert_eq!(own["me"]["state"], json!("pending"));
    assert_eq!(own["peers"].as_array().map(Vec::len), Some(0));

    let device = wgmesh_proto::parse_device_id(&pending_identity).expect("id");
    let services = Services::new(harness.store.clone(), harness.clock.clone());
    services
        .approve_device()
        .execute("test", device)
        .await
        .expect("approve");

    let (status, config, _) = harness
        .send(get_signed("/v1/config", &open, &open_identity, "n3"))
        .await;
    assert_eq!(status, StatusCode::OK, "{config}");
    let peers = config["peers"].as_array().expect("peers");
    assert_eq!(peers.len(), 1, "{config}");
    assert_eq!(peers[0]["device_id"], json!(pending_identity));
}

#[tokio::test]
async fn the_snapshot_carries_my_slot_the_assigned_relay_and_each_peers_bands() {
    let harness = Harness::new().await;
    let left = keypair(3);
    let right = keypair(4);

    let left_token = harness
        .mint_token(true, 1, Millis::from_secs(NOW_SECS + 600))
        .await;
    let (status, left_join) = join(
        &harness,
        &left_token,
        "left",
        &left,
        vec!["192.168.5.0/24".to_string()],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{left_join}");
    let left_identity = identity_of(&left_join);

    let right_token = harness
        .mint_token(true, 1, Millis::from_secs(NOW_SECS + 600))
        .await;
    let (status, right_join) = join(&harness, &right_token, "right", &right, vec![]).await;
    assert_eq!(status, StatusCode::OK, "{right_join}");
    let right_identity = identity_of(&right_join);

    let (status, config, etag) = harness
        .send(get_signed("/v1/config", &left, &left_identity, "c1"))
        .await;
    assert_eq!(status, StatusCode::OK, "{config}");

    let slot = config["me"]["slot_port"].as_u64().expect("my slot port");
    assert!(
        (51_900..=51_999).contains(&slot),
        "slot {slot} is outside the relay's range: {config}"
    );

    let assigned = config["relay"]["assigned"]
        .as_str()
        .expect("an assigned relay");
    assert_eq!(assigned, naming::relay_id(harness.relay_id));

    let slots = config["relay"]["slots"].as_array().expect("slots");
    assert_eq!(slots.len(), 1, "{config}");
    assert_eq!(slots[0]["slot_port"].as_u64(), Some(slot));
    assert_eq!(slots[0]["endpoint_host"], json!("198.51.100.4"));

    let peer = config["peers"]
        .as_array()
        .expect("peers")
        .iter()
        .find(|peer| peer["device_id"] == json!(right_identity))
        .cloned()
        .unwrap_or_else(|| panic!("right is not a peer: {config}"));
    assert!(
        !peer["advertised"].as_array().expect("bands").is_empty(),
        "every peer advertises at least its own tunnel address: {config}"
    );
    assert_eq!(peer["relay"], json!(assigned));
    let endpoint = peer["endpoint"].as_str().expect("endpoint");
    assert!(
        endpoint.starts_with("198.51.100.4:"),
        "phase one routes peers through their relay: {endpoint}"
    );

    // The band left reported survives into right's view of left.
    let (status, right_config, _) = harness
        .send(get_signed("/v1/config", &right, &right_identity, "c2"))
        .await;
    assert_eq!(status, StatusCode::OK, "{right_config}");
    let left_peer = right_config["peers"]
        .as_array()
        .expect("peers")
        .iter()
        .find(|peer| peer["device_id"] == json!(left_identity))
        .cloned()
        .expect("left is a peer");
    assert!(
        left_peer["advertised"]
            .as_array()
            .expect("bands")
            .iter()
            .any(|band| band == &json!("192.168.5.0/24")),
        "the subnet router's band is reported to its peers: {right_config}"
    );

    let etag = etag.expect("an etag");
    let request = Request::builder()
        .method("GET")
        .uri("/v1/config")
        .header(header::IF_NONE_MATCH, &etag)
        .header(
            header::AUTHORIZATION,
            signed("GET", "/v1/config", b"", &left, &left_identity, "c3"),
        )
        .body(Body::empty())
        .expect("request");
    let (status, _, _) = harness.send(request).await;
    assert_eq!(status, StatusCode::NOT_MODIFIED);
}

// --- authentication ---------------------------------------------------------

#[tokio::test]
async fn only_join_and_relay_enroll_answer_without_authentication() {
    let harness = Harness::new().await;

    for path in ["/v1/join", "/v1/relay/enroll"] {
        let (status, _, _) = harness.send(post(path, &json!({}))).await;
        assert_ne!(
            status,
            StatusCode::UNAUTHORIZED,
            "{path} must be reachable without a signature"
        );
    }

    let protected = [
        ("GET", "/v1/config"),
        ("POST", "/v1/endpoint"),
        ("POST", "/v1/punch"),
        ("POST", "/v1/rotate"),
        ("GET", "/v1/relay/assignment"),
        ("POST", "/v1/relay/observations"),
        ("POST", "/v1/relay/heartbeat"),
        ("GET", "/v1/relay/keyset"),
    ];

    for (method, path) in protected {
        let bare = Request::builder()
            .method(method)
            .uri(path)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from("{}"))
            .expect("request");
        let (status, body, _) = harness.send(bare).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "{method} {path} answered without a signature: {body}"
        );

        let garbled = Request::builder()
            .method(method)
            .uri(path)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::AUTHORIZATION, "WGMESH d_1 1 bm9uY2U= AAAA")
            .body(Body::from("{}"))
            .expect("request");
        let (status, _, _) = harness.send(garbled).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "{method} {path} accepted a garbled signature"
        );
    }
}

#[tokio::test]
async fn a_signature_over_a_different_body_is_refused() {
    let harness = Harness::new().await;
    let signing = keypair(5);
    let token = harness
        .mint_token(true, 1, Millis::from_secs(NOW_SECS + 600))
        .await;
    let (_, joined) = join(&harness, &token, "signed", &signing, vec![]).await;
    let identity = identity_of(&joined);

    let signed_body = json!({ "peer": naming::device_id(DeviceId(1)), "outcome": "direct" });
    let tampered = serde_json::to_vec(&json!({
        "peer": naming::device_id(DeviceId(2)),
        "outcome": "direct"
    }))
    .expect("json");
    let request = Request::builder()
        .method("POST")
        .uri("/v1/punch")
        .header(header::CONTENT_TYPE, "application/json")
        .header(
            header::AUTHORIZATION,
            signed(
                "POST",
                "/v1/punch",
                &serde_json::to_vec(&signed_body).expect("json"),
                &signing,
                &identity,
                "n1",
            ),
        )
        .body(Body::from(tampered))
        .expect("request");

    let (status, body, _) = harness.send(request).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
}

#[tokio::test]
async fn a_replayed_nonce_is_refused() {
    let harness = Harness::new().await;
    let signing = keypair(6);
    let token = harness
        .mint_token(true, 1, Millis::from_secs(NOW_SECS + 600))
        .await;
    let (_, joined) = join(&harness, &token, "replay", &signing, vec![]).await;
    let identity = identity_of(&joined);

    let (status, _, _) = harness
        .send(get_signed("/v1/config", &signing, &identity, "same"))
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _, _) = harness
        .send(get_signed("/v1/config", &signing, &identity, "same"))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_revoked_device_is_locked_out() {
    let harness = Harness::new().await;
    let signing = keypair(7);
    let token = harness
        .mint_token(true, 1, Millis::from_secs(NOW_SECS + 600))
        .await;
    let (_, joined) = join(&harness, &token, "gone", &signing, vec![]).await;
    let identity = identity_of(&joined);
    let device = wgmesh_proto::parse_device_id(&identity).expect("id");

    let services = Services::new(harness.store.clone(), harness.clock.clone());
    services
        .approve_device()
        .revoke("test", device)
        .await
        .expect("revoke");

    let (status, _, _) = harness
        .send(get_signed("/v1/config", &signing, &identity, "r1"))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// --- the relay surface ------------------------------------------------------

#[tokio::test]
async fn a_relay_reads_its_slots_pairs_and_keyset() {
    let harness = Harness::new().await;
    let device = keypair(8);
    let token = harness
        .mint_token(true, 1, Millis::from_secs(NOW_SECS + 600))
        .await;
    let (_, joined) = join(&harness, &token, "mine", &device, vec![]).await;
    let device_identity = identity_of(&joined);

    let relay_signing = SigningKey::from_bytes(&[9u8; 32]);
    let relay_identity = naming::relay_id(harness.relay_id);

    let (status, keyset, _) = harness
        .send(get_signed(
            "/v1/relay/keyset",
            &relay_signing,
            &relay_identity,
            "k1",
        ))
        .await;
    assert_eq!(status, StatusCode::OK, "{keyset}");
    let peers = keyset["networks"][0]["peers"].as_array().expect("peers");
    assert_eq!(peers.len(), 1, "{keyset}");
    assert_eq!(peers[0]["device_id"], json!(device_identity));
    assert_eq!(keyset["keyset_ttl_secs"], json!(300));

    let (status, assignment, _) = harness
        .send(get_signed(
            "/v1/relay/assignment",
            &relay_signing,
            &relay_identity,
            "k2",
        ))
        .await;
    assert_eq!(status, StatusCode::OK, "{assignment}");
    assert_eq!(assignment["slots"].as_array().map(Vec::len), Some(1));
    assert_eq!(assignment["slots"][0]["device_id"], json!(device_identity));
    assert_eq!(assignment["endpoint_host"], json!("198.51.100.4"));
}

#[tokio::test]
async fn a_relay_may_only_report_for_a_network_it_serves() {
    let harness = Harness::new().await;
    let device = keypair(2);
    let token = harness
        .mint_token(true, 1, Millis::from_secs(NOW_SECS + 600))
        .await;
    let (_, joined) = join(&harness, &token, "tenant", &device, vec![]).await;
    let device_identity = identity_of(&joined);

    let stray = harness
        .store
        .insert_relay(&NewRelay {
            name: "relay-2".to_string(),
            api_pubkey: PublicKey::from_bytes(
                SigningKey::from_bytes(&[8u8; 32])
                    .verifying_key()
                    .to_bytes(),
            ),
            state: RelayState::Active,
            endpoint_host: "203.0.113.9".to_string(),
            port_range: "52000-52099".to_string(),
            region: None,
            provider: None,
            operator: None,
            created_at: harness.clock.now(),
        })
        .await
        .expect("relay");

    let signing = SigningKey::from_bytes(&[8u8; 32]);
    let body = json!({
        "observations": [
            { "device_id": device_identity, "ip": "203.0.113.7", "port": 41287 }
        ]
    });
    let (status, response, _) = harness
        .send(post_signed(
            "/v1/relay/observations",
            &body,
            &signing,
            &naming::relay_id(stray.id),
            "o1",
        ))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{response}");
}
