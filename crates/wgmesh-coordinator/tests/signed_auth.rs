#![allow(clippy::unwrap_used, clippy::expect_used)]

// The acceptance tests for the signed-request surface: the clock window, the replay window, the
// state a device is in, the audit trail, and what a revoked device leaves behind.
//
// They run the real router against a real SQLite database, and the last one carries the answer
// through `wgmesh_core::diff` onto an interface, because "the peer list is the ACL" is only worth
// saying if losing the entry is what makes the packets stop.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};
use tower::ServiceExt;
use wgmesh_app::coordinator::Clock;
use wgmesh_app::coordinator::ports::{
    DeviceState, Directory, NewJoinToken, NewNetwork, NewRelay, RelayState, Reports, TokenKind,
    TokenStore,
};
use wgmesh_coordinator::clock::FixedClock;
use wgmesh_coordinator::router;
use wgmesh_coordinator::service::Services;
use wgmesh_coordinator::store::Sqlite;
use wgmesh_core::{DeviceId, Millis, PeerSpec, PublicKey, RelayId, diff};
use wgmesh_ports::WireGuard;
use wgmesh_ports::fake::FakeWireGuard;
use wgmesh_proto as naming;
use wgmesh_proto::encode_key;
use wgmesh_proto::sign as auth;
use wgmesh_proto::token as join_token;

const NOW_SECS: u64 = 1_760_000_000;

struct Harness {
    router: Router,
    store: Arc<Sqlite>,
    clock: Arc<FixedClock>,
    relay: RelayId,
    relay_signing: SigningKey,
    network_id: u32,
    minted: AtomicU8,
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
            relay: relay.id,
            relay_signing,
            network_id: network.id,
            minted: AtomicU8::new(0),
            _dir: dir,
        }
    }

    fn services(&self) -> Services {
        Services::new(self.store.clone(), self.clock.clone())
    }

    /// A fresh join token, and the text a device would be handed.
    async fn mint_token(&self, auto_approve: bool) -> String {
        let mut secret = [0u8; 20];
        secret[0] = self.minted.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        secret[19] = 0xa5;
        let text = join_token::format_token(&secret);
        self.store
            .insert_join_token(&NewJoinToken {
                network_id: self.network_id,
                kind: TokenKind::Device,
                token_hash: join_token::hash_secret(&secret),
                max_uses: 1,
                auto_approve,
                expires_at: Millis::from_secs(NOW_SECS + 3_600),
                created_by: "ops:token".to_string(),
                created_at: self.clock.now(),
            })
            .await
            .expect("token");
        text
    }

    /// Enrol a device and return its identity, its id, and the state it came out in.
    async fn enrol(
        &self,
        name: &str,
        signing: &SigningKey,
        auto_approve: bool,
    ) -> (String, DeviceId, String) {
        let token = self.mint_token(auto_approve).await;
        let body = json!({
            "token": token,
            "name": name,
            "wg_pubkey": encode_key(&PublicKey::from_bytes(signing.verifying_key().to_bytes())),
            "api_pubkey": encode_key(&PublicKey::from_bytes(signing.verifying_key().to_bytes())),
            "os": "linux",
            "agent_version": "0.1.0",
            "advertised": [],
        });
        let (status, value, _) = self.send(post("/v1/join", &body)).await;
        assert_eq!(status, StatusCode::OK, "join {name}: {value}");
        let identity = value["device_id"].as_str().expect("device id").to_string();
        let id = naming::parse_device_id(&identity).expect("id");
        let state = value["state"].as_str().expect("state").to_string();
        (identity, id, state)
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

    /// The snapshot the coordinator hands a device.
    async fn config(&self, signing: &SigningKey, identity: &str, nonce: &str) -> Value {
        let (status, value, _) = self
            .send(get_signed_at(
                "/v1/config",
                signing,
                identity,
                nonce,
                NOW_SECS as i64,
            ))
            .await;
        assert_eq!(status, StatusCode::OK, "{value}");
        value
    }
}

fn keypair(seed: u8) -> SigningKey {
    let mut bytes = [0u8; 32];
    bytes[0] = seed.max(1);
    bytes[31] = seed.max(1);
    SigningKey::from_bytes(&bytes)
}

fn signed_at(
    method: &str,
    path: &str,
    body: &[u8],
    signing: &SigningKey,
    identity: &str,
    nonce: &str,
    timestamp: i64,
) -> String {
    let message = auth::canonical(method, path, body, timestamp, nonce);
    let signature = signing.sign(&message).to_bytes();
    format!(
        "WGMESH {identity} {timestamp} {nonce} {}",
        base64::engine::general_purpose::STANDARD.encode(signature)
    )
}

fn get_signed_at(
    path: &str,
    signing: &SigningKey,
    identity: &str,
    nonce: &str,
    timestamp: i64,
) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(path)
        .header(
            header::AUTHORIZATION,
            signed_at("GET", path, b"", signing, identity, nonce, timestamp),
        )
        .body(Body::empty())
        .expect("request")
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
            signed_at(
                "POST",
                path,
                &bytes,
                signing,
                identity,
                nonce,
                NOW_SECS as i64,
            ),
        )
        .body(Body::from(bytes))
        .expect("request")
}

fn peer_ids(config: &Value) -> Vec<String> {
    config["peers"]
        .as_array()
        .expect("peers")
        .iter()
        .map(|peer| peer["device_id"].as_str().expect("id").to_string())
        .collect()
}

/// The specs a device's snapshot asks the interface to hold.
///
/// The AllowedIPs policy is deliberately not reconstructed here: this test is about which
/// devices the coordinator still lists, and the key each one is reachable by.
fn wants(config: &Value) -> Vec<PeerSpec> {
    config["peers"]
        .as_array()
        .expect("peers")
        .iter()
        .map(|peer| PeerSpec {
            id: naming::parse_device_id(peer["device_id"].as_str().expect("id"))
                .expect("device id"),
            key: naming::decode_key(peer["wg_pubkey"].as_str().expect("key")).expect("key"),
            allowed: Vec::new(),
            endpoint: None,
            keepalive: None,
        })
        .collect()
}

/// What the interface holds, in the shape `diff` compares against.
fn holds(interface: &FakeWireGuard) -> BTreeMap<DeviceId, PeerSpec> {
    interface
        .status(&[])
        .expect("status")
        .into_iter()
        .map(|status| {
            (
                status.device,
                PeerSpec {
                    id: status.device,
                    key: status.public_key,
                    allowed: status.allowed,
                    endpoint: status.endpoint,
                    keepalive: status.keepalive,
                },
            )
        })
        .collect()
}

/// What the kernel does with a packet from `from`: it looks the source up against the interface's
/// peer table, and an interface holding no entry for it has no key to try, so the packet is
/// dropped. `status` is the interface's own account of what it holds, which is what makes this
/// the check to write.
fn carries(interface: &FakeWireGuard, from: DeviceId) -> bool {
    !interface.status(&[from]).expect("status").is_empty()
}

// --- the clock window -------------------------------------------------------

#[tokio::test]
async fn a_request_further_than_a_minute_from_now_is_refused() {
    let harness = Harness::new().await;
    let signing = keypair(1);
    let (identity, _, state) = harness.enrol("clocked", &signing, true).await;
    assert_eq!(state, "active");

    for (offset, expected) in [
        (-61i64, StatusCode::UNAUTHORIZED),
        (-60, StatusCode::OK),
        (60, StatusCode::OK),
        (61, StatusCode::UNAUTHORIZED),
    ] {
        let nonce = format!("skew{offset}");
        let request = get_signed_at(
            "/v1/config",
            &signing,
            &identity,
            &nonce,
            NOW_SECS as i64 + offset,
        );
        let (status, body, _) = harness.send(request).await;
        assert_eq!(status, expected, "an offset of {offset}s: {body}");
    }
}

// --- what the database keeps ------------------------------------------------

/// The point of the step: nothing the coordinator stores is worth stealing.
#[tokio::test]
async fn the_database_keeps_hashes_and_public_keys_and_no_shared_secret() {
    let harness = Harness::new().await;
    let signing = keypair(2);
    let token = harness.mint_token(true).await;
    let (_, _, _) = harness.enrol("kept", &signing, true).await;

    let tables: Vec<(String,)> = sqlx::query_as(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
    )
    .fetch_all(harness.store.pool())
    .await
    .expect("tables");
    assert!(!tables.is_empty(), "the schema has tables");

    let mut columns: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (table,) in &tables {
        let rows: Vec<(String,)> = sqlx::query_as("SELECT name FROM pragma_table_info(?)")
            .bind(table)
            .fetch_all(harness.store.pool())
            .await
            .expect("columns");
        columns.insert(table.clone(), rows.into_iter().map(|row| row.0).collect());
    }

    // No column anywhere is named after a thing you would have to keep secret.
    for (table, names) in &columns {
        for name in names {
            let lower = name.to_lowercase();
            for forbidden in [
                "secret",
                "password",
                "passwd",
                "private",
                "passphrase",
                "shared",
                "seed",
            ] {
                assert!(
                    !lower.contains(forbidden),
                    "{table}.{name} is a column a shared secret could live in"
                );
            }
        }
    }

    // The one credential-shaped column is a hash, and there is no plaintext sibling.
    assert!(columns["join_tokens"].contains(&"token_hash".to_string()));
    assert!(!columns["join_tokens"].contains(&"token".to_string()));

    let stored: Vec<(Vec<u8>,)> = sqlx::query_as("SELECT token_hash FROM join_tokens")
        .fetch_all(harness.store.pool())
        .await
        .expect("token hashes");
    assert!(!stored.is_empty(), "a join token was spent");
    let secret = join_token::parse_token(&token).expect("the token round trips");
    assert!(
        stored
            .iter()
            .any(|row| row.0 == join_token::hash_secret(&secret).to_vec()),
        "a spent token is kept as its hash"
    );
    for row in &stored {
        assert_eq!(row.0.len(), 32, "a hash is 32 bytes");
        assert_ne!(row.0, secret.to_vec(), "the token itself is not stored");
        assert_ne!(
            row.0,
            token.as_bytes().to_vec(),
            "the token's text is not stored"
        );
    }

    // The device's keys are the public halves. The private seed the device holds is nowhere.
    let (wg, api): (Vec<u8>, Vec<u8>) =
        sqlx::query_as("SELECT wg_pubkey, api_pubkey FROM devices LIMIT 1")
            .fetch_one(harness.store.pool())
            .await
            .expect("device keys");
    assert_eq!(api, signing.verifying_key().to_bytes().to_vec());
    assert_eq!(wg, api, "the test enrols one key as both halves");
    assert_ne!(
        api,
        signing.to_bytes().to_vec(),
        "the private half is not stored"
    );
}

// --- revocation -------------------------------------------------------------

#[tokio::test]
async fn revoking_a_device_takes_it_out_of_the_peers_and_the_keyset() {
    let harness = Harness::new().await;
    let left = keypair(3);
    let right = keypair(4);

    let (left_identity, _, _) = harness.enrol("left", &left, true).await;
    let (right_identity, right_id, _) = harness.enrol("right", &right, true).await;

    let config = harness.config(&left, &left_identity, "before").await;
    assert_eq!(peer_ids(&config), vec![right_identity.clone()]);

    let keyset = harness
        .send(get_signed_at(
            "/v1/relay/keyset",
            &harness.relay_signing,
            &naming::relay_id(harness.relay),
            "keyset-before",
            NOW_SECS as i64,
        ))
        .await;
    assert_eq!(keyset.0, StatusCode::OK, "{}", keyset.1);
    let before: Vec<String> = keyset.1["networks"][0]["peers"]
        .as_array()
        .expect("peers")
        .iter()
        .map(|peer| peer["device_id"].as_str().expect("id").to_string())
        .collect();
    assert!(before.contains(&right_identity), "{before:?}");

    harness
        .services()
        .approve_device()
        .revoke("ops:oncall", right_id)
        .await
        .expect("revoke");

    // The next sync: gone from the peer list, which is the ACL.
    let config = harness.config(&left, &left_identity, "after").await;
    assert!(
        peer_ids(&config).is_empty(),
        "a revoked device is still a peer: {config}"
    );

    // And gone from the keyset the relay primes its sockets with.
    let keyset = harness
        .send(get_signed_at(
            "/v1/relay/keyset",
            &harness.relay_signing,
            &naming::relay_id(harness.relay),
            "keyset-after",
            NOW_SECS as i64,
        ))
        .await;
    assert_eq!(keyset.0, StatusCode::OK, "{}", keyset.1);
    let after: Vec<String> = keyset.1["networks"][0]["peers"]
        .as_array()
        .expect("peers")
        .iter()
        .map(|peer| peer["device_id"].as_str().expect("id").to_string())
        .collect();
    assert!(
        !after.contains(&right_identity),
        "the keyset still carries a revoked device: {after:?}"
    );

    // Its own requests stop working the moment it is revoked.
    let (status, _, _) = harness
        .send(get_signed_at(
            "/v1/config",
            &right,
            &right_identity,
            "revoked",
            NOW_SECS as i64,
        ))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// The same revocation, carried the rest of the way: what the interface does about it.
#[tokio::test]
async fn a_revoked_peer_loses_its_interface_entry_and_its_packets() {
    let harness = Harness::new().await;
    let left = keypair(5);
    let right = keypair(6);
    let (left_identity, _, _) = harness.enrol("left", &left, true).await;
    let (_, right_id, _) = harness.enrol("right", &right, true).await;

    let interface = FakeWireGuard::new();

    // Converge: the interface is given the peers the snapshot names.
    let config = harness.config(&left, &left_identity, "converge").await;
    let changes = diff(&wants(&config), &holds(&interface));
    interface.apply(&changes).expect("apply");
    assert!(
        carries(&interface, right_id),
        "the peer was not programmed: {changes:?}"
    );

    // Revoke, then let the device sync again.
    harness
        .services()
        .approve_device()
        .revoke("ops:oncall", right_id)
        .await
        .expect("revoke");
    let config = harness.config(&left, &left_identity, "resync").await;
    let changes = diff(&wants(&config), &holds(&interface));
    assert!(
        changes
            .iter()
            .any(|change| matches!(change, wgmesh_core::Change::Remove(id) if *id == right_id)),
        "the diff did not ask for the peer to go: {changes:?}"
    );
    interface.apply(&changes).expect("apply");

    assert!(
        !carries(&interface, right_id),
        "the interface still holds a peer the coordinator revoked"
    );
    assert_eq!(holds(&interface).len(), 0, "nothing else is left behind");
}

// --- approval ---------------------------------------------------------------

#[tokio::test]
async fn a_device_that_waited_for_approval_reaches_nothing_until_it_is_approved() {
    let harness = Harness::new().await;
    let signing = keypair(7);
    let (identity, id, state) = harness.enrol("held", &signing, false).await;
    assert_eq!(state, "pending", "auto_approve is off by default");

    let (status, device): (StatusCode, DeviceState) = (
        StatusCode::OK,
        harness
            .store
            .device_by_id(id)
            .await
            .expect("device")
            .expect("a record")
            .state,
    );
    assert_eq!(status, StatusCode::OK);
    assert_eq!(device, DeviceState::Pending);

    // It may read its own snapshot — that is how it learns it is waiting — and the snapshot
    // offers it nothing: no peers, and its own state says pending.
    let config = harness.config(&signing, &identity, "waiting").await;
    assert!(peer_ids(&config).is_empty(), "{config}");
    assert_eq!(config["me"]["state"], json!("pending"));

    // Everything that would act is refused.
    for (path, body) in [
        ("/v1/endpoint", json!({})),
        (
            "/v1/punch",
            json!({ "peer": identity, "outcome": "direct" }),
        ),
        (
            "/v1/rotate",
            json!({ "wg_pubkey": encode_key(&PublicKey::from_bytes([3u8; 32])) }),
        ),
    ] {
        let (status, response, _) = harness
            .send(post_signed(path, &body, &signing, &identity, "pending"))
            .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "a pending device reached {path}: {response}"
        );
    }

    // Approval puts it in the other device's peer list.
    let other = keypair(8);
    let (other_identity, _, _) = harness.enrol("approved", &other, true).await;
    harness
        .services()
        .approve_device()
        .execute("ops:alice", id)
        .await
        .expect("approve");

    let config = harness.config(&other, &other_identity, "peer-list").await;
    assert_eq!(peer_ids(&config), vec![identity.clone()]);
}

// --- the audit trail --------------------------------------------------------

#[tokio::test]
async fn joining_approving_rotating_and_revoking_are_audited_with_their_actor() {
    let harness = Harness::new().await;
    let signing = keypair(9);
    let (identity, id, state) = harness.enrol("audited", &signing, false).await;
    assert_eq!(state, "pending");

    harness
        .services()
        .approve_device()
        .execute("ops:alice", id)
        .await
        .expect("approve");

    let (status, body, _) = harness
        .send(post_signed(
            "/v1/rotate",
            &json!({ "wg_pubkey": encode_key(&PublicKey::from_bytes([4u8; 32])) }),
            &signing,
            &identity,
            "rotate",
        ))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    harness
        .services()
        .approve_device()
        .revoke("ops:bob", id)
        .await
        .expect("revoke");

    let entries = harness.store.recent_audit(50).await.expect("audit");
    let action = |name: &str| {
        entries
            .iter()
            .find(|entry| entry.action == name)
            .unwrap_or_else(|| panic!("no {name} row in {:?}", entries.len()))
            .clone()
    };

    assert_eq!(action("device.join").actor, "device:audited");
    assert_eq!(action("device.approve").actor, "ops:alice");
    assert_eq!(action("device.rotate").actor, format!("device:{identity}"));
    assert_eq!(action("device.revoke").actor, "ops:bob");

    // Each row names the device it is about, so an operator can read the trail.
    for name in [
        "device.join",
        "device.approve",
        "device.rotate",
        "device.revoke",
    ] {
        assert_eq!(action(name).device_id, Some(id), "{name} names its device");
    }
    assert!(
        action("device.join").at.0 >= Millis::from_secs(NOW_SECS).0,
        "the trail carries the time it happened"
    );
}
