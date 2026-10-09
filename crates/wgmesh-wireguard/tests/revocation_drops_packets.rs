#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use serde_json::Value;
use tower::ServiceExt;

use wgmesh_core::{Allowed, Change, DeviceId, PeerSpec, PublicKey, diff};
use wgmesh_coordinator::{ADMIN_HEADER, AdminAuth, AppState, Clock, Store, router};
use wgmesh_ports::{InterfaceSpec, WireGuard};
use wgmesh_wireguard::testing::FakeWireGuard;

struct FixedClock(AtomicI64);

impl Clock for FixedClock {
    fn now_secs(&self) -> i64 {
        self.0.load(Ordering::Relaxed)
    }
}

struct Device {
    key: String,
    secret: [u8; 32],
}

impl Device {
    fn signed(&self, method: &str, path: &str, body: &str, nonce: [u8; 16]) -> Request<Body> {
        let message = wgmesh_proto::canonical(method, path, body.as_bytes(), 1_000_000, &nonce);
        let signature = wgmesh_secrets::sign(&self.secret, &message);
        Request::builder()
            .method(method)
            .uri(path)
            .header(
                "authorization",
                format!(
                    "WGMESH {} 1000000 {} {}",
                    self.key,
                    wgmesh_proto::encode_base64(&nonce),
                    wgmesh_proto::encode_base64(&signature)
                ),
            )
            .body(Body::from(body.to_owned()))
            .unwrap()
    }
}

struct Harness {
    app: Router,
    store: Store,
    network: i64,
}

async fn join(harness: &Harness, name: &str, seed: u8) -> Device {
    let token = format!("WGMESH-REVOCATION-{name}");
    harness
        .store
        .create_join_token(harness.network, "device", &token, 1, true, 2_000_000, "admin", 1_000_000)
        .await
        .unwrap();
    let secret = [seed; 32];
    let body = serde_json::json!({
        "token": token,
        "wg_pubkey": wgmesh_proto::encode_base64(&[seed; 32]),
        "api_pubkey": wgmesh_proto::encode_base64(&wgmesh_secrets::public_key(&secret)),
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
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    Device {
        key: value["device_id"].as_str().unwrap().to_owned(),
        secret,
    }
}

async fn snapshot(harness: &Harness, device: &Device, nonce: u8) -> Value {
    let response = harness
        .app
        .clone()
        .oneshot(device.signed("GET", "/v1/config", "", [nonce; 16]))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn address(text: &str) -> Allowed {
    let (ip, length) = text.split_once('/').unwrap();
    let octets: Vec<u8> = ip.split('.').map(|part| part.parse().unwrap()).collect();
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&octets[..4]);
    Allowed::V4(bytes, length.parse().unwrap())
}

// The coordinator's peer list becomes the kernel's peer table the way the agent
// does it: the desired set is diffed against what is installed, and only the
// difference is applied.
fn desired_from(snapshot: &Value) -> Vec<PeerSpec> {
    snapshot["peers"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
        .map(|(index, peer)| {
            let key = wgmesh_proto::decode_base64(peer["wg_pubkey"].as_str().unwrap()).unwrap();
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&key[..32]);
            PeerSpec {
                id: DeviceId(index as u32 + 1),
                key: PublicKey::from_bytes(bytes),
                allowed: vec![address(peer["tunnel_ip"].as_str().unwrap())],
                endpoint: None,
                keepalive: None,
            }
        })
        .collect()
}

#[tokio::test]
async fn a_revoked_device_leaves_the_peer_list_and_its_packets_are_dropped() {
    let store = Store::open_in_memory().await.unwrap();
    let network = store
        .create_network("prod", "10.77.0.0/16", 1420, 1_000_000)
        .await
        .unwrap();
    let clock = Arc::new(FixedClock(AtomicI64::new(1_000_000)));
    let state = AppState::new(
        store.clone(),
        AdminAuth::from_token("admin-secret"),
        Arc::clone(&clock) as Arc<dyn Clock>,
    );
    let harness = Harness {
        app: router(state),
        store,
        network,
    };

    let alpha = join(&harness, "alpha", 31).await;
    let beta = join(&harness, "beta", 42).await;

    let tunnel_ip = harness.store.device(&beta.key).await.unwrap().unwrap().tunnel_ip;
    let dropped = address(&tunnel_ip);

    let wireguard = FakeWireGuard::new();
    wireguard
        .ensure_interface(&InterfaceSpec {
            name: String::from("wg0"),
            address: Allowed::V4([10, 77, 0, 1], 16),
            listen_port: 51820,
            mtu: 1420,
        })
        .unwrap();

    let before = snapshot(&harness, &alpha, 1).await;
    assert_eq!(before["keyset"].as_array().unwrap().len(), 1);
    let desired = desired_from(&before);
    assert_eq!(desired.len(), 1);
    wireguard.apply(&diff(&desired, &wireguard.peers())).unwrap();
    assert_eq!(
        wireguard.accepts_from(dropped),
        Some(DeviceId(1)),
        "before the revocation the peer's packets are accepted"
    );
    assert_eq!(wireguard.route_to(dropped), Some(DeviceId(1)));

    let revoked = harness
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/devices/{}/revoke", beta.key))
                .header(ADMIN_HEADER, "admin-secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(revoked.status(), StatusCode::OK);

    let after = snapshot(&harness, &alpha, 2).await;
    assert_eq!(after["peers"].as_array().unwrap().len(), 0);
    assert_eq!(after["keyset"].as_array().unwrap().len(), 0);
    assert_ne!(before["etag"], after["etag"]);

    let desired = desired_from(&after);
    let changes = diff(&desired, &wireguard.peers());
    assert_eq!(changes, vec![Change::Remove(DeviceId(1))]);
    wireguard.apply(&changes).unwrap();

    assert!(wireguard.peers().is_empty());
    assert_eq!(
        wireguard.accepts_from(dropped),
        None,
        "the revoked peer's packets are dropped: no peer claims its address any more"
    );
    assert_eq!(wireguard.route_to(dropped), None);
}
