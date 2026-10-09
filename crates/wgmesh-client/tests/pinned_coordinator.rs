#![allow(clippy::unwrap_used, clippy::expect_used)]

// The acceptance tests for the HTTPS client: a real TLS server in front of the coordinator's own
// router, and a client that pins it.
//
// Nothing here is a double except the clock. The server is `wgmesh_coordinator::router` over a real
// SQLite database, served over TLS with the certificate in `tests/data/server.pem`, so the
// signature the client produces is checked by the same `authenticate` extractor that checks a
// deployed device, and the pin is checked by a real handshake rather than by a mock.
//
// The two pins are the ones `openssl` reports for the two certificates:
//
//   openssl x509 -in server.pem -noout -pubkey | openssl pkey -pubin -outform DER | sha256sum
//
// They are written down here as constants so that `spki_sha256` is checked against a number it had
// no part in computing.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;

use axum::Router;
use base64::Engine as _;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::service::TowerToHyperService;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use wgmesh_app::coordinator::ports::{
    Directory, NewJoinToken, NewNetwork, NewRelay, RelayState, TokenKind, TokenStore,
};
use wgmesh_client::{ConfigExchange, Coordinator, spki_sha256};
use wgmesh_coordinator::clock::FixedClock;
use wgmesh_coordinator::router;
use wgmesh_coordinator::service::Services;
use wgmesh_coordinator::store::Sqlite;
use wgmesh_core::{Allowed, Millis, PublicKey};
use wgmesh_ports::{
    Class, Clock, CoordinatorApi, EnrollRequest, Enrollment, JoinToken, SecretError, SecretStore,
    Signature, Spki,
};
use wgmesh_proto as naming;
use wgmesh_proto::api::RelayEnrollBody;
use wgmesh_proto::token as join_token;
use wgmesh_secrets::{FileSecretStore, SecretSource};

const NOW_SECS: u64 = 1_760_000_000;

/// What `openssl` says the certificate in `tests/data/server.pem` holds.
const SERVER_PIN: &str = "880c346de24ce701d4c16430175ef26aafa1018bf712e266844f28b5a4357518";
/// And the other certificate, which nothing pins.
const OTHER_PIN: &str = "6007f67b59119c678b061e810213c113bf87a45467ea6217ec1e11be170a782a";

const SERVER_CERT: &str = include_str!("data/server.pem");
const SERVER_KEY: &str = include_str!("data/server.key.pem");
const OTHER_CERT: &str = include_str!("data/other.pem");

/// The device's key material, as the client's port wants it.
///
/// It is the workspace's own key file underneath, so the client signs with the same adapter a
/// deployed device signs with — the only difference is that this one lives in a temp directory.
struct Signer {
    store: FileSecretStore,
}
impl Signer {
    fn new(directory: impl AsRef<Path>) -> Self {
        Self {
            store: FileSecretStore::api(directory, SecretSource::LoadOrGenerate),
        }
    }

    fn public(&self) -> [u8; 32] {
        self.store.public_key().expect("the key is generated here")
    }
}

impl SecretStore for Signer {
    fn wireguard_public_key(&self) -> Result<PublicKey, SecretError> {
        Ok(PublicKey::from_bytes(self.public()))
    }

    fn public_key(&self) -> Result<PublicKey, SecretError> {
        Ok(PublicKey::from_bytes(self.public()))
    }

    fn sign(&self, message: &[u8]) -> Result<Signature, SecretError> {
        let signature = self
            .store
            .sign(message)
            .map_err(|error| SecretError::fatal(error.to_string()))?;
        Ok(Signature::from_bytes(signature))
    }
}

/// The coordinator's fixed clock, as the client's port wants it.
///
/// A request's timestamp comes from `wgmesh_ports::Clock` while the coordinator reads its own
/// clock, and they are two traits with the same shape; this wrapper is what keeps one instant on
/// both sides of the connection, so the skew window is never what a test is measuring.
struct PortClock(Arc<FixedClock>);

impl Clock for PortClock {
    fn now(&self) -> Millis {
        self.0.now()
    }
}

/// The coordinator, its database and a TLS listener in front of it.
struct Harness {
    origin: String,
    store: Arc<Sqlite>,
    clock: Arc<FixedClock>,
    port_clock: PortClock,
    network_id: u32,
    minted: AtomicU8,
    _dir: tempfile::TempDir,
}

impl Harness {
    async fn new() -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let url = format!(
            "sqlite://{}?mode=rwc",
            dir.path().join("coordinator.db").display()
        );
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

        let relay_signer = FileSecretStore::api(dir.path().join("relay-api"), SecretSource::LoadOrGenerate);
        let relay = store
            .insert_relay(&NewRelay {
                name: "relay-1".to_string(),
                api_pubkey: PublicKey::from_bytes(relay_signer.public_key().expect("relay key")),
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
        let origin = serve_tls(router(services)).await;
        let port_clock = PortClock(clock.clone());

        Self {
            origin,
            store,
            clock,
            port_clock,
            network_id: network.id,
            minted: AtomicU8::new(0),
            _dir: dir,
        }
    }

    /// A directory under this test's temp dir, for one principal's key.
    fn key_dir(&self, name: &str) -> PathBuf {
        self._dir.path().join(name)
    }

    /// A fresh join token, and the text a person would hand over.
    async fn mint(&self, kind: TokenKind, auto_approve: bool) -> String {
        let mut secret = [0u8; 20];
        secret[0] = self.minted.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        secret[19] = 0xa5;
        let text = join_token::format_token(&secret);
        self.store
            .insert_join_token(&NewJoinToken {
                network_id: self.network_id,
                kind,
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
}

/// A client for this harness, pinned to the certificate the server presents.
fn pinned_client<'a>(
    harness: &'a Harness,
    signer: &'a Signer,
    pin: &str,
) -> Coordinator<'a, Signer, PortClock> {
    Coordinator::new(harness.origin.as_str(), spki(pin), signer, &harness.port_clock)
        .expect("a client")
}

/// Enrol through the client, and answer what the coordinator said.
async fn enrol(
    client: &Coordinator<'_, Signer, PortClock>,
    signer: &Signer,
    token: &str,
    name: &str,
) -> Enrollment {
    client
        .enroll(EnrollRequest {
            token: JoinToken::new(token),
            signer: signer.public_key().expect("public key"),
            wireguard: signer.wireguard_public_key().expect("wireguard key"),
            hostname: Some(name.to_string()),
        })
        .await
        .unwrap_or_else(|error| panic!("enrolling {name} failed: {error}"))
}

/// A pin from its 64 hex characters.
fn spki(text: &str) -> Spki {
    let mut bytes = [0u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).expect("hex");
    }
    Spki::from_bytes(bytes)
}

/// The PEM body of a certificate or key, as DER.
fn pem_der(text: &str) -> Vec<u8> {
    let body: String = text
        .lines()
        .filter(|line| !line.trim_start().starts_with("-----"))
        .collect();
    base64::engine::general_purpose::STANDARD
        .decode(body)
        .expect("a PEM body is base64")
}

/// The certificate and key the test server presents.
fn server_config() -> Arc<rustls::ServerConfig> {
    let certificate = CertificateDer::from(pem_der(SERVER_CERT));
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pem_der(SERVER_KEY)));
    Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("the provider supports the default versions")
        .with_no_client_auth()
        .with_single_cert(vec![certificate], key)
        .expect("the certificate and key go together"),
    )
}

/// Serve `app` over TLS on a loopback port, and answer the origin to reach it at.
async fn serve_tls(app: Router) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("the bound address").port();
    let acceptor = TlsAcceptor::from(server_config());
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let app = app.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(stream).await else {
                    // A handshake the client refused ends here, which is the point of the
                    // pin-mismatch test: there is no request and no answer.
                    return;
                };
                let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                    .serve_connection_with_upgrades(
                        TokioIo::new(tls),
                        TowerToHyperService::new(app),
                    )
                    .await;
            });
        }
    });
    format!("https://127.0.0.1:{port}")
}

/// The host address of a tunnel prefix, which is what the coordinator publishes as a peer's band.
fn host(prefix: Allowed) -> Allowed {
    match prefix {
        Allowed::V4(address, _) => Allowed::V4(address, 32),
        Allowed::V6(address, _) => Allowed::V6(address, 128),
    }
}

// --- the pin ----------------------------------------------------------------

/// The extractor, against a number `openssl` computed for a real certificate.
#[test]
fn the_pin_is_the_key_openssl_reports() {
    let expected: [u8; 32] = *spki(SERVER_PIN).as_bytes();
    assert_eq!(spki_sha256(&pem_der(SERVER_CERT)), Some(expected));
    let expected: [u8; 32] = *spki(OTHER_PIN).as_bytes();
    assert_eq!(spki_sha256(&pem_der(OTHER_CERT)), Some(expected));
    assert_ne!(spki_sha256(&pem_der(SERVER_CERT)), spki_sha256(&pem_der(OTHER_CERT)));
}

// --- (a) a pinned client joins and syncs ------------------------------------

#[tokio::test]
async fn a_pinned_client_enrols_and_reads_the_world() {
    let harness = Harness::new().await;
    let left_key = Signer::new(harness.key_dir("left"));
    let right_key = Signer::new(harness.key_dir("right"));
    let left = pinned_client(&harness, &left_key, SERVER_PIN);
    let right = pinned_client(&harness, &right_key, SERVER_PIN);

    let token = harness.mint(TokenKind::Device, true).await;
    let left_device = enrol(&left, &left_key, &token, "left").await;
    assert_eq!(left_device.network, "prod");
    let token = harness.mint(TokenKind::Device, true).await;
    let right_device = enrol(&right, &right_key, &token, "right").await;

    // The enrollment taught the client its own name: a signed call follows without being told.
    assert_eq!(
        left.identity().as_deref(),
        Some(naming::device_id(left_device.device).as_str())
    );

    let snapshot = left.config(None).await.expect("the world");
    assert!(snapshot.etag.starts_with('"'), "{}", snapshot.etag);
    assert_eq!(snapshot.network, vec![Allowed::V4([10, 77, 0, 0], 16)]);
    assert_eq!(
        snapshot.advertised,
        vec![host(right_device.tunnel_ip.clone())]
    );

    let peer = snapshot
        .peers
        .iter()
        .find(|peer| peer.id == right_device.device)
        .unwrap_or_else(|| panic!("the world does not name the other device: {snapshot:?}"));
    assert_eq!(
        peer.key,
        PublicKey::from_bytes(right_key.public()),
        "the peer's key is the one it enrolled with"
    );
    assert_eq!(peer.allowed, vec![host(right_device.tunnel_ip.clone())]);
    assert_eq!(peer.keepalive, Some(Duration::from_secs(25)));
}

// --- (b) a wrong pin is a trust failure, not a retry -------------------------

#[tokio::test]
async fn a_wrong_pin_refuses_the_connection_and_is_a_trust_failure() {
    let harness = Harness::new().await;
    let signer = Signer::new(harness.key_dir("device"));

    // The other certificate's key is pinned; the server presents the first one's.
    let client = pinned_client(&harness, &signer, OTHER_PIN);
    let token = harness.mint(TokenKind::Device, true).await;
    let error = client
        .enroll(EnrollRequest {
            token: JoinToken::new(&token),
            signer: signer.public_key().expect("public key"),
            wireguard: signer.wireguard_public_key().expect("wireguard key"),
            hostname: Some("refused".to_string()),
        })
        .await
        .expect_err("a wrong pin must not connect");
    assert_eq!(error.class(), Class::Trust, "{error}");
    assert!(
        !error.class().is_retryable(),
        "a pin mismatch is the one failure nothing retries"
    );
    // The detail a person needs: both keys, so the two sides can be compared.
    assert!(error.detail().contains(SERVER_PIN), "{error}");
    assert!(error.detail().contains(OTHER_PIN), "{error}");

    // Nothing reached the coordinator. The one-use token is still there for a client that pins
    // the key it was told to expect, which is what "the connection was refused" means.
    let honest = pinned_client(&harness, &signer, SERVER_PIN);
    let enrolled = enrol(&honest, &signer, &token, "honest").await;
    assert_ne!(enrolled.device.0, 0);
}

// --- (c) the signed request passes the coordinator's own authenticator -------

#[tokio::test]
async fn a_signed_request_passes_the_coordinators_authenticator() {
    let harness = Harness::new().await;
    let signer = Signer::new(harness.key_dir("device"));
    let client = pinned_client(&harness, &signer, SERVER_PIN);
    let token = harness.mint(TokenKind::Device, true).await;
    let device = enrol(&client, &signer, &token, "signed").await;

    // GET /v1/config sits behind `require_device`, which reads the `Authorization` header, finds
    // the device by the id in it, and verifies the signature over the canonical string. A 200 is
    // that whole path having agreed with what this client produced.
    let answer = client.exchange_config(None).await.expect("authenticated");
    assert!(matches!(answer, ConfigExchange::Fresh { .. }), "no body");

    // And it is verified rather than trusted: the same device id, a key that is not its own.
    let impostor_key = Signer::new(harness.key_dir("impostor"));
    let impostor = pinned_client(&harness, &impostor_key, SERVER_PIN)
        .with_identity(naming::device_id(device.device));
    let error = impostor
        .exchange_config(None)
        .await
        .expect_err("a signature by the wrong key must be refused");
    assert_eq!(error.class(), Class::Recoverable, "{error}");
    assert!(error.detail().contains("401"), "{error}");
}

// --- (d) the configuration version, and what a 304 means --------------------

#[tokio::test]
async fn the_config_etag_round_trips_as_a_304() {
    let harness = Harness::new().await;
    let signer = Signer::new(harness.key_dir("device"));
    let client = pinned_client(&harness, &signer, SERVER_PIN);
    let token = harness.mint(TokenKind::Device, true).await;
    enrol(&client, &signer, &token, "versioned").await;

    let etag = match client.exchange_config(None).await.expect("first read") {
        ConfigExchange::Fresh { etag, .. } => etag,
        other => panic!("a first read is a body, not {other:?}"),
    };

    // Naming the version the world still is: no body comes back.
    match client.exchange_config(Some(&etag)).await.expect("second read") {
        ConfigExchange::NotModified { etag: returned } => {
            assert_eq!(returned.as_deref(), Some(etag.as_str()));
        }
        other => panic!("expected a 304, got {other:?}"),
    }

    // The port hands a caller the world either way, out of what the 200 remembered.
    let snapshot = client.config(Some(&etag)).await.expect("the world");
    assert_eq!(snapshot.etag, etag);

    // A version the coordinator does not hold is answered with the body.
    assert!(matches!(
        client.exchange_config(Some("\"stale\"")).await.expect("stale"),
        ConfigExchange::Fresh { .. }
    ));
}

// --- the relay's own path ---------------------------------------------------

#[tokio::test]
async fn a_relay_enrols_and_fetches_its_assignment_over_the_signed_path() {
    let harness = Harness::new().await;
    let signer = Signer::new(harness.key_dir("relay"));
    let relay = pinned_client(&harness, &signer, SERVER_PIN).with_name("relay-9");

    let token = harness.mint(TokenKind::Relay, true).await;
    let enrolled = relay
        .relay_enroll(&RelayEnrollBody {
            token,
            name: "relay-9".to_string(),
            api_pubkey: naming::encode_key(&signer.public_key().expect("public key")),
            endpoint_host: "198.51.100.9".to_string(),
            port_range: "52000-52099".to_string(),
            region: None,
            provider: None,
            operator: None,
            networks: Vec::new(),
        })
        .await
        .expect("a relay enrols with a relay token");
    assert_eq!(enrolled.state, "active");
    assert!(enrolled.relay_id.starts_with("relay_"), "{enrolled:?}");
    assert_eq!(relay.identity().as_deref(), Some(enrolled.relay_id.as_str()));

    // The id enrollment produced is what signs the assignment, which is behind `require_relay`.
    let assignment = relay.relay_assignment().await.expect("the assignment");
    assert_eq!(assignment.relay_id, enrolled.relay_id);
    assert_eq!(assignment.endpoint_host, "198.51.100.9");
    assert!(assignment.slots.is_empty(), "{assignment:?}");
}
