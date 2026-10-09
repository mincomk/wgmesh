#![allow(clippy::unwrap_used, clippy::expect_used)]

// The adapter end to end: a real TLS handshake against a throwaway rustls server, the pin
// doing its job, the ETag round trip, and the retry policy.

mod support;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use wgmesh_client::{
    ApiSigner, ClientError, ClientSettings, HttpsCoordinator, RetryPolicy, SigningError, SpkiPin,
    canonical, sha256_hex,
};
use wgmesh_proto::{ApiErrorCode, ConfigSnapshot, PubKeyB64};

use support::{HttpResponse, Reply, TestCert, TestServer};

/// A signer with a fixed key that remembers every message it was asked to sign.
struct RecordingSigner {
    key: PubKeyB64,
    seen: Mutex<Vec<Vec<u8>>>,
}

impl RecordingSigner {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            key: PubKeyB64::from_bytes([9u8; 32]),
            seen: Mutex::new(Vec::new()),
        })
    }

    fn messages(&self) -> Vec<Vec<u8>> {
        self.seen.lock().unwrap().clone()
    }
}

impl ApiSigner for RecordingSigner {
    fn api_public_key(&self) -> PubKeyB64 {
        self.key
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.seen.lock().unwrap().push(message.to_vec());
        vec![0x5a; 64]
    }
}

fn snapshot_json() -> String {
    format!(
        concat!(
            "{{\"network\":{{\"id\":1,\"name\":\"prod\",\"cidr\":\"10.77.0.0/16\",\"mtu\":1420,\"dns\":[\"10.77.0.1\"]}},",
            "\"peers\":[{{\"device_id\":2,\"name\":\"edge-2\",\"wg_pubkey\":\"{}\",\"tunnel_ip\":\"10.77.0.2/32\",",
            "\"advertised_prefixes\":[\"10.77.3.0/24\"]}}],",
            "\"relay\":{{\"relay_id\":5,\"endpoint_host\":\"relay.example.com\",\"slot\":31000,\"pairs\":[]}},",
            "\"observations\":[{{\"device_id\":1,\"ip\":\"203.0.113.9\",\"port\":51820,\"seen_at\":1760000000}}],",
            "\"generated_at\":1760000000}}"
        ),
        PubKeyB64::from_bytes([2u8; 32])
    )
}

fn client_with(
    cert: &TestCert,
    url: &str,
    signer: Option<Arc<RecordingSigner>>,
    retry: RetryPolicy,
) -> HttpsCoordinator {
    let mut settings = ClientSettings::new(url).with_pin(cert.pin);
    settings.retry = retry;
    settings.request_timeout = Duration::from_secs(5);
    settings.connect_timeout = Duration::from_secs(5);
    let signer = signer.map(|signer| signer as Arc<dyn ApiSigner>);
    HttpsCoordinator::new(&settings, signer).expect("the client settings are valid")
}

#[tokio::test]
async fn a_pinned_client_accepts_the_certificate_it_pins() {
    let cert = TestCert::load("a");
    let server = TestServer::start(TestCert::load("a"), |_request, _index| {
        Reply::Respond(HttpResponse::json(&snapshot_json()))
    });
    let signer = RecordingSigner::new();
    let client = client_with(
        &cert,
        &server.url(),
        Some(Arc::clone(&signer)),
        RetryPolicy::once(),
    );

    let fetched = client
        .config(None)
        .await
        .expect("the pinned certificate is accepted");
    let snapshot: ConfigSnapshot = fetched.value().expect("a fresh body");
    assert_eq!(snapshot.network.name, "prod");
    assert_eq!(snapshot.peers.len(), 1);
    assert_eq!(snapshot.peers[0].advertised_prefixes.len(), 1);
    assert_eq!(snapshot.relay.as_ref().map(|relay| relay.slot), Some(31000));
    assert_eq!(snapshot.observations.len(), 1);
    assert_eq!(server.request_count(), 1);
}

#[tokio::test]
async fn a_pinned_client_refuses_a_certificate_whose_spki_differs() {
    let server = TestServer::start(TestCert::load("a"), |_request, _index| {
        Reply::Respond(HttpResponse::json(&snapshot_json()))
    });
    // The server presents certificate a, the client pins certificate b.
    let other = TestCert::load("b");
    let signer = RecordingSigner::new();
    let client = client_with(&other, &server.url(), Some(signer), RetryPolicy::once());

    let error = client
        .config(None)
        .await
        .expect_err("the pin must refuse this certificate");
    assert!(
        matches!(error, ClientError::Transport(_)),
        "expected a transport failure, got {error}"
    );
    let text = error.to_string();
    assert!(
        text.contains("certificate") || text.contains("Certificate"),
        "the refusal must name the certificate: {text}"
    );
}

#[tokio::test]
async fn the_refusal_says_which_pins_disagree() {
    let other = TestCert::load("b");
    let presented = TestCert::load("a");
    let error = other
        .pin
        .verify(&presented.chain[0])
        .expect_err("the pins differ");
    let text = error.to_string();
    assert!(text.contains(&other.pin.to_hex()));
    assert!(text.contains(&presented.pin.to_hex()));
}

#[tokio::test]
async fn the_signature_covers_the_bytes_the_server_actually_received() {
    let cert = TestCert::load("a");
    let server = TestServer::start(TestCert::load("a"), |_request, _index| {
        Reply::Respond(HttpResponse::json(&snapshot_json()))
    });
    let signer = RecordingSigner::new();
    let client = client_with(
        &cert,
        &server.url(),
        Some(Arc::clone(&signer)),
        RetryPolicy::once(),
    );

    client
        .config(Some("\"v1\""))
        .await
        .expect("the request succeeds");

    let seen = server.requests();
    assert_eq!(seen.len(), 1);
    let request = &seen[0];
    let authorization = request.header("authorization").expect("a signed request");
    let fields: Vec<&str> = authorization.split(' ').collect();
    assert_eq!(fields.len(), 5);
    assert_eq!(fields[0], "WGMESH");
    assert_eq!(fields[1], signer.key.to_string());
    let ts: i64 = fields[2].parse().expect("a timestamp");
    let nonce = fields[3];
    let expected = canonical(
        &request.method,
        &request.target,
        &request.body,
        ts,
        nonce.as_bytes(),
    );
    assert_eq!(
        signer.messages(),
        vec![expected],
        "the signed bytes must be the sent bytes"
    );
    assert_eq!(request.header("if-none-match"), Some("\"v1\""));
}

#[tokio::test]
async fn a_matching_etag_comes_back_as_not_modified_without_reading_the_body() {
    let cert = TestCert::load("a");
    let server = TestServer::start(TestCert::load("a"), |_request, _index| {
        Reply::Respond(HttpResponse::not_modified_with_a_body_that_must_not_be_read())
    });
    let signer = RecordingSigner::new();
    let client = client_with(&cert, &server.url(), Some(signer), RetryPolicy::once());

    let fetched = client
        .config(Some("\"v1\""))
        .await
        .expect("a 304 is a fine answer");
    assert!(fetched.is_not_modified());
    assert_eq!(fetched.value(), None);
    assert_eq!(server.requests()[0].header("if-none-match"), Some("\"v1\""));
}

#[tokio::test]
async fn a_fresh_answer_carries_the_etag_to_send_next_time() {
    let cert = TestCert::load("a");
    let server = TestServer::start(TestCert::load("a"), |request, _index| {
        if request.header("if-none-match") == Some("\"v7\"") {
            Reply::Respond(HttpResponse::not_modified("\"v7\""))
        } else {
            Reply::Respond(HttpResponse::json_with_etag(&snapshot_json(), "\"v7\""))
        }
    });
    let signer = RecordingSigner::new();
    let client = client_with(&cert, &server.url(), Some(signer), RetryPolicy::once());

    let first = client.config(None).await.expect("the first fetch succeeds");
    assert_eq!(first.etag(), Some("\"v7\""));
    let token = first.etag().expect("an etag").to_owned();

    let second = client
        .config(Some(&token))
        .await
        .expect("the second fetch succeeds");
    assert!(second.is_not_modified());
    assert_eq!(second.etag(), Some("\"v7\""));
    assert_eq!(server.request_count(), 2);
    assert_eq!(server.requests()[0].header("if-none-match"), None);
    assert_eq!(server.requests()[1].header("if-none-match"), Some("\"v7\""));
}

#[tokio::test]
async fn a_transient_server_error_is_retried_with_a_fresh_signature() {
    let cert = TestCert::load("a");
    let server = TestServer::start(TestCert::load("a"), |_request, index| {
        if index == 0 {
            Reply::Respond(HttpResponse::api_error(503, "internal", "try again"))
        } else {
            Reply::Respond(HttpResponse::json(&snapshot_json()))
        }
    });
    let signer = RecordingSigner::new();
    let mut settings = ClientSettings::new(server.url()).with_pin(cert.pin);
    settings.retry = RetryPolicy {
        attempts: 3,
        base_delay: Duration::from_millis(40),
        max_delay: Duration::from_millis(200),
    };
    let client = HttpsCoordinator::new(&settings, Some(Arc::clone(&signer) as Arc<dyn ApiSigner>))
        .expect("valid settings");

    let started = Instant::now();
    let fetched = client
        .config(None)
        .await
        .expect("the second attempt succeeds");
    assert!(fetched.value().is_some());
    assert!(
        started.elapsed() >= Duration::from_millis(40),
        "the retry must wait"
    );
    assert_eq!(server.request_count(), 2);

    let seen = server.requests();
    let first: Vec<&str> = seen[0]
        .header("authorization")
        .unwrap()
        .split(' ')
        .collect();
    let second: Vec<&str> = seen[1]
        .header("authorization")
        .unwrap()
        .split(' ')
        .collect();
    assert_ne!(
        first[3], second[3],
        "a retry must use a fresh nonce, not the one that may have been seen"
    );
}

#[tokio::test]
async fn a_client_error_is_not_retried() {
    let cert = TestCert::load("a");
    let server = TestServer::start(TestCert::load("a"), |_request, _index| {
        Reply::Respond(HttpResponse::api_error(
            401,
            "unauthorized",
            "the signature did not verify",
        ))
    });
    let signer = RecordingSigner::new();
    let mut settings = ClientSettings::new(server.url()).with_pin(cert.pin);
    settings.retry = RetryPolicy {
        attempts: 3,
        base_delay: Duration::from_millis(10),
        max_delay: Duration::from_millis(10),
    };
    let client = HttpsCoordinator::new(&settings, Some(signer as Arc<dyn ApiSigner>))
        .expect("valid settings");

    let error = client.config(None).await.expect_err("401 is final");
    match error {
        ClientError::Api { status, body } => {
            assert_eq!(status, 401);
            assert_eq!(body.code, ApiErrorCode::Unauthorized);
        }
        other => panic!("expected an API error, got {other}"),
    }
    assert_eq!(server.request_count(), 1, "a 401 must not be retried");
}

#[tokio::test]
async fn the_retry_budget_is_honoured_and_then_given_up_on() {
    let cert = TestCert::load("a");
    let server = TestServer::start(TestCert::load("a"), |_request, _index| {
        Reply::Respond(HttpResponse::api_error(500, "internal", "still broken"))
    });
    let signer = RecordingSigner::new();
    let mut settings = ClientSettings::new(server.url()).with_pin(cert.pin);
    settings.retry = RetryPolicy {
        attempts: 2,
        base_delay: Duration::from_millis(10),
        max_delay: Duration::from_millis(10),
    };
    let client = HttpsCoordinator::new(&settings, Some(signer as Arc<dyn ApiSigner>))
        .expect("valid settings");

    let error = client
        .config(None)
        .await
        .expect_err("500 with no third attempt");
    assert_eq!(error.status(), Some(500));
    assert_eq!(server.request_count(), 2);
}

#[tokio::test]
async fn a_server_that_never_answers_hits_the_request_timeout() {
    let cert = TestCert::load("a");
    let server = TestServer::start(TestCert::load("a"), |_request, _index| Reply::Hang);
    let signer = RecordingSigner::new();
    let mut settings = ClientSettings::new(server.url()).with_pin(cert.pin);
    settings.retry = RetryPolicy::once();
    settings.request_timeout = Duration::from_millis(300);
    let client = HttpsCoordinator::new(&settings, Some(signer as Arc<dyn ApiSigner>))
        .expect("valid settings");

    let error = client.config(None).await.expect_err("the timeout fires");
    assert!(
        matches!(error, ClientError::Timeout),
        "expected a timeout, got {error}"
    );
}

#[tokio::test]
async fn a_signed_call_without_a_signer_is_refused_before_it_leaves() {
    let cert = TestCert::load("a");
    let settings = ClientSettings::new("https://127.0.0.1:1").with_pin(cert.pin);
    let client = HttpsCoordinator::new(&settings, None).expect("valid settings");
    let error = client
        .config(None)
        .await
        .expect_err("a signed call needs a signer");
    assert!(matches!(error, ClientError::NoSigner(_)));
    assert!(error.to_string().contains("/v1/config"));
}

#[tokio::test]
async fn a_body_the_coordinator_must_see_is_the_body_that_is_hashed() {
    let cert = TestCert::load("a");
    let server = TestServer::start(TestCert::load("a"), |_request, _index| {
        Reply::Respond(HttpResponse::json("{\"ok\":true}"))
    });
    let signer = RecordingSigner::new();
    let client = client_with(
        &cert,
        &server.url(),
        Some(Arc::clone(&signer)),
        RetryPolicy::once(),
    );
    let report = wgmesh_proto::EndpointReport {
        candidates: vec![wgmesh_proto::CandidateReport {
            kind: wgmesh_proto::CandidateKind::Lan,
            endpoint: "192.168.1.20:51820".parse().unwrap(),
        }],
        reported_at: 1760000000,
    };

    client
        .report_endpoint(&report)
        .await
        .expect("the report is accepted");

    let seen = server.requests();
    let request = &seen[0];
    assert_eq!(request.method, "POST");
    assert_eq!(request.target, "/v1/endpoint");
    assert_eq!(
        String::from_utf8(request.body.clone()).unwrap(),
        "{\"candidates\":[{\"kind\":\"lan\",\"endpoint\":\"192.168.1.20:51820\"}],\"reported_at\":1760000000}"
    );
    let fields: Vec<&str> = request
        .header("authorization")
        .unwrap()
        .split(' ')
        .collect();
    let ts: i64 = fields[2].parse().unwrap();
    assert_eq!(
        signer.messages(),
        vec![canonical(
            "POST",
            "/v1/endpoint",
            &request.body,
            ts,
            fields[3].as_bytes()
        )]
    );
    assert_eq!(sha256_hex(&request.body).len(), 64);
}

#[tokio::test]
async fn the_enrollment_path_sends_the_body_unsigned_as_the_design_asks() {
    let cert = TestCert::load("a");
    let server = TestServer::start(TestCert::load("a"), |_request, _index| {
        Reply::Respond(HttpResponse::json(
            "{\"device_id\":1,\"network\":{\"id\":1,\"name\":\"prod\",\"cidr\":\"10.77.0.0/16\",\"mtu\":1420,\"dns\":[]},\"peers\":[],\"relay_pool\":[]}",
        ))
    });
    let client = client_with(&cert, &server.url(), None, RetryPolicy::once());
    let request = wgmesh_proto::JoinRequest {
        token: "WGMESH-7K3M-9QXA-4PZ2".to_owned(),
        wg_pubkey: PubKeyB64::from_bytes([4u8; 32]),
        api_pubkey: PubKeyB64::from_bytes([5u8; 32]),
        name: "edge-1".to_owned(),
        os: Some("linux".to_owned()),
        agent_version: "0.1.0".to_owned(),
    };

    let answer = client.join(&request).await.expect("enrollment succeeds");
    assert_eq!(answer.device_id, 1);
    let seen = server.requests();
    assert_eq!(seen[0].target, "/v1/join");
    assert_eq!(
        seen[0].header("authorization"),
        None,
        "the join token is the credential, not a signature"
    );
    assert!(
        String::from_utf8(seen[0].body.clone())
            .unwrap()
            .contains("WGMESH-7K3M-9QXA-4PZ2")
    );
}

#[tokio::test]
async fn the_relay_keyset_revision_travels_in_the_query_string_and_is_signed_with_it() {
    let cert = TestCert::load("a");
    let server = TestServer::start(TestCert::load("a"), |_request, _index| {
        Reply::Respond(HttpResponse::json(
            "{\"revision\":42,\"networks\":[],\"retired_networks\":[]}",
        ))
    });
    let signer = RecordingSigner::new();
    let client = client_with(
        &cert,
        &server.url(),
        Some(Arc::clone(&signer)),
        RetryPolicy::once(),
    );

    let keyset = client.relay_keyset(41).await.expect("the keyset arrives");
    assert_eq!(keyset.revision, 42);
    let seen = server.requests();
    assert_eq!(seen[0].target, "/v1/relay/keyset?since=41");
    let fields: Vec<&str> = seen[0]
        .header("authorization")
        .unwrap()
        .split(' ')
        .collect();
    let ts: i64 = fields[2].parse().unwrap();
    assert_eq!(
        signer.messages(),
        vec![canonical(
            "GET",
            "/v1/relay/keyset?since=41",
            &[],
            ts,
            fields[3].as_bytes()
        )],
        "the signed path must include the query string the server sees"
    );
}

#[tokio::test]
async fn a_fetch_reports_a_body_the_api_defines_as_an_error() {
    let cert = TestCert::load("a");
    let server = TestServer::start(TestCert::load("a"), |_request, _index| {
        Reply::Respond(HttpResponse::api_error(
            403,
            "pending",
            "waiting for approval",
        ))
    });
    let signer = RecordingSigner::new();
    let client = client_with(&cert, &server.url(), Some(signer), RetryPolicy::once());
    let error = client
        .config(None)
        .await
        .expect_err("pending devices are refused");
    match error {
        ClientError::Api { status, body } => {
            assert_eq!(status, 403);
            assert_eq!(body.code, ApiErrorCode::Pending);
            assert!(body.message.contains("approval"));
        }
        other => panic!("expected an API error, got {other}"),
    }
}

#[test]
fn a_signing_failure_is_not_retried_and_a_pin_that_is_not_hex_is_refused() {
    assert!(!ClientError::Signing(SigningError::EmptyNonce).is_retryable());
    assert!(SpkiPin::parse("nonsense").is_err());
}
