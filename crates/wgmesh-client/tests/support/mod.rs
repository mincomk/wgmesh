#![allow(clippy::unwrap_used, clippy::expect_used, dead_code)]

// A throwaway HTTPS server for the transport tests: rustls terminates TLS with one of the
// self signed fixtures, and a closure decides what each request is answered with. It records
// every request, so a test can assert what actually went on the wire.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};

use wgmesh_client::SpkiPin;

/// One request as the server saw it.
#[derive(Clone, Debug)]
pub struct SeenRequest {
    /// Method, uppercase as sent.
    pub method: String,
    /// Request target, path and query.
    pub target: String,
    /// Headers, lowercased names.
    pub headers: Vec<(String, String)>,
    /// Body bytes as received.
    pub body: Vec<u8>,
}

impl SeenRequest {
    /// A header by lowercased name.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }
}

/// What the server does with a request.
pub enum Reply {
    /// Answer with this.
    Respond(HttpResponse),
    /// Accept the connection and never answer, so the client runs into its timeout.
    Hang,
}

/// A response the test server writes by hand.
pub struct HttpResponse {
    pub status: u16,
    pub reason: &'static str,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// A `200` with a JSON body.
    pub fn json(body: &str) -> Self {
        Self {
            status: 200,
            reason: "OK",
            headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
            body: body.as_bytes().to_vec(),
        }
    }

    /// A `200` with a JSON body and an ETag.
    pub fn json_with_etag(body: &str, etag: &str) -> Self {
        let mut response = Self::json(body);
        response.headers.push(("ETag".to_owned(), etag.to_owned()));
        response
    }

    /// A `304` that repeats an ETag.
    pub fn not_modified(etag: &str) -> Self {
        Self {
            status: 304,
            reason: "Not Modified",
            headers: vec![("ETag".to_owned(), etag.to_owned())],
            body: Vec::new(),
        }
    }

    /// A `304` that also carries a body, which the protocol forbids: it is here so a test can
    /// show that a client which honours the status never looks at the body.
    pub fn not_modified_with_a_body_that_must_not_be_read() -> Self {
        Self {
            status: 304,
            reason: "Not Modified",
            headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
            body: b"this is not json and a client that parsed it would fail".to_vec(),
        }
    }

    /// An error response with the API's error body.
    pub fn api_error(status: u16, code: &str, message: &str) -> Self {
        Self {
            status,
            reason: "Error",
            headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
            body: format!("{{\"code\":\"{code}\",\"message\":\"{message}\"}}").into_bytes(),
        }
    }
}

/// A test certificate: its chain, its key and the pin a client would record.
pub struct TestCert {
    pub chain: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
    pub pin: SpkiPin,
}

impl TestCert {
    /// Load fixture `a` or `b`.
    pub fn load(which: &str) -> Self {
        let (cert, key) = match which {
            "a" => (
                include_bytes!("../fixtures/a.crt.der").as_slice(),
                include_bytes!("../fixtures/a.key.der").as_slice(),
            ),
            "b" => (
                include_bytes!("../fixtures/b.crt.der").as_slice(),
                include_bytes!("../fixtures/b.key.der").as_slice(),
            ),
            other => panic!("unknown fixture {other}"),
        };
        let chain = vec![CertificateDer::from(cert.to_vec())];
        let pin = SpkiPin::of_certificate(cert).expect("the fixture is a certificate");
        Self {
            chain,
            key: PrivateKeyDer::Pkcs8(key.to_vec().into()),
            pin,
        }
    }
}

/// A server that answers every request through `reply`.
pub struct TestServer {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<SeenRequest>>>,
}

impl TestServer {
    /// Start a server for `cert`, answering with `reply`. The closure also receives the
    /// zero based request count, so a test can fail once and then succeed.
    pub fn start<F>(cert: TestCert, reply: F) -> Self
    where
        F: Fn(&SeenRequest, usize) -> Reply + Send + Sync + 'static,
    {
        let config = Arc::new(
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .expect("the ring provider supports the default versions")
                .with_no_client_auth()
                .with_single_cert(cert.chain.clone(), cert.key.clone_key())
                .expect("the fixture certificate and key match"),
        );
        let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
        let addr = listener.local_addr().expect("the bound address");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let collected = Arc::clone(&seen);
        let reply = Arc::new(reply);
        let counter = Arc::new(AtomicUsize::new(0));
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let config = Arc::clone(&config);
                let collected = Arc::clone(&collected);
                let reply = Arc::clone(&reply);
                let counter = Arc::clone(&counter);
                std::thread::spawn(move || {
                    let index = counter.fetch_add(1, Ordering::SeqCst);
                    serve(stream, config, reply.as_ref(), &collected, index);
                });
            }
        });
        Self { addr, seen }
    }

    /// The base URL of this server.
    pub fn url(&self) -> String {
        format!("https://127.0.0.1:{}", self.addr.port())
    }

    /// Everything the server has been asked so far.
    pub fn requests(&self) -> Vec<SeenRequest> {
        self.seen
            .lock()
            .expect("the request log is not poisoned")
            .clone()
    }

    /// How many requests have arrived.
    pub fn request_count(&self) -> usize {
        self.seen
            .lock()
            .expect("the request log is not poisoned")
            .len()
    }
}

fn serve<F>(
    stream: TcpStream,
    config: Arc<ServerConfig>,
    reply: &F,
    seen: &Mutex<Vec<SeenRequest>>,
    index: usize,
) where
    F: Fn(&SeenRequest, usize) -> Reply,
{
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("a read timeout can be set");
    let connection = match ServerConnection::new(config) {
        Ok(connection) => connection,
        Err(_) => return,
    };
    let mut tls = StreamOwned::new(connection, stream);
    let Some(request) = read_request(&mut tls) else {
        return;
    };
    seen.lock()
        .expect("the request log is not poisoned")
        .push(request.clone());
    match reply(&request, index) {
        Reply::Hang => {
            std::thread::sleep(Duration::from_secs(5));
        }
        Reply::Respond(response) => {
            let mut head = format!("HTTP/1.1 {} {}\r\n", response.status, response.reason);
            for (name, value) in &response.headers {
                head.push_str(&format!("{name}: {value}\r\n"));
            }
            head.push_str(&format!(
                "Content-Length: {}\r\nConnection: close\r\n\r\n",
                response.body.len()
            ));
            let _ = tls.write_all(head.as_bytes());
            let _ = tls.write_all(&response.body);
            let _ = tls.flush();
        }
    }
    tls.conn.send_close_notify();
    let _ = tls.flush();
}

fn read_request<S: Read + Write>(
    tls: &mut StreamOwned<ServerConnection, S>,
) -> Option<SeenRequest> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 1024];
    let head_end = loop {
        if let Some(position) = find(&buffer, b"\r\n\r\n") {
            break position + 4;
        }
        match tls.read(&mut chunk) {
            Ok(0) => return None,
            Ok(read) => buffer.extend_from_slice(&chunk[..read]),
            Err(_) => return None,
        }
        if buffer.len() > 64 * 1024 {
            return None;
        }
    };
    let head = String::from_utf8_lossy(&buffer[..head_end]).to_string();
    let mut lines = head.split("\r\n");
    let request_line = lines.next()?;
    let mut parts = request_line.split(' ');
    let method = parts.next()?.to_owned();
    let target = parts.next()?.to_owned();
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
        }
    }
    let content_length: usize = headers
        .iter()
        .find(|(name, _)| name == "content-length")
        .and_then(|(_, value)| value.parse().ok())
        .unwrap_or(0);
    let mut body = buffer[head_end..].to_vec();
    while body.len() < content_length {
        match tls.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => body.extend_from_slice(&chunk[..read]),
            Err(_) => break,
        }
    }
    body.truncate(content_length);
    Some(SeenRequest {
        method,
        target,
        headers,
        body,
    })
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
