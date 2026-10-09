// The HTTPS adapter over the coordinator API (design document sections 5.5, 5.6 and 7).
//
// Three things are worth knowing before reading it:
//
//  * the signature covers the exact body bytes, so the body is serialised once, hashed, and
//    then sent; nothing here re-serialises the request after signing it.
//  * retries re-sign with a fresh timestamp and nonce, because the coordinator refuses a
//    nonce it has already seen. Only transport failures, timeouts, 429 and 5xx are retried.
//  * `GET /v1/config` sends the ETag it holds as `If-None-Match`, and a 304 comes back as
//    `Fetch::NotModified` without the body ever being read or parsed.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, ETAG, IF_NONE_MATCH};
use reqwest::{Method, StatusCode};

use wgmesh_proto::{
    Ack, ApiErrorBody, ConfigSnapshot, EndpointReport, JoinRequest, JoinResponse, PunchReport,
    PunchResponse, RelayAssignmentResponse, RelayEnrollRequest, RelayEnrollment, RelayHeartbeat,
    RelayKeysetResponse, RelayObservationBatch, RotateRequest, RotateResponse, paths,
};

use crate::pin::{PinError, SpkiPin, pinned_client_config};
use crate::signing::{ApiSigner, SigningError, sign_now};

/// A JSON request body the caller may retry: the trait the wire types are built on.
pub use wgmesh_proto::serde::{Serialize, de::DeserializeOwned};

/// How many times a request is tried and how long it waits in between.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Total attempts, the first one included. Must be at least one.
    pub attempts: u32,
    /// The wait before the second attempt.
    pub base_delay: Duration,
    /// The ceiling the backoff never passes.
    pub max_delay: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            attempts: 3,
            base_delay: Duration::from_millis(200),
            max_delay: Duration::from_secs(2),
        }
    }
}

impl RetryPolicy {
    /// One attempt, no waiting: the policy for a caller that retries itself.
    pub const fn once() -> Self {
        Self {
            attempts: 1,
            base_delay: Duration::ZERO,
            max_delay: Duration::ZERO,
        }
    }

    /// The wait before `attempt`, which counts from one.
    pub fn delay_for(&self, attempt: u32) -> Duration {
        let shift = attempt.saturating_sub(1).min(16);
        let scaled = self.base_delay.saturating_mul(1u32 << shift);
        scaled.min(self.max_delay)
    }
}

/// What this client needs to reach a coordinator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientSettings {
    /// The coordinator base URL, for example `https://wgmesh.example.com`.
    pub base_url: String,
    /// The pinned leaf SPKI hash. Required for `https`.
    pub pin: Option<SpkiPin>,
    /// Whole request timeout.
    pub request_timeout: Duration,
    /// Connection timeout.
    pub connect_timeout: Duration,
    /// Retry policy for transient failures.
    pub retry: RetryPolicy,
    /// User agent sent with every request.
    pub user_agent: String,
}

impl ClientSettings {
    /// Settings for `base_url` with the defaults the design document implies.
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            pin: None,
            request_timeout: Duration::from_secs(30),
            connect_timeout: Duration::from_secs(10),
            retry: RetryPolicy::default(),
            user_agent: format!("wgmesh/{}", env!("CARGO_PKG_VERSION")),
        }
    }

    /// Pin the coordinator's leaf key.
    pub fn with_pin(mut self, pin: SpkiPin) -> Self {
        self.pin = Some(pin);
        self
    }
}

/// Waits between retries.
///
/// The adapter keeps its own runtime out of the picture: it needs to wait, not to own a
/// timer, so the default implementation wakes the task from a helper thread and a caller
/// whose runtime has a timer can inject its own.
pub trait Sleeper: Send + Sync + fmt::Debug {
    /// Wait for `delay`, yielding the task meanwhile.
    fn sleep<'a>(&'a self, delay: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>>;
}

/// The default sleeper: a helper thread waits and wakes the task.
#[derive(Debug, Default, Clone, Copy)]
pub struct ThreadSleeper;

impl Sleeper for ThreadSleeper {
    fn sleep<'a>(&'a self, delay: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(wake_after(delay))
    }
}

struct WakeState {
    fired: bool,
    waker: Option<Waker>,
}

/// Resolve after `delay` without a runtime timer.
fn wake_after(delay: Duration) -> impl Future<Output = ()> {
    let state = Arc::new(std::sync::Mutex::new(WakeState {
        fired: false,
        waker: None,
    }));
    let signaller = Arc::clone(&state);
    std::thread::spawn(move || {
        std::thread::sleep(delay);
        let mut guard = match signaller.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.fired = true;
        if let Some(waker) = guard.waker.take() {
            waker.wake();
        }
    });
    std::future::poll_fn(move |cx: &mut Context<'_>| {
        let mut guard = match state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if guard.fired {
            Poll::Ready(())
        } else {
            guard.waker = Some(cx.waker().clone());
            Poll::Pending
        }
    })
}

/// Anything that can go wrong while talking to a coordinator.
#[derive(Debug)]
pub enum ClientError {
    /// An `https` base URL without a pin: the design refuses to run that way.
    MissingPin {
        /// The URL that has no pin.
        base_url: String,
    },
    /// A base URL that is neither http nor https.
    InvalidUrl(String),
    /// The pinned TLS configuration could not be built.
    Tls(PinError),
    /// A connection, TLS or protocol failure.
    Transport(reqwest::Error),
    /// The request ran past its timeout.
    Timeout,
    /// The coordinator answered with an error body.
    Api {
        /// HTTP status.
        status: u16,
        /// The parsed error body.
        body: ApiErrorBody,
    },
    /// A status this API never answers a successful call with.
    UnexpectedStatus {
        /// HTTP status.
        status: u16,
        /// The body, truncated, for the log.
        text: String,
    },
    /// A response body that is not the JSON this call expects.
    Decode(String),
    /// A request body that could not be serialised.
    Encode(String),
    /// A signed call with no signer configured.
    NoSigner(String),
    /// A call that needed a signature and could not make one.
    Signing(SigningError),
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingPin { base_url } => write!(
                f,
                "{base_url} is https and no SPKI pin is configured; record one with `wgmesh pin` or `wgmesh trust`"
            ),
            Self::InvalidUrl(url) => write!(f, "not an http or https URL: {url}"),
            Self::Tls(error) => write!(f, "pinned TLS setup failed: {error}"),
            Self::Transport(error) => {
                write!(f, "transport failed: {error}")?;
                let mut cause = std::error::Error::source(error);
                while let Some(inner) = cause {
                    write!(f, ": {inner}")?;
                    cause = inner.source();
                }
                Ok(())
            }
            Self::Timeout => f.write_str("the request timed out"),
            Self::Api { status, body } => write!(
                f,
                "the coordinator answered {status}: {:?}: {}",
                body.code, body.message
            ),
            Self::UnexpectedStatus { status, text } => {
                write!(f, "unexpected status {status}: {text}")
            }
            Self::Decode(error) => write!(f, "the response body could not be read: {error}"),
            Self::Encode(error) => write!(f, "the request body could not be written: {error}"),
            Self::NoSigner(path) => {
                write!(f, "{path} must be signed and this client has no signer")
            }
            Self::Signing(error) => write!(f, "the request could not be signed: {error}"),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<reqwest::Error> for ClientError {
    fn from(error: reqwest::Error) -> Self {
        if error.is_timeout() {
            Self::Timeout
        } else {
            Self::Transport(error)
        }
    }
}

impl From<SigningError> for ClientError {
    fn from(error: SigningError) -> Self {
        Self::Signing(error)
    }
}

impl From<PinError> for ClientError {
    fn from(error: PinError) -> Self {
        Self::Tls(error)
    }
}

impl ClientError {
    /// Whether trying the same request again could plausibly succeed.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Transport(_) | Self::Timeout => true,
            Self::Api { status, .. } | Self::UnexpectedStatus { status, .. } => {
                *status == StatusCode::TOO_MANY_REQUESTS.as_u16() || (500..=599).contains(status)
            }
            Self::MissingPin { .. }
            | Self::InvalidUrl(_)
            | Self::Tls(_)
            | Self::Decode(_)
            | Self::Encode(_) => false,
            Self::NoSigner(_) | Self::Signing(_) => false,
        }
    }

    /// The HTTP status, when the coordinator answered at all.
    pub const fn status(&self) -> Option<u16> {
        match self {
            Self::Api { status, .. } | Self::UnexpectedStatus { status, .. } => Some(*status),
            _ => None,
        }
    }
}

/// The answer to a request that may be answered with `304 Not Modified`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fetch<T> {
    /// The coordinator says our copy is current, and sent no body.
    NotModified {
        /// The ETag it repeated, when it sent one.
        etag: Option<String>,
    },
    /// A fresh body, and the ETag to send next time.
    Fresh {
        /// The decoded body.
        value: T,
        /// The ETag the coordinator published, when it did.
        etag: Option<String>,
    },
}

impl<T> Fetch<T> {
    /// The value, when there is one.
    pub fn value(self) -> Option<T> {
        match self {
            Self::Fresh { value, .. } => Some(value),
            Self::NotModified { .. } => None,
        }
    }

    /// The ETag, whether this answer carried a body or not.
    pub fn etag(&self) -> Option<&str> {
        match self {
            Self::NotModified { etag } | Self::Fresh { etag, .. } => etag.as_deref(),
        }
    }

    /// Whether the coordinator said nothing changed.
    pub const fn is_not_modified(&self) -> bool {
        matches!(self, Self::NotModified { .. })
    }
}

/// The HTTPS client for the coordinator API.
pub struct HttpsCoordinator {
    base_url: String,
    http: reqwest::Client,
    signer: Option<Arc<dyn ApiSigner>>,
    retry: RetryPolicy,
    request_timeout: Duration,
    sleeper: Arc<dyn Sleeper>,
}

impl fmt::Debug for HttpsCoordinator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpsCoordinator")
            .field("base_url", &self.base_url)
            .field("signed", &self.signer.is_some())
            .field("retry", &self.retry)
            .field("request_timeout", &self.request_timeout)
            .finish()
    }
}

impl HttpsCoordinator {
    /// Build a client. An `https` base URL must carry a pin, which is what the design
    /// document asks for: without it a man in the middle could replace the peer list.
    pub fn new(
        settings: &ClientSettings,
        signer: Option<Arc<dyn ApiSigner>>,
    ) -> Result<Self, ClientError> {
        if settings.retry.attempts == 0 {
            return Err(ClientError::InvalidUrl(
                "a retry policy of zero attempts".to_owned(),
            ));
        }
        let base_url = settings.base_url.trim_end_matches('/').to_owned();
        let https = base_url.starts_with("https://");
        if !https && !base_url.starts_with("http://") {
            return Err(ClientError::InvalidUrl(settings.base_url.clone()));
        }
        let mut builder = reqwest::Client::builder()
            .user_agent(settings.user_agent.clone())
            .connect_timeout(settings.connect_timeout)
            .timeout(settings.request_timeout);
        match (https, settings.pin) {
            (true, Some(pin)) => {
                builder = builder.use_preconfigured_tls(pinned_client_config(pin)?)
            }
            (true, None) => {
                return Err(ClientError::MissingPin {
                    base_url: settings.base_url.clone(),
                });
            }
            (false, _) => {}
        }
        let http = builder.build().map_err(ClientError::Transport)?;
        Ok(Self {
            base_url,
            http,
            signer,
            retry: settings.retry,
            request_timeout: settings.request_timeout,
            sleeper: Arc::new(ThreadSleeper),
        })
    }

    /// Replace the retry sleeper, for a runtime that wants to use its own timer.
    pub fn with_sleeper(mut self, sleeper: Arc<dyn Sleeper>) -> Self {
        self.sleeper = sleeper;
        self
    }

    /// The base URL this client talks to.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Enroll with a join token. Not signed: the token is the credential.
    pub async fn join(&self, request: &JoinRequest) -> Result<JoinResponse, ClientError> {
        self.expect(
            self.call::<JoinRequest, JoinResponse>(
                Method::POST,
                paths::JOIN,
                false,
                None,
                Some(request),
            )
            .await?,
        )
    }

    /// Fetch the configuration snapshot, telling the coordinator which ETag we hold.
    pub async fn config(&self, etag: Option<&str>) -> Result<Fetch<ConfigSnapshot>, ClientError> {
        let answer = self
            .call::<(), ConfigSnapshot>(Method::GET, paths::CONFIG, true, etag, None)
            .await?;
        Ok(match answer {
            (Some(value), etag) => Fetch::Fresh { value, etag },
            (None, etag) => Fetch::NotModified { etag },
        })
    }

    /// Report our own endpoints and candidates.
    pub async fn report_endpoint(&self, report: &EndpointReport) -> Result<Ack, ClientError> {
        self.expect(
            self.call::<EndpointReport, Ack>(
                Method::POST,
                paths::ENDPOINT,
                true,
                None,
                Some(report),
            )
            .await?,
        )
    }

    /// Send punch results and receive the directives for this round.
    pub async fn report_punch(&self, report: &PunchReport) -> Result<PunchResponse, ClientError> {
        self.expect(
            self.call::<PunchReport, PunchResponse>(
                Method::POST,
                paths::PUNCH,
                true,
                None,
                Some(report),
            )
            .await?,
        )
    }

    /// Submit a new tunnel public key, signed with the API key we already have.
    pub async fn rotate(&self, request: &RotateRequest) -> Result<RotateResponse, ClientError> {
        self.expect(
            self.call::<RotateRequest, RotateResponse>(
                Method::POST,
                paths::ROTATE,
                true,
                None,
                Some(request),
            )
            .await?,
        )
    }

    /// Enroll a relay. Not signed: the relay join token is the credential.
    pub async fn relay_enroll(
        &self,
        request: &RelayEnrollRequest,
    ) -> Result<RelayEnrollment, ClientError> {
        self.expect(
            self.call::<RelayEnrollRequest, RelayEnrollment>(
                Method::POST,
                paths::RELAY_ENROLL,
                false,
                None,
                Some(request),
            )
            .await?,
        )
    }

    /// Fetch this relay's slots, pairs and keysets.
    pub async fn relay_assignment(&self) -> Result<RelayAssignmentResponse, ClientError> {
        self.expect(
            self.call::<(), RelayAssignmentResponse>(
                Method::GET,
                paths::RELAY_ASSIGNMENT,
                true,
                None,
                None,
            )
            .await?,
        )
    }

    /// Report the source addresses this relay has seen.
    pub async fn relay_observations(
        &self,
        batch: &RelayObservationBatch,
    ) -> Result<Ack, ClientError> {
        self.expect(
            self.call::<RelayObservationBatch, Ack>(
                Method::POST,
                paths::RELAY_OBSERVATIONS,
                true,
                None,
                Some(batch),
            )
            .await?,
        )
    }

    /// Report relay health and traffic counters.
    pub async fn relay_heartbeat(&self, heartbeat: &RelayHeartbeat) -> Result<Ack, ClientError> {
        self.expect(
            self.call::<RelayHeartbeat, Ack>(
                Method::POST,
                paths::RELAY_HEARTBEAT,
                true,
                None,
                Some(heartbeat),
            )
            .await?,
        )
    }

    /// Fetch the public key update for this relay since `revision`.
    pub async fn relay_keyset(&self, revision: u64) -> Result<RelayKeysetResponse, ClientError> {
        let path = format!("{}?since={revision}", paths::RELAY_KEYSET);
        self.expect(
            self.call::<(), RelayKeysetResponse>(Method::GET, &path, true, None, None)
                .await?,
        )
    }

    fn expect<T>(&self, answer: (Option<T>, Option<String>)) -> Result<T, ClientError> {
        answer.0.ok_or_else(|| ClientError::UnexpectedStatus {
            status: StatusCode::NOT_MODIFIED.as_u16(),
            text: "the coordinator answered 304 to a request that cannot be conditional".to_owned(),
        })
    }

    /// One call, retried according to the policy. The first element of the answer is `None`
    /// for a `304`.
    async fn call<B, R>(
        &self,
        method: Method,
        path: &str,
        signed: bool,
        if_none_match: Option<&str>,
        body: Option<&B>,
    ) -> Result<(Option<R>, Option<String>), ClientError>
    where
        B: Serialize + ?Sized,
        R: DeserializeOwned,
    {
        let body_bytes = match body {
            Some(value) => self.serialize_body(&format!("{}{}", self.base_url, path), value)?,
            None => Vec::new(),
        };
        for attempt in 0..self.retry.attempts {
            if attempt > 0 {
                self.sleeper.sleep(self.retry.delay_for(attempt)).await;
            }
            match self
                .attempt::<R>(&method, path, signed, if_none_match, &body_bytes)
                .await
            {
                Ok(answer) => return Ok(answer),
                Err(error) => {
                    let last = attempt + 1 == self.retry.attempts;
                    if last || !error.is_retryable() {
                        return Err(error);
                    }
                }
            }
        }
        Err(ClientError::UnexpectedStatus {
            status: 0,
            text: "the retry policy ran out without an answer".to_owned(),
        })
    }

    async fn attempt<R>(
        &self,
        method: &Method,
        path: &str,
        signed: bool,
        if_none_match: Option<&str>,
        body_bytes: &[u8],
    ) -> Result<(Option<R>, Option<String>), ClientError>
    where
        R: DeserializeOwned,
    {
        let url = format!("{}{}", self.base_url, path);
        let mut builder = self
            .http
            .request(method.clone(), &url)
            .timeout(self.request_timeout);
        if let Some(etag) = if_none_match {
            builder = builder.header(IF_NONE_MATCH, etag);
        }
        if signed {
            let signer = self
                .signer
                .as_ref()
                .ok_or_else(|| ClientError::NoSigner(path.to_owned()))?;
            let signed_request = sign_now(signer.as_ref(), method.as_str(), path, body_bytes)?;
            builder = builder.header(AUTHORIZATION, signed_request.authorization);
        }
        if !body_bytes.is_empty() {
            builder = builder
                .header(CONTENT_TYPE, "application/json")
                .body(body_bytes.to_vec());
        }
        let response = builder.send().await?;
        let status = response.status().as_u16();
        let etag = response
            .headers()
            .get(ETAG)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        if status == StatusCode::NOT_MODIFIED.as_u16() {
            return Ok((None, etag));
        }
        if status == StatusCode::OK.as_u16() {
            let value = response.json::<R>().await.map_err(ClientError::from)?;
            return Ok((Some(value), etag));
        }
        if let Ok(body) = response.json::<ApiErrorBody>().await {
            return Err(ClientError::Api { status, body });
        }
        Err(ClientError::UnexpectedStatus {
            status,
            text: "the body was not an error the API defines".to_owned(),
        })
    }

    /// The exact bytes of `value` as JSON, which is what the signature covers.
    fn serialize_body<B: Serialize + ?Sized>(
        &self,
        url: &str,
        value: &B,
    ) -> Result<Vec<u8>, ClientError> {
        let probe = self
            .http
            .post(url)
            .json(value)
            .build()
            .map_err(ClientError::Transport)?;
        let bytes = probe
            .body()
            .and_then(reqwest::Body::as_bytes)
            .ok_or_else(|| {
                ClientError::Encode("the request body is not held in memory".to_owned())
            })?;
        Ok(bytes.to_vec())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn a_retry_policy_backs_off_and_stops_at_the_ceiling() {
        let policy = RetryPolicy {
            attempts: 5,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_millis(400),
        };
        assert_eq!(policy.delay_for(1), Duration::from_millis(100));
        assert_eq!(policy.delay_for(2), Duration::from_millis(200));
        assert_eq!(policy.delay_for(3), Duration::from_millis(400));
        assert_eq!(policy.delay_for(4), Duration::from_millis(400));
        assert_eq!(RetryPolicy::once().delay_for(4), Duration::ZERO);
    }

    #[test]
    fn an_https_base_url_without_a_pin_is_refused() {
        let settings = ClientSettings::new("https://wgmesh.example.com");
        let error = HttpsCoordinator::new(&settings, None).unwrap_err();
        assert!(matches!(error, ClientError::MissingPin { .. }));
        assert!(error.to_string().contains("pin"));
    }

    #[test]
    fn a_base_url_that_is_not_http_is_refused() {
        let settings = ClientSettings::new("wgmesh.example.com");
        assert!(matches!(
            HttpsCoordinator::new(&settings, None).unwrap_err(),
            ClientError::InvalidUrl(_)
        ));
    }

    #[test]
    fn a_retry_policy_with_no_attempts_is_refused() {
        let mut settings = ClientSettings::new("http://127.0.0.1:1");
        settings.retry = RetryPolicy {
            attempts: 0,
            ..RetryPolicy::default()
        };
        assert!(matches!(
            HttpsCoordinator::new(&settings, None).unwrap_err(),
            ClientError::InvalidUrl(_)
        ));
    }

    #[test]
    fn a_trailing_slash_on_the_base_url_does_not_double_up() {
        let settings = ClientSettings::new("http://127.0.0.1:1/");
        let client = HttpsCoordinator::new(&settings, None).unwrap();
        assert_eq!(client.base_url(), "http://127.0.0.1:1");
    }

    #[test]
    fn only_transient_failures_are_retried() {
        assert!(ClientError::Timeout.is_retryable());
        assert!(
            ClientError::Api {
                status: 503,
                body: ApiErrorBody {
                    code: wgmesh_proto::ApiErrorCode::Internal,
                    message: String::new()
                }
            }
            .is_retryable()
        );
        assert!(
            ClientError::UnexpectedStatus {
                status: 429,
                text: String::new()
            }
            .is_retryable()
        );
        assert!(
            !ClientError::Api {
                status: 401,
                body: ApiErrorBody {
                    code: wgmesh_proto::ApiErrorCode::Unauthorized,
                    message: String::new()
                }
            }
            .is_retryable()
        );
        assert!(
            !ClientError::UnexpectedStatus {
                status: 404,
                text: String::new()
            }
            .is_retryable()
        );
        assert!(!ClientError::NoSigner(paths::ROTATE.to_owned()).is_retryable());
        assert_eq!(
            ClientError::UnexpectedStatus {
                status: 404,
                text: String::new()
            }
            .status(),
            Some(404)
        );
    }

    #[test]
    fn a_fetch_keeps_its_etag_on_both_answers() {
        let fresh = Fetch::Fresh {
            value: 7,
            etag: Some("abc".to_owned()),
        };
        assert_eq!(fresh.etag(), Some("abc"));
        assert!(!fresh.is_not_modified());
        assert_eq!(fresh.value(), Some(7));
        let unchanged: Fetch<u8> = Fetch::NotModified {
            etag: Some("abc".to_owned()),
        };
        assert!(unchanged.is_not_modified());
        assert_eq!(unchanged.etag(), Some("abc"));
        assert_eq!(unchanged.value(), None);
    }

    #[test]
    fn the_body_that_is_signed_is_the_body_that_is_sent() {
        let settings = ClientSettings::new("http://127.0.0.1:1");
        let client = HttpsCoordinator::new(&settings, None).unwrap();
        let request = RotateRequest {
            wg_pubkey: wgmesh_proto::PubKeyB64::from_bytes([1u8; 32]),
        };
        let bytes = client
            .serialize_body("http://127.0.0.1:1/v1/rotate", &request)
            .unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert_eq!(text, format!("{{\"wg_pubkey\":\"{}\"}}", request.wg_pubkey));
    }
}
