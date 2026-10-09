use std::collections::HashMap;
use std::sync::Mutex;

use wgmesh_proto::signed::{HeaderError, NONCE_WINDOW_SECS, SignedRequest};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceState {
    Pending,
    Active,
    Revoked,
}

impl DeviceState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Revoked => "revoked",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "pending" => Some(Self::Pending),
            "active" => Some(Self::Active),
            "revoked" => Some(Self::Revoked),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    Missing,
    Malformed(HeaderError),
    UnknownIdentity(String),
    NotActive { device_id: String, state: DeviceState },
    ClockSkew { skew_secs: i64 },
    NonceReused,
    BadSignature,
}

impl AuthError {
    // A stable machine-readable name per rejection reason, so a caller (or a
    // test) can tell the five verification steps apart without matching text.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Missing => "missing_authorization",
            Self::Malformed(_) => "malformed_authorization",
            Self::UnknownIdentity(_) => "unknown_identity",
            Self::NotActive { .. } => "identity_not_active",
            Self::ClockSkew { .. } => "clock_skew",
            Self::NonceReused => "nonce_reused",
            Self::BadSignature => "bad_signature",
        }
    }
}

impl core::fmt::Display for AuthError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Missing => f.write_str("no Authorization header"),
            Self::Malformed(error) => write!(f, "the Authorization header is malformed: {error}"),
            Self::UnknownIdentity(id) => write!(f, "no device is enrolled under {id}"),
            Self::NotActive { device_id, state } => {
                write!(f, "device {device_id} is {} and may not call this API", state.as_str())
            }
            Self::ClockSkew { skew_secs } => {
                write!(f, "the request timestamp is {skew_secs} seconds away from now")
            }
            Self::NonceReused => f.write_str("this nonce was already used"),
            Self::BadSignature => f.write_str("the signature does not match the request"),
        }
    }
}

// The one server-side piece of state this scheme needs. It is not a secret: it
// only remembers which nonces were seen recently, so a captured request cannot
// be replayed inside the window. Entries older than the window are pruned
// lazily on insert, and the whole map dies with the process, which is correct
// because the window is shorter than any restart matters.
pub struct NonceCache {
    window_secs: u64,
    seen: Mutex<HashMap<[u8; wgmesh_proto::signed::NONCE_BYTES], i64>>,
}

impl NonceCache {
    pub fn new(window_secs: u64) -> Self {
        Self {
            window_secs,
            seen: Mutex::new(HashMap::new()),
        }
    }

    pub fn window_secs(&self) -> u64 {
        self.window_secs
    }

    // `true` means "this nonce is fresh, the request may proceed". A nonce seen
    // inside the window is refused.
    pub fn accept(&self, nonce: &[u8; wgmesh_proto::signed::NONCE_BYTES], now_secs: i64) -> bool {
        let mut seen = match self.seen.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let window = self.window_secs as i64;
        seen.retain(|_, first_seen| now_secs.saturating_sub(*first_seen) < window);
        if seen.contains_key(nonce) {
            return false;
        }
        seen.insert(*nonce, now_secs);
        true
    }

    pub fn len(&self) -> usize {
        match self.seen.lock() {
            Ok(guard) => guard.len(),
            Err(poisoned) => poisoned.into_inner().len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for NonceCache {
    fn default() -> Self {
        Self::new(NONCE_WINDOW_SECS)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    pub device_id: String,
    pub api_pubkey: [u8; 32],
    pub state: DeviceState,
}

pub trait IdentityDirectory {
    fn credential(&self, device_id: &str) -> Option<Credential>;
}

pub struct OneRow(pub Option<Credential>);

impl IdentityDirectory for OneRow {
    fn credential(&self, device_id: &str) -> Option<Credential> {
        self.0
            .as_ref()
            .filter(|credential| credential.device_id == device_id)
            .cloned()
    }
}

// The five verification steps of the design, in the order the design states
// them: identity lookup, then `active`, then the clock window, then the nonce,
// then the signature. Every step that fails names itself in the error, so a
// caller can log which one it was.
pub fn authenticate_signed(
    request: &SignedRequest,
    method: &str,
    path: &str,
    body: &[u8],
    now_secs: i64,
    nonces: &NonceCache,
    directory: &dyn IdentityDirectory,
) -> Result<Credential, AuthError> {
    let credential = directory
        .credential(&request.device_id)
        .ok_or_else(|| AuthError::UnknownIdentity(request.device_id.clone()))?;

    if credential.state != DeviceState::Active {
        return Err(AuthError::NotActive {
            device_id: credential.device_id.clone(),
            state: credential.state,
        });
    }

    if !request.clock_matches(now_secs) {
        return Err(AuthError::ClockSkew {
            skew_secs: now_secs.saturating_sub(request.ts),
        });
    }

    if !nonces.accept(&request.nonce, now_secs) {
        return Err(AuthError::NonceReused);
    }

    let message = request.message(method, path, body);
    if !wgmesh_secrets::verify(&credential.api_pubkey, &message, &request.signature) {
        return Err(AuthError::BadSignature);
    }

    Ok(credential)
}

pub fn authenticate(
    header: Option<&str>,
    method: &str,
    path: &str,
    body: &[u8],
    now_secs: i64,
    nonces: &NonceCache,
    directory: &dyn IdentityDirectory,
) -> Result<Credential, AuthError> {
    let header = header.ok_or(AuthError::Missing)?;
    let request = SignedRequest::parse(header).map_err(AuthError::Malformed)?;
    authenticate_signed(&request, method, path, body, now_secs, nonces, directory)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use wgmesh_proto::signed::{NONCE_BYTES, SignedRequest};

    const SECRET: [u8; 32] = [7u8; 32];

    struct Directory(Option<Credential>);

    impl IdentityDirectory for Directory {
        fn credential(&self, device_id: &str) -> Option<Credential> {
            self.0
                .as_ref()
                .filter(|credential| credential.device_id == device_id)
                .cloned()
        }
    }

    fn directory(state: DeviceState) -> Directory {
        Directory(Some(Credential {
            device_id: String::from("d_alpha"),
            api_pubkey: wgmesh_secrets::public_key(&SECRET),
            state,
        }))
    }

    fn request(nonce: [u8; NONCE_BYTES], ts: i64, path: &str) -> SignedRequest {
        let message = wgmesh_proto::signed::canonical("GET", path, b"", ts, &nonce);
        SignedRequest {
            device_id: String::from("d_alpha"),
            ts,
            nonce,
            signature: wgmesh_secrets::sign(&SECRET, &message),
        }
    }

    #[test]
    fn a_signed_request_from_an_active_device_is_accepted() {
        let nonces = NonceCache::default();
        let signed = request([1u8; NONCE_BYTES], 1000, "/v1/config");
        let credential = authenticate(
            Some(&signed.format()),
            "GET",
            "/v1/config",
            b"",
            1000,
            &nonces,
            &directory(DeviceState::Active),
        )
        .unwrap();
        assert_eq!(credential.device_id, "d_alpha");
    }

    #[test]
    fn a_missing_header_is_refused() {
        let nonces = NonceCache::default();
        assert_eq!(
            authenticate(None, "GET", "/v1/config", b"", 1000, &nonces, &directory(DeviceState::Active)),
            Err(AuthError::Missing)
        );
    }

    #[test]
    fn a_reused_nonce_is_refused_inside_the_window() {
        let nonces = NonceCache::default();
        let signed = request([2u8; NONCE_BYTES], 1000, "/v1/config");
        let header = signed.format();
        assert!(
            authenticate(Some(&header), "GET", "/v1/config", b"", 1000, &nonces, &directory(DeviceState::Active))
                .is_ok()
        );
        assert_eq!(
            authenticate(Some(&header), "GET", "/v1/config", b"", 1000, &nonces, &directory(DeviceState::Active))
                .unwrap_err()
                .code(),
            "nonce_reused"
        );
    }

    #[test]
    fn a_skewed_timestamp_is_refused_past_sixty_seconds() {
        let nonces = NonceCache::default();
        let signed = request([3u8; NONCE_BYTES], 1000, "/v1/config");
        assert_eq!(
            authenticate(
                Some(&signed.format()),
                "GET",
                "/v1/config",
                b"",
                1061,
                &nonces,
                &directory(DeviceState::Active)
            )
            .unwrap_err()
            .code(),
            "clock_skew"
        );
    }

    #[test]
    fn a_pending_or_revoked_device_is_refused_before_anything_else() {
        for state in [DeviceState::Pending, DeviceState::Revoked] {
            let nonces = NonceCache::default();
            let signed = request([4u8; NONCE_BYTES], 1000, "/v1/config");
            assert_eq!(
                authenticate(
                    Some(&signed.format()),
                    "GET",
                    "/v1/config",
                    b"",
                    1000,
                    &nonces,
                    &directory(state)
                )
                .unwrap_err()
                .code(),
                "identity_not_active"
            );
        }
    }

    #[test]
    fn a_malformed_signature_is_refused() {
        let nonces = NonceCache::default();
        let mut signed = request([5u8; NONCE_BYTES], 1000, "/v1/config");
        signed.signature[0] ^= 0xff;
        assert_eq!(
            authenticate(
                Some(&signed.format()),
                "GET",
                "/v1/config",
                b"",
                1000,
                &nonces,
                &directory(DeviceState::Active)
            )
            .unwrap_err()
            .code(),
            "bad_signature"
        );
    }

    #[test]
    fn the_window_prunes_entries_that_are_older_than_it() {
        let nonces = NonceCache::new(120);
        assert_eq!(nonces.window_secs(), 120);
        assert!(nonces.accept(&[9u8; NONCE_BYTES], 0));
        assert!(!nonces.accept(&[9u8; NONCE_BYTES], 119));
        assert!(nonces.accept(&[9u8; NONCE_BYTES], 120));
        assert_eq!(nonces.len(), 1);
    }
}
