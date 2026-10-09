use base64ct::{Base64, Encoding};
use serde::Serialize;
use sha2::{Digest, Sha256};
use wgmesh_core::Millis;

pub const SCHEME: &str = "WGMESH";
/// How far a client's clock may be from ours.
pub const MAX_SKEW_SECS: u64 = 60;
/// How long a nonce is remembered, so a captured request cannot be replayed.
/// Longer than [`MAX_SKEW_SECS`], so a capture cannot be replayed inside the
/// window the timestamp still permits.
pub const NONCE_TTL_SECS: u64 = 120;

/// The exact bytes a client signs:
///
/// ```text
/// WGMESHv1\n<method>\n<path>\n<sha256_hex(body)>\n<unix_ts>\n<nonce>
/// ```
///
/// `nonce` is the base64 text exactly as it appears in the header, so both
/// sides sign the same string. The body enters as its digest, which is what
/// lets the coordinator verify a request without keeping the body around.
pub fn canonical(method: &str, path: &str, body: &[u8], timestamp: i64, nonce: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(b"WGMESHv1\n");
    out.extend_from_slice(method.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(path.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(sha256_hex(body).as_bytes());
    out.push(b'\n');
    out.extend_from_slice(timestamp.to_string().as_bytes());
    out.push(b'\n');
    out.extend_from_slice(nonce.as_bytes());
    out
}

pub fn sha256_hex(body: &[u8]) -> String {
    hex::encode(Sha256::digest(body))
}

/// An entity tag over a response body, so a node that is already in step gets a
/// 304 and no work.
pub fn etag<T: Serialize>(value: &T) -> Option<String> {
    let encoded = serde_json::to_vec(value).ok()?;
    let digest = sha256_hex(&encoded);
    Some(format!("\"{}\"", &digest[..32]))
}

/// `Authorization: WGMESH <id> <unix_ts> <nonce_b64> <sig_b64>`
#[derive(Clone, Debug)]
pub struct SignedRequest {
    pub identity: String,
    pub timestamp: i64,
    pub nonce: String,
    pub signature: Vec<u8>,
}

pub fn parse_authorization(header: &str) -> Option<SignedRequest> {
    let mut parts = header.split_whitespace();
    if parts.next()? != SCHEME {
        return None;
    }
    let identity = parts.next()?.to_string();
    let timestamp: i64 = parts.next()?.parse().ok()?;
    let nonce = parts.next()?.to_string();
    let signature = Base64::decode_vec(parts.next()?).ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some(SignedRequest {
        identity,
        timestamp,
        nonce,
        signature,
    })
}

pub fn within_skew(timestamp: i64, now: Millis) -> bool {
    let now = i64::try_from(now.0 / 1000).unwrap_or(i64::MAX);
    now.abs_diff(timestamp) <= MAX_SKEW_SECS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_canonical_string_has_the_documented_shape() {
        let message = canonical("GET", "/v1/config", b"", 1_760_000_000, "bm9uY2U=");
        let text = String::from_utf8(message).expect("ascii");
        let fields: Vec<&str> = text.split('\n').collect();
        assert_eq!(fields[0], "WGMESHv1");
        assert_eq!(fields[1], "GET");
        assert_eq!(fields[2], "/v1/config");
        assert_eq!(fields[3], sha256_hex(b""));
        assert_eq!(fields[4], "1760000000");
        assert_eq!(fields[5], "bm9uY2U=");
    }

    #[test]
    fn the_body_changes_the_signature_input() {
        assert_ne!(
            canonical("POST", "/v1/join", b"{}", 1, "n"),
            canonical("POST", "/v1/join", b"[]", 1, "n")
        );
    }

    #[test]
    fn a_header_round_trips() {
        let header = "WGMESH d_7 1760000000 bm9uY2U= AAAA";
        let parsed = parse_authorization(header).expect("parses");
        assert_eq!(parsed.identity, "d_7");
        assert_eq!(parsed.timestamp, 1_760_000_000);
        assert_eq!(parsed.nonce, "bm9uY2U=");
        assert!(parse_authorization("Bearer x").is_none());
        assert!(parse_authorization("WGMESH d_7 1 n").is_none());
        assert!(parse_authorization("WGMESH d_7 1 n !!!").is_none());
    }

    #[test]
    fn skew_is_measured_in_both_directions() {
        let now = Millis::from_secs(1_000);
        assert!(within_skew(1_000, now));
        assert!(within_skew(1_060, now));
        assert!(!within_skew(1_061, now));
        assert!(within_skew(940, now));
        assert!(!within_skew(939, now));
    }

    #[test]
    fn an_etag_is_quoted_and_changes_with_the_body() {
        let left = etag(&"a").expect("etag");
        let right = etag(&"b").expect("etag");
        assert!(left.starts_with('"') && left.ends_with('"'));
        assert_eq!(left.len(), 34);
        assert_ne!(left, right);
    }
}
