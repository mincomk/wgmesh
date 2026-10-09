use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use sha2::{Digest, Sha256};

/// The scheme word in the `Authorization` header.
pub const SCHEME: &str = "WGMESH";

/// The label the signature is domain-separated with.
pub const PREFIX: &str = "WGMESHv1\n";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuthError {
    #[error("no WGMESH authorization header")]
    Missing,
    #[error("the authorization header is malformed")]
    Malformed,
    #[error("the timestamp is not an integer")]
    Timestamp,
    #[error("the nonce is not base64")]
    Nonce,
    #[error("the signature is not base64")]
    Signature,
}

/// A parsed `Authorization: WGMESH <id> <ts> <nonce> <signature>` header.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Credentials {
    pub id: String,
    pub timestamp: i64,
    pub nonce: Vec<u8>,
    pub signature: Vec<u8>,
}

/// The bytes a device signs, and the bytes the coordinator verifies. Both sides
/// call this, which is the only reason they cannot drift.
pub fn canonical(method: &str, path: &str, body: &[u8], timestamp: i64, nonce: &[u8]) -> Vec<u8> {
    let digest = hex::encode(Sha256::digest(body));
    let mut out = Vec::with_capacity(PREFIX.len() + method.len() + path.len() + digest.len() + 32);
    out.extend_from_slice(PREFIX.as_bytes());
    out.extend_from_slice(method.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(path.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(digest.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(timestamp.to_string().as_bytes());
    out.push(b'\n');
    out.extend_from_slice(nonce);
    out
}

pub fn parse_authorization(header: &str) -> Result<Credentials, AuthError> {
    let mut parts = header.split_whitespace();
    match parts.next() {
        Some(scheme) if scheme == SCHEME => {}
        Some(_) => return Err(AuthError::Malformed),
        None => return Err(AuthError::Missing),
    }
    let id = parts.next().ok_or(AuthError::Malformed)?.to_owned();
    let timestamp: i64 = parts
        .next()
        .ok_or(AuthError::Malformed)?
        .parse()
        .map_err(|_| AuthError::Timestamp)?;
    let nonce = STANDARD
        .decode(parts.next().ok_or(AuthError::Malformed)?)
        .map_err(|_| AuthError::Nonce)?;
    let signature = STANDARD
        .decode(parts.next().ok_or(AuthError::Malformed)?)
        .map_err(|_| AuthError::Signature)?;
    if parts.next().is_some() || id.is_empty() || signature.len() != 64 {
        return Err(AuthError::Malformed);
    }
    Ok(Credentials {
        id,
        timestamp,
        nonce,
        signature,
    })
}

/// Render the header a client sends. Kept beside the parser so a change to one
/// cannot silently outrun the other.
pub fn format_authorization(id: &str, timestamp: i64, nonce: &[u8], signature: &[u8]) -> String {
    format!(
        "{SCHEME} {id} {timestamp} {} {}",
        STANDARD.encode(nonce),
        STANDARD.encode(signature)
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn signature() -> Vec<u8> {
        vec![7u8; 64]
    }

    #[test]
    fn a_header_round_trips_through_its_parser() {
        let header = format_authorization("d_7Hq2", 1_760_000_000, b"nonce-bytes", &signature());
        let parsed = parse_authorization(&header).unwrap();
        assert_eq!(parsed.id, "d_7Hq2");
        assert_eq!(parsed.timestamp, 1_760_000_000);
        assert_eq!(parsed.nonce, b"nonce-bytes");
        assert_eq!(parsed.signature, signature());
    }

    #[test]
    fn a_header_for_another_scheme_is_refused() {
        assert_eq!(parse_authorization("Bearer abc"), Err(AuthError::Malformed));
        assert_eq!(parse_authorization(""), Err(AuthError::Missing));
    }

    #[test]
    fn a_header_with_a_field_too_many_or_too_few_is_refused() {
        let good = format_authorization("d_1", 1, b"n", &signature());
        assert!(parse_authorization(&format!("{good} extra")).is_err());
        let short = good.split(' ').take(4).collect::<Vec<_>>().join(" ");
        assert!(parse_authorization(&short).is_err());
    }

    #[test]
    fn a_signature_that_is_not_64_bytes_is_refused() {
        let header = format_authorization("d_1", 1, b"n", &[1u8; 32]);
        assert_eq!(parse_authorization(&header), Err(AuthError::Malformed));
    }

    #[test]
    fn a_nonce_that_is_not_base64_is_refused() {
        let header = format!(
            "{SCHEME} d_1 1 not-base64!! {}",
            STANDARD.encode(signature())
        );
        assert_eq!(parse_authorization(&header), Err(AuthError::Nonce));
    }

    #[test]
    fn the_canonical_bytes_change_when_any_part_changes() {
        let body = br#"{"token":"t"}"#;
        let base = canonical("POST", "/v1/join", body, 1_760_000_000, b"nonce");
        assert_ne!(
            base,
            canonical("GET", "/v1/join", body, 1_760_000_000, b"nonce")
        );
        assert_ne!(
            base,
            canonical("POST", "/v1/config", body, 1_760_000_000, b"nonce")
        );
        assert_ne!(
            base,
            canonical("POST", "/v1/join", b"{}", 1_760_000_000, b"nonce")
        );
        assert_ne!(
            base,
            canonical("POST", "/v1/join", body, 1_760_000_001, b"nonce")
        );
        assert_ne!(
            base,
            canonical("POST", "/v1/join", body, 1_760_000_000, b"nonce!")
        );
        assert_eq!(
            base,
            canonical("POST", "/v1/join", body, 1_760_000_000, b"nonce")
        );
    }

    #[test]
    fn the_canonical_string_is_the_documented_shape() {
        let text = String::from_utf8(canonical("POST", "/v1/join", b"", 42, b"n")).unwrap();
        let digest = hex::encode(Sha256::digest(b""));
        assert_eq!(text, format!("WGMESHv1\nPOST\n/v1/join\n{digest}\n42\nn"));
    }
}
