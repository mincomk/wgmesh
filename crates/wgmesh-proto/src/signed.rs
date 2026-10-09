use base64ct::{Base64, Encoding};
use sha2::{Digest, Sha256};

pub const SCHEME: &str = "WGMESH";
pub const VERSION_TAG: &str = "WGMESHv1";
pub const NONCE_BYTES: usize = 16;
pub const MAX_CLOCK_SKEW_SECS: i64 = 60;
pub const NONCE_WINDOW_SECS: u64 = 120;

pub fn sha256_hex(body: &[u8]) -> String {
    let digest = Sha256::digest(body);
    hex::encode(digest)
}

pub fn canonical(method: &str, path: &str, body: &[u8], ts: i64, nonce: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(96 + body.len());
    message.extend_from_slice(VERSION_TAG.as_bytes());
    for field in [method, path, &sha256_hex(body), &ts.to_string(), &Base64::encode_string(nonce)]
    {
        message.push(b'\n');
        message.extend_from_slice(field.as_bytes());
    }
    message
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedRequest {
    pub device_id: String,
    pub ts: i64,
    pub nonce: [u8; NONCE_BYTES],
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderError {
    Missing,
    WrongScheme,
    WrongPartCount,
    Timestamp,
    Nonce,
    Signature,
}

impl core::fmt::Display for HeaderError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let text = match self {
            Self::Missing => "no Authorization header",
            Self::WrongScheme => "the Authorization header does not use the WGMESH scheme",
            Self::WrongPartCount => "the Authorization header does not have five parts",
            Self::Timestamp => "the timestamp is not a signed 64-bit second count",
            Self::Nonce => "the nonce is not 16 base64 bytes",
            Self::Signature => "the signature is not 64 base64 bytes",
        };
        f.write_str(text)
    }
}

impl SignedRequest {
    pub fn format(&self) -> String {
        format!(
            "{SCHEME} {} {} {} {}",
            self.device_id,
            self.ts,
            Base64::encode_string(&self.nonce),
            Base64::encode_string(&self.signature)
        )
    }

    pub fn parse(header: &str) -> Result<Self, HeaderError> {
        let mut parts = header.split(' ');
        if parts.next() != Some(SCHEME) {
            return Err(HeaderError::WrongScheme);
        }
        let (Some(device_id), Some(ts), Some(nonce), Some(signature), None) =
            (parts.next(), parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(HeaderError::WrongPartCount);
        };
        let ts = ts.parse::<i64>().map_err(|_| HeaderError::Timestamp)?;
        let nonce = Base64::decode_vec(nonce).map_err(|_| HeaderError::Nonce)?;
        let nonce: [u8; NONCE_BYTES] = nonce.try_into().map_err(|_| HeaderError::Nonce)?;
        let signature = Base64::decode_vec(signature).map_err(|_| HeaderError::Signature)?;
        let signature: [u8; 64] = signature.try_into().map_err(|_| HeaderError::Signature)?;
        Ok(Self {
            device_id: device_id.to_owned(),
            ts,
            nonce,
            signature,
        })
    }

    pub fn message(&self, method: &str, path: &str, body: &[u8]) -> Vec<u8> {
        canonical(method, path, body, self.ts, &self.nonce)
    }

    pub fn clock_matches(&self, now: i64) -> bool {
        now.abs_diff(self.ts) <= MAX_CLOCK_SKEW_SECS as u64
    }
}

pub fn fresh_nonce(bytes: [u8; NONCE_BYTES]) -> [u8; NONCE_BYTES] {
    bytes
}

pub fn encode_base64(bytes: &[u8]) -> String {
    Base64::encode_string(bytes)
}

pub fn decode_base64(text: &str) -> Option<Vec<u8>> {
    Base64::decode_vec(text).ok()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn sample() -> SignedRequest {
        SignedRequest {
            device_id: String::from("d_7Hq2Vx9"),
            ts: 1_760_000_000,
            nonce: [7u8; NONCE_BYTES],
            signature: [9u8; 64],
        }
    }

    #[test]
    fn the_canonical_string_is_exactly_the_version_tag_five_fields() {
        let message = canonical("POST", "/v1/config", b"{\"a\":1}", 1_760_000_000, &[1, 2, 3]);
        let body_hash = sha256_hex(b"{\"a\":1}");
        let expected = format!(
            "WGMESHv1\nPOST\n/v1/config\n{body_hash}\n1760000000\n{}",
            Base64::encode_string(&[1, 2, 3])
        );
        assert_eq!(message, expected.as_bytes());
        assert_eq!(message.iter().filter(|byte| **byte == b'\n').count(), 5);
    }

    #[test]
    fn the_body_hash_is_sha256_in_lowercase_hex() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(sha256_hex(b"abc").len(), 64);
    }

    #[test]
    fn a_header_round_trips() {
        let request = sample();
        assert_eq!(SignedRequest::parse(&request.format()).unwrap(), request);
        assert_eq!(
            request.format(),
            format!(
                "WGMESH {} {} {} {}",
                request.device_id,
                request.ts,
                Base64::encode_string(&request.nonce),
                Base64::encode_string(&request.signature)
            )
        );
        assert_eq!(request.format().split(' ').count(), 5);
        assert!(request.format().starts_with("WGMESH d_7Hq2Vx9 1760000000 "));
    }

    #[test]
    fn a_missing_or_misshapen_header_is_refused() {
        assert_eq!(SignedRequest::parse(""), Err(HeaderError::WrongScheme));
        assert_eq!(
            SignedRequest::parse("Bearer token"),
            Err(HeaderError::WrongScheme)
        );
        assert_eq!(SignedRequest::parse("WGMESH a b c"), Err(HeaderError::WrongPartCount));
        assert_eq!(
            SignedRequest::parse("WGMESH d 1 2 3 4"),
            Err(HeaderError::WrongPartCount)
        );
    }

    #[test]
    fn a_non_numeric_timestamp_is_refused() {
        assert_eq!(
            SignedRequest::parse("WGMESH d not-a-number BwcHBwcHBwcHBwcHBwcHBw== CQkJCQ=="),
            Err(HeaderError::Timestamp)
        );
    }

    #[test]
    fn a_short_or_long_nonce_and_signature_are_refused() {
        let short_nonce = Base64::encode_string(&[0u8; 8]);
        let signature = Base64::encode_string(&[0u8; 64]);
        assert_eq!(
            SignedRequest::parse(&format!("WGMESH d 1 {short_nonce} {signature}")),
            Err(HeaderError::Nonce)
        );
        let nonce = Base64::encode_string(&[0u8; NONCE_BYTES]);
        assert!(
            SignedRequest::parse(&format!("WGMESH d 1 {nonce} {signature}")).is_ok(),
            "a well-formed header parses; the signature itself is only checked against a key later"
        );
        let short_signature = Base64::encode_string(&[0u8; 12]);
        assert_eq!(
            SignedRequest::parse(&format!("WGMESH d 1 {nonce} {short_signature}")),
            Err(HeaderError::Signature)
        );
    }

    #[test]
    fn the_message_covers_the_method_the_path_the_body_and_the_replay_fields() {
        let request = sample();
        let base = request.message("GET", "/v1/config", b"");
        assert_ne!(base, request.message("POST", "/v1/config", b""));
        assert_ne!(base, request.message("GET", "/v1/peers", b""));
        assert_ne!(base, request.message("GET", "/v1/config", b"x"));
        let mut other = request.clone();
        other.ts += 1;
        assert_ne!(base, other.message("GET", "/v1/config", b""));
        let mut third = request.clone();
        third.nonce = [8u8; NONCE_BYTES];
        assert_ne!(base, third.message("GET", "/v1/config", b""));
    }

    #[test]
    fn the_clock_window_is_sixty_seconds_either_way() {
        let request = sample();
        assert!(request.clock_matches(request.ts));
        assert!(request.clock_matches(request.ts + MAX_CLOCK_SKEW_SECS));
        assert!(request.clock_matches(request.ts - MAX_CLOCK_SKEW_SECS));
        assert!(!request.clock_matches(request.ts + MAX_CLOCK_SKEW_SECS + 1));
        assert!(!request.clock_matches(request.ts - MAX_CLOCK_SKEW_SECS - 1));
    }

    #[test]
    fn a_sha256_hex_string_carries_no_uppercase_and_is_the_right_length() {
        let hexed = sha256_hex(b"the body");
        assert_eq!(hexed.len(), 64);
        assert!(hexed.chars().all(|character| character.is_ascii_hexdigit()));
        assert_eq!(hexed, hexed.to_lowercase());
    }

    #[test]
    fn an_empty_message_hash_matches_an_explicit_sha256_of_no_bytes() {
        let digest = Sha256::digest([]);
        assert_eq!(sha256_hex(b""), hex::encode(digest));
    }

    #[test]
    fn fresh_nonce_is_the_identity_so_callers_own_the_randomness() {
        let bytes = [3u8; NONCE_BYTES];
        assert_eq!(fresh_nonce(bytes), bytes);
        assert_eq!(NONCE_WINDOW_SECS, 120);
    }
}
