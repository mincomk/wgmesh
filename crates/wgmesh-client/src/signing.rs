// The signed request path of design document section 5.5, on the client side.
//
//   Authorization: WGMESH <api_pubkey_b64> <unix_ts> <nonce_b64> <sig_b64>
//   sig = Ed25519(priv, "WGMESHv1\n" + method + "\n" + path + "\n" +
//                 sha256_hex(body) + "\n" + ts + "\n" + nonce_b64)
//
// This crate computes the body digest (that is why `sha2` lives here and nowhere else) and
// then calls the one shared implementation of the preimage in `wgmesh-proto`. The identity
// in the header is the API public key itself, so the coordinator can look the caller up
// from the header alone.
//
// The nonce is the base64 text that the header carries, and it is that text, not the bytes
// behind it, that the signature covers: both sides read the field off the wire.
//
// The private key never appears here: a signer is asked for a signature and nothing else,
// which is what lets the key stay inside the secret store.

use std::fmt;

use base64ct::{Base64, Encoding};
use sha2::{Digest, Sha256};

use wgmesh_proto::{AUTH_SCHEME, PubKeyB64};

/// The number of random bytes behind a nonce.
pub const NONCE_LEN: usize = 16;

/// The length of an Ed25519 signature.
pub const SIGNATURE_LEN: usize = 64;

/// Anything that can go wrong while signing a request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SigningError {
    /// A signature that is not 64 bytes.
    SignatureLength(usize),
    /// An empty nonce would make two requests indistinguishable.
    EmptyNonce,
    /// The system has no entropy to make a nonce from.
    NoEntropy,
    /// The clock is before the unix epoch, so there is no timestamp to sign.
    ClockBeforeEpoch,
}

impl fmt::Display for SigningError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SignatureLength(len) => {
                write!(f, "a signature must be {SIGNATURE_LEN} bytes, got {len}")
            }
            Self::EmptyNonce => f.write_str("a nonce must not be empty"),
            Self::NoEntropy => f.write_str("the system random source failed"),
            Self::ClockBeforeEpoch => f.write_str("the system clock is before the unix epoch"),
        }
    }
}

impl std::error::Error for SigningError {}

/// Lowercase hex of the SHA-256 of the exact body bytes, spelled the way `wgmesh-proto`
/// spells it.
pub fn sha256_hex(body: &[u8]) -> String {
    wgmesh_proto::hex_encode(&Sha256::digest(body))
}

/// The exact bytes a signature is made over, for a request body rather than for its digest.
///
/// This is the client side of the shared preimage: the coordinator computes the digest from
/// the body it received and calls the same `wgmesh_proto::canonical`. `nonce` is the nonce
/// text the header carries.
pub fn canonical(method: &str, path: &str, body: &[u8], ts: i64, nonce: &[u8]) -> Vec<u8> {
    wgmesh_proto::canonical(method, path, &sha256_hex(body), ts, nonce)
}

/// Something that can sign, and that knows which public key the coordinator looks up.
pub trait ApiSigner: Send + Sync {
    /// The Ed25519 public key this signer's requests are identified by.
    fn api_public_key(&self) -> PubKeyB64;

    /// Sign a message. For Ed25519 this returns 64 bytes.
    fn sign(&self, message: &[u8]) -> Vec<u8>;
}

/// The pieces of one signed request, before they are put on the wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedRequest {
    /// The full Authorization header value.
    pub authorization: String,
    /// The unix timestamp that was signed, in seconds.
    pub ts: i64,
    /// The base64 nonce that was signed, exactly as the header carries it.
    pub nonce: String,
    /// The exact bytes the signature covers.
    pub preimage: Vec<u8>,
}

/// The current time in unix seconds.
pub fn unix_now() -> Result<i64, SigningError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| SigningError::ClockBeforeEpoch)?;
    i64::try_from(now.as_secs()).map_err(|_| SigningError::ClockBeforeEpoch)
}

/// A fresh nonce, as the base64 text the header carries.
///
/// The nonce only has to be unique per (identity, window), so 16 random bytes are far more
/// than enough; they come from the TLS provider's random source rather than a hand rolled
/// counter or the clock.
pub fn fresh_nonce() -> Result<String, SigningError> {
    let provider = rustls::crypto::ring::default_provider();
    let mut bytes = [0u8; NONCE_LEN];
    provider
        .secure_random
        .fill(&mut bytes)
        .map_err(|_| SigningError::NoEntropy)?;
    Ok(Base64::encode_string(&bytes))
}

/// The signed request for one call, with an explicit timestamp and nonce text.
pub fn signed_request<S: ApiSigner + ?Sized>(
    signer: &S,
    method: &str,
    path: &str,
    body: &[u8],
    ts: i64,
    nonce: &str,
) -> Result<SignedRequest, SigningError> {
    if nonce.is_empty() {
        return Err(SigningError::EmptyNonce);
    }
    let preimage = canonical(method, path, body, ts, nonce.as_bytes());
    let signature = signer.sign(&preimage);
    if signature.len() != SIGNATURE_LEN {
        return Err(SigningError::SignatureLength(signature.len()));
    }
    let authorization = format!(
        "{AUTH_SCHEME} {} {ts} {nonce} {}",
        signer.api_public_key(),
        Base64::encode_string(&signature)
    );
    Ok(SignedRequest {
        authorization,
        ts,
        nonce: nonce.to_owned(),
        preimage,
    })
}

/// The signed request for one call, taking the clock and a fresh nonce.
pub fn sign_now<S: ApiSigner + ?Sized>(
    signer: &S,
    method: &str,
    path: &str,
    body: &[u8],
) -> Result<SignedRequest, SigningError> {
    let ts = unix_now()?;
    let nonce = fresh_nonce()?;
    signed_request(signer, method, path, body, ts, &nonce)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::sync::Mutex;

    use super::*;

    /// A signer that returns a fixed signature and remembers what it was asked to sign.
    struct RecordingSigner {
        key: PubKeyB64,
        signature: Vec<u8>,
        seen: Mutex<Vec<Vec<u8>>>,
    }

    impl RecordingSigner {
        fn new(signature_len: usize) -> Self {
            Self {
                key: PubKeyB64::from_bytes([3u8; 32]),
                signature: vec![0xab; signature_len],
                seen: Mutex::new(Vec::new()),
            }
        }

        fn last_message(&self) -> Vec<u8> {
            self.seen
                .lock()
                .unwrap()
                .last()
                .cloned()
                .unwrap_or_default()
        }
    }

    impl ApiSigner for RecordingSigner {
        fn api_public_key(&self) -> PubKeyB64 {
            self.key
        }

        fn sign(&self, message: &[u8]) -> Vec<u8> {
            self.seen.lock().unwrap().push(message.to_vec());
            self.signature.clone()
        }
    }

    #[test]
    fn the_client_passes_every_shared_conformance_vector() {
        let signer = RecordingSigner::new(SIGNATURE_LEN);
        for vector in wgmesh_proto::conformance_vectors() {
            let signed = signed_request(
                &signer,
                vector.method,
                vector.path,
                vector.body,
                vector.ts,
                vector.nonce,
            )
            .unwrap();
            assert_eq!(
                signed.preimage, vector.expected,
                "vector {} diverged from the shared preimage",
                vector.name
            );
        }
    }

    #[test]
    fn the_body_digest_of_every_vector_matches_the_digest_the_vector_publishes() {
        for vector in wgmesh_proto::conformance_vectors() {
            assert_eq!(
                sha256_hex(vector.body),
                vector.body_sha256_hex,
                "vector {} has a stale digest",
                vector.name
            );
        }
    }

    #[test]
    fn the_digest_of_an_empty_body_is_the_well_known_one() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn the_digest_is_lowercase_hex_of_the_right_length() {
        let digest = sha256_hex(b"wgmesh");
        assert_eq!(digest.len(), 64);
        assert!(
            digest
                .chars()
                .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character))
        );
    }

    #[test]
    fn the_header_has_the_fields_the_design_asks_for() {
        let signer = RecordingSigner::new(SIGNATURE_LEN);
        let signed = signed_request(
            &signer,
            "GET",
            "/v1/config",
            b"",
            1760000000,
            "AAECAwQFBgcICQoLDA0ODw==",
        )
        .unwrap();
        let fields: Vec<&str> = signed.authorization.split(' ').collect();
        assert_eq!(fields.len(), 5, "{}", signed.authorization);
        assert_eq!(fields[0], AUTH_SCHEME);
        assert_eq!(fields[1], signer.key.to_string());
        assert_eq!(fields[2], "1760000000");
        assert_eq!(fields[3], "AAECAwQFBgcICQoLDA0ODw==");
        assert_eq!(
            fields[4],
            Base64::encode_string(&[0xab; SIGNATURE_LEN]),
            "the signature must be base64 of what the signer returned"
        );
    }

    #[test]
    fn the_message_the_signer_sees_is_the_shared_preimage_and_nothing_else() {
        let signer = RecordingSigner::new(SIGNATURE_LEN);
        let body = b"{\"wg_pubkey\":\"x\"}";
        signed_request(
            &signer,
            "POST",
            "/v1/rotate",
            body,
            1760000009,
            "nonce-text",
        )
        .unwrap();
        assert_eq!(
            signer.last_message(),
            wgmesh_proto::canonical(
                "POST",
                "/v1/rotate",
                &sha256_hex(body),
                1760000009,
                b"nonce-text"
            )
        );
    }

    #[test]
    fn a_different_body_or_timestamp_produces_a_different_signature_input() {
        let signer = RecordingSigner::new(SIGNATURE_LEN);
        let first = signed_request(&signer, "POST", "/v1/rotate", b"a", 10, "n").unwrap();
        let second = signed_request(&signer, "POST", "/v1/rotate", b"b", 10, "n").unwrap();
        let third = signed_request(&signer, "POST", "/v1/rotate", b"a", 11, "n").unwrap();
        assert_ne!(first.preimage, second.preimage);
        assert_ne!(first.preimage, third.preimage);
    }

    #[test]
    fn a_signature_of_the_wrong_length_is_refused() {
        let signer = RecordingSigner::new(32);
        assert_eq!(
            signed_request(&signer, "GET", "/v1/config", b"", 1, "n"),
            Err(SigningError::SignatureLength(32))
        );
    }

    #[test]
    fn an_empty_nonce_is_refused() {
        let signer = RecordingSigner::new(SIGNATURE_LEN);
        assert_eq!(
            signed_request(&signer, "GET", "/v1/config", b"", 1, ""),
            Err(SigningError::EmptyNonce)
        );
    }

    #[test]
    fn a_fresh_nonce_is_random_base64_of_the_expected_length() {
        let first = fresh_nonce().unwrap();
        let second = fresh_nonce().unwrap();
        let third = fresh_nonce().unwrap();
        assert_ne!(first, second);
        assert_ne!(second, third);
        assert_ne!(first, third);
        let decoded = Base64::decode_vec(&first).unwrap();
        assert_eq!(decoded.len(), NONCE_LEN);
        assert_eq!(Base64::encode_string(&decoded), first);
    }

    #[test]
    fn sign_now_takes_the_clock_and_still_matches_the_shared_preimage() {
        let signer = RecordingSigner::new(SIGNATURE_LEN);
        let body = b"{}";
        let signed = sign_now(&signer, "POST", "/v1/rotate", body).unwrap();
        assert!(
            signed.ts > 1_600_000_000,
            "the clock looks wrong: {}",
            signed.ts
        );
        assert_eq!(
            signer.last_message(),
            wgmesh_proto::canonical(
                "POST",
                "/v1/rotate",
                &sha256_hex(body),
                signed.ts,
                signed.nonce.as_bytes()
            )
        );
        assert!(signed.authorization.contains(&signed.nonce));
        assert_ne!(
            sign_now(&signer, "POST", "/v1/rotate", body).unwrap().nonce,
            signed.nonce
        );
    }

    #[test]
    fn the_two_signing_errors_explain_themselves() {
        assert!(SigningError::ClockBeforeEpoch.to_string().contains("epoch"));
        assert!(SigningError::NoEntropy.to_string().contains("random"));
        assert!(SigningError::SignatureLength(7).to_string().contains('7'));
        assert!(SigningError::EmptyNonce.to_string().contains("nonce"));
    }
}
