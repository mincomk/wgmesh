// The signing preimage from the design document, section 5.5. The coordinator and both
// clients (device and relay) must produce exactly these bytes, so this module owns the
// one implementation and the conformance vectors that both sides test against.
//
//   sig = Ed25519(priv, "WGMESHv1\n" + method + "\n" + path + "\n" +
//                 sha256_hex(body) + "\n" + ts + "\n" + nonce)
//
// The body digest is an argument rather than something computed here on purpose: the
// crates that hash bodies (wgmesh-client, and later the coordinator) own their hash
// dependency, and this crate stays free of any crypto dependency, so the coordinator can
// share the same function without pulling in the client's hash stack.

use crate::WireError;

/// The version tag every signing preimage starts with, including its trailing newline.
pub const CANONICAL_PREFIX: &[u8] = b"WGMESHv1\n";

/// Lowercase hex, the spelling the body digest has in the preimage.
///
/// This lives here rather than in each crate that hashes a body so that the digest both
/// sides compare is written the same way everywhere.
pub fn hex_encode(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Decode hex, either case, refusing anything that is not whole bytes.
pub fn hex_decode(text: &str) -> Result<Vec<u8>, WireError> {
    hex::decode(text).map_err(|_| WireError::Hex(text.to_owned()))
}

/// One conformance vector: a request shape, the body digest a client must compute for it,
/// and the exact bytes the signature must be made over.
///
/// The vector carries the raw `body` as well so a crate that owns a SHA-256 implementation
/// can check that its digest matches `body_sha256_hex` before comparing the preimage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CanonicalVector {
    /// Stable name of the case, used in assertion messages.
    pub name: &'static str,
    /// HTTP method, uppercase.
    pub method: &'static str,
    /// Request path, with any query string, exactly as it goes on the wire.
    pub path: &'static str,
    /// The request body bytes exactly as they are sent.
    pub body: &'static [u8],
    /// Lowercase hex SHA-256 of `body`.
    pub body_sha256_hex: &'static str,
    /// Unix timestamp in seconds, as carried in the Authorization header.
    pub ts: i64,
    /// Nonce text, as carried in the Authorization header.
    pub nonce: &'static str,
    /// The exact bytes that are signed.
    pub expected: &'static [u8],
}

/// Build the signing preimage for one request.
///
/// `body_sha256_hex` must be the lowercase hex SHA-256 of the exact body bytes, the empty
/// string included (`e3b0c442...`). `nonce` is the nonce text as it appears in the
/// Authorization header, not the decoded bytes. Nothing here is normalised, escaped or
/// trimmed: the function is a concatenation of the arguments, so both sides agree byte for
/// byte as long as they pass the same values.
pub fn canonical(
    method: &str,
    path: &str,
    body_sha256_hex: &str,
    ts: i64,
    nonce: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        CANONICAL_PREFIX.len()
            + method.len()
            + path.len()
            + body_sha256_hex.len()
            + nonce.len()
            + 24,
    );
    out.extend_from_slice(CANONICAL_PREFIX);
    out.extend_from_slice(method.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(path.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(body_sha256_hex.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(ts.to_string().as_bytes());
    out.push(b'\n');
    out.extend_from_slice(nonce);
    out
}

/// The conformance vectors every implementation of the signing preimage must pass.
///
/// `wgmesh-client` checks them with raw bodies (it owns the SHA-256), and the coordinator
/// checks them with the digests it computes itself. A change here is a protocol change.
const VECTORS: &[CanonicalVector] = &[
    CanonicalVector {
        name: "get_config_with_no_body",
        method: "GET",
        path: "/v1/config",
        body: b"",
        body_sha256_hex: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ts: 1760000000,
        nonce: "0f9a3c1d2b4e",
        expected: b"WGMESHv1\nGET\n/v1/config\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n1760000000\n0f9a3c1d2b4e",
    },
    CanonicalVector {
        name: "post_join_with_json_body",
        method: "POST",
        path: "/v1/join",
        body: b"{\"token\":\"WGMESH-7K3M-9QXA-4PZ2\",\"name\":\"edge-1\",\"wg_pubkey\":\"hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=\"}",
        body_sha256_hex: "ed6e7f54a62bb7bb993ed8079b9649940829facc0923170b9dd766b07cd37fe1",
        ts: 1760000001,
        nonce: "5Xq/7bA+9kLm",
        expected: b"WGMESHv1\nPOST\n/v1/join\ned6e7f54a62bb7bb993ed8079b9649940829facc0923170b9dd766b07cd37fe1\n1760000001\n5Xq/7bA+9kLm",
    },
    CanonicalVector {
        name: "get_with_a_query_string",
        method: "GET",
        path: "/v1/relay/assignment?since=41",
        body: b"",
        body_sha256_hex: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ts: 1760000002,
        nonce: "aa",
        expected: b"WGMESHv1\nGET\n/v1/relay/assignment?since=41\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n1760000002\naa",
    },
    CanonicalVector {
        name: "post_with_a_body_over_one_sha256_block",
        method: "POST",
        path: "/v1/endpoint",
        body: b"0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmno",
        body_sha256_hex: "c42debc003290127e664a5c857c6e454cff4a7d512fcb8e5a942fb0d9c045e5f",
        ts: 1760000003,
        nonce: "Zz09",
        expected: b"WGMESHv1\nPOST\n/v1/endpoint\nc42debc003290127e664a5c857c6e454cff4a7d512fcb8e5a942fb0d9c045e5f\n1760000003\nZz09",
    },
    CanonicalVector {
        name: "post_rotate_with_an_empty_object_body",
        method: "POST",
        path: "/v1/rotate",
        body: b"{}",
        body_sha256_hex: "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
        ts: 1760000004,
        nonce: "-_",
        expected: b"WGMESHv1\nPOST\n/v1/rotate\n44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a\n1760000004\n-_",
    },
    CanonicalVector {
        name: "post_with_a_multiline_body",
        method: "POST",
        path: "/v1/punch",
        body: b"{\n  \"peer\": 7,\n  \"outcome\": \"failed\"\n}\n",
        body_sha256_hex: "dce709d8e7ed1049c28fa9749a0c02b938b8c203f26128eaff73a4e9ec329e89",
        ts: 1760000005,
        nonce: "9v",
        expected: b"WGMESHv1\nPOST\n/v1/punch\ndce709d8e7ed1049c28fa9749a0c02b938b8c203f26128eaff73a4e9ec329e89\n1760000005\n9v",
    },
];

/// The shared conformance vectors, in the order they must be tested.
pub fn conformance_vectors() -> &'static [CanonicalVector] {
    VECTORS
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn every_conformance_vector_matches_byte_for_byte() {
        for vector in conformance_vectors() {
            let produced = canonical(
                vector.method,
                vector.path,
                vector.body_sha256_hex,
                vector.ts,
                vector.nonce.as_bytes(),
            );
            assert_eq!(
                produced,
                vector.expected,
                "vector {} produced {:?}",
                vector.name,
                String::from_utf8_lossy(&produced)
            );
        }
    }

    #[test]
    fn the_preimage_starts_with_the_version_tag_once() {
        for vector in conformance_vectors() {
            let produced = canonical(
                vector.method,
                vector.path,
                vector.body_sha256_hex,
                vector.ts,
                vector.nonce.as_bytes(),
            );
            assert!(
                produced.starts_with(CANONICAL_PREFIX),
                "vector {} lost the prefix",
                vector.name
            );
            assert_eq!(
                produced
                    .windows(CANONICAL_PREFIX.len())
                    .filter(|window| *window == CANONICAL_PREFIX)
                    .count(),
                1,
                "vector {} carried the version tag more than once",
                vector.name
            );
        }
    }

    #[test]
    fn the_fields_are_joined_with_single_newlines_in_a_fixed_order() {
        let produced = canonical("POST", "/v1/join", "abc123", 1760000000, b"nonce-text");
        assert_eq!(
            produced,
            b"WGMESHv1\nPOST\n/v1/join\nabc123\n1760000000\nnonce-text"
        );
        assert_eq!(
            produced.iter().filter(|byte| **byte == b'\n').count(),
            5,
            "the version tag and the five fields must produce exactly five newlines"
        );
    }

    #[test]
    fn the_body_digest_is_carried_verbatim_and_never_rehashed_or_normalised() {
        let uppercase = canonical("GET", "/v1/config", "E3B0C442", 1, b"n");
        assert_eq!(uppercase, b"WGMESHv1\nGET\n/v1/config\nE3B0C442\n1\nn");
    }

    #[test]
    fn a_negative_timestamp_keeps_its_sign() {
        let produced = canonical("GET", "/v1/config", "d", -1, b"n");
        assert_eq!(produced, b"WGMESHv1\nGET\n/v1/config\nd\n-1\nn");
    }

    #[test]
    fn a_different_timestamp_or_nonce_changes_the_preimage() {
        let base = canonical("GET", "/v1/config", "d", 1760000000, b"n");
        assert_ne!(base, canonical("GET", "/v1/config", "d", 1760000001, b"n"));
        assert_ne!(base, canonical("GET", "/v1/config", "d", 1760000000, b"m"));
        assert_ne!(base, canonical("GET", "/v1/config", "e", 1760000000, b"n"));
        assert_ne!(base, canonical("POST", "/v1/config", "d", 1760000000, b"n"));
        assert_ne!(base, canonical("GET", "/v1/relay", "d", 1760000000, b"n"));
    }

    #[test]
    fn hex_is_written_lowercase_and_reads_back_either_case() {
        assert_eq!(hex_encode(&[0x00, 0x9f, 0xff]), "009fff");
        assert_eq!(hex_encode(&[]), "");
        assert_eq!(hex_decode("009fff"), Ok(vec![0x00, 0x9f, 0xff]));
        assert_eq!(hex_decode("009FFF"), Ok(vec![0x00, 0x9f, 0xff]));
        assert_eq!(hex_decode(""), Ok(Vec::new()));
    }

    #[test]
    fn hex_that_is_not_whole_bytes_is_refused() {
        assert!(matches!(hex_decode("abc"), Err(WireError::Hex(_))));
        assert!(matches!(hex_decode("zz"), Err(WireError::Hex(_))));
    }

    #[test]
    fn the_digests_the_vectors_publish_are_lowercase_hex_of_32_bytes() {
        for vector in conformance_vectors() {
            assert_eq!(vector.body_sha256_hex.len(), 64);
            assert!(
                vector
                    .body_sha256_hex
                    .chars()
                    .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character)),
                "vector {} does not publish lowercase hex",
                vector.name
            );
            assert_eq!(
                hex_decode(vector.body_sha256_hex).expect("decodes").len(),
                32
            );
        }
    }

    #[test]
    fn every_api_verb_appears_in_the_vectors() {
        let names: Vec<&str> = conformance_vectors()
            .iter()
            .map(|vector| vector.method)
            .collect();
        assert!(names.contains(&"GET"));
        assert!(names.contains(&"POST"));
        assert!(
            conformance_vectors()
                .iter()
                .any(|vector| !vector.body.is_empty())
        );
        assert!(
            conformance_vectors()
                .iter()
                .any(|vector| vector.body.is_empty())
        );
    }
}
