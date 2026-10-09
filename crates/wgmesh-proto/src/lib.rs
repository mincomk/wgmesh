#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

// The wire contract of the coordinator API: the JSON bodies both sides agree
// on, the bytes a signed request is signed over, the spelling of a key and of a
// join token. Nothing here touches the network or a database.

pub mod api;
pub mod bands;
pub mod id;
pub mod key;
pub mod sign;
pub mod token;

pub use id::{device_id, parse_device_id, parse_relay_id, relay_id};
pub use key::{decode_key, encode_key};
pub use sign::{SignedRequest, canonical, etag, parse_authorization, sha256_hex, within_skew};
pub use token::{SECRET_LEN, format_token, hash_secret, hash_token_text, parse_token};
