// The `wgmesh` node's and relay's view of the coordinator: the HTTPS adapter that speaks the
// wire types of `wgmesh-proto`, signs its requests, and refuses to talk to a coordinator whose
// leaf certificate does not match the pinned key.

pub mod http;
pub mod pin;
pub mod signing;

pub use http::{
    ClientError, ClientSettings, Fetch, HttpsCoordinator, RetryPolicy, Sleeper, ThreadSleeper,
};
pub use pin::{
    PinError, PinnedSpkiVerifier, SPKI_SHA256_LEN, SpkiPin, pinned_client_config, spki_sha256,
    spki_sha256_hex,
};
pub use signing::{
    ApiSigner, NONCE_LEN, SIGNATURE_LEN, SignedRequest, SigningError, canonical, fresh_nonce,
    sha256_hex, sign_now, signed_request, unix_now,
};
