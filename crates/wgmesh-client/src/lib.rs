#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

// The HTTPS client: the one adapter that reaches a different host over a wire.
//
// A node and a relay both speak to the coordinator through this crate, and both do it the same
// way: the leaf certificate the coordinator presents must hash to the pin this device holds,
// every request after enrollment is signed with the device's own key, and the answer is parsed
// into the port's vocabulary.
//
// Three things are worth knowing before reading the code.
//
// **The pin replaces the certificate chain.** No root store is consulted and no name is checked:
// the trust decision is "the public key behind this leaf certificate is the one I was told to
// expect", and nothing else. That is what makes a privately-issued certificate workable and a
// stolen certificate useless. Renewing the certificate keeps the pin, because the pin is the key
// rather than the certificate.
//
// **Every request is signed over the bytes that are actually sent.** The canonical string is
// `wgmesh_proto::sign::canonical(method, path, sha256(body), timestamp, nonce)`, so the body the
// signature covers is the body in the request. The nonce is fresh randomness per request, and the
// timestamp comes from the `Clock` port, which is why a test can replay a whole conversation at a
// fixed instant.
//
// **A failure carries what a caller may do about it.** `PortError`'s class is computed here, once,
// from the status and the kind of failure — see `Coordinator::status_error` for the table. The one
// that matters most is `Class::Trust`: it is what a wrong pin becomes, and it is the class nothing
// retries.

pub mod http;
pub mod pin;

pub use http::{ConfigExchange, Coordinator, DEFAULT_TIMEOUT_SECS};
pub use pin::{PinnedVerifier, client_config, spki_sha256};
