#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use ed25519_dalek::{Signature, VerifyingKey};
use wgmesh_core::PublicKey;

/// Check an Ed25519 signature against a public key the store already holds.
///
/// This is here rather than in the coordination surface because it is the one
/// operation that has to be right: a private key never leaves the machine it
/// was generated on, and everything else about authentication is bookkeeping
/// around this call.
pub fn verify(public_key: &PublicKey, message: &[u8], signature: &[u8]) -> bool {
    let Ok(key) = VerifyingKey::from_bytes(public_key.as_bytes()) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(signature) else {
        return false;
    };
    key.verify_strict(message, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;

    fn signing_key() -> SigningKey {
        let mut seed = [0u8; 32];
        seed[0] = 3;
        seed[31] = 9;
        SigningKey::from_bytes(&seed)
    }

    fn public_key(signing: &SigningKey) -> PublicKey {
        PublicKey::from_bytes(signing.verifying_key().to_bytes())
    }

    #[test]
    fn a_real_signature_verifies() {
        let signing = signing_key();
        let message = b"WGMESHv1\nGET\n/v1/config\n...";
        let signature = signing.sign(message).to_bytes();
        assert!(verify(&public_key(&signing), message, &signature));
    }

    #[test]
    fn a_signature_over_another_message_does_not() {
        let signing = signing_key();
        let signature = signing.sign(b"one message").to_bytes();
        assert!(!verify(
            &public_key(&signing),
            b"another message",
            &signature
        ));
    }

    #[test]
    fn another_key_does_not_verify_it() {
        let signing = signing_key();
        let message = b"hello";
        let signature = signing.sign(message).to_bytes();
        let mut seed = [0u8; 32];
        seed[0] = 4;
        seed[31] = 9;
        let stranger =
            PublicKey::from_bytes(SigningKey::from_bytes(&seed).verifying_key().to_bytes());
        assert!(!verify(&stranger, message, &signature));
    }

    #[test]
    fn a_malformed_signature_is_refused_rather_than_panicking() {
        let signing = signing_key();
        assert!(!verify(&public_key(&signing), b"hello", &[]));
        assert!(!verify(&public_key(&signing), b"hello", &[0u8; 7]));
    }
}
