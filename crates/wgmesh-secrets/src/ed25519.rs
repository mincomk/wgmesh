use ed25519_dalek::{Signature as DalekSignature, Signer, SigningKey, VerifyingKey};

pub type SecretKey = [u8; 32];
pub type PublicKey = [u8; 32];
pub type Signature = [u8; 64];

pub fn public_key(secret: &SecretKey) -> PublicKey {
    SigningKey::from_bytes(secret).verifying_key().to_bytes()
}

pub fn sign(secret: &SecretKey, message: &[u8]) -> Signature {
    SigningKey::from_bytes(secret).sign(message).to_bytes()
}

pub fn verify(public: &PublicKey, message: &[u8], signature: &Signature) -> bool {
    let Ok(key) = VerifyingKey::from_bytes(public) else {
        return false;
    };
    key.verify_strict(message, &DalekSignature::from_bytes(signature))
        .is_ok()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    const SECRET: SecretKey = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];

    #[test]
    fn a_signature_verifies_against_its_own_public_key() {
        let public = public_key(&SECRET);
        let message = b"WGMESHv1\nGET\n/v1/config\nabc\n1760000000\nnonce";
        let signature = sign(&SECRET, message);
        assert!(verify(&public, message, &signature));
    }

    #[test]
    fn a_signature_does_not_verify_against_a_changed_message() {
        let public = public_key(&SECRET);
        let signature = sign(&SECRET, b"one message");
        assert!(!verify(&public, b"another message", &signature));
    }

    #[test]
    fn a_signature_does_not_verify_against_another_key() {
        let mut other = SECRET;
        other[0] ^= 0xff;
        let signature = sign(&SECRET, b"message");
        assert!(!verify(&public_key(&other), b"message", &signature));
    }

    #[test]
    fn a_garbage_signature_is_refused_rather_than_accepted() {
        let public = public_key(&SECRET);
        assert!(!verify(&public, b"message", &[0u8; 64]));
        let good = sign(&SECRET, b"message");
        let mut flipped = good;
        flipped[63] ^= 0x01;
        assert!(!verify(&public, b"message", &flipped));
    }

    #[test]
    fn the_public_key_is_the_verifying_key_of_the_secret() {
        let public = public_key(&SECRET);
        let signature = sign(&SECRET, b"payload");
        assert!(verify(&public, b"payload", &signature));
        assert_eq!(public.len(), 32);
        assert_eq!(sign(&SECRET, b"payload").len(), 64);
    }
}
