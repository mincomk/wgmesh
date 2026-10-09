use sha2::{Digest, Sha256};

use crate::der;

pub fn hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push_str(&format!("{byte:02x}"));
    }
    text
}

pub fn spki_sha256(certificate_der: &[u8]) -> Option<String> {
    let spki = der::certificate_spki(certificate_der)?;
    Some(hex(&Sha256::digest(spki)))
}

pub fn normalize(pin: &str) -> String {
    pin.chars()
        .filter(|character| *character != ':' && !character.is_whitespace())
        .flat_map(char::to_lowercase)
        .collect()
}

pub fn matches(pinned: &str, certificate_der: &[u8]) -> bool {
    match spki_sha256(certificate_der) {
        Some(observed) => observed == normalize(pinned),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    const CERT_A: &[u8] = include_bytes!("../tests/fixtures/coordinator-a.der");
    const CERT_B: &[u8] = include_bytes!("../tests/fixtures/coordinator-b.der");

    // Computed outside this crate, with
    //   openssl x509 -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum
    const PIN_A: &str = "eef4fe3c04c8f4fb8a918abab36cd3fc76f6274aee0efaeb942e595ac03f3a1c";
    const PIN_B: &str = "126305e03335353e8ced874514512ee646fa380247802e061c539b2c7a8a00d5";

    #[test]
    fn the_pin_of_a_certificate_matches_an_independent_computation() {
        assert_eq!(spki_sha256(CERT_A).unwrap(), PIN_A);
        assert_eq!(spki_sha256(CERT_B).unwrap(), PIN_B);
    }

    #[test]
    fn a_pin_matches_only_its_own_certificate() {
        assert!(matches(PIN_A, CERT_A));
        assert!(!matches(PIN_A, CERT_B));
        assert!(matches(PIN_B, CERT_B));
    }

    #[test]
    fn a_pin_is_compared_case_insensitively_and_ignores_separators() {
        assert!(matches(&PIN_A.to_uppercase(), CERT_A));
        let colons: Vec<String> = PIN_A
            .as_bytes()
            .chunks(2)
            .map(|pair| String::from_utf8_lossy(pair).into_owned())
            .collect();
        assert!(matches(&colons.join(":"), CERT_A));
        assert_eq!(normalize("AA:bb CC"), "aabbcc");
    }

    #[test]
    fn something_that_is_not_a_certificate_never_matches() {
        assert!(spki_sha256(b"not a certificate").is_none());
        assert!(!matches(PIN_A, b"not a certificate"));
    }

    #[test]
    fn hex_lowercases_and_doubles_every_byte() {
        assert_eq!(hex(&[0x00, 0x0f, 0xff]), "000fff");
    }
}
