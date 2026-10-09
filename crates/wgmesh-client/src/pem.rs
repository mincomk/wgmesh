use base64ct::{Base64, Encoding};

const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
const END: &str = "-----END CERTIFICATE-----";

// A certificate arrives either as the DER the TLS layer hands over or as the PEM
// an operator copied out of the proxy's configuration, and pinning has to accept
// both, so the reader sniffs rather than making the caller say which it is.
pub fn decode(input: &[u8]) -> Option<Vec<u8>> {
    let Ok(text) = core::str::from_utf8(input) else {
        // Binary input is already the DER a TLS layer would hand over.
        return Some(input.to_vec());
    };
    let Some(begin) = text.find(BEGIN) else {
        return Some(input.to_vec());
    };
    let rest = text.get(begin + BEGIN.len()..)?;
    let end = rest.find(END)?;
    let body: String = rest
        .get(..end)?
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    Base64::decode_vec(&body).ok()
}

pub fn load(path: &std::path::Path) -> Result<Vec<u8>, String> {
    let bytes =
        std::fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    decode(&bytes).ok_or_else(|| format!("{} is neither a certificate nor PEM", path.display()))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    const PEM: &[u8] = include_bytes!("../tests/fixtures/coordinator-a.pem");
    const DER: &[u8] = include_bytes!("../tests/fixtures/coordinator-a.der");

    #[test]
    fn a_pem_certificate_decodes_to_the_same_bytes_as_its_der() {
        assert_eq!(decode(PEM).unwrap(), DER);
    }

    #[test]
    fn bare_der_is_passed_through() {
        assert_eq!(decode(DER).unwrap(), DER);
    }

    #[test]
    fn the_pin_of_a_pem_and_of_its_der_are_the_same() {
        let from_pem = crate::pin::spki_sha256(&decode(PEM).unwrap()).unwrap();
        let from_der = crate::pin::spki_sha256(&decode(DER).unwrap()).unwrap();
        assert_eq!(from_pem, from_der);
    }

    #[test]
    fn a_pem_without_an_end_marker_is_refused() {
        assert!(decode(b"-----BEGIN CERTIFICATE-----\nAAAA\n").is_none());
        assert!(decode(b"not a certificate").is_some());
    }
}
