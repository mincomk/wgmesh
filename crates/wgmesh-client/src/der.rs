pub const SEQUENCE: u8 = 0x30;
pub const CONTEXT_ZERO: u8 = 0xa0;

#[derive(Debug, Clone, Copy)]
pub struct Element<'a> {
    pub tag: u8,
    pub contents: &'a [u8],
    pub total_len: usize,
}

pub fn read(input: &[u8]) -> Option<Element<'_>> {
    if input.len() < 2 {
        return None;
    }
    let tag = input[0];
    let first = input[1];
    let (length, header_len) = if first < 0x80 {
        (usize::from(first), 2usize)
    } else if first == 0x80 {
        // Indefinite length belongs to BER, not DER. A certificate never uses it.
        return None;
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 || input.len() < 2 + count {
            return None;
        }
        let mut value = 0usize;
        for byte in &input[2..2 + count] {
            value = (value << 8) | usize::from(*byte);
        }
        (value, 2 + count)
    };
    if length > input.len().saturating_sub(header_len) {
        return None;
    }
    Some(Element {
        tag,
        contents: &input[header_len..header_len + length],
        total_len: header_len + length,
    })
}

// Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
// TBSCertificate ::= SEQUENCE { [0] version, serialNumber, signature, issuer,
//                               validity, subject, subjectPublicKeyInfo, ... }
//
// The pin is the whole SubjectPublicKeyInfo element, header included, which is
// what every other implementation means by "SPKI pin": a re-issued certificate
// that keeps the key keeps the pin, and a new key changes it.
pub fn certificate_spki(certificate: &[u8]) -> Option<&[u8]> {
    let outer = read(certificate)?;
    if outer.tag != SEQUENCE || outer.total_len != certificate.len() {
        return None;
    }
    let tbs = read(outer.contents)?;
    if tbs.tag != SEQUENCE {
        return None;
    }
    let mut rest = tbs.contents;
    let first = read(rest)?;
    if first.tag == CONTEXT_ZERO {
        rest = &rest[first.total_len..];
    }
    for _ in 0..5 {
        let element = read(rest)?;
        rest = &rest[element.total_len..];
    }
    let spki = read(rest)?;
    if spki.tag != SEQUENCE {
        return None;
    }
    rest.get(..spki.total_len)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    const CERT_A: &[u8] = include_bytes!("../tests/fixtures/coordinator-a.der");
    const CERT_B: &[u8] = include_bytes!("../tests/fixtures/coordinator-b.der");

    #[test]
    fn a_two_byte_element_reads_its_header_and_contents() {
        let element = read(&[0x02, 0x01, 0x2a]).unwrap();
        assert_eq!(element.tag, 0x02);
        assert_eq!(element.contents, &[0x2a]);
        assert_eq!(element.total_len, 3);
    }

    #[test]
    fn a_long_form_length_reads_correctly() {
        let mut bytes = vec![SEQUENCE, 0x81, 0x80];
        bytes.extend(std::iter::repeat_n(0u8, 0x80));
        let element = read(&bytes).unwrap();
        assert_eq!(element.contents.len(), 0x80);
        assert_eq!(element.total_len, 3 + 0x80);
    }

    #[test]
    fn a_truncated_or_indefinite_element_is_refused() {
        assert!(read(&[]).is_none());
        assert!(read(&[0x30]).is_none());
        assert!(read(&[0x30, 0x05, 0x00]).is_none());
        assert!(read(&[0x30, 0x80, 0x00, 0x00]).is_none());
        assert!(read(&[0x30, 0x85, 0, 0, 0, 0, 1]).is_none());
    }

    #[test]
    fn the_spki_of_a_real_certificate_is_isolated() {
        let spki_a = certificate_spki(CERT_A).unwrap();
        let spki_b = certificate_spki(CERT_B).unwrap();
        assert!(spki_a.len() > 40);
        assert_ne!(spki_a, spki_b);
        assert_eq!(spki_a[0], SEQUENCE);
        assert_eq!(read(spki_a).unwrap().total_len, spki_a.len());
    }

    #[test]
    fn a_certificate_shaped_blob_that_is_not_one_is_refused() {
        assert!(certificate_spki(&[]).is_none());
        assert!(certificate_spki(&[0x30, 0x01, 0x00]).is_none());
        assert!(certificate_spki(&[0x02, 0x01, 0x00]).is_none());
    }
}
