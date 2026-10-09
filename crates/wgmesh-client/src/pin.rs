// Coordinator identity for the node side: the node pins the SHA-256 of the leaf
// certificate's SubjectPublicKeyInfo and refuses any connection whose leaf does not match
// (design document section 5.6). Pinning replaces the webpki chain walk on purpose: the pin
// is the trust anchor, so a certificate signed by anybody is acceptable as long as its
// public key is the one we recorded at enroll time.
//
// The SPKI hash is computed from the certificate DER here rather than by an extra X.509
// crate, because the hash covers exactly one DER element and finding it is a short walk
// down the certificate structure with no parsing of the fields in between.

use std::fmt;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, Error as TlsError, SignatureScheme,
};
use sha2::{Digest, Sha256};

/// The length of an SPKI SHA-256 pin.
pub const SPKI_SHA256_LEN: usize = 32;

/// Hex digits of a pin, without separators.
const PIN_HEX_LEN: usize = SPKI_SHA256_LEN * 2;

/// Anything that can go wrong while handling a pin or a certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PinError {
    /// The certificate is not DER we can walk, or is missing the fields we need.
    MalformedCertificate(&'static str),
    /// The pin text is not 32 hex encoded bytes.
    InvalidPin(String),
    /// A certificate whose SPKI does not match the pin.
    Mismatch {
        /// The pin the client was configured with.
        expected: [u8; SPKI_SHA256_LEN],
        /// The leaf certificate's actual SPKI hash.
        actual: [u8; SPKI_SHA256_LEN],
    },
}

impl fmt::Display for PinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedCertificate(what) => write!(f, "malformed certificate: {what}"),
            Self::InvalidPin(text) => write!(f, "a pin must be 64 hex digits, got {text:?}"),
            Self::Mismatch { expected, actual } => write!(
                f,
                "the leaf certificate's SPKI hash {} does not match the pin {}",
                wgmesh_proto::hex_encode(actual),
                wgmesh_proto::hex_encode(expected)
            ),
        }
    }
}

impl std::error::Error for PinError {}

/// Decode hex, accepting separators and either case the way a pin is written by hand.
fn decode_hex(text: &str) -> Result<Vec<u8>, PinError> {
    let cleaned: String = text
        .chars()
        .filter(|character| !matches!(character, ':' | ' ' | '-' | '_'))
        .collect();
    if cleaned.len() != PIN_HEX_LEN {
        return Err(PinError::InvalidPin(text.to_owned()));
    }
    wgmesh_proto::hex_decode(&cleaned).map_err(|_| PinError::InvalidPin(text.to_owned()))
}

/// The SHA-256 of a leaf certificate's SubjectPublicKeyInfo, the value a node records at
/// enroll time and checks on every connection afterwards.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SpkiPin([u8; SPKI_SHA256_LEN]);

impl SpkiPin {
    /// Wrap raw hash bytes.
    pub const fn from_bytes(bytes: [u8; SPKI_SHA256_LEN]) -> Self {
        Self(bytes)
    }

    /// The raw hash bytes.
    pub const fn as_bytes(&self) -> &[u8; SPKI_SHA256_LEN] {
        &self.0
    }

    /// Parse lowercase or uppercase hex, with or without `:` separators.
    pub fn parse(text: &str) -> Result<Self, PinError> {
        let bytes = decode_hex(text)?;
        let array: [u8; SPKI_SHA256_LEN] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| PinError::InvalidPin(text.to_owned()))?;
        Ok(Self(array))
    }

    /// Lowercase hex, the form written to the configuration file.
    pub fn to_hex(self) -> String {
        wgmesh_proto::hex_encode(&self.0)
    }

    /// The SPKI hash of a certificate, as this pin.
    pub fn of_certificate(cert_der: &[u8]) -> Result<Self, PinError> {
        spki_sha256(cert_der).map(Self)
    }

    /// Check a certificate against this pin.
    pub fn verify(&self, cert_der: &[u8]) -> Result<(), PinError> {
        let actual = spki_sha256(cert_der)?;
        if actual == self.0 {
            Ok(())
        } else {
            Err(PinError::Mismatch {
                expected: self.0,
                actual,
            })
        }
    }
}

impl fmt::Display for SpkiPin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for SpkiPin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SpkiPin({})", self.to_hex())
    }
}

impl std::str::FromStr for SpkiPin {
    type Err = PinError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}

/// One DER element: its tag, where its content starts, how long its content is.
struct Element {
    tag: u8,
    header_len: usize,
    content_len: usize,
}

impl Element {
    fn end(&self, start: usize) -> usize {
        start + self.header_len + self.content_len
    }
}

/// Read the DER element that starts at `offset`, refusing anything but the definite length
/// encoding that X.509 certificates use.
fn read_element(input: &[u8], offset: usize) -> Result<Element, PinError> {
    let tag = *input
        .get(offset)
        .ok_or(PinError::MalformedCertificate("no element tag"))?;
    let first = *input
        .get(offset + 1)
        .ok_or(PinError::MalformedCertificate("no element length"))?;
    let (header_len, content_len) = if first & 0x80 == 0 {
        (2usize, first as usize)
    } else {
        let count = (first & 0x7f) as usize;
        if count == 0 || count > 4 {
            return Err(PinError::MalformedCertificate(
                "unsupported length encoding",
            ));
        }
        let mut len = 0usize;
        for index in 0..count {
            let byte = *input
                .get(offset + 2 + index)
                .ok_or(PinError::MalformedCertificate("truncated length"))?;
            len = (len << 8) | byte as usize;
        }
        (2 + count, len)
    };
    let element = Element {
        tag,
        header_len,
        content_len,
    };
    if element.end(offset) > input.len() {
        return Err(PinError::MalformedCertificate(
            "element runs past the input",
        ));
    }
    Ok(element)
}

/// The starting offset of the SubjectPublicKeyInfo element inside a certificate, checking
/// each element in front of it so a malformed certificate cannot shift the answer.
fn spki_offset(cert_der: &[u8]) -> Result<usize, PinError> {
    let certificate = read_element(cert_der, 0)?;
    if certificate.tag != 0x30 {
        return Err(PinError::MalformedCertificate(
            "the certificate is not a sequence",
        ));
    }
    let tbs = read_element(cert_der, certificate.header_len)?;
    if tbs.tag != 0x30 {
        return Err(PinError::MalformedCertificate(
            "tbsCertificate is not a sequence",
        ));
    }
    let mut offset = certificate.header_len + tbs.header_len;
    let limit = tbs.end(certificate.header_len);

    let first = read_element(cert_der, offset)?;
    if first.tag == 0xa0 {
        offset = first.end(offset);
    }

    for (index, what) in [
        (0usize, "serialNumber"),
        (1, "signature"),
        (2, "issuer"),
        (3, "validity"),
        (4, "subject"),
    ] {
        let element = read_element(cert_der, offset)?;
        let expected_tag = if index == 0 { 0x02 } else { 0x30 };
        if element.tag != expected_tag {
            return Err(PinError::MalformedCertificate(what));
        }
        offset = element.end(offset);
    }

    let spki = read_element(cert_der, offset)?;
    if spki.tag != 0x30 || spki.end(offset) > limit {
        return Err(PinError::MalformedCertificate("subjectPublicKeyInfo"));
    }
    Ok(offset)
}

/// The SHA-256 of the SubjectPublicKeyInfo element of a certificate in DER form.
///
/// This is the value pinned at enroll time: a certificate renewal that keeps the key keeps
/// the pin, and a different key changes it.
pub fn spki_sha256(cert_der: &[u8]) -> Result<[u8; SPKI_SHA256_LEN], PinError> {
    let offset = spki_offset(cert_der)?;
    let element = read_element(cert_der, offset)?;
    let end = element.end(offset);
    let digest = Sha256::digest(&cert_der[offset..end]);
    let mut out = [0u8; SPKI_SHA256_LEN];
    out.copy_from_slice(&digest);
    Ok(out)
}

/// The SPKI hash of a certificate as lowercase hex, the form the design document writes.
pub fn spki_sha256_hex(cert_der: &[u8]) -> Result<String, PinError> {
    spki_sha256(cert_der).map(|hash| wgmesh_proto::hex_encode(&hash))
}

/// A `rustls` server certificate verifier that accepts exactly one leaf public key.
///
/// The chain is not walked: the pin is the anchor. The handshake signature is still
/// verified against the pinned certificate, so a peer that does not hold the private key
/// cannot complete the handshake even though the pin matched.
pub struct PinnedSpkiVerifier {
    pin: SpkiPin,
    provider: Arc<CryptoProvider>,
}

impl PinnedSpkiVerifier {
    /// A verifier for `pin`, using the process default or the ring provider.
    pub fn new(pin: SpkiPin) -> Self {
        Self {
            pin,
            provider: Arc::new(rustls::crypto::ring::default_provider()),
        }
    }

    /// The pin this verifier enforces.
    pub const fn pin(&self) -> &SpkiPin {
        &self.pin
    }
}

impl fmt::Debug for PinnedSpkiVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PinnedSpkiVerifier({})", self.pin.to_hex())
    }
}

impl ServerCertVerifier for PinnedSpkiVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        match self.pin.verify(end_entity.as_ref()) {
            Ok(()) => Ok(ServerCertVerified::assertion()),
            Err(error) => Err(TlsError::InvalidCertificate(certificate_error(error))),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn certificate_error(error: PinError) -> CertificateError {
    match error {
        PinError::MalformedCertificate(_) => CertificateError::BadEncoding,
        PinError::Mismatch { .. } | PinError::InvalidPin(_) => {
            CertificateError::ApplicationVerificationFailure
        }
    }
}

/// A `rustls` client configuration that trusts exactly the pinned leaf key.
pub fn pinned_client_config(pin: SpkiPin) -> Result<ClientConfig, PinError> {
    Ok(
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|_| PinError::MalformedCertificate("no usable protocol version"))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedSpkiVerifier::new(pin)))
            .with_no_client_auth(),
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    // Two self signed certificates, generated once with
    //   openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 ...
    // Their SPKI hashes below come from openssl, not from this code:
    //   openssl x509 -in a.crt.pem -pubkey -noout | openssl pkey -pubin -outform DER | openssl dgst -sha256
    const CERT_A: &[u8] = include_bytes!("../tests/fixtures/a.crt.der");
    const KEY_A: &[u8] = include_bytes!("../tests/fixtures/a.key.der");
    const CERT_B: &[u8] = include_bytes!("../tests/fixtures/b.crt.der");
    const KEY_B: &[u8] = include_bytes!("../tests/fixtures/b.key.der");
    const PIN_A_HEX: &str = "fc4f9ece7c356bdc55cb72fd15a8c348ec9629f70ee40b69ae382efa257f661e";
    const PIN_B_HEX: &str = "165ff3e35c95464141b491ca067fb84f976db5001b015bd0d0b33167c993d31b";

    fn pin_a() -> SpkiPin {
        PIN_A_HEX.parse().unwrap()
    }

    fn pin_b() -> SpkiPin {
        PIN_B_HEX.parse().unwrap()
    }

    #[test]
    fn the_spki_hash_of_a_certificate_matches_what_openssl_computes() {
        assert_eq!(spki_sha256_hex(CERT_A).unwrap(), PIN_A_HEX);
        assert_eq!(spki_sha256_hex(CERT_B).unwrap(), PIN_B_HEX);
        assert_eq!(SpkiPin::of_certificate(CERT_A).unwrap(), pin_a());
        assert_ne!(pin_a(), pin_b());
    }

    #[test]
    fn a_certificate_verifies_against_its_own_pin_and_not_against_the_other() {
        assert_eq!(pin_a().verify(CERT_A), Ok(()));
        assert_eq!(pin_b().verify(CERT_B), Ok(()));
        assert!(matches!(
            pin_a().verify(CERT_B),
            Err(PinError::Mismatch { .. })
        ));
        assert!(matches!(
            pin_b().verify(CERT_A),
            Err(PinError::Mismatch { .. })
        ));
    }

    #[test]
    fn a_mismatch_reports_both_hashes_so_an_operator_can_see_what_changed() {
        let error = pin_a().verify(CERT_B).unwrap_err();
        let text = error.to_string();
        assert!(text.contains(PIN_A_HEX), "{text}");
        assert!(text.contains(PIN_B_HEX), "{text}");
    }

    #[test]
    fn a_pin_parses_with_separators_and_either_case() {
        let upper = PIN_A_HEX.to_uppercase();
        assert_eq!(upper.parse::<SpkiPin>().unwrap(), pin_a());
        let colons = PIN_A_HEX
            .as_bytes()
            .chunks(2)
            .map(|pair| std::str::from_utf8(pair).unwrap().to_owned())
            .collect::<Vec<String>>()
            .join(":");
        assert_eq!(colons.parse::<SpkiPin>().unwrap(), pin_a());
        assert_eq!(colons.parse::<SpkiPin>().unwrap().to_hex(), PIN_A_HEX);
        assert_eq!(pin_a().to_string(), PIN_A_HEX);
    }

    #[test]
    fn a_pin_that_is_not_32_bytes_of_hex_is_rejected() {
        assert!(matches!(
            "deadbeef".parse::<SpkiPin>(),
            Err(PinError::InvalidPin(_))
        ));
        assert!(matches!(
            "zz".repeat(32).parse::<SpkiPin>(),
            Err(PinError::InvalidPin(_))
        ));
        assert!(matches!(
            "".parse::<SpkiPin>(),
            Err(PinError::InvalidPin(_))
        ));
    }

    #[test]
    fn a_certificate_that_is_not_der_is_rejected_rather_than_guessed_at() {
        assert!(matches!(
            spki_sha256(&[]),
            Err(PinError::MalformedCertificate(_))
        ));
        assert!(matches!(
            spki_sha256(&[0x30]),
            Err(PinError::MalformedCertificate(_))
        ));
        assert!(matches!(
            spki_sha256(&[0x30, 0x03, 0x02, 0x01, 0x00]),
            Err(PinError::MalformedCertificate(_))
        ));
    }

    #[test]
    fn a_certificate_with_the_wrong_first_element_is_rejected() {
        let mut wrong = CERT_A.to_vec();
        wrong[0] = 0x31;
        assert!(matches!(
            spki_sha256(&wrong),
            Err(PinError::MalformedCertificate(
                "the certificate is not a sequence"
            ))
        ));
    }

    #[test]
    fn a_truncated_certificate_is_rejected() {
        let truncated = &CERT_A[..CERT_A.len() - 8];
        assert!(matches!(
            spki_sha256(truncated),
            Err(PinError::MalformedCertificate(_))
        ));
    }

    #[test]
    fn the_verifier_accepts_the_pinned_certificate_and_rejects_the_other() {
        let verifier = PinnedSpkiVerifier::new(pin_a());
        let name = ServerName::try_from("wgmesh.test").unwrap();
        let leaf = CertificateDer::from(CERT_A.to_vec());
        assert!(
            verifier
                .verify_server_cert(
                    &leaf,
                    &[],
                    &name,
                    &[],
                    UnixTime::since_unix_epoch(std::time::Duration::from_secs(1))
                )
                .is_ok()
        );
        let other = CertificateDer::from(CERT_B.to_vec());
        let rejected = verifier.verify_server_cert(
            &other,
            &[],
            &name,
            &[],
            UnixTime::since_unix_epoch(std::time::Duration::from_secs(1)),
        );
        assert!(matches!(
            rejected,
            Err(TlsError::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure
            ))
        ));
    }

    #[test]
    fn a_certificate_that_is_not_der_at_all_is_refused_as_bad_encoding() {
        let verifier = PinnedSpkiVerifier::new(pin_a());
        let name = ServerName::try_from("wgmesh.test").unwrap();
        let leaf = CertificateDer::from(vec![0x41, 0x42, 0x43]);
        assert!(matches!(
            verifier.verify_server_cert(
                &leaf,
                &[],
                &name,
                &[],
                UnixTime::since_unix_epoch(std::time::Duration::from_secs(1))
            ),
            Err(TlsError::InvalidCertificate(CertificateError::BadEncoding))
        ));
    }

    #[test]
    fn the_verifier_offers_the_schemes_the_provider_signs_with() {
        let verifier = PinnedSpkiVerifier::new(pin_a());
        let schemes = verifier.supported_verify_schemes();
        assert!(schemes.contains(&SignatureScheme::ECDSA_NISTP256_SHA256));
        assert!(!schemes.is_empty());
    }

    #[test]
    fn both_test_keys_are_the_ones_the_fixtures_hold() {
        assert!(!KEY_A.is_empty());
        assert!(!KEY_B.is_empty());
        assert_ne!(KEY_A, KEY_B);
    }
}
