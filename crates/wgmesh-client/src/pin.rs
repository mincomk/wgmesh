// The trust decision, in one place: which public key the coordinator is allowed to present.
//
// A pin is neither a certificate nor a name. It is the SHA-256 of the leaf certificate's
// SubjectPublicKeyInfo — the same 32 bytes `wgmesh trust show` prints and the state file holds —
// so a certificate can be renewed without telling every node, as long as the key behind it stays
// the same. The verifier below is what makes that decision on a live connection, and it is the
// only place in the workspace where a pin is compared against something a network handed us.

use std::fmt;
use std::sync::{Arc, Mutex};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{
    CryptoProvider, WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature,
};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error, SignatureScheme};
use sha2::{Digest, Sha256};
use wgmesh_ports::{PortError, Spki};

const SEQUENCE: u8 = 0x30;
const CONTEXT_0: u8 = 0xa0;

/// The SHA-256 of a certificate's SubjectPublicKeyInfo.
///
/// This is the value `openssl x509 -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum`
/// prints, and the value a node writes into its configuration as `coordinator.spki_sha256`.
///
/// The certificate is walked rather than decoded: the only thing needed is the seventh element of
/// the `tbsCertificate` (the version, when present, leads it), and a decoder for X.509 would be a
/// dependency and an authority this function does not want. `None` means the bytes are not a
/// certificate — never a pin of zeroes, which could be compared against by accident.
pub fn spki_sha256(certificate: &[u8]) -> Option<[u8; 32]> {
    let outer = element(certificate)?;
    if outer.tag != SEQUENCE || !outer.rest.is_empty() {
        return None;
    }
    let tbs = element(outer.content)?;
    if tbs.tag != SEQUENCE {
        return None;
    }

    // tbsCertificate ::= SEQUENCE { [0] version OPTIONAL, serialNumber, signature, issuer,
    //                               validity, subject, subjectPublicKeyInfo, ... }
    let mut cursor = tbs.content;
    if cursor.first() == Some(&CONTEXT_0) {
        cursor = element(cursor)?.rest;
    }
    for _ in 0..5 {
        cursor = element(cursor)?.rest;
    }
    let spki = element(cursor)?;
    if spki.tag != SEQUENCE {
        return None;
    }

    let digest: [u8; 32] = Sha256::digest(spki.tlv).into();
    Some(digest)
}

/// One DER element: its tag, its contents, the whole element as it appeared, and what followed it.
struct Element<'a> {
    tag: u8,
    content: &'a [u8],
    tlv: &'a [u8],
    rest: &'a [u8],
}

/// Read one DER element off the front of `input`.
///
/// Only definite lengths are accepted — the indefinite form is BER, and a certificate is DER — and
/// every read is bounds-checked, so a truncated certificate is a `None` rather than a panic.
fn element(input: &[u8]) -> Option<Element<'_>> {
    let tag = *input.first()?;
    let first = *input.get(1)?;
    let (header, length) = if first & 0x80 == 0 {
        (2usize, usize::from(first))
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 {
            return None;
        }
        let mut length = 0usize;
        for index in 0..count {
            length = (length << 8) | usize::from(*input.get(2 + index)?);
        }
        (2 + count, length)
    };
    let total = header.checked_add(length)?;
    let tlv = input.get(..total)?;
    Some(Element {
        tag,
        content: tlv.get(header..)?,
        tlv,
        rest: input.get(total..)?,
    })
}

/// The key a certificate presented when the pin refused it.
///
/// It is taken rather than read, because a refusal belongs to the connection it happened on: the
/// caller that saw the handshake fail reports it, and the next handshake records its own.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Refusal {
    /// The key the coordinator actually presented.
    pub presented: [u8; 32],
    /// The key this device pins.
    pub pinned: [u8; 32],
}

impl fmt::Display for Refusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "the coordinator presented a certificate whose SPKI is {}, and this device pins {}; \
             a pin changes only through `wgmesh trust rotate`",
            Spki::from_bytes(self.presented),
            Spki::from_bytes(self.pinned)
        )
    }
}

/// A TLS verifier that accepts exactly one public key, and no name, issuer or expiry with it.
///
/// The signature the server proves its key with is still checked — that is what `verify_tls12_
/// signature` and `verify_tls13_signature` are for below — so a certificate is only as good as the
/// private key behind it. What is deliberately not checked is everything else a PKI would: this
/// device was told which key to expect when it enrolled, and that is the whole of its trust.
pub struct PinnedVerifier {
    /// The key this verifier accepts, or `None` when it is learning what is presented.
    expect: Option<[u8; 32]>,
    provider: Arc<CryptoProvider>,
    refusal: Mutex<Option<Refusal>>,
    presented: Mutex<Option<[u8; 32]>>,
}

impl fmt::Debug for PinnedVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.expect {
            Some(pin) => write!(formatter, "PinnedVerifier({})", Spki::from_bytes(pin)),
            None => formatter.write_str("PinnedVerifier(learning)"),
        }
    }
}

impl PinnedVerifier {
    /// A verifier for one pin.
    pub fn new(pin: Spki) -> Self {
        Self::with(Some(*pin.as_bytes()))
    }

    /// A verifier that accepts whatever the coordinator presents, and remembers it.
    ///
    /// This is `wgmesh pin`: a person who has not written a pin into a configuration yet has to
    /// learn the one the coordinator really presents, and there is nothing to compare it against
    /// until they do. It is deliberately not reachable from `Coordinator` — a device that was
    /// already told which key to expect never takes the answer from the network.
    pub fn learn() -> Self {
        Self::with(None)
    }

    fn with(expect: Option<[u8; 32]>) -> Self {
        Self {
            expect,
            provider: Arc::new(rustls::crypto::ring::default_provider()),
            refusal: Mutex::new(None),
            presented: Mutex::new(None),
        }
    }

    /// The crypto this verifier checks signatures with.
    pub fn provider(&self) -> Arc<CryptoProvider> {
        self.provider.clone()
    }

    /// Take the refusal this verifier last recorded, if any.
    pub fn take_refusal(&self) -> Option<Refusal> {
        self.refusal
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
    }

    /// The key the coordinator last presented, whether or not it was accepted.
    pub fn presented(&self) -> Option<[u8; 32]> {
        *self
            .presented
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let Some(presented) = spki_sha256(end_entity.as_ref()) else {
            return Err(Error::General(
                "the coordinator presented bytes that are not a DER certificate".to_string(),
            ));
        };
        *self
            .presented
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(presented);

        let expected = match self.expect {
            // Learning: whatever is presented is the answer, and the caller reads it back.
            None => return Ok(ServerCertVerified::assertion()),
            Some(expected) => expected,
        };
        if presented != expected {
            let refusal = Refusal {
                presented,
                pinned: expected,
            };
            *self
                .refusal
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(refusal);
            return Err(Error::General(refusal.to_string()));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(message, certificate, signature, self.algorithms())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(message, certificate, signature, self.algorithms())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms().supported_schemes()
    }
}

impl PinnedVerifier {
    fn algorithms(&self) -> &WebPkiSupportedAlgorithms {
        &self.provider.signature_verification_algorithms
    }
}

/// The rustls configuration a pinned client runs on.
///
/// There is no root store and no client certificate: the pin is the whole of the trust, and the
/// identity is proven by the `Authorization` header rather than by mutual TLS.
pub fn client_config(verifier: &Arc<PinnedVerifier>) -> Result<rustls::ClientConfig, PortError> {
    rustls::ClientConfig::builder_with_provider(verifier.provider())
        .with_safe_default_protocol_versions()
        .map_err(|error| {
            PortError::fatal(format!(
                "rustls refused the default protocol versions: {error}"
            ))
        })
        .map(|builder| {
            builder
                .dangerous()
                .with_custom_certificate_verifier(verifier.clone())
                .with_no_client_auth()
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A DER SEQUENCE of the given parts, with a one-byte length.
    fn sequence(parts: &[&[u8]]) -> Vec<u8> {
        let mut body = Vec::new();
        for part in parts {
            body.extend_from_slice(part);
        }
        let mut out = vec![SEQUENCE, body.len() as u8];
        out.extend_from_slice(&body);
        out
    }

    /// A certificate: SEQUENCE { tbsCertificate, signatureAlgorithm, signature }.
    ///
    /// The tbs holds the same shape a real one does — serialNumber, signature, issuer, validity,
    /// subject, subjectPublicKeyInfo — because the walk counts those six positions.
    fn certificate(spki: &[u8], version: bool) -> Vec<u8> {
        let integer = [0x02, 0x01, 0x07];
        let empty = [SEQUENCE, 0x00];
        let header = [CONTEXT_0, 0x03, 0x02, 0x01, 0x02];
        let tbs = if version {
            sequence(&[&header, &integer, &empty, &empty, &empty, &empty, spki])
        } else {
            sequence(&[&integer, &empty, &empty, &empty, &empty, spki])
        };
        sequence(&[&tbs, &empty, &empty])
    }

    fn spki_of(body: &[u8]) -> Vec<u8> {
        sequence(&[body])
    }

    #[test]
    fn a_pin_is_the_digest_of_the_subject_public_key_info() {
        let info = spki_of(&[0x03, 0x02, 0x00, 0xab]);
        let der = certificate(&info, false);
        let expected: [u8; 32] = Sha256::digest(&info).into();
        assert_eq!(spki_sha256(&der), Some(expected));
    }

    #[test]
    fn an_optional_version_does_not_move_the_pin() {
        let info = spki_of(&[0x03, 0x02, 0x00, 0xab]);
        assert_eq!(
            spki_sha256(&certificate(&info, true)),
            spki_sha256(&certificate(&info, false))
        );
    }

    #[test]
    fn truncated_or_alien_bytes_are_not_a_pin() {
        assert!(spki_sha256(b"").is_none());
        assert!(spki_sha256(&[SEQUENCE]).is_none());
        assert!(spki_sha256(&[SEQUENCE, 0x7f]).is_none());
        assert!(
            spki_sha256(&[0x31, 0x00]).is_none(),
            "a SET is not a certificate"
        );
        assert!(
            spki_sha256(&[SEQUENCE, 0x02, 0x30, 0x00]).is_none(),
            "too few elements"
        );
    }
}
