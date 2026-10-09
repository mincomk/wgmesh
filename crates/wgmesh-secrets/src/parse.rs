use base64ct::{Base64, Encoding};

use crate::SecretError;

/// The length of every key this product stores.
pub const KEY_LEN: usize = 32;

/// The length of a key written as one line of padded base64.
pub const BASE64_KEY_LEN: usize = 44;

/// How a key file happened to be written.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KeyFormat {
    /// Thirty two bytes of raw key material, as this product writes.
    Raw,
    /// One line of base64, as `wg genkey` and sops-nix write.
    Base64,
}

/// Read a key file that may hold raw bytes or base64.
///
/// Exactly thirty two bytes is taken as raw key material. Anything else is read as
/// text, and must then be one line of padded base64 that decodes to thirty two bytes.
/// Both spellings of the same key are accepted so that `wg genkey`, a text secret from
/// sops-nix and a file this product wrote all pass through one loader.
pub fn parse_key(bytes: &[u8]) -> Result<([u8; KEY_LEN], KeyFormat), SecretError> {
    if bytes.len() == KEY_LEN {
        let mut key = [0u8; KEY_LEN];
        key.copy_from_slice(bytes);
        return Ok((key, KeyFormat::Raw));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| SecretError::NotUtf8 { len: bytes.len() })?;
    let trimmed = text.trim_end_matches(['\n', '\r']);
    if trimmed.contains(['\n', '\r']) {
        return Err(SecretError::NotAKey {
            len: bytes.len(),
            reason: "the file holds more than one line",
        });
    }
    if trimmed.len() != BASE64_KEY_LEN {
        return Err(SecretError::NotAKey {
            len: bytes.len(),
            reason: "a key file is either 32 raw bytes or one 44 character base64 line",
        });
    }
    let decoded = Base64::decode_vec(trimmed).map_err(|error| SecretError::Base64 {
        message: error.to_string(),
    })?;
    if decoded.len() != KEY_LEN {
        return Err(SecretError::WrongLength {
            decoded: decoded.len(),
        });
    }
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&decoded);
    Ok((key, KeyFormat::Base64))
}

/// Write a key the way `wg genkey` does: one line of padded base64 plus a newline.
pub fn encode_key(key: &[u8; KEY_LEN]) -> String {
    let mut document = Base64::encode_string(key);
    document.push('\n');
    document
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; KEY_LEN] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn thirty_two_raw_bytes_are_a_key() {
        match parse_key(&KEY) {
            Ok((key, format)) => {
                assert_eq!(key, KEY);
                assert_eq!(format, KeyFormat::Raw);
            }
            Err(error) => panic!("a raw key was refused: {error}"),
        }
    }

    #[test]
    fn one_line_of_base64_is_a_key_with_or_without_a_trailing_newline() {
        let text = encode_key(&KEY);
        assert_eq!(
            text.len(),
            BASE64_KEY_LEN + 1,
            "the encoded line is not 44 characters"
        );
        for bytes in [text.as_bytes(), text.trim_end().as_bytes()] {
            match parse_key(bytes) {
                Ok((key, format)) => {
                    assert_eq!(key, KEY);
                    assert_eq!(format, KeyFormat::Base64);
                }
                Err(error) => panic!("a base64 key was refused: {error}"),
            }
        }
    }

    #[test]
    fn a_key_written_by_wg_genkey_reads_back_to_the_same_bytes() {
        // The form `wg genkey > wg.key` produces: one base64 line, trailing newline.
        let line = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\n";
        let (key, format) = match parse_key(line.as_bytes()) {
            Ok(key) => key,
            Err(error) => panic!("{error}"),
        };
        assert_eq!(format, KeyFormat::Base64);
        assert_eq!(encode_key(&key).trim_end(), line.trim_end());
    }

    #[test]
    fn anything_that_is_neither_raw_nor_one_base64_line_is_refused() {
        let cases: [(&str, Vec<u8>); 9] = [
            ("empty", Vec::new()),
            ("thirty one bytes", KEY[..31].to_vec()),
            ("thirty three bytes", [&KEY[..], &[0u8]].concat()),
            ("a short base64 line", b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==".to_vec()),
            ("a long base64 line", b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==".to_vec()),
            ("a base64 line of sixteen bytes", b"AAAAAAAAAAAAAAAAAAAAAA==\n".to_vec()),
            ("base64 spelling a whole different length", b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n".to_vec()),
            ("hex text", hex(&KEY).into_bytes()),
            ("two lines", b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n".to_vec()),
        ];
        for (name, bytes) in cases {
            assert!(parse_key(&bytes).is_err(), "{name} was accepted as a key");
        }
    }

    #[test]
    fn a_raw_key_is_never_confused_with_base64() {
        // A 32 byte file that is also valid text stays raw: the length decides.
        let text = b"0123456789abcdef0123456789abcdef";
        assert_eq!(text.len(), KEY_LEN);
        match parse_key(text) {
            Ok((key, format)) => {
                assert_eq!(format, KeyFormat::Raw);
                assert_eq!(&key, text);
            }
            Err(error) => panic!("{error}"),
        }
    }

    #[test]
    fn a_key_survives_the_round_trip_through_its_text_form() {
        let text = encode_key(&KEY);
        let (key, _) = match parse_key(text.as_bytes()) {
            Ok(key) => key,
            Err(error) => panic!("{error}"),
        };
        assert_eq!(key, KEY);
        assert_eq!(hex(&key), hex(&KEY));
    }
}
