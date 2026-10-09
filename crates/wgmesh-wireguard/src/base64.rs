// Standard base64 with padding, as wg(8) writes keys.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encode `bytes` as standard base64 with padding.
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);

        out.push(char::from(ALPHABET[usize::from(first >> 2)]));
        out.push(char::from(
            ALPHABET[usize::from(((first & 0x03) << 4) | (second >> 4))],
        ));
        if chunk.len() > 1 {
            out.push(char::from(
                ALPHABET[usize::from(((second & 0x0f) << 2) | (third >> 6))],
            ));
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(char::from(ALPHABET[usize::from(third & 0x3f)]));
        } else {
            out.push('=');
        }
    }
    out
}

/// Decode standard base64 with padding, `None` when `text` is not one.
#[allow(
    clippy::manual_is_multiple_of,
    reason = "the workspace MSRV is 1.85 and `is_multiple_of` is stable since 1.87"
)]
pub fn decode(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if bytes.len() % 4 != 0 {
        return None;
    }

    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let groups = bytes.len() / 4;
    for (group, chunk) in bytes.chunks(4).enumerate() {
        let mut values = [0u8; 4];
        let mut padding = 0usize;
        for (index, byte) in chunk.iter().enumerate() {
            if *byte == b'=' {
                // Padding only ever closes the last group, and only its last
                // one or two characters.
                if index < 2 || group + 1 != groups {
                    return None;
                }
                padding += 1;
            } else {
                if padding > 0 {
                    return None;
                }
                values[index] = index_of(*byte)?;
            }
        }

        out.push((values[0] << 2) | (values[1] >> 4));
        if padding < 2 {
            out.push((values[1] << 4) | (values[2] >> 2));
        }
        if padding < 1 {
            out.push((values[2] << 6) | values[3]);
        }
    }
    Some(out)
}

pub(crate) fn index_of(byte: u8) -> Option<u8> {
    ALPHABET
        .iter()
        .position(|candidate| *candidate == byte)
        .map(|index| index as u8)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn a_wireguard_key_round_trips() {
        let key: [u8; 32] = [
            0x7b, 0x2c, 0x41, 0x00, 0xff, 0x10, 0x9e, 0x39, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
            0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x66, 0x77, 0x88, 0x99,
        ];
        let encoded = encode(&key);
        assert_eq!(encoded.len(), 44);
        assert!(encoded.ends_with('='));
        assert_eq!(decode(&encoded).as_deref(), Some(key.as_slice()));
    }

    #[test]
    fn every_length_round_trips() {
        let bytes: Vec<u8> = (0..=255u8).collect();
        for length in 0..=bytes.len() {
            let encoded = encode(&bytes[..length]);
            assert_eq!(
                decode(&encoded).as_deref(),
                Some(&bytes[..length]),
                "length {length}"
            );
        }
    }

    #[test]
    fn padding_is_where_the_reference_puts_it() {
        assert_eq!(encode(b"f"), "Zg==");
        assert_eq!(encode(b"fo"), "Zm8=");
        assert_eq!(encode(b"foo"), "Zm9v");
    }

    #[test]
    fn malformed_input_is_rejected() {
        for text in [
            "Zg=", "Zg===", "Zm9vY", "====", "Z===", "Zg==Zg==", "Zm9!", "Zg==Z",
        ] {
            assert!(decode(text).is_none(), "{text} decoded");
        }
    }
}
