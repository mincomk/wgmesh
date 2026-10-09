use base64ct::{Base64, Encoding};
use wgmesh_core::PublicKey;

/// WireGuard keys travel as base64, the spelling `wg(8)` uses in a config file:
/// 32 bytes, 44 characters with padding.
pub fn encode_key(key: &PublicKey) -> String {
    Base64::encode_string(key.as_bytes())
}

pub fn decode_key(text: &str) -> Option<PublicKey> {
    let raw = Base64::decode_vec(text.trim()).ok()?;
    let bytes: [u8; 32] = raw.as_slice().try_into().ok()?;
    Some(PublicKey::from_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_round_trips() {
        let key = PublicKey::from_bytes([7u8; 32]);
        let text = encode_key(&key);
        assert_eq!(text.len(), 44);
        assert_eq!(decode_key(&text), Some(key));
    }

    #[test]
    fn a_key_of_the_wrong_length_is_refused() {
        assert!(decode_key("AAAA").is_none());
        assert!(decode_key("not base64 at all").is_none());
    }
}
