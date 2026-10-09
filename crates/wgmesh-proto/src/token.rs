use sha2::{Digest, Sha256};

/// Crockford's Base32: no `I`, `L`, `O` or `U`, so a token read off a screen or
/// typed by hand cannot be confused with another.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

pub const PREFIX: &str = "WGMESH";
/// 160 bits, the length the design fixes for a join token.
pub const SECRET_LEN: usize = 20;
const SYMBOLS: usize = 32;

/// `WGMESH-7K3M-9QXA-...`
pub fn format_token(secret: &[u8; SECRET_LEN]) -> String {
    let encoded = encode(secret);
    let mut text = String::with_capacity(PREFIX.len() + 1 + SYMBOLS + SYMBOLS / 4);
    text.push_str(PREFIX);
    for chunk in encoded.as_bytes().chunks(4) {
        text.push('-');
        text.push_str(std::str::from_utf8(chunk).unwrap_or_default());
    }
    text
}

/// Decode a token back to the 160 bits it was made from. Case and the
/// separators do not matter; anything that is not a full token is `None`.
pub fn parse_token(text: &str) -> Option<[u8; SECRET_LEN]> {
    let trimmed = text.trim();
    let body = trimmed
        .strip_prefix(PREFIX)
        .or_else(|| trimmed.strip_prefix(&PREFIX.to_ascii_lowercase()))
        .unwrap_or(trimmed);
    if symbol_count(body) != SYMBOLS {
        return None;
    }
    let bytes = decode(body)?;
    let secret: [u8; SECRET_LEN] = bytes.as_slice().try_into().ok()?;
    Some(secret)
}

/// What the server keeps: never the token, only its hash.
pub fn hash_secret(secret: &[u8; SECRET_LEN]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(secret);
    hasher.finalize().into()
}

/// The hash of a token a client sent, or `None` if it did not even decode —
/// which the caller must refuse exactly like a spent token.
pub fn hash_token_text(text: &str) -> Option<[u8; 32]> {
    parse_token(text).map(|secret| hash_secret(&secret))
}

fn symbol_count(text: &str) -> usize {
    text.chars()
        .filter(|letter| *letter != '-' && !letter.is_whitespace())
        .count()
}

/// Base32, five bits at a time, most significant first. Used for tokens and for
/// the short identifiers in [`crate::id`].
pub(crate) fn encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len() * 8 / 5 + 1);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for byte in input {
        buffer = (buffer << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let index = ((buffer >> bits) & 0x1f) as usize;
            out.push(ALPHABET[index] as char);
        }
        buffer &= (1u32 << bits) - 1;
    }
    if bits > 0 {
        let index = ((buffer << (5 - bits)) & 0x1f) as usize;
        out.push(ALPHABET[index] as char);
    }
    out
}

pub(crate) fn decode(input: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() * 5 / 8);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for letter in input.chars() {
        if letter == '-' || letter.is_whitespace() {
            continue;
        }
        let value = symbol(letter)?;
        buffer = (buffer << 5) | u32::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
            buffer &= (1u32 << bits) - 1;
        }
    }
    if bits > 0 && buffer != 0 {
        return None;
    }
    Some(out)
}

fn symbol(letter: char) -> Option<u8> {
    let upper = letter.to_ascii_uppercase();
    let folded = match upper {
        'O' => '0',
        'I' | 'L' => '1',
        other => other,
    };
    ALPHABET
        .iter()
        .position(|candidate| *candidate as char == folded)
        .map(|index| index as u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_token_round_trips_through_its_text_form() {
        let secret: [u8; SECRET_LEN] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
        ];
        let text = format_token(&secret);
        assert!(text.starts_with("WGMESH-"));
        assert_eq!(parse_token(&text), Some(secret));
    }

    #[test]
    fn a_token_is_thirty_two_symbols_after_the_prefix() {
        let text = format_token(&[7u8; SECRET_LEN]);
        let body: String = text
            .trim_start_matches("WGMESH-")
            .chars()
            .filter(|character| *character != '-')
            .collect();
        assert_eq!(body.len(), SYMBOLS);
    }

    #[test]
    fn decoding_tolerates_case_and_confusable_letters() {
        let secret = [0x5au8; SECRET_LEN];
        let text = format_token(&secret);
        assert_eq!(parse_token(&text.to_ascii_lowercase()), Some(secret));

        let mut mangled = text.clone();
        if let Some(position) = mangled.find('0') {
            mangled.replace_range(position..position + 1, "O");
        }
        assert_eq!(parse_token(&mangled), Some(secret));
    }

    #[test]
    fn a_truncated_or_corrupt_token_is_refused() {
        let text = format_token(&[3u8; SECRET_LEN]);
        assert!(parse_token(&text[..text.len() - 1]).is_none());
        assert!(parse_token("WGMESH-!!!!-!!!!-!!!!-!!!!-!!!!-!!!!-!!!!-!!!!").is_none());
        assert!(parse_token("").is_none());
        assert!(parse_token("not-a-token").is_none());
    }

    #[test]
    fn the_hash_depends_on_the_secret_not_the_spelling() {
        let secret = [0x33u8; SECRET_LEN];
        let text = format_token(&secret);
        assert_eq!(hash_token_text(&text), Some(hash_secret(&secret)));
        assert_eq!(
            hash_token_text(&text),
            hash_token_text(&text.to_ascii_lowercase())
        );
    }
}
