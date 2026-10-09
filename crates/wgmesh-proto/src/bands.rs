/// A device's advertised bands, as they are stored and as they appear on the
/// wire: a JSON array of CIDR strings. The column is text, so the spelling has
/// to have one home.
pub fn encode(bands: &[String]) -> String {
    serde_json::to_string(bands).unwrap_or_else(|_| "[]".to_string())
}

pub fn decode(text: &str) -> Vec<String> {
    serde_json::from_str(text).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bands_round_trip() {
        let bands = vec!["10.77.0.7/32".to_string(), "192.168.5.0/24".to_string()];
        assert_eq!(decode(&encode(&bands)), bands);
    }

    #[test]
    fn damaged_text_reads_as_no_bands() {
        assert!(decode("not json").is_empty());
    }
}
