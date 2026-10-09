use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use wgmesh_core::Allowed;

/// One thing wrong with a settings file. Validation collects every problem
/// rather than failing on the first, so `wgmesh config check` can print them
/// all in one pass.
#[derive(Clone, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
pub struct Problem {
    pub field: String,
    pub message: String,
}

impl Problem {
    pub fn new(field: &str, message: impl Into<String>) -> Self {
        Self {
            field: field.to_owned(),
            message: message.into(),
        }
    }
}

/// Parse `10.77.0.0/16` or `fd00::/64` into the core prefix type.
pub fn parse_allowed(text: &str) -> Option<Allowed> {
    let (address, bits) = text.split_once('/')?;
    let bits: u8 = bits.parse().ok()?;
    match address.parse::<IpAddr>().ok()? {
        IpAddr::V4(address) => {
            if bits > 32 {
                return None;
            }
            Some(Allowed::V4(address.octets(), bits))
        }
        IpAddr::V6(address) => {
            if bits > 128 {
                return None;
            }
            Some(Allowed::V6(address.octets(), bits))
        }
    }
}

/// A tunnel address with its prefix, e.g. `10.77.0.7/16`.
pub fn parse_host_prefix(text: &str) -> Option<Allowed> {
    parse_allowed(text)
}

pub fn format_ip(address: &IpAddr) -> String {
    address.to_string()
}

/// Whether a string is exactly 64 hexadecimal characters — the shape of a
/// SHA-256 SPKI pin.
pub fn is_sha256_hex(text: &str) -> bool {
    text.len() == 64 && text.chars().all(|ch| ch.is_ascii_hexdigit())
}

/// The coordinator URL must be https and must not carry userinfo: credentials
/// in a URL end up in logs and in `ps` output.
pub fn check_coordinator_url(url: &str, field: &str, problems: &mut Vec<Problem>) {
    if url.is_empty() {
        problems.push(Problem::new(field, "is required"));
        return;
    }
    let Some(rest) = url.strip_prefix("https://") else {
        problems.push(Problem::new(
            field,
            "must start with https:// — plaintext is never accepted",
        ));
        return;
    };
    if rest.is_empty() || rest.starts_with('/') {
        problems.push(Problem::new(field, "has no host"));
    }
    if rest.contains('@') {
        problems.push(Problem::new(
            field,
            "must not carry userinfo (user:password@host)",
        ));
    }
}

pub fn check_spki(pin: &str, field: &str, problems: &mut Vec<Problem>) {
    if pin.is_empty() {
        problems.push(Problem::new(
            field,
            "is required — without the coordinator's TLS pin any MITM can inject peers",
        ));
    } else if !is_sha256_hex(pin) {
        problems.push(Problem::new(field, "must be 64 hex characters (SHA-256)"));
    }
}

pub fn check_absolute_dir(dir: &str, field: &str, problems: &mut Vec<Problem>) {
    if !dir.starts_with('/') {
        problems.push(Problem::new(field, "must be an absolute path"));
    }
}

/// The first address in a network block, which is where a device's tunnel
/// address is drawn from.
pub fn block_start(prefix: &Allowed) -> Option<IpAddr> {
    match prefix {
        Allowed::V4(octets, _) => Some(IpAddr::V4(Ipv4Addr::from(*octets))),
        Allowed::V6(octets, _) => Some(IpAddr::V6(Ipv6Addr::from(*octets))),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn cidrs_parse_in_both_families() {
        assert_eq!(
            parse_allowed("10.77.0.0/16"),
            Some(Allowed::V4([10, 77, 0, 0], 16))
        );
        assert_eq!(
            parse_allowed("0.0.0.0/0"),
            Some(Allowed::V4([0, 0, 0, 0], 0))
        );
        assert_eq!(
            parse_allowed("2001:db8::/32"),
            Some(Allowed::V6(
                [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                32
            ))
        );
    }

    #[test]
    fn a_cidr_that_is_not_one_is_refused() {
        assert_eq!(parse_allowed("10.77.0.0"), None);
        assert_eq!(parse_allowed("10.77.0.0/33"), None);
        assert_eq!(parse_allowed("fd00::/129"), None);
        assert_eq!(parse_allowed("not-an-address/8"), None);
    }

    #[test]
    fn a_pin_must_be_sixty_four_hex_characters() {
        assert!(is_sha256_hex(&"9f2c".repeat(16)));
        assert!(!is_sha256_hex("9f2c"));
        assert!(!is_sha256_hex(&"zzzz".repeat(16)));
    }

    #[test]
    fn an_http_url_is_refused_and_so_is_userinfo() {
        let mut problems = Vec::new();
        check_coordinator_url("http://coord.example.com", "coordinator.url", &mut problems);
        assert_eq!(problems.len(), 1);
        assert!(problems[0].message.contains("https"));

        let mut problems = Vec::new();
        check_coordinator_url(
            "https://user:pw@coord.example.com",
            "coordinator.url",
            &mut problems,
        );
        assert!(problems[0].message.contains("userinfo"));
    }

    #[test]
    fn a_missing_pin_is_a_problem_not_a_default() {
        let mut problems = Vec::new();
        check_spki("", "coordinator.spki_sha256", &mut problems);
        assert_eq!(problems.len(), 1);
        assert!(problems[0].message.contains("required"));
    }
}
