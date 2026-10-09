use std::net::{IpAddr, Ipv6Addr};

use wgmesh_core::Allowed;

use crate::RouteError;

/// The `proto` value that marks every route this package installs.
///
/// iproute2 ships the reserved names in `etc/iproute2/rt_protos`; the highest number it
/// assigns today is 192 (`eigrp`), so 250 is unassigned and free to claim. The marker is
/// what makes `wgmesh routes reset` safe: routes are deleted by marker, never by table, so
/// a route the host put in the same table is untouchable.
pub const MARKER_PROTO: u8 = 250;

/// The address family flag `ip` takes for a prefix: `-4` or `-6`.
pub fn family_flag(prefix: &Allowed) -> &'static str {
    match prefix {
        Allowed::V4(..) => "-4",
        Allowed::V6(..) => "-6",
    }
}

/// A prefix in the form `ip` writes and reads.
pub fn format_prefix(prefix: &Allowed) -> String {
    match prefix {
        Allowed::V4(bytes, bits) => {
            format!(
                "{}.{}.{}.{}/{}",
                bytes[0], bytes[1], bytes[2], bytes[3], bits
            )
        }
        Allowed::V6(bytes, bits) => format!("{}/{}", Ipv6Addr::from(*bytes), bits),
    }
}

/// Read back what [`format_prefix`] wrote, in the shape `ip` prints: a CIDR prefix, or the
/// `default` spelling iproute2 uses for a zero-length prefix.
pub fn parse_prefix(text: &str) -> Result<Allowed, RouteError> {
    let text = text.trim();
    if text == "default" {
        return Ok(Allowed::V4([0, 0, 0, 0], 0));
    }
    let (address, bits) = match text.split_once('/') {
        Some((address, bits)) => (address.trim(), Some(bits.trim())),
        None => (text, None),
    };
    let parsed: IpAddr = address.parse().map_err(|_| {
        RouteError::fatal(format!(
            "`{text}` is not an address the kernel could have written"
        ))
    })?;
    let widest = match parsed {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    let bits = match bits {
        None => widest,
        Some(bits) => {
            let bits: u8 = bits.parse().map_err(|_| {
                RouteError::fatal(format!(
                    "`{text}` carries a prefix length that is not a number"
                ))
            })?;
            if bits > widest {
                return Err(RouteError::fatal(format!(
                    "`{text}` carries a prefix length wider than /{widest}"
                )));
            }
            bits
        }
    };
    Ok(match parsed {
        IpAddr::V4(v4) => Allowed::V4(v4.octets(), bits),
        IpAddr::V6(v6) => Allowed::V6(v6.octets(), bits),
    })
}

/// Whether the prefix is the default route, which this product never puts in the kernel
/// routing table.
pub fn is_catch_all(prefix: &Allowed) -> bool {
    match prefix {
        Allowed::V4(bytes, bits) => *bits == 0 && bytes.iter().all(|byte| *byte == 0),
        Allowed::V6(bytes, bits) => *bits == 0 && bytes.iter().all(|byte| *byte == 0),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn a_prefix_round_trips_through_its_text_form() {
        for text in [
            "10.77.0.0/16",
            "192.168.5.0/24",
            "0.0.0.0/0",
            "fd00::/64",
            "::/0",
        ] {
            let parsed = parse_prefix(text).expect("parses");
            assert_eq!(format_prefix(&parsed), text);
        }
        assert_eq!(
            format_prefix(&parse_prefix("10.77.0.7").unwrap()),
            "10.77.0.7/32"
        );
    }

    #[test]
    fn the_default_spelling_the_kernel_prints_is_read() {
        assert_eq!(
            parse_prefix("default").unwrap(),
            Allowed::V4([0, 0, 0, 0], 0)
        );
        assert!(is_catch_all(&parse_prefix("default").unwrap()));
        assert!(is_catch_all(&parse_prefix("::/0").unwrap()));
        assert!(!is_catch_all(&parse_prefix("0.0.0.0/1").unwrap()));
    }

    #[test]
    fn a_prefix_that_is_not_a_prefix_is_refused() {
        for text in ["10.77.0.0/33", "fd00::/129", "hello", "10.77.0.0/x"] {
            assert!(parse_prefix(text).is_err(), "{text} was accepted");
        }
    }

    #[test]
    fn the_marker_sits_above_every_name_iproute2_reserves() {
        // 192 is `eigrp`, the highest name iproute2's `rt_protos` assigns.
        const HIGHEST_RESERVED: u8 = 192;
        const _: () = assert!(MARKER_PROTO > HIGHEST_RESERVED);
    }
}
