use wgmesh_core::{DeviceId, RelayId};

use crate::token;

/// The identity a device or relay shows in its `Authorization` header and in
/// every identifier the API hands back. Internal ids are integers; these are
/// their stable text form.
pub fn device_id(id: DeviceId) -> String {
    format!("d_{}", base32_uint(id.0))
}

pub fn relay_id(id: RelayId) -> String {
    format!("relay_{}", base32_uint(u32::from(id.0)))
}

pub fn parse_device_id(text: &str) -> Option<DeviceId> {
    let body = text.strip_prefix("d_")?;
    Some(DeviceId(uint_from_base32(body)?))
}

pub fn parse_relay_id(text: &str) -> Option<RelayId> {
    let body = text.strip_prefix("relay_")?;
    let value = uint_from_base32(body)?;
    u16::try_from(value).ok().map(RelayId)
}

/// Base32 without leading zeros: id 1 is `1`, id 32 is `10`.
fn base32_uint(value: u32) -> String {
    let bytes = value.to_be_bytes();
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len() - 1);
    token::encode(&bytes[first..])
}

fn uint_from_base32(text: &str) -> Option<u32> {
    if text.is_empty() || text.len() > 7 {
        return None;
    }
    let bytes = token::decode(text)?;
    if bytes.len() > 4 {
        return None;
    }
    let mut value = 0u32;
    for byte in bytes {
        value = (value << 8) | u32::from(byte);
    }
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_device_id_round_trips() {
        for raw in [1u32, 2, 31, 32, 4095, 1_000_000, u32::MAX] {
            let text = device_id(DeviceId(raw));
            assert!(text.starts_with("d_"), "{text}");
            assert_eq!(parse_device_id(&text), Some(DeviceId(raw)), "{text}");
        }
    }

    #[test]
    fn a_relay_id_round_trips_within_its_range() {
        for raw in [1u16, 255, 4096, u16::MAX] {
            let text = relay_id(RelayId(raw));
            assert!(text.starts_with("relay_"), "{text}");
            assert_eq!(parse_relay_id(&text), Some(RelayId(raw)), "{text}");
        }
    }

    #[test]
    fn the_two_namespaces_do_not_collide() {
        assert!(parse_device_id("relay_1").is_none());
        assert!(parse_relay_id("d_1").is_none());
        assert!(parse_device_id("d_").is_none());
    }
}
