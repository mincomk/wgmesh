use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};

/// Split `10.77.0.0/16` into its address and prefix length.
pub fn parse_cidr(text: &str) -> Option<(IpAddr, u8)> {
    let (address, length) = text.trim().split_once('/')?;
    let address: IpAddr = address.trim().parse().ok()?;
    let length: u8 = length.trim().parse().ok()?;
    match address {
        IpAddr::V4(_) if length <= 32 => Some((address, length)),
        IpAddr::V6(_) if length <= 128 => Some((address, length)),
        _ => None,
    }
}

/// The host prefix a device owns. `10.77.0.7/16` becomes `10.77.0.7/32`, which
/// is what a peer's AllowedIPs list holds for it under the `peer` policy.
pub fn host_prefix(tunnel_ip: &str) -> String {
    let bare = tunnel_ip.split('/').next().unwrap_or(tunnel_ip).trim();
    let bits = if bare.contains(':') { 128 } else { 32 };
    format!("{bare}/{bits}")
}

/// The lowest address of `cidr` that no device holds yet.
///
/// `reserved_below` keeps the first few addresses out of the pool (the network
/// address itself and the gateway). IPv4 only: the design is IPv4-first, and a
/// /64 would not fit in this enumeration anyway.
pub fn next_free_host(cidr: &str, used: &[String], reserved_below: u32) -> Option<String> {
    let (address, length) = parse_cidr(cidr)?;
    let IpAddr::V4(network) = address else {
        return None;
    };

    let base = u32::from(network) & mask(length);
    let size = 1u32.checked_shl(32 - u32::from(length)).unwrap_or(u32::MAX);
    let taken: BTreeSet<u32> = used
        .iter()
        .filter_map(|text| text.split('/').next()?.trim().parse::<Ipv4Addr>().ok())
        .map(u32::from)
        .collect();

    let start = reserved_below.max(2);
    let stop = size.min(start.saturating_add(4096));
    for offset in start..stop {
        let candidate = base.checked_add(offset)?;
        if candidate >= base.saturating_add(size) {
            break;
        }
        if !taken.contains(&candidate) {
            return Some(Ipv4Addr::from(candidate).to_string());
        }
    }
    None
}

/// `51820-51999` into its bounds.
pub fn parse_port_range(text: &str) -> Option<(u16, u16)> {
    let (low, high) = text.trim().split_once('-')?;
    let low: u16 = low.trim().parse().ok()?;
    let high: u16 = high.trim().parse().ok()?;
    (low <= high).then_some((low, high))
}

/// The lowest port of `range` that no device holds on this relay.
pub fn next_free_port(range: &str, used: &[u16]) -> Option<u16> {
    let (low, high) = parse_port_range(range)?;
    (low..=high).find(|port| !used.contains(port))
}

fn mask(length: u8) -> u32 {
    if length == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(length))
    }
}
