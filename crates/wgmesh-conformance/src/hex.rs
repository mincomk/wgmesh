// Hex and socket-address conversions for the wire forms.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

pub fn decode32(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (index, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(text.get(index * 2..index * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// Parse `ip:port`, accepting both `127.0.0.1:9000` and `[::1]:9000`.
pub fn parse_socket_addr(text: &str) -> Option<SocketAddr> {
    if let Ok(addr) = text.parse::<SocketAddr>() {
        return Some(addr);
    }
    let (host, port) = text.rsplit_once(':')?;
    let port: u16 = port.parse().ok()?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let ip: IpAddr = if let Ok(v4) = host.parse::<Ipv4Addr>() {
        IpAddr::V4(v4)
    } else {
        IpAddr::V6(host.parse::<Ipv6Addr>().ok()?)
    };
    Some(SocketAddr::new(ip, port))
}
