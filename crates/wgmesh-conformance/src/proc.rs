// Linux `/proc` socket accounting.
//
// Used to answer a structural question rather than a behavioural one: *which*
// sockets a process actually holds. `/proc/<pid>/fd` gives the socket inodes a
// process owns; `/proc/net/udp` (and `udp6`) gives the inodes that are UDP
// sockets in this network namespace. The intersection is the set of UDP
// sockets the process holds — which for the coordinator must be empty.
//
// `SO_` free, no dependencies, and it sees sockets the process never asked
// anyone about.

use std::collections::BTreeSet;
use std::fs;

/// The socket inodes owned by `pid`.
pub fn process_socket_inodes(pid: u32) -> BTreeSet<u64> {
    let mut inodes = BTreeSet::new();
    let Ok(entries) = fs::read_dir(format!("/proc/{pid}/fd")) else {
        return inodes;
    };
    for entry in entries.flatten() {
        let Ok(target) = fs::read_link(entry.path()) else {
            continue;
        };
        let Some(text) = target.to_str() else {
            continue;
        };
        let Some(rest) = text.strip_prefix("socket:[") else {
            continue;
        };
        let Some(number) = rest.strip_suffix(']') else {
            continue;
        };
        if let Ok(inode) = number.parse::<u64>() {
            inodes.insert(inode);
        }
    }
    inodes
}

fn inodes_from(path: &str) -> BTreeSet<u64> {
    let mut inodes = BTreeSet::new();
    let Ok(text) = fs::read_to_string(path) else {
        return inodes;
    };
    for line in text.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if let Some(value) = fields.get(9) {
            if let Ok(inode) = value.parse::<u64>() {
                inodes.insert(inode);
            }
        }
    }
    inodes
}

/// Every UDP socket inode in this network namespace.
pub fn udp_inodes() -> BTreeSet<u64> {
    let mut all = inodes_from("/proc/net/udp");
    all.extend(inodes_from("/proc/net/udp6"));
    all
}

/// Every TCP socket inode in this network namespace.
pub fn tcp_inodes() -> BTreeSet<u64> {
    let mut all = inodes_from("/proc/net/tcp");
    all.extend(inodes_from("/proc/net/tcp6"));
    all
}

/// The UDP sockets `pid` holds.
pub fn process_udp_inodes(pid: u32) -> BTreeSet<u64> {
    let udp = udp_inodes();
    process_socket_inodes(pid)
        .into_iter()
        .filter(|inode| udp.contains(inode))
        .collect()
}

/// The TCP sockets `pid` holds.
pub fn process_tcp_inodes(pid: u32) -> BTreeSet<u64> {
    let tcp = tcp_inodes();
    process_socket_inodes(pid)
        .into_iter()
        .filter(|inode| tcp.contains(inode))
        .collect()
}

/// The `/proc/net/udp` rows for `pid`'s UDP sockets, for the report.
pub fn describe_udp(pid: u32) -> Vec<String> {
    let wanted = process_socket_inodes(pid);
    let mut rows = Vec::new();
    for path in ["/proc/net/udp", "/proc/net/udp6"] {
        let Ok(text) = fs::read_to_string(path) else {
            continue;
        };
        for line in text.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let Some(inode) = fields.get(9).and_then(|v| v.parse::<u64>().ok()) else {
                continue;
            };
            if wanted.contains(&inode) {
                rows.push(format!("{path}: {line}"));
            }
        }
    }
    rows
}
