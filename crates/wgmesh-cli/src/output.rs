// Printing: one JSON document per `--json` command, and the human form of the same facts.

use serde::Serialize;

use wgmesh_core::{Allowed, Endpoint, Millis, Path};

/// The schema version every `--json` document carries.
pub const SCHEMA: u32 = 1;

/// Serialize a value as the single JSON document a `--json` command prints.
pub fn json<T: Serialize>(value: &T) -> String {
    match serde_json::to_string_pretty(value) {
        Ok(text) => text,
        Err(error) => format!("{{\"schema\": {SCHEMA}, \"serialize_error\": \"{error}\"}}"),
    }
}

/// A prefix the way an operator writes it.
pub fn prefix(prefix: &Allowed) -> String {
    crate::simulated::write_prefix(prefix)
}

/// A list of prefixes, comma separated.
pub fn prefixes(list: &[Allowed]) -> String {
    if list.is_empty() {
        return "-".to_string();
    }
    list.iter().map(prefix).collect::<Vec<_>>().join(", ")
}

/// A list of prefixes already written as text.
pub fn prefixes_text(list: &[String]) -> String {
    if list.is_empty() {
        "-".to_string()
    } else {
        list.join(", ")
    }
}

/// An endpoint, or a dash when there is none.
pub fn endpoint(endpoint: Option<Endpoint>) -> String {
    match endpoint {
        Some(endpoint) => endpoint.addr().to_string(),
        None => "-".to_string(),
    }
}

/// The word the human output uses for a path.
pub fn path(path: Path) -> &'static str {
    match path {
        Path::Unknown => "unknown",
        Path::Relayed => "relayed",
        Path::Direct => "direct",
    }
}

/// An age, in the largest unit that still says something.
pub fn age(seconds: u64) -> String {
    match seconds {
        0 => "now".to_string(),
        1..=59 => format!("{seconds}s ago"),
        60..=3599 => format!("{}m ago", seconds / 60),
        3600..=86_399 => format!("{}h ago", seconds / 3600),
        _ => format!("{}d ago", seconds / 86_400),
    }
}

/// A byte count in binary units.
pub fn bytes(count: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = count as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{count}B")
    } else {
        format!("{value:.1}{}", UNITS[unit])
    }
}

/// The Unix second a `Millis` sits in, when it is set.
pub fn unix_seconds(at: Millis) -> Option<u64> {
    (at.as_millis() > 0).then_some(at.as_millis() / 1000)
}
