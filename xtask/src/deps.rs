// The dependency rules of the blueprint, section 1.1, checked against the real
// dependency graph rather than against good intentions.
//
// Three rules:
//
//   1. Every workspace crate except the tooling crate `xtask` has a row in the
//      table below, and may use only the internal crates and the external crates
//      its own row names.
//   2. Nothing that ships may reach the world through a crate the row does not
//      name. Development dependencies are exempt: they do not ship, and property
//      tests legitimately borrow crates the product does not use.
//   3. `wgmesh-core` is pure. No crate whose name mentions any of the tokens in
//      `FORBIDDEN_IN_CORE` may appear anywhere in its transitive tree, at any
//      depth. That is what makes "pure core" a fact rather than a slogan.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

// (crate, internal crates it may use, external crates it may use)
const ALLOWED: &[(&str, &[&str], &[&str])] = &[
    ("wgmesh-core", &[], &["blake2"]),
    (
        "wgmesh-conformance",
        &["wgmesh-core"],
        &["blake2", "serde", "serde_json"],
    ),
    ("wgmesh-ports", &["wgmesh-core"], &["async-trait"]),
    ("wgmesh-app", &["wgmesh-core", "wgmesh-ports"], &["tracing"]),
    (
        "wgmesh-config",
        &["wgmesh-core"],
        &["serde", "toml", "humantime-serde", "thiserror"],
    ),
    (
        "wgmesh-state",
        &["wgmesh-core"],
        &["serde_json", "tempfile", "rustix"],
    ),
    (
        "wgmesh-secrets",
        &["wgmesh-core"],
        &[
            "ed25519-dalek",
            "x25519-dalek",
            "rand_core",
            "zeroize",
            "base64ct",
        ],
    ),
    (
        "wgmesh-proto",
        &["wgmesh-core"],
        &["serde", "base64ct", "hex"],
    ),
    (
        "wgmesh-wireguard",
        &["wgmesh-core", "wgmesh-ports"],
        &["rtnetlink", "nl-wireguard", "tokio"],
    ),
    (
        "wgmesh-client",
        &["wgmesh-core", "wgmesh-ports", "wgmesh-proto"],
        &["reqwest", "rustls", "sha2", "base64ct"],
    ),
    (
        "wgmesh-coordinator",
        &[
            "wgmesh-core",
            "wgmesh-app",
            "wgmesh-proto",
            "wgmesh-config",
            "wgmesh-state",
            "wgmesh-secrets",
        ],
        &["axum", "sqlx", "tokio", "tower-http"],
    ),
    (
        "wgmesh-relay",
        &[
            "wgmesh-core",
            "wgmesh-app",
            "wgmesh-proto",
            "wgmesh-config",
            "wgmesh-state",
            "wgmesh-secrets",
            "wgmesh-client",
        ],
        &["tokio", "socket2", "tracing"],
    ),
    (
        "wgmesh-cli",
        &[
            "wgmesh-core",
            "wgmesh-ports",
            "wgmesh-app",
            "wgmesh-config",
            "wgmesh-state",
            "wgmesh-secrets",
            "wgmesh-proto",
            "wgmesh-wireguard",
            "wgmesh-client",
            "wgmesh-coordinator",
            "wgmesh-relay",
        ],
        &["clap", "tokio", "tracing-subscriber"],
    ),
];

// Tooling crates that the table does not govern.
const EXEMPT: &[&str] = &["xtask"];

// A crate whose name contains one of these must never enter `wgmesh-core`'s tree.
const FORBIDDEN_IN_CORE: &[&str] = &[
    "tokio", "reqwest", "axum", "sqlx", "hyper", "rustls", "netlink", "libc", "nix",
];

const CORE: &str = "wgmesh-core";

pub fn check() -> Result<(), Vec<String>> {
    let metadata = crate::metadata().map_err(|error| vec![error])?;

    let packages = packages_by_name(&metadata);
    let by_id = names_by_package_id(&metadata);
    let members = workspace_members(&metadata);
    let mut errors = Vec::new();

    let table: BTreeMap<&str, (&[&str], &[&str])> = ALLOWED
        .iter()
        .map(|(name, internal, external)| (*name, (*internal, *external)))
        .collect();

    // Rule 1, half of it: every crate that is not tooling is in the table.
    for member in &members {
        if EXEMPT.contains(&member.as_str()) {
            continue;
        }
        if !table.contains_key(member.as_str()) {
            errors.push(format!(
                "{member}: no row in the dependency table, so its dependencies are unconstrained"
            ));
        }
    }

    // Rule 1, the other half: each row's crate uses only what its row allows.
    for (name, (allowed_internal, allowed_external)) in &table {
        if !members.contains(*name) {
            errors.push(format!(
                "{name}: has a dependency row but is not a workspace member"
            ));
            continue;
        }
        let Some(package) = packages.get(*name) else {
            errors.push(format!("{name}: cargo metadata has no such package"));
            continue;
        };
        for dependency in package["dependencies"].as_array().into_iter().flatten() {
            let Some(dependency_name) = dependency["name"].as_str() else {
                continue;
            };
            if dependency["kind"].as_str() == Some("dev") {
                continue;
            }
            if dependency_name == *name {
                continue;
            }
            if members.contains(dependency_name) {
                if !allowed_internal.contains(&dependency_name) {
                    errors.push(format!(
                        "{name} depends on {dependency_name}, which its row does not allow"
                    ));
                }
            } else if !allowed_external.contains(&dependency_name) {
                errors.push(format!(
                    "{name} depends on the external crate {dependency_name}, which its row does not allow"
                ));
            }
        }
    }

    // Rule 3: the core's transitive tree stays pure.
    errors.extend(check_core_is_pure(&metadata, &by_id));

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn check_core_is_pure(metadata: &Value, by_id: &BTreeMap<String, String>) -> Vec<String> {
    let Some(core_id) = by_id
        .iter()
        .find(|(_, name)| name.as_str() == CORE)
        .map(|(id, _)| id.clone())
    else {
        return vec![format!("{CORE}: cargo metadata has no such package")];
    };

    let nodes: BTreeMap<&str, &Value> = metadata["resolve"]["nodes"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|node| node["id"].as_str().map(|id| (id, node)))
        .collect();

    let mut errors = Vec::new();
    let mut visited: BTreeSet<String> = BTreeSet::new();
    let mut queue: Vec<String> = vec![core_id];

    while let Some(id) = queue.pop() {
        if !visited.insert(id.clone()) {
            continue;
        }
        let Some(node) = nodes.get(id.as_str()) else {
            continue;
        };
        for dependency in node["deps"].as_array().into_iter().flatten() {
            let shipped = dependency["dep_kinds"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|kind| kind["kind"].is_null());
            if !shipped {
                continue;
            }
            let Some(package_id) = dependency["pkg"].as_str() else {
                continue;
            };
            let name = by_id
                .get(package_id)
                .cloned()
                .unwrap_or_else(|| String::from(package_id));

            let through = by_id.get(&id).map(String::as_str).unwrap_or(CORE);
            for forbidden in FORBIDDEN_IN_CORE {
                if name.to_lowercase().contains(forbidden) {
                    errors.push(format!(
                        "{CORE} reaches {name} through {through}, and {forbidden} must not be in its tree"
                    ));
                }
            }

            queue.push(String::from(package_id));
        }
    }

    errors
}

fn packages_by_name(metadata: &Value) -> BTreeMap<String, &Value> {
    metadata["packages"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|package| {
            package["name"]
                .as_str()
                .map(|name| (String::from(name), package))
        })
        .collect()
}

fn names_by_package_id(metadata: &Value) -> BTreeMap<String, String> {
    metadata["packages"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|package| {
            let id = package["id"].as_str()?;
            let name = package["name"].as_str()?;
            Some((String::from(id), String::from(name)))
        })
        .collect()
}

fn workspace_members(metadata: &Value) -> BTreeSet<String> {
    let ids: BTreeSet<&str> = metadata["workspace_members"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|id| id.as_str())
        .collect();

    metadata["packages"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|package| package["id"].as_str().is_some_and(|id| ids.contains(id)))
        .filter_map(|package| package["name"].as_str().map(String::from))
        .collect()
}
