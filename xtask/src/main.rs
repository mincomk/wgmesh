// `cargo xtask <task>` runs the workspace's own repository checks.
//
//   cargo xtask check-deps    the dependency rules of the blueprint, section 1.1
//   cargo xtask check-style   the style rules of the blueprint, section 16
//
// The rules live here, in code, so that a reviewer does not have to remember them
// and so that CI and a developer run exactly the same thing.

mod deps;
mod style;

use std::path::PathBuf;
use std::process::{Command, ExitCode};

fn main() -> ExitCode {
    let task = match std::env::args().nth(1) {
        Some(task) => task,
        None => return usage(),
    };

    let outcome = match task.as_str() {
        "check-deps" => deps::check(),
        "check-style" => style::check(),
        _ => return usage(),
    };

    match outcome {
        Ok(()) => {
            println!("xtask {task}: ok");
            ExitCode::SUCCESS
        }
        Err(errors) => {
            eprintln!("xtask {task}: {} problem(s)", errors.len());
            for error in &errors {
                eprintln!("  {error}");
            }
            ExitCode::FAILURE
        }
    }
}

fn usage() -> ExitCode {
    eprintln!("usage: cargo xtask <check-deps|check-style>");
    ExitCode::from(2)
}

// Run `cargo metadata` from this crate's own directory, so the command works from
// any directory inside the workspace, and hand back what cargo parsed. The parsed
// document also carries the absolute path of the workspace root, which is what the
// style check walks.
fn metadata() -> Result<serde_json::Value, String> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| String::from("cargo"));
    let output = Command::new(cargo)
        .args(["metadata", "--format-version", "1"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .map_err(|error| format!("could not run `cargo metadata`: {error}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("`cargo metadata` failed: {}", stderr.trim()));
    }

    serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("could not parse the output of `cargo metadata`: {error}"))
}

fn workspace_root() -> Result<PathBuf, String> {
    let metadata = metadata()?;
    match metadata["workspace_root"].as_str() {
        Some(root) => Ok(PathBuf::from(root)),
        None => Err(String::from("`cargo metadata` reported no workspace root")),
    }
}
