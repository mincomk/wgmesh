// The style rules of the blueprint, section 16. Two greps, in Rust, so that they
// run everywhere the checks run:
//
//   1. No file-level comment (`//!`) in any Rust source under `crates/` or `xtask/`.
//   2. No Hangul in any Rust source under those directories, comments included.

use std::fs;
use std::path::Path;

// The directories the two greps cover.
const SCANNED: &[&str] = &["crates", "xtask"];

const HANGUL_FIRST: char = '\u{AC00}';
const HANGUL_LAST: char = '\u{D7A3}';

pub fn check() -> Result<(), Vec<String>> {
    let root = crate::workspace_root().map_err(|error| vec![error])?;
    let mut errors = Vec::new();

    for directory in SCANNED {
        let path = root.join(directory);
        if !path.is_dir() {
            errors.push(format!(
                "{directory}: is not a directory of the workspace root {}",
                root.display()
            ));
            continue;
        }
        walk(&path, &root, &mut errors);
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn walk(directory: &Path, root: &Path, errors: &mut Vec<String>) {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) => {
            errors.push(format!(
                "{}: could not be read: {error}",
                shown(directory, root)
            ));
            return;
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, root, errors);
        } else if path.extension().and_then(|extension| extension.to_str()) == Some("rs") {
            scan(&path, root, errors);
        }
    }
}

fn scan(path: &Path, root: &Path, errors: &mut Vec<String>) {
    let file = shown(path, root);
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) => {
            errors.push(format!("{file}: could not be read as UTF-8: {error}"));
            return;
        }
    };

    for (index, line) in text.lines().enumerate() {
        let number = index + 1;

        if line.starts_with("//!") {
            errors.push(format!(
                "{file}:{number}: a file-level comment (`//!`) is forbidden"
            ));
        }

        if let Some(character) = line
            .chars()
            .find(|character| (HANGUL_FIRST..=HANGUL_LAST).contains(character))
        {
            errors.push(format!(
                "{file}:{number}: Hangul (U+{:04X}) is forbidden in Rust sources, comments included",
                u32::from(character)
            ));
        }
    }
}

fn shown(path: &Path, root: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
}
