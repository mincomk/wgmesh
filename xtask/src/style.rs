// The style rules of the blueprint, section 16. Two greps, in Rust, so that they
// run everywhere the checks run:
//
//   1. No file-level comment in any Rust source of the workspace. The line form,
//      the block form and the crate-level doc attribute all declare the same
//      thing, so all three are out; the rule is about the doc, not the spelling.
//   2. No Hangul in any Rust source of the workspace, comments included.
//
// The walk starts at the workspace root, so a source file cannot escape the rules
// by sitting outside `crates/`. `target/` and dot-directories are skipped, and
// symlinks are not followed: a link inside the tree could otherwise pull in a tree
// of someone else's sources.

use std::fs;
use std::path::{Path, PathBuf};

const HANGUL_FIRST: char = '\u{AC00}';
const HANGUL_LAST: char = '\u{D7A3}';

// Directory names never walked.
const SKIPPED: &[&str] = &["target"];

pub fn check() -> Result<(), Vec<String>> {
    let root = crate::workspace_root().map_err(|error| vec![error])?;
    let mut errors = Vec::new();
    walk(&root, &root, &mut errors);

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
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if kind.is_symlink() {
            continue;
        }
        let path: PathBuf = entry.path();
        if kind.is_dir() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with('.') || SKIPPED.contains(&name.as_ref()) {
                continue;
            }
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

        if declares_the_document(line) {
            errors.push(format!(
                "{file}:{number}: a file-level comment is forbidden, in any of its three spellings"
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

// `//!` and `/*!` are the line and block form of the same declaration, and
// `#![doc = ...]` is the attribute form. Leading whitespace is irrelevant, and so
// is a stray carriage return.
fn declares_the_document(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("//!") || trimmed.starts_with("/*!") || trimmed.starts_with("#![doc")
}

fn shown(path: &Path, root: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
}
