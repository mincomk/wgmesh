pub mod agent;
pub mod coordinator;
pub mod relay;
pub mod validate;

use std::path::{Path, PathBuf};

pub use validate::{Problem, parse_allowed};

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("reading {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("parsing {path}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
}

/// Read and parse one settings file. Defaults fill whatever the file omits, so
/// a five-line file is a complete configuration.
pub fn load<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, ConfigError> {
    let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    toml::from_str(&text).map_err(|source| ConfigError::Parse {
        path: path.to_path_buf(),
        source,
    })
}

pub fn parse<T: serde::de::DeserializeOwned>(text: &str) -> Result<T, toml::de::Error> {
    toml::from_str(text)
}

/// Render a settings value as the TOML a user could edit — the same text
/// `wgmesh config show` prints, with every default spelled out.
pub fn render<T: serde::Serialize>(settings: &T) -> String {
    toml::to_string_pretty(settings).unwrap_or_else(|error| format!("# {error}\n"))
}
