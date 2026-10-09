#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use std::fmt;

use wgmesh_core::Millis;

pub mod coordinator;

/// The only source of time in the system, so decisions can be replayed in a test.
pub trait Clock: Send + Sync {
    fn now(&self) -> Millis;
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PortErrorKind {
    NotFound,
    Conflict,
    Refused,
    Storage,
}

/// A storage-agnostic failure. Adapters translate their own errors into this
/// shape so the usecases never learn what is behind the port.
#[derive(Clone, Debug)]
pub struct PortError {
    kind: PortErrorKind,
    message: String,
}

impl PortError {
    pub fn new(kind: PortErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(PortErrorKind::NotFound, message)
    }

    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(PortErrorKind::Conflict, message)
    }

    pub fn refused(message: impl Into<String>) -> Self {
        Self::new(PortErrorKind::Refused, message)
    }

    pub fn storage(message: impl Into<String>) -> Self {
        Self::new(PortErrorKind::Storage, message)
    }

    pub fn kind(&self) -> PortErrorKind {
        self.kind
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for PortError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.message)
    }
}

impl std::error::Error for PortError {}
