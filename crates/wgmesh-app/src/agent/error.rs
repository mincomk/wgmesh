// What the agent fails with.

use std::fmt;

use wgmesh_core::RoutingError;
use wgmesh_ports::{ApiError, Class, RouteError, SecretError, Spki, StateError, WireGuardError};

/// A failure in one of the agent's use cases.
///
/// Every variant is either a decision the agent made — a trust mismatch, a missing token, a
/// configuration the routing policy refuses — or a port failure passed through with its class
/// intact. Nothing here swallows a classification: `AppError::class` always has an answer, and
/// it is the answer a caller's retry logic runs on.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum AppError {
    /// The state pins one coordination-plane key and the configuration expects another.
    ///
    /// This stops the work. It is never retried, never downgraded to a warning, and the pin is
    /// never moved as a consequence of trying again: `wgmesh trust rotate` is the only thing
    /// that moves it.
    TrustMismatch {
        /// The key the state was enrolled under.
        pinned: Spki,
        /// The key the configuration expects.
        configured: Spki,
    },
    /// There is no state to resume from, and no join token to enroll with.
    MissingJoinToken,
    /// There is no state to operate on.
    NotEnrolled,
    /// The routing policy refused the configuration.
    Routing(RoutingError),
    /// The secret store refused.
    Secrets(SecretError),
    /// The state store refused.
    State(StateError),
    /// The coordination plane refused.
    Coordinator(ApiError),
    /// The WireGuard interface refused.
    WireGuard(WireGuardError),
    /// The routing table refused.
    Routes(RouteError),
}

impl AppError {
    /// What a caller may do about this failure.
    pub fn class(&self) -> Class {
        match self {
            Self::TrustMismatch { .. } => Class::Trust,
            Self::MissingJoinToken | Self::NotEnrolled | Self::Routing(_) => Class::Fatal,
            Self::Secrets(error) | Self::State(error) => error.class(),
            Self::Coordinator(error) | Self::WireGuard(error) | Self::Routes(error) => {
                error.class()
            }
        }
    }

    /// Whether an automated retry is worth attempting.
    pub fn retryable(&self) -> bool {
        self.class().is_retryable()
    }
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TrustMismatch { pinned, configured } => write!(
                f,
                "the state pins the coordination-plane key {pinned} but the configuration \
                 expects {configured}; rotate the pin deliberately with `wgmesh trust rotate --yes`"
            ),
            Self::MissingJoinToken => {
                f.write_str("there is no state to resume from and no join token to enroll with")
            }
            Self::NotEnrolled => f.write_str("there is no state to operate on"),
            Self::Routing(error) => write!(f, "routing policy: {error:?}"),
            Self::Secrets(error) => write!(f, "secret store: {error}"),
            Self::State(error) => write!(f, "state store: {error}"),
            Self::Coordinator(error) => write!(f, "coordination plane: {error}"),
            Self::WireGuard(error) => write!(f, "wireguard: {error}"),
            Self::Routes(error) => write!(f, "routes: {error}"),
        }
    }
}

impl std::error::Error for AppError {}
