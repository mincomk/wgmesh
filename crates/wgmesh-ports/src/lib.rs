// The traits the use cases depend on, and the error taxonomy they speak.
//
// Everything the agent does is either a pure decision — which lives in `wgmesh-core`, and
// nowhere else — or an interaction with something outside the process. This crate is the
// boundary: it names the interactions as traits, and `wgmesh-app` is written entirely against
// them. Tests supply in-memory implementations and never touch a kernel or a network.
//
// Three things the design insists on.
//
// **The private key does not leave the store.** `SecretStore` hands out public keys and a
// `sign` operation, and nothing else: there is no `private_key()` and no `api_key()`, because a
// private key that travels as a return value is a private key in a caller's variable. Signing
// happens inside the store, so what leaves is a signature.
//
// **The unit of `WireGuard::apply` is `Change`.** `wgmesh_core::Change` is the core's type, and
// the adapter does not decide what it means: `wgmesh_core::diff` decides what to add, update or
// remove, and the adapter translates the list into netlink messages.
//
// **`Routes` is separate from `WireGuard`.** AllowedIPs are cryptokey routing — which peer may
// claim which address inside the tunnel. The kernel routing table is a different thing with a
// different lifetime and a different owner, so it gets its own port. The value of the split is
// that the WireGuard adapter never has to know what `ip route` is.
//
// The error taxonomy is the other half of the crate. Every port fails with `PortError`, and
// every failure carries a `Class` saying what a caller may do about it; the agent's retry,
// re-enroll and refuse-to-continue decisions are all made from that class.

pub mod coordinator;
pub mod fake;
pub mod prefix;
pub mod routes;
pub mod routing;
pub mod stores;
pub mod wireguard;

use std::fmt;

pub use coordinator::{
    ConfigSnapshot, CoordinatorApi, EnrollRequest, Enrollment, JoinToken, Observation,
    PunchOutcome, PunchReport, RelayAssignment,
};
pub use prefix::{MARKER_PROTO, family_flag, format_prefix, is_catch_all, parse_prefix};
pub use routes::Routes;
pub use routing::{
    ChangeAction, Firewall, ForwardingPolicy, NamedPeer, PeerReport, RouteChangeView,
    RoutePlanView, Sysctl, reset_routes,
};
pub use stores::{
    Clock, CoordinatorLink, PeerRecord, PersistedState, RelayState, SecretStore, Signature, Spki,
    StateStore,
};
pub use wireguard::{InterfaceSpec, PeerStatus, WireGuard};

/// What a caller may do about a failure.
///
/// Every failing port call lands in exactly one of these, and the agent's reaction — retry in
/// place, re-enroll, stop and tell a person, or refuse to continue on a trust decision — is a
/// function of the class alone.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Class {
    /// Retrying the same call may succeed. The world was briefly unavailable.
    Transient,
    /// Retrying may succeed once something else has happened: a fresh enrollment, a new
    /// configuration, a peer that comes back.
    Recoverable,
    /// Retrying cannot help. A person has to intervene.
    Fatal,
    /// A trust decision failed. Never retried, and never worked around.
    Trust,
}

impl Class {
    /// Whether an automated retry is worth attempting.
    pub const fn is_retryable(self) -> bool {
        matches!(self, Self::Transient | Self::Recoverable)
    }

    /// The class as a lowercase word, for logs and metrics.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Transient => "transient",
            Self::Recoverable => "recoverable",
            Self::Fatal => "fatal",
            Self::Trust => "trust",
        }
    }
}

/// A port failure: a class, and a human-readable detail.
///
/// Adapters format whatever their underlying error was into `detail` rather than wrapping it, so
/// that the whole agent fails with one error type and a classification is never lost in a
/// conversion.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PortError {
    class: Class,
    detail: String,
}

impl PortError {
    /// A failure of the given class with the given detail.
    pub fn new(class: Class, detail: impl Into<String>) -> Self {
        Self {
            class,
            detail: detail.into(),
        }
    }

    /// A failure that may go away on its own.
    pub fn transient(detail: impl Into<String>) -> Self {
        Self::new(Class::Transient, detail)
    }

    /// A failure that may go away once something else has happened.
    pub fn recoverable(detail: impl Into<String>) -> Self {
        Self::new(Class::Recoverable, detail)
    }

    /// A failure no retry can fix.
    pub fn fatal(detail: impl Into<String>) -> Self {
        Self::new(Class::Fatal, detail)
    }

    /// A failure of a trust decision.
    pub fn trust(detail: impl Into<String>) -> Self {
        Self::new(Class::Trust, detail)
    }

    /// Which class this failure is in.
    pub const fn class(&self) -> Class {
        self.class
    }

    /// The human-readable detail.
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for PortError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.class.as_str(), self.detail)
    }
}

impl std::error::Error for PortError {}

/// The failure of the coordination plane.
pub type ApiError = PortError;
/// The failure of the kernel WireGuard interface.
pub type WireGuardError = PortError;
/// The failure of the kernel routing table.
pub type RouteError = PortError;
/// The failure of the state store.
pub type StateError = PortError;
/// The failure of the secret store.
pub type SecretError = PortError;
