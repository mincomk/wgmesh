use std::fmt;

use wgmesh_app::{ConvergenceError, RoutingPolicyError};
use wgmesh_config::RoutingConfigError;
use wgmesh_core::RoutingError;
use wgmesh_ports::RouteError;

/// Everything the command line can fail at, in one type, so `main` has one place to print.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum CliError {
    /// The arguments themselves were wrong; the message carries the usage line.
    Usage(String),
    Config(RoutingConfigError),
    Policy(RoutingPolicyError),
    Routing(RoutingError),
    Net(RouteError),
    State(String),
    Output(String),
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CliError::Usage(text) => formatter.write_str(text),
            CliError::Config(error) => write!(formatter, "{error}"),
            CliError::Policy(error) => write!(formatter, "{error}"),
            CliError::Routing(error) => formatter.write_str(&wgmesh_app::describe_routing(error)),
            CliError::Net(error) => write!(formatter, "{error}"),
            CliError::State(text) => formatter.write_str(text),
            CliError::Output(text) => formatter.write_str(text),
        }
    }
}

impl std::error::Error for CliError {}

impl From<RoutingConfigError> for CliError {
    fn from(error: RoutingConfigError) -> Self {
        CliError::Config(error)
    }
}

impl From<RoutingPolicyError> for CliError {
    fn from(error: RoutingPolicyError) -> Self {
        CliError::Policy(error)
    }
}

impl From<RoutingError> for CliError {
    fn from(error: RoutingError) -> Self {
        CliError::Routing(error)
    }
}

impl From<RouteError> for CliError {
    fn from(error: RouteError) -> Self {
        CliError::Net(error)
    }
}

impl From<ConvergenceError> for CliError {
    fn from(error: ConvergenceError) -> Self {
        match error {
            ConvergenceError::Routing(error) => CliError::Routing(error),
            ConvergenceError::Routes(error) => CliError::Net(error),
        }
    }
}
