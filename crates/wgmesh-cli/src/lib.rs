// The `wgmesh` binary: the composition root, its commands, and the one module where the concrete
// adapters meet the use cases.
//
// Everything a command does is either a call into `wgmesh-app` (which knows only the ports) or a
// read of a file or the kernel. This crate is where the ports get something behind them, which is
// why it is the only crate that names every adapter.

pub mod adapters;
pub mod agent;
pub mod cli;
pub mod commands;
pub mod container;
pub mod error;
pub mod output;
pub mod simulated;
pub mod view;

pub use error::{CliError, Problem, Severity};
