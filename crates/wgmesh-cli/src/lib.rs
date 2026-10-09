#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod args;
pub mod commands;
pub mod error;
pub mod json;
pub mod state;

pub use args::{Args, Command};
pub use error::CliError;
