use std::process::ExitCode;

use clap::{Parser, Subcommand};

use wgmesh_cli::trust::{TrustArgs, run as run_trust};

#[derive(Debug, Parser)]
#[command(name = "wgmesh", version, about = "A mesh over WireGuard, with a coordinator.")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    // The coordinator's TLS identity, pinned at enrollment and moved only here.
    Trust(TrustArgs),
}

#[allow(clippy::print_stdout, clippy::print_stderr)]
fn main() -> ExitCode {
    let cli = Cli::parse();
    let outcome = match &cli.command {
        Command::Trust(args) => run_trust(args),
    };
    match outcome {
        Ok(message) => {
            println!("{message}");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}
