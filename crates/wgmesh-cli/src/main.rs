#![allow(clippy::print_stdout)]

use std::io::{self, Write};
use std::process::ExitCode;

use wgmesh_cli::args::{Args, Command};
use wgmesh_cli::{CliError, commands};

fn main() -> ExitCode {
    let args = match Args::parse(std::env::args()) {
        Ok(args) => args,
        Err(error) => {
            eprintln!("wgmesh: {error}");
            return ExitCode::from(2);
        }
    };

    let stdout = io::stdout();
    let mut out = stdout.lock();
    match dispatch(&args, &mut out) {
        Ok(()) => {
            let _ = out.flush();
            ExitCode::SUCCESS
        }
        Err(error) => {
            let _ = out.flush();
            eprintln!("wgmesh: {error}");
            ExitCode::FAILURE
        }
    }
}

fn dispatch(args: &Args, out: &mut dyn Write) -> Result<(), CliError> {
    match args.command {
        Command::Peers => commands::peers::run(args, out),
        Command::RoutesPlan => commands::routes::plan(args, out),
        Command::RoutesReset => commands::routes::reset(args, out),
        Command::Doctor => commands::doctor::run(args, out),
    }
}
