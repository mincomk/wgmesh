#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Parser, Subcommand};

use wgmesh_cli::{doctor, natprobe};
use wgmesh_config::agent as settings;

#[derive(Parser, Debug)]
#[command(
    name = "wgmesh",
    about = "NAT-traversing peer-to-peer WireGuard",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Diagnose this node: routing, forwarding and NAT behaviour.
    Doctor {
        #[arg(long, default_value = "/etc/wgmesh/agent.toml")]
        config: PathBuf,
        /// A coordinator snapshot to check the peers against. Without one the
        /// routing checks have nothing to compare `prefixes` with.
        #[arg(long)]
        snapshot: Option<PathBuf>,
        /// Print the report as JSON.
        #[arg(long)]
        json: bool,
        /// Ask this address what it sees our source address as. Repeat with a
        /// second address to tell a cone NAT from a symmetric one.
        #[arg(long = "nat-probe")]
        nat_probe: Vec<SocketAddr>,
    },
    /// Work with the configuration file.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
}

#[derive(Subcommand, Debug)]
enum ConfigCommand {
    /// Print the effective configuration, defaults included.
    Show {
        #[arg(long, default_value = "/etc/wgmesh/agent.toml")]
        config: PathBuf,
    },
    /// Report every problem in the configuration at once.
    Check {
        #[arg(long, default_value = "/etc/wgmesh/agent.toml")]
        config: PathBuf,
        #[arg(long)]
        json: bool,
    },
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("wgmesh: {error}");
            std::process::ExitCode::from(2)
        }
    }
}

fn run(cli: Cli) -> Result<std::process::ExitCode, Box<dyn std::error::Error>> {
    match cli.command {
        Command::Config { command } => match command {
            ConfigCommand::Show { config } => {
                let settings: settings::Settings = wgmesh_config::load(&config)?;
                print!("{}", wgmesh_config::render(&settings));
                Ok(std::process::ExitCode::SUCCESS)
            }
            ConfigCommand::Check { config, json } => {
                let settings: settings::Settings = wgmesh_config::load(&config)?;
                let problems = settings.validate();
                if json {
                    println!("{}", serde_json::to_string_pretty(&problems)?);
                } else if problems.is_empty() {
                    println!("{}: no problems found", config.display());
                } else {
                    for problem in &problems {
                        println!("{}: {}", problem.field, problem.message);
                    }
                }
                Ok(if problems.is_empty() {
                    std::process::ExitCode::SUCCESS
                } else {
                    std::process::ExitCode::from(1)
                })
            }
        },
        Command::Doctor {
            config,
            snapshot,
            json,
            nat_probe,
        } => {
            let settings: settings::Settings = wgmesh_config::load(&config)?;
            let snapshot = match &snapshot {
                Some(path) => Some(serde_json::from_str(&std::fs::read_to_string(path)?)?),
                None => None,
            };
            let report = doctor::run(&settings, snapshot.as_ref(), &doctor::ProcSysctl)?;
            let nat = if nat_probe.is_empty() {
                None
            } else {
                Some(natprobe::probe(&nat_probe)?)
            };
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&doctor::as_json(&report, nat.as_ref()))?
                );
            } else {
                print!("{}", doctor::render(&report, nat.as_ref()));
            }
            Ok(if report.findings.is_empty() {
                std::process::ExitCode::SUCCESS
            } else {
                std::process::ExitCode::from(1)
            })
        }
    }
}
