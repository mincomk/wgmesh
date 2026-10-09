use std::path::PathBuf;

use clap::{Args, Subcommand};

use wgmesh_client::{TrustError, TrustStore, load_certificate};

pub const DEFAULT_CONFIG: &str = "/etc/wgmesh/agent.toml";

#[derive(Debug, Args)]
pub struct TrustArgs {
    #[command(subcommand)]
    pub command: TrustCommand,
}

#[derive(Debug, Subcommand)]
pub enum TrustCommand {
    // What the node currently pins, and where the pin lives.
    Show {
        #[arg(long, default_value = DEFAULT_CONFIG)]
        config: PathBuf,
    },
    // Re-pin to the coordinator's current certificate. The certificate is given
    // explicitly: an operator rotating ahead of a renewal holds it already. A
    // node that has no copy yet takes it from the live TLS session, which is the
    // HTTPS client adapter's job.
    Rotate {
        #[arg(long, default_value = DEFAULT_CONFIG)]
        config: PathBuf,
        #[arg(long)]
        from_cert: PathBuf,
    },
    // The pin a certificate would produce, without touching any configuration.
    Pin {
        certificate: PathBuf,
    },
}

pub fn run(args: &TrustArgs) -> Result<String, String> {
    match &args.command {
        TrustCommand::Show { config } => {
            let store = TrustStore::new(config);
            match store.show() {
                Ok(pin) => Ok(format!("{pin}\n  pinned in {}", store.path().display())),
                Err(TrustError::NoPin(path)) => Ok(format!("no pin in {path}")),
                Err(error) => Err(error.to_string()),
            }
        }
        TrustCommand::Rotate { config, from_cert } => {
            let store = TrustStore::new(config);
            let certificate = load_certificate(from_cert)?;
            let rotation = store
                .rotate(&certificate)
                .map_err(|error| error.to_string())?;
            let previous = rotation
                .previous
                .clone()
                .unwrap_or_else(|| String::from("none"));
            Ok(format!(
                "pinned {}\n  was {previous}\n  file {}",
                rotation.current,
                store.path().display()
            ))
        }
        TrustCommand::Pin { certificate } => {
            let bytes = load_certificate(certificate)?;
            wgmesh_client::spki_sha256(&bytes)
                .ok_or_else(|| String::from("that is not a certificate"))
        }
    }
}
