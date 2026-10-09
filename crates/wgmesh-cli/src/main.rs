use clap::Parser;

use wgmesh_cli::cli::Cli;
use wgmesh_cli::commands;

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    commands::init_logging(&cli);

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("wgmesh: could not start the runtime: {error}");
            return std::process::ExitCode::from(1);
        }
    };

    match runtime.block_on(commands::dispatch(cli)) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            std::process::ExitCode::from(error.exit_code() as u8)
        }
    }
}
