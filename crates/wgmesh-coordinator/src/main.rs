use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::Arc;

use wgmesh_coordinator::{AdminAuth, AppState, Store, SystemClock, router};

fn env_or(name: &str, fallback: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| String::from(fallback))
}

async fn serve() -> Result<(), String> {
    let database = env_or("WGMESH_DATABASE", "/var/lib/wgmesh/coordinator.db");
    let listen = env_or("WGMESH_LISTEN", "127.0.0.1:8080");
    let admin_token = std::env::var("WGMESH_ADMIN_TOKEN").map_err(|_| {
        String::from("WGMESH_ADMIN_TOKEN must name the operator's bootstrap credential")
    })?;

    let store = Store::open_file(&database)
        .await
        .map_err(|error| format!("cannot open {database}: {error}"))?;
    let state = AppState::new(
        store,
        AdminAuth::from_token(&admin_token),
        Arc::new(SystemClock),
    );

    let address: SocketAddr = listen
        .parse()
        .map_err(|error| format!("WGMESH_LISTEN is not an address: {error}"))?;
    let listener = tokio::net::TcpListener::bind(address)
        .await
        .map_err(|error| format!("cannot bind {address}: {error}"))?;
    eprintln!("wgmeshd listening on {address}, state in {database}");
    axum::serve(listener, router(state))
        .await
        .map_err(|error| format!("the server stopped: {error}"))
}

fn main() -> ExitCode {
    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("cannot start the runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(serve()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
