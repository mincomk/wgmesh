#![allow(clippy::print_stdout)]

use std::io::Read;
use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use tokio::net::TcpListener;
use wgmesh_app::coordinator::Clock;
use wgmesh_app::coordinator::ports::{
    AuditEntry, DeviceState, Directory, Network, NewJoinToken, NewNetwork, NewRelay, RelayState,
    Reports, TokenKind, TokenStore,
};
use wgmesh_coordinator::clock::SystemClock;
use wgmesh_coordinator::router;
use wgmesh_coordinator::service::Services;
use wgmesh_coordinator::store::Sqlite;
use wgmesh_core::Millis;
use wgmesh_proto::{
    SECRET_LEN, decode_key, device_id, encode_key, parse_device_id, parse_relay_id, relay_id,
    token as join_token,
};

#[derive(Parser)]
#[command(name = "wgmeshd", about = "the wgmesh coordinator")]
struct Cli {
    /// SQLite URL. TLS is not this process's job: put a reverse proxy in front.
    #[arg(
        long,
        global = true,
        default_value = "sqlite://wgmesh-coordinator.db?mode=rwc"
    )]
    database: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve the API on plain HTTP.
    Run {
        #[arg(long, default_value = "127.0.0.1:8080")]
        listen: String,
    },
    /// Create the database and a first network.
    Bootstrap {
        #[arg(long)]
        network: String,
        #[arg(long, default_value = "10.77.0.0/16")]
        cidr: String,
        #[arg(long, default_value_t = 1420)]
        mtu: u32,
        #[arg(long, default_value = "admin")]
        actor: String,
    },
    Network {
        #[command(subcommand)]
        command: NetworkCommand,
    },
    Token {
        #[command(subcommand)]
        command: TokenCommand,
    },
    Device {
        #[command(subcommand)]
        command: DeviceCommand,
    },
    Relay {
        #[command(subcommand)]
        command: RelayCommand,
    },
}

#[derive(Subcommand)]
enum NetworkCommand {
    List,
    Create {
        #[arg(long)]
        name: String,
        #[arg(long)]
        cidr: String,
        #[arg(long, default_value_t = 1420)]
        mtu: u32,
        #[arg(long, default_value = "any")]
        relay_policy: String,
        #[arg(long, default_value = "admin")]
        actor: String,
    },
}

#[derive(Subcommand)]
enum TokenCommand {
    /// Mint a token. This is the only time it is ever shown.
    Create {
        #[arg(long)]
        network: String,
        #[arg(long, default_value = "device")]
        kind: String,
        #[arg(long, default_value_t = 1)]
        max_uses: u32,
        #[arg(long, default_value_t = 86_400)]
        expires_secs: u64,
        #[arg(long)]
        auto_approve: bool,
        #[arg(long, default_value = "admin")]
        actor: String,
    },
    Revoke {
        token: String,
        #[arg(long, default_value = "admin")]
        actor: String,
    },
}

#[derive(Subcommand)]
enum DeviceCommand {
    List {
        #[arg(long)]
        network: Option<String>,
    },
    Approve {
        device_id: String,
        #[arg(long, default_value = "admin")]
        actor: String,
    },
    Revoke {
        device_id: String,
        #[arg(long, default_value = "admin")]
        actor: String,
    },
}

#[derive(Subcommand)]
enum RelayCommand {
    List,
    Approve {
        relay_id: String,
        #[arg(long, default_value = "admin")]
        actor: String,
    },
    Retire {
        relay_id: String,
        #[arg(long, default_value = "admin")]
        actor: String,
    },
    /// Register a relay out of band, when it cannot reach the join endpoint.
    Enroll {
        #[arg(long)]
        name: String,
        #[arg(long)]
        api_pubkey: String,
        #[arg(long)]
        endpoint_host: String,
        #[arg(long, default_value = "51820-51999")]
        port_range: String,
        #[arg(long)]
        region: Option<String>,
        #[arg(long, default_value = "admin")]
        actor: String,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("wgmeshd: {message}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), String> {
    let cli = Cli::parse();
    let store = Arc::new(
        Sqlite::open(&cli.database, 8)
            .await
            .map_err(|error| error.to_string())?,
    );
    store.migrate().await.map_err(|error| error.to_string())?;
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let now = clock.now();

    match cli.command {
        Command::Run { listen } => {
            let services = Services::new(store, clock);
            let app = router(services);
            let address: SocketAddr = listen.parse().map_err(|error| format!("{error}"))?;
            let listener = TcpListener::bind(address)
                .await
                .map_err(|error| error.to_string())?;
            println!("wgmeshd listening on http://{address}");
            axum::serve(listener, app)
                .await
                .map_err(|error| error.to_string())?;
        }
        Command::Bootstrap {
            network,
            cidr,
            mtu,
            actor,
        } => {
            let created = ensure_network(&store, &network, &cidr, mtu, "any", &actor, now).await?;
            println!(
                "network {} ({}) id={}",
                created.name, created.cidr, created.id
            );
        }
        Command::Network { command } => match command {
            NetworkCommand::List => {
                for network in store.networks().await.map_err(|e| e.to_string())? {
                    println!(
                        "{}\t{}\t{}\tmtu={}\t{}",
                        network.id, network.name, network.cidr, network.mtu, network.relay_policy
                    );
                }
            }
            NetworkCommand::Create {
                name,
                cidr,
                mtu,
                relay_policy,
                actor,
            } => {
                let created =
                    ensure_network(&store, &name, &cidr, mtu, &relay_policy, &actor, now).await?;
                println!(
                    "network {} ({}) id={}",
                    created.name, created.cidr, created.id
                );
            }
        },
        Command::Token { command } => match command {
            TokenCommand::Create {
                network,
                kind,
                max_uses,
                expires_secs,
                auto_approve,
                actor,
            } => {
                let Some(record) = store
                    .network_by_name(&network)
                    .await
                    .map_err(|e| e.to_string())?
                else {
                    return Err(format!("no network named {network}"));
                };
                let Some(kind) = TokenKind::parse(&kind) else {
                    return Err(format!("unknown token kind {kind}"));
                };
                let secret = random_secret()?;
                let text = join_token::format_token(&secret);
                store
                    .insert_join_token(&NewJoinToken {
                        network_id: record.id,
                        kind,
                        token_hash: join_token::hash_secret(&secret),
                        max_uses,
                        auto_approve,
                        expires_at: Millis::from_millis(now.0 + expires_secs * 1000),
                        created_by: actor.clone(),
                        created_at: now,
                    })
                    .await
                    .map_err(|e| e.to_string())?;
                store
                    .audit(&AuditEntry {
                        at: now,
                        actor,
                        action: "token.create".to_string(),
                        network_id: Some(record.id),
                        device_id: None,
                        relay_id: None,
                        detail: Some(format!("kind={} max_uses={max_uses}", kind.as_str())),
                    })
                    .await
                    .map_err(|e| e.to_string())?;
                println!("{text}");
            }
            TokenCommand::Revoke { token, actor } => {
                let Some(hash) = join_token::hash_token_text(&token) else {
                    return Err("that is not a wgmesh join token".to_string());
                };
                let revoked = store
                    .revoke_join_token(&hash, now)
                    .await
                    .map_err(|e| e.to_string())?;
                store
                    .audit(&AuditEntry {
                        at: now,
                        actor,
                        action: "token.revoke".to_string(),
                        network_id: None,
                        device_id: None,
                        relay_id: None,
                        detail: Some(format!("revoked={revoked}")),
                    })
                    .await
                    .map_err(|e| e.to_string())?;
                println!("revoked: {revoked}");
            }
        },
        Command::Device { command } => match command {
            DeviceCommand::List { network } => {
                for record in store.networks().await.map_err(|e| e.to_string())? {
                    if let Some(wanted) = &network {
                        if &record.name != wanted {
                            continue;
                        }
                    }
                    for device in store
                        .devices_of(record.id)
                        .await
                        .map_err(|e| e.to_string())?
                    {
                        println!(
                            "{}\t{}\t{}\t{}\t{}",
                            device_id(device.id),
                            device.name,
                            device.state.as_str(),
                            device.tunnel_ip,
                            encode_key(&device.wg_pubkey)
                        );
                    }
                }
            }
            DeviceCommand::Approve { device_id, actor } => {
                let device = parse_device_id(&device_id)
                    .ok_or_else(|| format!("not a device id: {device_id}"))?;
                let services = Services::new(store, clock);
                let record = services
                    .approve_device()
                    .execute(&actor, device)
                    .await
                    .map_err(|error| error.to_string())?;
                println!("{device_id} is now {}", record.state.as_str());
            }
            DeviceCommand::Revoke { device_id, actor } => {
                let device = parse_device_id(&device_id)
                    .ok_or_else(|| format!("not a device id: {device_id}"))?;
                let services = Services::new(store, clock);
                services
                    .approve_device()
                    .revoke(&actor, device)
                    .await
                    .map_err(|error| error.to_string())?;
                println!("{device_id} is now {}", DeviceState::Revoked.as_str());
            }
        },
        Command::Relay { command } => match command {
            RelayCommand::List => {
                for network in store.networks().await.map_err(|e| e.to_string())? {
                    for relay in store
                        .relays_of(network.id)
                        .await
                        .map_err(|e| e.to_string())?
                    {
                        println!(
                            "{}\t{}\t{}\t{}\t{}",
                            relay_id(relay.id),
                            relay.name,
                            relay.state.as_str(),
                            relay.endpoint_host,
                            relay.port_range
                        );
                    }
                }
            }
            RelayCommand::Approve { relay_id, actor } => {
                set_relay_state(&store, &relay_id, RelayState::Active, &actor, now).await?;
            }
            RelayCommand::Retire { relay_id, actor } => {
                set_relay_state(&store, &relay_id, RelayState::Retired, &actor, now).await?;
            }
            RelayCommand::Enroll {
                name,
                api_pubkey,
                endpoint_host,
                port_range,
                region,
                actor,
            } => {
                let key = decode_key(&api_pubkey)
                    .ok_or_else(|| "api_pubkey must be a 32-byte base64 key".to_string())?;
                let relay = store
                    .insert_relay(&NewRelay {
                        name: name.clone(),
                        api_pubkey: key,
                        state: RelayState::Active,
                        endpoint_host,
                        port_range,
                        region,
                        provider: None,
                        operator: None,
                        created_at: now,
                    })
                    .await
                    .map_err(|e| e.to_string())?;
                for network in store.networks().await.map_err(|e| e.to_string())? {
                    store
                        .link_relay_network(relay.id, network.id)
                        .await
                        .map_err(|e| e.to_string())?;
                }
                store
                    .audit(&AuditEntry {
                        at: now,
                        actor,
                        action: "relay.enroll".to_string(),
                        network_id: None,
                        device_id: None,
                        relay_id: Some(relay.id),
                        detail: Some(name),
                    })
                    .await
                    .map_err(|e| e.to_string())?;
                println!("{}", relay_id(relay.id));
            }
        },
    }
    Ok(())
}

/// 160 bits from the kernel's random source. The coordinator never sees this
/// value again — only its hash is stored.
fn random_secret() -> Result<[u8; SECRET_LEN], String> {
    let mut secret = [0u8; SECRET_LEN];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut secret))
        .map_err(|error| format!("no randomness available: {error}"))?;
    Ok(secret)
}

async fn ensure_network(
    store: &Sqlite,
    name: &str,
    cidr: &str,
    mtu: u32,
    relay_policy: &str,
    actor: &str,
    now: Millis,
) -> Result<Network, String> {
    if let Some(existing) = store
        .network_by_name(name)
        .await
        .map_err(|e| e.to_string())?
    {
        return Ok(existing);
    }
    let created = store
        .insert_network(&NewNetwork {
            name: name.to_string(),
            cidr: cidr.to_string(),
            mtu,
            relay_policy: relay_policy.to_string(),
            created_at: now,
        })
        .await
        .map_err(|e| e.to_string())?;
    store
        .audit(&AuditEntry {
            at: now,
            actor: actor.to_string(),
            action: "network.create".to_string(),
            network_id: Some(created.id),
            device_id: None,
            relay_id: None,
            detail: Some(created.cidr.clone()),
        })
        .await
        .map_err(|e| e.to_string())?;
    Ok(created)
}

async fn set_relay_state(
    store: &Sqlite,
    relay_id: &str,
    state: RelayState,
    actor: &str,
    now: Millis,
) -> Result<(), String> {
    let relay = parse_relay_id(relay_id).ok_or_else(|| format!("not a relay id: {relay_id}"))?;
    store
        .set_relay_state(relay, state)
        .await
        .map_err(|e| e.to_string())?;
    store
        .audit(&AuditEntry {
            at: now,
            actor: actor.to_string(),
            action: format!("relay.{}", state.as_str()),
            network_id: None,
            device_id: None,
            relay_id: Some(relay),
            detail: None,
        })
        .await
        .map_err(|e| e.to_string())?;
    println!("{relay_id} is now {}", state.as_str());
    Ok(())
}
