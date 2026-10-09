#![allow(clippy::unwrap_used, clippy::expect_used)]

// The daemon's own settings file, end to end: `wgmeshd run --config <path>` is how
// the NixOS module starts this binary, and the file it points at is the one the module
// renders. Before this the flag did not exist at all — the service could not start —
// and the values in it were never read.

use std::io::{BufRead as _, BufReader, Write as _};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use wgmesh_app::coordinator::ports::{
    DeviceState, Directory, NewDevice, NewNetwork, NewRelay, Placement, RelayState,
};
use wgmesh_coordinator::store::Sqlite;
use wgmesh_core::{DeviceId, Millis, PublicKey, RelayId};

/// One HTTP request by hand, because the test is about the daemon and not about a
/// client library.
fn post(address: &str, path: &str, body: &str) -> String {
    let mut stream = TcpStream::connect(address).expect("the daemon is listening");
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {address}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(request.as_bytes())
        .expect("the request goes out");
    let mut response = String::new();
    std::io::Read::read_to_string(&mut stream, &mut response).expect("the response comes back");
    response
}

fn status_line(response: &str) -> &str {
    response.lines().next().unwrap_or_default()
}

#[test]
fn the_daemon_reads_the_settings_file_the_nixos_module_renders() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("coordinator.db");
    let config = dir.path().join("coordinator.toml");
    // The shape the module renders, with one knob that only the file can carry.
    std::fs::write(
        &config,
        format!(
            "[api]\nlisten = \"127.0.0.1:0\"\n\n\
             [database]\nurl = \"sqlite://{}?mode=rwc\"\n\n\
             [policy]\njoin_rate_limit_per_minute = 2\n",
            database.display()
        ),
    )
    .expect("the config is written");

    let mut child: Child = Command::new(env!("CARGO_BIN_EXE_wgmeshd"))
        .args(["run", "--config"])
        .arg(&config)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the daemon starts");

    // `api.listen` says port 0, so the daemon picks one and says which.
    let address = wait_for_address(&mut child);

    // The allowance came from the file, so the third request is refused. (Each
    // request brings a token that does not exist, which the handler will refuse for
    // its own reason — the limiter counts before any handler runs.)
    let body =
        r#"{"token":"WGMESH-NOPE-NOPE-NOPE","name":"n","wg_pubkey":"AAAA","api_pubkey":"BBBB"}"#;
    for index in 0..2 {
        let response = post(&address, "/v1/join", body);
        assert!(
            !status_line(&response).contains("429"),
            "request {index} inside the allowance was refused: {}",
            status_line(&response)
        );
    }
    let refused = post(&address, "/v1/join", body);
    assert!(
        status_line(&refused).contains("429"),
        "the file's allowance of two per minute did not reach the limiter: {}",
        status_line(&refused)
    );
    assert!(
        refused.to_lowercase().contains("retry-after"),
        "a refusal has to say how long to wait:\n{refused}"
    );

    let _ = Command::new("kill")
        .arg("-TERM")
        .arg(child.id().to_string())
        .status();
    let _ = child.wait();
    assert!(database.exists(), "the database the file named was opened");
}

/// The line the daemon prints once it is listening. `api.listen` says port 0, so
/// the daemon picks a port and this is the only place it is written down.
fn wait_for_address(child: &mut Child) -> String {
    let stdout = child.stdout.take().expect("stdout");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        line.clear();
        let read = reader.read_line(&mut line).expect("stdout is readable");
        if let Some(rest) = line.trim().strip_prefix("wgmeshd listening on http://") {
            return rest.to_owned();
        }
        assert!(
            read > 0 && Instant::now() < deadline,
            "the daemon never said where it listens: {line:?}"
        );
    }
}

/// The wall clock the daemon itself reads, for the two facts the test has to place
/// in real time rather than on a fixed one.
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the clock is past the epoch")
        .as_millis() as u64
}

/// The daemon's own timer, end to end: a pair is left on a relay that is not
/// answering, the daemon is started the way the NixOS module starts it, and the
/// pair moves with nobody calling anything.
///
/// The other tests around this one call the sweep and the watch themselves. This is
/// the one that says the running daemon starts them at all. Which numbers the sweep
/// then judges a relay by is
/// [`the_deadline_in_the_settings_file_is_the_one_the_running_daemon_sweeps_by`]'s
/// question, in this file as well: a pair on a relay that has *never* reported is
/// quiet under any policy, so this test on its own cannot tell a daemon that read
/// the file from one that ignored it.
#[tokio::test]
async fn the_running_daemon_re_homes_a_pair_without_being_asked() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("coordinator.db");
    let config = dir.path().join("coordinator.toml");
    let url = format!("sqlite://{}?mode=rwc", database.display());

    // The fleet as it stands before the daemon starts. relay-1 has never reported,
    // which is not a place a pair may be; relay-2 reports once the daemon is up,
    // which is what a relay does on its own timer anyway. Both devices hold a slot
    // on both relays, so a re-assignment needs no new round trip.
    let store = Sqlite::open(&url, 4).await.expect("open");
    store.migrate().await.expect("migrate");
    let at = Millis::from_millis(now_ms());
    let network = store
        .insert_network(&NewNetwork {
            name: "prod".to_string(),
            cidr: "10.77.0.0/16".to_string(),
            mtu: 1420,
            relay_policy: "any".to_string(),
            created_at: at,
        })
        .await
        .expect("network")
        .id;
    let mut relays: Vec<RelayId> = Vec::new();
    for (name, host, key) in [
        ("relay-1", "198.51.100.4", 1_u8),
        ("relay-2", "198.51.100.5", 2_u8),
    ] {
        let relay = store
            .insert_relay(&NewRelay {
                name: name.to_string(),
                api_pubkey: PublicKey::from_bytes([key; 32]),
                state: RelayState::Active,
                endpoint_host: host.to_string(),
                port_range: "51900-51999".to_string(),
                region: None,
                provider: None,
                operator: None,
                created_at: at,
            })
            .await
            .expect("relay")
            .id;
        store
            .link_relay_network(relay, network)
            .await
            .expect("link");
        relays.push(relay);
    }
    let (first, second) = (relays[0], relays[1]);
    let mut devices: Vec<DeviceId> = Vec::new();
    for (index, name) in ["a", "b"].into_iter().enumerate() {
        let device = store
            .insert_device(&NewDevice {
                network_id: network,
                name: name.to_string(),
                wg_pubkey: PublicKey::from_bytes([7 + index as u8; 32]),
                api_pubkey: PublicKey::from_bytes([100 + index as u8; 32]),
                tunnel_ip: format!("10.77.0.{}", 7 + index),
                state: DeviceState::Active,
                advertised: Vec::new(),
                created_at: at,
            })
            .await
            .expect("device")
            .id;
        for (relay, base) in [(first, 54_000_u16), (second, 54_100)] {
            store
                .assign_slot(relay, device, base + index as u16)
                .await
                .expect("slot");
        }
        devices.push(device);
    }
    let (a, b) = (devices[0], devices[1]);
    store.assign_pair(a, b, first, at).await.expect("assign");
    let before = store.config_version().await.expect("version");

    // Two seconds for one heartbeat and three misses before a relay is gone: the
    // file's numbers, which are what the daemon has to read.
    std::fs::write(
        &config,
        format!(
            "[api]\nlisten = \"127.0.0.1:0\"\n\n\
             [database]\nurl = \"{url}\"\n\n\
             [relay]\nheartbeat_timeout_secs = 2\nreassign_after_misses = 3\n"
        ),
    )
    .expect("the config is written");

    let mut child: Child = Command::new(env!("CARGO_BIN_EXE_wgmeshd"))
        .args(["run", "--config"])
        .arg(&config)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the daemon starts");
    let _address = wait_for_address(&mut child);

    // relay-2 is up: this heartbeat is the only thing the coordinator ever hears
    // from a relay, and it is the relay that would send it.
    store
        .record_heartbeat(second, Millis::from_millis(now_ms()), None)
        .await
        .expect("heartbeat");

    // Nobody runs anything now. The pair is on a relay that has never reported, a
    // fresh relay is in the pool, and the daemon's own sweep is the only actor left.
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let on = store.relay_for_pair(a, b).await.expect("pair");
        if on == Some(second) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the running daemon never re-homed the pair: it is still on {on:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    assert_ne!(
        store.config_version().await.expect("version"),
        before,
        "the re-homing has to change the version a stream pushes"
    );

    let _ = Command::new("kill")
        .arg("-TERM")
        .arg(child.id().to_string())
        .status();
    let _ = child.wait();
}

/// The file's own numbers, end to end: the deadline `[relay]` states is the one the
/// running daemon's sweep judges a relay by.
///
/// [`the_running_daemon_re_homes_a_pair_without_being_asked`] says the daemon starts
/// the sweep at all. It cannot say the sweep reads the file: its pair sits on a relay
/// that has never reported, `PlacePolicy::is_fresh(None, _)` is false, and that relay
/// is therefore quiet under *every* policy — including the shipped default a daemon
/// that never read `[relay]` would build. This test moves the seed into the gap
/// between the two deadlines, where the answer depends on which policy the daemon
/// built.
///
/// relay-1 last reported four seconds ago. The file's deadline — `heartbeat_timeout_secs
/// = 1` times `reassign_after_misses = 2` — is two seconds, so relay-1 has gone quiet
/// and its pair has to move. The shipped default's is five times three, fifteen
/// seconds, so a daemon that read the numbers and did nothing with them still calls
/// relay-1 fresh — and relay-1 is the relay the pair is already on, so the sticky rule
/// in `select_relay` keeps the pair exactly where it is.
///
/// The pair is given six seconds. The daemon needs a fraction of that at the file's
/// pace, which is a sweep every 250ms for a one-second window. The number that matters
/// is the other side of the gap: a daemon sweeping by the shipped policy would need
/// eleven seconds before it reached the opposite reading — fifteen seconds of deadline
/// minus the four the seed is already old — so a daemon that ignored the file cannot
/// pass this test by being waited on.
#[tokio::test]
async fn the_deadline_in_the_settings_file_is_the_one_the_running_daemon_sweeps_by() {
    /// How far in the past relay-1's last heartbeat is placed: well past the file's
    /// two-second deadline, and nowhere near the shipped fifteen-second one.
    const RELAY_1_SILENT_FOR_MS: u64 = 4_000;
    /// How long the pair is given to move. See the note above: it has to stay under
    /// the eleven seconds the shipped policy would need.
    const RE_HOME_BUDGET: Duration = Duration::from_secs(6);

    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("coordinator.db");
    let config = dir.path().join("coordinator.toml");
    let url = format!("sqlite://{}?mode=rwc", database.display());

    // The fleet as it stands before the daemon starts. Both devices hold a slot on
    // both relays, so a re-assignment needs no new round trip.
    let store = Sqlite::open(&url, 4).await.expect("open");
    store.migrate().await.expect("migrate");
    let at = Millis::from_millis(now_ms());
    let network = store
        .insert_network(&NewNetwork {
            name: "prod".to_string(),
            cidr: "10.77.0.0/16".to_string(),
            mtu: 1420,
            relay_policy: "any".to_string(),
            created_at: at,
        })
        .await
        .expect("network")
        .id;
    let mut relays: Vec<RelayId> = Vec::new();
    for (name, host, key) in [
        ("relay-1", "198.51.100.4", 1_u8),
        ("relay-2", "198.51.100.5", 2_u8),
    ] {
        let relay = store
            .insert_relay(&NewRelay {
                name: name.to_string(),
                api_pubkey: PublicKey::from_bytes([key; 32]),
                state: RelayState::Active,
                endpoint_host: host.to_string(),
                port_range: "51900-51999".to_string(),
                region: None,
                provider: None,
                operator: None,
                created_at: at,
            })
            .await
            .expect("relay")
            .id;
        store
            .link_relay_network(relay, network)
            .await
            .expect("link");
        relays.push(relay);
    }
    let (first, second) = (relays[0], relays[1]);
    let mut devices: Vec<DeviceId> = Vec::new();
    for (index, name) in ["a", "b"].into_iter().enumerate() {
        let device = store
            .insert_device(&NewDevice {
                network_id: network,
                name: name.to_string(),
                wg_pubkey: PublicKey::from_bytes([7 + index as u8; 32]),
                api_pubkey: PublicKey::from_bytes([100 + index as u8; 32]),
                tunnel_ip: format!("10.77.0.{}", 7 + index),
                state: DeviceState::Active,
                advertised: Vec::new(),
                created_at: at,
            })
            .await
            .expect("device")
            .id;
        for (relay, base) in [(first, 54_000_u16), (second, 54_100)] {
            store
                .assign_slot(relay, device, base + index as u16)
                .await
                .expect("slot");
        }
        devices.push(device);
    }
    let (a, b) = (devices[0], devices[1]);
    store.assign_pair(a, b, first, at).await.expect("assign");

    // The seed, and the whole point of this test: relay-1 *has* reported, but not
    // within the deadline the file is about to state. relay-2 has never reported —
    // nothing has been heard from it — and starts reporting once the daemon is up.
    store
        .record_heartbeat(
            first,
            Millis::from_millis(now_ms().saturating_sub(RELAY_1_SILENT_FOR_MS)),
            None,
        )
        .await
        .expect("heartbeat");
    let before = store.config_version().await.expect("version");

    // One second is the window a heartbeat is given and two misses are what the
    // operator allows before a relay is gone: a two-second deadline, which the seed
    // above is already past by four seconds. The shipped default is five and three,
    // fifteen seconds, which the same seed is comfortably inside.
    std::fs::write(
        &config,
        format!(
            "[api]\nlisten = \"127.0.0.1:0\"\n\n\
             [database]\nurl = \"{url}\"\n\n\
             [relay]\nheartbeat_timeout_secs = 1\nreassign_after_misses = 2\n"
        ),
    )
    .expect("the config is written");

    let mut child: Child = Command::new(env!("CARGO_BIN_EXE_wgmeshd"))
        .args(["run", "--config"])
        .arg(&config)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the daemon starts");
    let _address = wait_for_address(&mut child);

    // From here nothing in this process runs a sweep, a watch or a placement: the
    // daemon's own timer is the only actor left. All the loop does is keep relay-2
    // reporting — the way a live relay does, and the way the file's one-second window
    // expects — and watch where the pair is.
    let deadline = Instant::now() + RE_HOME_BUDGET;
    loop {
        store
            .record_heartbeat(second, Millis::from_millis(now_ms()), None)
            .await
            .expect("heartbeat");
        let on = store.relay_for_pair(a, b).await.expect("pair");
        if on == Some(second) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the running daemon did not move the pair off a relay that has been silent \
             for longer than the file's two-second deadline: the pair is still on \
             {on:?}. A daemon sweeping by the shipped fifteen-second policy would look \
             exactly like this."
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    assert_ne!(
        store.config_version().await.expect("version"),
        before,
        "the re-homing has to change the version a stream pushes"
    );

    let _ = Command::new("kill")
        .arg("-TERM")
        .arg(child.id().to_string())
        .status();
    let _ = child.wait();
}
