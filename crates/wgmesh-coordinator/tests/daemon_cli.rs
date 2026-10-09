#![allow(clippy::unwrap_used, clippy::expect_used)]

// The daemon's own settings file, end to end: `wgmeshd run --config <path>` is how
// the NixOS module starts this binary, and the file it points at is the one the module
// renders. Before this the flag did not exist at all — the service could not start —
// and the values in it were never read.

use std::io::{BufRead as _, BufReader, Write as _};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

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
    let stdout = child.stdout.take().expect("stdout");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    let deadline = Instant::now() + Duration::from_secs(20);
    let address = loop {
        line.clear();
        let read = reader.read_line(&mut line).expect("stdout is readable");
        if let Some(rest) = line.trim().strip_prefix("wgmeshd listening on http://") {
            break rest.to_owned();
        }
        assert!(
            read > 0 && Instant::now() < deadline,
            "the daemon never said where it listens: {line:?}"
        );
    };

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
