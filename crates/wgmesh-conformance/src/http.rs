// A blocking, dependency-light HTTP/1.1 client and server.
//
// This is not a general HTTP implementation: one request per connection, one
// response, `Connection: close`, a JSON body, and a fixed set of methods. That
// is all the control plane needs, and it keeps the coordinator's dependency
// surface (and therefore its audit surface) small.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use serde::Serialize;
use serde::de::DeserializeOwned;

const IO_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

impl Response {
    pub fn json<T: Serialize>(value: &T) -> Self {
        match serde_json::to_vec(value) {
            Ok(body) => Self { status: 200, body },
            Err(error) => Self {
                status: 500,
                body: format!("{{\"error\":\"{error}\"}}").into_bytes(),
            },
        }
    }

    pub fn text(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            body: body.into(),
        }
    }

    pub fn error(status: u16, message: &str) -> Self {
        Self {
            status,
            body: format!("{{\"error\":\"{message}\"}}").into_bytes(),
        }
    }
}

/// Serve requests until the listener fails, one thread per connection.
pub fn serve<F>(listener: TcpListener, handler: F)
where
    F: Fn(Request) -> Response + Send + Sync + 'static,
{
    let handler = Arc::new(handler);
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let handler = Arc::clone(&handler);
        thread::spawn(move || {
            let _ = respond(stream, handler.as_ref());
        });
    }
}

fn respond<F>(stream: TcpStream, handler: &F) -> std::io::Result<()>
where
    F: Fn(Request) -> Response,
{
    stream.set_nodelay(true).ok();
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let mut reader = BufReader::new(stream.try_clone()?);

    let mut request_line = String::new();
    if reader.read_line(&mut request_line)? == 0 {
        return Ok(());
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let path = parts.next().unwrap_or_default().to_string();

    let mut content_length = 0usize;
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header)? == 0 {
            break;
        }
        let header = header.trim_end_matches(['\r', '\n']);
        if header.is_empty() {
            break;
        }
        if let Some(value) = header.to_ascii_lowercase().strip_prefix("content-length:") {
            content_length = value.trim().parse().unwrap_or(0);
        }
    }

    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body)?;
    }

    let response = handler(Request { method, path, body });
    let reason = match response.status {
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        503 => "Service Unavailable",
        _ => "Status",
    };
    let mut out = stream;
    write!(
        out,
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response.status,
        reason,
        response.body.len()
    )?;
    out.write_all(&response.body)?;
    out.flush()
}

fn split_url(url: &str) -> std::io::Result<(SocketAddr, String)> {
    let rest = url.strip_prefix("http://").unwrap_or(url);
    let (authority, path) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, "/"),
    };
    let authority = if authority.contains(':') {
        authority.to_string()
    } else {
        format!("{authority}:80")
    };
    let addr: SocketAddr = authority
        .parse()
        .map_err(|error| std::io::Error::other(format!("bad url {url}: {error}")))?;
    Ok((addr, path.to_string()))
}

pub fn request(method: &str, url: &str, body: &[u8]) -> std::io::Result<(u16, Vec<u8>)> {
    let (addr, path) = split_url(url)?;
    let mut stream = TcpStream::connect(addr)?;
    stream.set_nodelay(true).ok();
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(body)?;
    stream.flush()?;

    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    reader.read_line(&mut status_line)?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);

    let mut content_length: Option<usize> = None;
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header)? == 0 {
            break;
        }
        let header = header.trim_end_matches(['\r', '\n']);
        if header.is_empty() {
            break;
        }
        if let Some(value) = header.to_ascii_lowercase().strip_prefix("content-length:") {
            content_length = value.trim().parse().ok();
        }
    }

    let mut rest = Vec::new();
    let _ = reader.read_to_end(&mut rest);
    let body = match content_length {
        Some(len) if rest.len() >= len => rest[..len].to_vec(),
        _ => rest,
    };
    Ok((status, body))
}

pub fn post_json<T: Serialize, R: DeserializeOwned>(url: &str, value: &T) -> std::io::Result<R> {
    let body = serde_json::to_vec(value).map_err(std::io::Error::other)?;
    let (status, raw) = request("POST", url, &body)?;
    if status != 200 {
        return Err(std::io::Error::other(format!(
            "POST {url} -> {status}: {}",
            String::from_utf8_lossy(&raw)
        )));
    }
    serde_json::from_slice(&raw).map_err(std::io::Error::other)
}

pub fn get_json<R: DeserializeOwned>(url: &str) -> std::io::Result<R> {
    let (status, raw) = request("GET", url, &[])?;
    if status != 200 {
        return Err(std::io::Error::other(format!(
            "GET {url} -> {status}: {}",
            String::from_utf8_lossy(&raw)
        )));
    }
    serde_json::from_slice(&raw).map_err(std::io::Error::other)
}
