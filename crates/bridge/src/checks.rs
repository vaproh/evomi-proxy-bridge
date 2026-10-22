//! Independent exit-IP and geo checks through the upstream proxy (blocking).
//!
//! CONNECTs to the target through the upstream (TLS-wrapping the upstream leg
//! when configured), then GETs the check endpoint. Nested TLS (TLS target
//! inside a TLS upstream) works because rustls streams compose: a
//! `StreamOwned` presents Read+Write and can itself back another one.

use std::io::{BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use crate::proxy::redact;

const MAX_HEAD: usize = 65536;
const IP_CHECK_HOST: &str = "ip.evomi.com";
const IP_CHECK_PORT: u16 = 443;
const IP_CHECK_PATH: &str = "/s";

#[derive(Debug)]
pub enum CheckError {
    Auth,
    Refused(String),
    Net(String),
    Empty,
}

impl std::fmt::Display for CheckError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CheckError::Auth => f.write_str("upstream rejected credentials (407)"),
            CheckError::Refused(s) => write!(f, "CONNECT refused: {s}"),
            CheckError::Net(s) => write!(f, "network error: {s}"),
            CheckError::Empty => f.write_str("empty check response"),
        }
    }
}

impl std::error::Error for CheckError {}

fn root_store(cafile: &str) -> Result<rustls::RootCertStore, CheckError> {
    let mut store = rustls::RootCertStore::empty();
    store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if !cafile.is_empty() {
        let file = std::fs::File::open(cafile).map_err(|e| CheckError::Net(format!("open cafile: {e}")))?;
        let mut reader = BufReader::new(file);
        for cert in rustls_pemfile::certs(&mut reader) {
            let cert = cert.map_err(|e| CheckError::Net(format!("read cafile: {e}")))?;
            store.add(cert).map_err(|e| CheckError::Net(format!("bad cafile cert: {e:?}")))?;
        }
    }
    Ok(store)
}

fn client_config(cafile: &str) -> Result<Arc<rustls::ClientConfig>, CheckError> {
    Ok(Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store(cafile)?)
            .with_no_client_auth(),
    ))
}

fn server_name(host: &str) -> Result<rustls::pki_types::ServerName<'static>, CheckError> {
    rustls::pki_types::ServerName::try_from(host)
        .map(|n| {
            let n: rustls::pki_types::ServerName<'_> = n;
            n.to_owned()
        })
        .map_err(|_| CheckError::Net(format!("bad TLS hostname: {host}")))
}

/// Read until end of headers. Returns (head, extra bytes already read).
fn read_head(sock: &mut dyn Read) -> Result<(Vec<u8>, Vec<u8>), CheckError> {
    // Note: read timeouts are set on the underlying TcpStream; they apply
    // through every TLS layer stacked above it.
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let extra = buf[pos + 4..].to_vec();
            buf.truncate(pos + 4);
            return Ok((buf, extra));
        }
        if buf.len() > MAX_HEAD {
            return Err(CheckError::Net("oversize response head".into()));
        }
        match sock.read(&mut chunk) {
            Ok(0) => return Err(CheckError::Net("connection closed".into())),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) => return Err(CheckError::Net(e.to_string())),
        }
    }
}

fn status_code(head: &[u8]) -> String {
    let line = head.split(|&b| b == b'\r').next().unwrap_or(b"");
    String::from_utf8_lossy(line).split_whitespace().nth(1).unwrap_or("").to_string()
}

fn status_line(head: &[u8]) -> String {
    let line = head.split(|&b| b == b'\r').next().unwrap_or(b"");
    String::from_utf8_lossy(line).into_owned()
}

fn resolve(host: &str, port: u16, timeout: Duration) -> Result<SocketAddr, CheckError> {
    format!("{host}:{port}")
        .to_socket_addrs()
        .map_err(|e| CheckError::Net(format!("resolve {host}: {e}")))?
        .next()
        .ok_or_else(|| CheckError::Net(format!("resolve {host}: no address")))
        .inspect(|_| {
            let _ = timeout;
        })
}

#[allow(clippy::too_many_arguments)]
fn get_via_upstream(
    username: &str,
    password: &str,
    upstream_host: &str,
    upstream_port: u16,
    upstream_tls: bool,
    target_host: &str,
    target_port: u16,
    path: &str,
    target_tls: bool,
    timeout: Duration,
    cafile: &str,
) -> Result<Vec<u8>, CheckError> {
    let token = format!("{username}:{password}");
    // base64 without extra deps
    let token = {
        const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let b = token.as_bytes();
        let mut o = String::new();
        for c in b.chunks(3) {
            let mut n = 0u32;
            for (j, &x) in c.iter().enumerate() {
                n |= (x as u32) << (16 - 8 * j);
            }
            for j in 0..4 - (3 - c.len()) {
                o.push(A[((n >> (18 - 6 * j)) & 63) as usize] as char);
            }
            for _ in 0..3 - c.len() {
                o.push('=');
            }
        }
        o
    };
    let addr = resolve(upstream_host, upstream_port, timeout)?;
    let tcp = TcpStream::connect_timeout(&addr, timeout).map_err(|e| CheckError::Net(format!("connect {upstream_host}: {e}")))?;
    tcp.set_read_timeout(Some(timeout)).map_err(|e| CheckError::Net(e.to_string()))?;
    tcp.set_write_timeout(Some(timeout)).map_err(|e| CheckError::Net(e.to_string()))?;

    // Box the tunnel so both plain and TLS legs share one type downstream.
    enum Tunnel {
        Plain(TcpStream),
        Tls(rustls::StreamOwned<rustls::ClientConnection, TcpStream>),
    }
    impl Read for Tunnel {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            match self {
                Tunnel::Plain(s) => s.read(buf),
                Tunnel::Tls(s) => s.read(buf),
            }
        }
    }
    impl Write for Tunnel {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            match self {
                Tunnel::Plain(s) => s.write(buf),
                Tunnel::Tls(s) => s.write(buf),
            }
        }
        fn flush(&mut self) -> std::io::Result<()> {
            match self {
                Tunnel::Plain(s) => s.flush(),
                Tunnel::Tls(s) => s.flush(),
            }
        }
    }

    let mut tunnel = if upstream_tls {
        let cfg = client_config(cafile)?;
        let conn = rustls::ClientConnection::new(cfg, server_name(upstream_host)?)
            .map_err(|e| CheckError::Net(format!("TLS setup: {e}")))?;
        let mut s = rustls::StreamOwned::new(conn, tcp);
        s.flush().map_err(|e| CheckError::Net(format!("upstream TLS handshake: {e}")))?;
        Tunnel::Tls(s)
    } else {
        Tunnel::Plain(tcp)
    };

    tunnel
        .write_all(format!("CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\nProxy-Authorization: Basic {token}\r\n\r\n").as_bytes())
        .map_err(|e| CheckError::Net(e.to_string()))?;
    tunnel.flush().map_err(|e| CheckError::Net(e.to_string()))?;
    let (head, extra) = read_head(&mut tunnel)?;
    match status_code(&head).as_str() {
        "407" => return Err(CheckError::Auth),
        "200" => {}
        _ => return Err(CheckError::Refused(redact(&status_line(&head)))),
    }

    let mut body: Vec<u8> = Vec::new();
    if target_tls {
        let cfg = client_config(cafile)?;
        return match &mut tunnel {
            Tunnel::Plain(tcp) => https_get(tcp, &cfg, target_host, path, timeout, &extra),
            Tunnel::Tls(tls1) => https_get(tls1, &cfg, target_host, path, timeout, &extra),
        };
    }
    // Plain HTTP through the tunnel.
    tunnel
        .write_all(format!("GET {path} HTTP/1.1\r\nHost: {target_host}\r\nConnection: close\r\n\r\n").as_bytes())
        .map_err(|e| CheckError::Net(e.to_string()))?;
    tunnel.flush().map_err(|e| CheckError::Net(e.to_string()))?;
    body.extend_from_slice(&extra);
    loop {
        let mut chunk = [0u8; 4096];
        match tunnel.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => body.extend_from_slice(&chunk[..n]),
            Err(e) => {
                if e.kind() == std::io::ErrorKind::TimedOut || e.kind() == std::io::ErrorKind::WouldBlock {
                    break;
                }
                return Err(CheckError::Net(e.to_string()));
            }
        }
        if body.len() > 262144 {
            break;
        }
    }
    Ok(split_body(&body))
}

/// HTTPS GET over any Read+Write transport. When the transport is itself an
/// (upstream) TLS stream, rustls nests cleanly: StreamOwned<ClientConnection,
/// Stream<ClientConnection, _>> composes because inner streams are Read+Write.
fn https_get<S: Read + Write>(
    transport: &mut S,
    cfg: &Arc<rustls::ClientConfig>,
    host: &str,
    path: &str,
    _timeout: Duration,
    extra: &[u8],
) -> Result<Vec<u8>, CheckError> {
    // Prepend any CONNECT over-read bytes ahead of the transport so the outer
    // handshake sees the exact server byte stream.
    struct Prefix<'a, S: Read + Write> {
        prefix: Vec<u8>,
        inner: &'a mut S,
    }
    impl<S: Read + Write> Read for Prefix<'_, S> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if !self.prefix.is_empty() {
                let n = self.prefix.len().min(buf.len());
                buf[..n].copy_from_slice(&self.prefix[..n]);
                self.prefix.drain(..n);
                return Ok(n);
            }
            self.inner.read(buf)
        }
    }
    impl<S: Read + Write> Write for Prefix<'_, S> {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.inner.write(buf)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.inner.flush()
        }
    }
    let mut chained = Prefix { prefix: extra.to_vec(), inner: transport };
    let conn2 = rustls::ClientConnection::new(Arc::clone(cfg), server_name(host)?)
        .map_err(|e| CheckError::Net(format!("TLS setup: {e}")))?;
    let mut outer2 = rustls::StreamOwned::new(conn2, &mut chained);
    let mut resp: Vec<u8> = Vec::new();
    outer2
        .write_all(format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes())
        .map_err(|e| CheckError::Net(format!("target write: {e}")))?;
    outer2.flush().map_err(|e| CheckError::Net(format!("target write: {e}")))?;
    loop {
        let mut chunk = [0u8; 4096];
        match outer2.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => resp.extend_from_slice(&chunk[..n]),
            Err(e) => {
                // Unclean close (no close_notify) after a complete response
                // counts as EOF, mirroring Python ssl behavior.
                if response_complete(&resp) {
                    break;
                }
                return Err(CheckError::Net(format!("target read: {e}")));
            }
        }
        if resp.len() > 262144 {
            break;
        }
    }
    Ok(split_body(&resp))
}

fn split_body(resp: &[u8]) -> Vec<u8> {
    if let Some(pos) = resp.windows(4).position(|w| w == b"\r\n\r\n") {
        resp[pos + 4..].to_vec()
    } else {
        resp.to_vec()
    }
}

/// True when resp holds complete headers plus the declared body (if any).
/// Servers that close without close_notify still count as complete when the
/// declared body is fully present (matches Python ssl leniency, 1:1 parity).
fn response_complete(resp: &[u8]) -> bool {
    let Some(pos) = resp.windows(4).position(|w| w == b"\r\n\r\n") else {
        return false;
    };
    let head = String::from_utf8_lossy(&resp[..pos]);
    let body_len = resp.len() - (pos + 4);
    for line in head.lines().skip(1) {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                if let Ok(n) = v.trim().parse::<usize>() {
                    return body_len >= n;
                }
            }
        }
    }
    // No declared length: body runs to close; any complete head counts.
    true
}

#[derive(Debug, Clone, Default)]
pub struct GeoInfo {
    pub country: String,
    pub country_code: String,
    pub region: String,
    pub city: String,
    pub isp: String,
    pub org: String,
    pub query: String,
}

fn json_field(body: &[u8], key: &str) -> String {
    let text = String::from_utf8_lossy(body);
    let needle = format!("\"{key}\"");
    let Some(mut pos) = text.find(&needle) else { return String::new() };
    pos += needle.len();
    let rest = &text[pos..];
    let Some(colon) = rest.find(':') else { return String::new() };
    let mut val = rest[colon + 1..].trim_start().to_string();
    if val.starts_with('"') {
        val.remove(0);
        let mut out = String::new();
        let mut esc = false;
        for c in val.chars() {
            if esc {
                out.push(c);
                esc = false;
            } else if c == '\\' {
                esc = true;
            } else if c == '"' {
                break;
            } else {
                out.push(c);
            }
        }
        return out;
    }
    val.split([',', '}']).next().unwrap_or("").trim().to_string()
}

/// Public exit IP seen through the upstream (blocking; run off the async loop).
#[allow(clippy::too_many_arguments)]
pub fn check_exit_ip_blocking(
    username: &str,
    password: &str,
    upstream_host: &str,
    upstream_port: u16,
    upstream_tls: bool,
    timeout: Duration,
    cafile: &str,
) -> Result<String, CheckError> {
    check_exit_ip_blocking_via(
        username, password, upstream_host, upstream_port, upstream_tls,
        IP_CHECK_HOST, IP_CHECK_PORT, IP_CHECK_PATH, timeout, cafile,
    )
}

/// Same, but against an explicit target (used by tests with a local fixture).
#[allow(clippy::too_many_arguments)]
pub fn check_exit_ip_blocking_via(
    username: &str,
    password: &str,
    upstream_host: &str,
    upstream_port: u16,
    upstream_tls: bool,
    target_host: &str,
    target_port: u16,
    target_path: &str,
    timeout: Duration,
    cafile: &str,
) -> Result<String, CheckError> {
    let body = get_via_upstream(
        username, password, upstream_host, upstream_port, upstream_tls,
        target_host, target_port, target_path, true, timeout, cafile,
    )?;
    let ip = String::from_utf8_lossy(&body).split_whitespace().next().unwrap_or("").to_string();
    if ip.is_empty() {
        return Err(CheckError::Empty);
    }
    Ok(ip)
}

/// Best-effort geo lookup of the exit IP via ip-api.com (free tier, through proxy).
pub fn check_geo_blocking(
    username: &str,
    password: &str,
    upstream_host: &str,
    upstream_port: u16,
    upstream_tls: bool,
    ip: &str,
    timeout: Duration,
) -> GeoInfo {
    let path = format!("/json/{ip}?fields=status,message,country,countryCode,regionName,city,isp,org,as,query");
    let Ok(body) = get_via_upstream(
        username, password, upstream_host, upstream_port, upstream_tls,
        "ip-api.com", 80, &path, false, timeout, "",
    ) else {
        return GeoInfo::default();
    };
    if json_field(&body, "status") != "success" {
        return GeoInfo::default();
    }
    GeoInfo {
        country: json_field(&body, "country"),
        country_code: json_field(&body, "countryCode"),
        region: json_field(&body, "regionName"),
        city: json_field(&body, "city"),
        isp: json_field(&body, "isp"),
        org: json_field(&body, "org"),
        query: json_field(&body, "query"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn geo_field_extraction() {
        let body = br#"{"status":"success","country":"Germany","countryCode":"DE","regionName":"Bavaria","city":"Munich","isp":"ExampleNet","org":"ExampleOrg","as":"AS123","query":"1.2.3.4"}"#;
        assert_eq!(json_field(body, "country"), "Germany");
        assert_eq!(json_field(body, "city"), "Munich");
        assert_eq!(json_field(body, "missing"), "");
        assert_eq!(json_field(br#"{"status":"fail"}"#, "country"), "");
    }
}
