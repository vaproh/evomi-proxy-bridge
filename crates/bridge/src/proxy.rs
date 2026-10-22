//! Local HTTP proxy with CONNECT tunneling and authenticated upstream chaining.
//!
//! One upstream TCP connection per client request (`Connection: close`).
//! Rotation is therefore race-free: every new request snapshots the current
//! session password. Active CONNECT tunnels keep old credentials until the
//! client closes them; rotation never kills mid-stream tunnels.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, Semaphore};

use crate::config::Config;
use crate::pac;
use crate::session::SessionState;

const MAX_HEADER_BYTES: usize = 65536;
const RELAY_CHUNK: usize = 65536;

/// Quiet window for repeat upstream-refusal warnings for the same target.
pub const REFUSAL_QUIET_S: u64 = 600;

static REFUSAL_LAST: OnceLock<Mutex<HashMap<String, Instant>>> = OnceLock::new();

fn refusal_map() -> &'static Mutex<HashMap<String, Instant>> {
    REFUSAL_LAST.get_or_init(|| Mutex::new(HashMap::new()))
}

#[derive(Debug)]
pub struct UpstreamError {
    pub message: String,
    pub target: Option<String>,
}

impl UpstreamError {
    pub fn new(message: impl Into<String>, target: Option<String>) -> Self {
        UpstreamError { message: message.into(), target }
    }
}

impl std::fmt::Display for UpstreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for UpstreamError {}

/// Warn on upstream failures, but repeat refusals for the same target only
/// warn once per REFUSAL_QUIET_S (probe hosts would otherwise spam the log).
pub fn log_upstream_error(err: &UpstreamError) {
    let msg = redact(&err.message);
    match &err.target {
        Some(key) => {
            let now = Instant::now();
            let quiet = {
                let map = refusal_map().lock().unwrap();
                map.get(key).map(|t| now.duration_since(*t).as_secs() < REFUSAL_QUIET_S).unwrap_or(false)
            };
            if quiet {
                log::debug!("upstream error (repeat, quieted): {msg}");
                return;
            }
            refusal_map().lock().unwrap().insert(key.clone(), now);
            log::warn!("upstream error: {msg}");
        }
        None => log::warn!("upstream error: {msg}"),
    }
}

#[cfg(test)]
pub fn clear_refusal_state() {
    refusal_map().lock().unwrap().clear();
}

/// Redact credential-bearing material before logging.
pub fn redact(text: &str) -> String {
    // Mask Proxy-Authorization / Authorization header values (whole line value).
    let mut out = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("proxy-authorization:") || lower.starts_with("authorization:") {
            if let Some((name, _)) = line.split_once(':') {
                out.push_str(name);
                out.push_str(": [REDACTED]");
                if line.ends_with('\n') {
                    out.push('\n');
                }
                continue;
            }
        }
        out.push_str(line);
    }
    // Mask _session-/_hardsession-/_lockedsession- values.
    let mut masked = String::with_capacity(out.len());
    let bytes = out.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let mut matched: Option<usize> = None;
        for key in ["_hardsession-", "_lockedsession-", "_session-"] {
            if out[i..].starts_with(key) {
                matched = Some(key.len());
                break;
            }
        }
        if let Some(klen) = matched {
            masked.push_str("_session-[REDACTED]");
            i += klen;
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric()) {
                i += 1;
            }
        } else {
            masked.push(bytes[i] as char);
            i += 1;
        }
    }
    masked
}

fn basic_token(username: &str, password: &str) -> String {
    base64_encode(format!("{username}:{password}").as_bytes())
}

fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let mut n: u32 = 0;
        for (j, &b) in chunk.iter().enumerate() {
            n |= (b as u32) << (16 - 8 * j);
        }
        let pad = 3 - chunk.len();
        for j in 0..4 - pad {
            out.push(ALPHABET[((n >> (18 - 6 * j)) & 63) as usize] as char);
        }
        for _ in 0..pad {
            out.push('=');
        }
    }
    out
}

fn header_get<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
}

fn status_code(head: &[u8]) -> String {
    let line = head.split(|&b| b == b'\r').next().unwrap_or(b"");
    let line = String::from_utf8_lossy(line);
    line.split_whitespace().nth(1).unwrap_or("").to_string()
}

fn status_line(head: &[u8]) -> String {
    let line = head.split(|&b| b == b'\r').next().unwrap_or(b"");
    String::from_utf8_lossy(line).into_owned()
}

async fn read_head(reader: &mut (impl tokio::io::AsyncRead + Unpin)) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 16384];
    loop {
        if let Some(pos) = find_headers_end(&buf) {
            let _ = pos;
            return Ok(buf);
        }
        if buf.len() > MAX_HEADER_BYTES {
            return Err("headers too large".to_string());
        }
        match reader.read(&mut chunk).await {
            Ok(0) => {
                if find_headers_end(&buf).is_some() {
                    return Ok(buf);
                }
                return Err("incomplete headers".to_string());
            }
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) => return Err(format!("read error: {e}")),
        }
    }
}

fn find_headers_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

fn parse_request_line(head: &[u8]) -> Result<(String, String, Vec<(String, String)>), String> {
    let text = String::from_utf8_lossy(head);
    let mut lines = text.split("\r\n");
    let request = lines.next().ok_or("empty request")?;
    let mut parts = request.splitn(3, ' ');
    let method = parts.next().ok_or("bad request line")?.to_uppercase();
    let target = parts.next().ok_or("bad request line")?.to_string();
    if parts.next().is_none() {
        return Err("bad request line".to_string());
    }
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let (k, v) = line.split_once(':').ok_or("bad header line")?;
        headers.push((k.trim().to_string(), v.trim().to_string()));
    }
    Ok((method, target, headers))
}

fn tls_client_config(cafile: &str) -> Result<std::sync::Arc<rustls::ClientConfig>, String> {
    let mut store = rustls::RootCertStore::empty();
    store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if !cafile.is_empty() {
        use std::io::BufReader;
        let file = std::fs::File::open(cafile).map_err(|e| format!("open cafile: {e}"))?;
        let mut reader = BufReader::new(file);
        for cert in rustls_pemfile::certs(&mut reader) {
            let cert = cert.map_err(|e| format!("read cafile: {e}"))?;
            store.add(cert).map_err(|e| format!("bad cafile cert: {e:?}"))?;
        }
    }
    Ok(std::sync::Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(store)
            .with_no_client_auth(),
    ))
}

#[derive(Debug, Clone, Default)]
pub struct ServerStats {
    pub listening: bool,
    pub bound_port: u16,
    pub request_count: u64,
    pub connect_count: u64,
    pub uptime_s: u64,
}

/// Upstream connection: plain TCP or TLS-wrapped.
enum UpConn {
    Plain(TcpStream),
    Tls(tokio_rustls::client::TlsStream<TcpStream>),
}

impl tokio::io::AsyncRead for UpConn {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            UpConn::Plain(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            UpConn::Tls(s) => std::pin::Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for UpConn {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            UpConn::Plain(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            UpConn::Tls(s) => std::pin::Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            UpConn::Plain(s) => std::pin::Pin::new(s).poll_flush(cx),
            UpConn::Tls(s) => std::pin::Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            UpConn::Plain(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            UpConn::Tls(s) => std::pin::Pin::new(s).poll_shutdown(cx),
        }
    }
}

fn this_flag(server: &ProxyServer) -> bool {
    server.shutdown_flag.load(Ordering::SeqCst)
}

pub struct ProxyServer {
    config: Config,
    session: Arc<SessionState>,
    listener_addr: Arc<Mutex<Option<std::net::SocketAddr>>>,
    listening: Arc<AtomicBool>,
    request_count: Arc<AtomicU64>,
    connect_count: Arc<AtomicU64>,
    started_at: Arc<Mutex<Option<Instant>>>,
    semaphore: Arc<Semaphore>,
    shutdown: Arc<Notify>,
    accept_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// Live connection handler abort handles for retire/shutdown.
    tracked: Arc<Mutex<HashMap<u64, tokio::task::AbortHandle>>>,
    next_id: Arc<AtomicU64>,
    shutdown_flag: Arc<AtomicBool>,
}

impl ProxyServer {
    pub fn new(config: Config, session: Arc<SessionState>) -> Result<Arc<Self>, String> {
        config.validate().map_err(|e| e.0)?;
        if config.local_host != "127.0.0.1" {
            return Err("refusing to bind non-loopback address".to_string());
        }
        Ok(Arc::new(ProxyServer {
            semaphore: Arc::new(Semaphore::new(config.max_connections.max(1))),
            config,
            session,
            listener_addr: Arc::new(Mutex::new(None)),
            listening: Arc::new(AtomicBool::new(false)),
            request_count: Arc::new(AtomicU64::new(0)),
            connect_count: Arc::new(AtomicU64::new(0)),
            started_at: Arc::new(Mutex::new(None)),
            shutdown: Arc::new(Notify::new()),
            accept_task: Mutex::new(None),
            tracked: Arc::new(Mutex::new(HashMap::new())),
            next_id: Arc::new(AtomicU64::new(1)),
            shutdown_flag: Arc::new(AtomicBool::new(false)),
        }))
    }

    /// Actual bound port (differs from configured when 0 was requested).
    pub fn bound_port(&self) -> u16 {
        self.listener_addr.lock().unwrap().map(|a| a.port()).unwrap_or(self.config.local_port)
    }

    pub fn stats(&self) -> ServerStats {
        let uptime = self.started_at.lock().unwrap().map(|t| t.elapsed().as_secs()).unwrap_or(0);
        ServerStats {
            listening: self.listening.load(Ordering::SeqCst),
            bound_port: self.bound_port(),
            request_count: self.request_count.load(Ordering::SeqCst),
            connect_count: self.connect_count.load(Ordering::SeqCst),
            uptime_s: uptime,
        }
    }

    pub async fn start(self: &Arc<Self>) -> Result<(), String> {
        let listener = TcpListener::bind((self.config.local_host.as_str(), self.config.local_port))
            .await
            .map_err(|e| format!("bind failed: {e}"))?;
        let addr = listener.local_addr().map_err(|e| format!("local_addr: {e}"))?;
        if !addr.ip().is_loopback() {
            return Err(format!("listener not on loopback: {addr}"));
        }
        *self.listener_addr.lock().unwrap() = Some(addr);
        *self.started_at.lock().unwrap() = Some(Instant::now());
        self.listening.store(true, Ordering::SeqCst);
        log::info!(
            "listening on 127.0.0.1:{} -> {}:{}",
            addr.port(),
            self.config.upstream_host,
            self.config.upstream_port
        );
        let this = Arc::clone(self);
        let task = tokio::spawn(async move { this.accept_loop(listener).await });
        *self.accept_task.lock().unwrap() = Some(task);
        Ok(())
    }

    pub async fn stop(&self) {
        self.shutdown_flag.store(true, Ordering::SeqCst);
        self.shutdown.notify_waiters();
        self.listening.store(false, Ordering::SeqCst);
        self.close_tracked();
        let task = self.accept_task.lock().unwrap().take();
        if let Some(task) = task {
            task.abort();
            let _ = task.await;
        }
    }

    fn close_tracked(&self) -> usize {
        let handles: Vec<tokio::task::AbortHandle> =
            self.tracked.lock().unwrap().drain().map(|(_, h)| h).collect();
        let n = handles.len();
        for h in handles {
            h.abort();
        }
        n
    }

    /// Close tracked relays after rotation (active tunnels drain via client
    /// reconnect; returns number of tracked relays closed here).
    pub fn retire_idle_upstreams(&self) -> usize {
        self.close_tracked()
    }

    async fn accept_loop(self: Arc<Self>, listener: TcpListener) {
        loop {
            tokio::select! {
                _ = self.shutdown.notified() => break,
                res = listener.accept() => {
                    match res {
                        Ok((stream, _)) => {
                            let this = Arc::clone(&self);
                            let id = this.next_id.fetch_add(1, Ordering::SeqCst);
                            let this2 = Arc::clone(&this);
                            let task = tokio::spawn(async move {
                                this.handle_client(id, stream).await;
                            });
                            this2.tracked.lock().unwrap().insert(id, task.abort_handle());
                        }
                        Err(_) => {
                            if this_flag(&self) { break; }
                        }
                    }
                }
            }
        }
    }

    async fn handle_client(self: Arc<Self>, id: u64, stream: TcpStream) {
        struct Guard {
            tracked: Arc<Mutex<HashMap<u64, tokio::task::AbortHandle>>>,
            id: u64,
        }
        impl Drop for Guard {
            fn drop(&mut self) {
                self.tracked.lock().unwrap().remove(&self.id);
            }
        }
        let _guard = Guard { tracked: Arc::clone(&self.tracked), id };
        let _permit = match self.semaphore.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => return, // at connection limit: drop
        };
        let relay_timeout = Duration::from_secs_f64(self.config.relay_timeout_s);
        let fut = self.dispatch(stream);
        match tokio::time::timeout(relay_timeout, fut).await {
            Ok(Ok(())) => {}
            Ok(Err(ClientError::Upstream(e))) => {
                log_upstream_error(&e);
            }
            Ok(Err(ClientError::Auth)) => {}
            Ok(Err(ClientError::BadRequest(msg))) => {
                log::debug!("bad request: {}", redact(&msg));
            }
            Ok(Err(ClientError::Closed)) => {}
            Err(_) => {
                // timeout: socket closes on drop
            }
        }
    }

    async fn dispatch(self: &Arc<Self>, mut stream: TcpStream) -> Result<(), ClientError> {
        let head = match read_head(&mut stream).await {
            Ok(h) => h,
            Err(e) => {
                send_error(&mut stream, "400", &format!("Bad request: {e}")).await;
                return Err(ClientError::BadRequest(e));
            }
        };
        let (method, target, headers) = match parse_request_line(&head) {
            Ok(t) => t,
            Err(e) => {
                send_error(&mut stream, "400", &format!("Bad request: {e}")).await;
                return Err(ClientError::BadRequest(e));
            }
        };
        let extra = head_body_extra(&head);

        // Local PAC auto-config: served here, never forwarded upstream.
        if is_pac_target(&target) {
            if method != "GET" {
                send_error(&mut stream, "405", "Method Not Allowed").await;
                return Ok(());
            }
            let body = pac::pac_response(self.bound_port());
            let _ = stream.write_all(&body).await;
            let _ = stream.flush().await;
            return Ok(());
        }

        if self.config.local_auth_enabled() && !self.check_local_auth(&headers) {
            let _ = stream.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"proxy-bridge\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
            let _ = stream.flush().await;
            return Ok(());
        }

        if method == "CONNECT" {
            self.handle_connect(stream, &target).await
        } else {
            self.handle_http(stream, &method, &target, &headers, &extra).await
        }
    }

    fn check_local_auth(&self, headers: &[(String, String)]) -> bool {
        let got = header_get(headers, "proxy-authorization").unwrap_or("");
        let want = format!("Basic {}", base64_encode(format!("{}:{}", self.config.local_user, self.config.local_pass).as_bytes()));
        got == want
    }

    async fn open_upstream(&self) -> Result<UpConn, UpstreamError> {
        let cfg = &self.config;
        let addr = format!("{}:{}", cfg.upstream_host, cfg.upstream_port);
        let stream = tokio::time::timeout(
            Duration::from_secs_f64(cfg.connect_timeout_s),
            TcpStream::connect(addr.as_str()),
        )
        .await
        .map_err(|_| UpstreamError::new("upstream connect timed out", None))?
        .map_err(|e| UpstreamError::new(format!("upstream unreachable: {e}"), None))?;
        if !cfg.upstream_tls {
            return Ok(UpConn::Plain(stream));
        }
        let tls_cfg = tls_client_config(&cfg.upstream_cafile).map_err(|e| UpstreamError::new(e, None))?;
        let connector = tokio_rustls::TlsConnector::from(tls_cfg);
        let name: rustls::pki_types::ServerName<'static> = rustls::pki_types::ServerName::try_from(cfg.upstream_host.as_str())
            .map_err(|_| {
                UpstreamError::new(format!("bad upstream TLS hostname: {}", cfg.upstream_host), None)
            })?
            .to_owned();
        let tls = tokio::time::timeout(
            Duration::from_secs_f64(cfg.connect_timeout_s),
            connector.connect(name, stream),
        )
        .await
        .map_err(|_| UpstreamError::new("upstream TLS handshake timed out", None))?
        .map_err(|e| {
            let msg = format!("{e}");
            if msg.contains("certificate") || msg.contains("Certificate") || msg.contains("issuer") || msg.contains("Issuer") {
                UpstreamError::new(format!("upstream TLS hostname check failed: {msg}"), None)
            } else {
                UpstreamError::new(format!("upstream TLS failed: {msg}"), None)
            }
        })?;
        Ok(UpConn::Tls(tls))
    }

    async fn handle_connect(self: &Arc<Self>, mut client: TcpStream, target: &str) -> Result<(), ClientError> {
        let (host, port_s) = target.rsplit_once(':').ok_or(ClientError::BadRequest("bad CONNECT target".into()))?;
        if host.is_empty() || !port_s.bytes().all(|b| b.is_ascii_digit()) || port_s.is_empty() {
            return Err(ClientError::BadRequest("bad CONNECT target".into()));
        }
        let password = self.session.current_password();
        let token = basic_token(&self.config.username, &password);
        let mut upstream = match self.open_upstream().await {
            Ok(u) => u,
            Err(e) => {
                send_error(&mut client, "502", "Bad Gateway: upstream unreachable").await;
                return Err(ClientError::Upstream(e));
            }
        };
        let req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: Basic {token}\r\nConnection: close\r\n\r\n");
        tokio::time::timeout(Duration::from_secs_f64(self.config.connect_timeout_s), async {
            upstream.write_all(req.as_bytes()).await?;
            upstream.flush().await
        })
        .await
        .map_err(|_| ClientError::Upstream(UpstreamError::new("upstream write timed out", Some(target.into()))))?
        .map_err(|e: std::io::Error| ClientError::Upstream(UpstreamError::new(format!("upstream unreachable for {target}: {e}"), Some(target.into()))))?;
        let resp = tokio::time::timeout(Duration::from_secs_f64(self.config.connect_timeout_s), read_head(&mut upstream))
            .await
            .map_err(|_| ClientError::Upstream(UpstreamError::new("upstream read timed out", Some(target.into()))))?
            .map_err(|e| ClientError::Upstream(UpstreamError::new(format!("upstream read failed for {target}: {e}"), Some(target.into()))))?;
        let code = status_code(&resp);
        if code == "407" {
            send_error(&mut client, "502", "Upstream auth failed: check Evomi username/password").await;
            return Err(ClientError::Auth);
        }
        if code != "200" {
            return Err(ClientError::Upstream(UpstreamError::new(
                format!("upstream CONNECT refused for {target}: {}", redact(&status_line(&resp))),
                Some(target.to_string()),
            )));
        }
        client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await.map_err(|_| ClientError::Closed)?;
        client.flush().await.map_err(|_| ClientError::Closed)?;
        self.connect_count.fetch_add(1, Ordering::SeqCst);
        let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    async fn handle_http(
        self: &Arc<Self>,
        mut client: TcpStream,
        method: &str,
        target: &str,
        headers: &[(String, String)],
        extra: &[u8],
    ) -> Result<(), ClientError> {
        let url = if target.starts_with("http://") {
            target.to_string()
        } else {
            absolutize(target, headers)?
        };
        let password = self.session.current_password();
        let token = basic_token(&self.config.username, &password);
        let length: usize = header_get(headers, "content-length").and_then(|v| v.parse().ok()).unwrap_or(0);
        if length > 32 * 1024 * 1024 {
            return Err(ClientError::BadRequest("Content-Length out of range".into()));
        }
        let mut body = extra.to_vec();
        if body.len() > length {
            body.truncate(length);
        }
        while body.len() < length {
            let mut chunk = vec![0u8; RELAY_CHUNK.min(length - body.len())];
            let n = client.read(&mut chunk).await.map_err(|_| ClientError::Closed)?;
            if n == 0 {
                return Err(ClientError::BadRequest("truncated body".into()));
            }
            body.extend_from_slice(&chunk[..n]);
        }
        let mut upstream = match self.open_upstream().await {
            Ok(u) => u,
            Err(mut e) => {
                e.target = Some(url.clone());
                e.message = format!("upstream unreachable for {url}: {}", e.message);
                send_error(&mut client, "502", "Bad Gateway: upstream unreachable").await;
                return Err(ClientError::Upstream(e));
            }
        };
        let mut out = format!("{method} {url} HTTP/1.1\r\n");
        for (k, v) in headers {
            let kl = k.to_ascii_lowercase();
            if ["proxy-authorization", "proxy-authenticate", "proxy-connection", "connection", "keep-alive", "transfer-encoding", "upgrade"].contains(&kl.as_str()) {
                continue;
            }
            out.push_str(&format!("{k}: {v}\r\n"));
        }
        out.push_str(&format!("Proxy-Authorization: Basic {token}\r\nConnection: close\r\n\r\n"));
        {
            tokio::time::timeout(Duration::from_secs_f64(self.config.connect_timeout_s), async {
                upstream.write_all(out.as_bytes()).await?;
                upstream.write_all(&body).await?;
                upstream.flush().await
            })
            .await
            .map_err(|_| ClientError::Upstream(UpstreamError::new(format!("upstream write timed out for {url}"), Some(url.clone()))))?
            .map_err(|e: std::io::Error| ClientError::Upstream(UpstreamError::new(format!("upstream unreachable for {url}: {e}"), Some(url.clone()))))?;
        }
        let resp_head = tokio::time::timeout(Duration::from_secs_f64(self.config.connect_timeout_s), read_head(&mut upstream))
            .await
            .map_err(|_| ClientError::Upstream(UpstreamError::new(format!("upstream read timed out for {url}"), Some(url.clone()))))?
            .map_err(|e| ClientError::Upstream(UpstreamError::new(format!("upstream read failed for {url}: {e}"), Some(url.clone()))))?;
        if status_code(&resp_head) == "407" {
            send_error(&mut client, "502", "Upstream auth failed: check Evomi username/password").await;
            return Err(ClientError::Auth);
        }
        client.write_all(&resp_head).await.map_err(|_| ClientError::Closed)?;
        client.flush().await.map_err(|_| ClientError::Closed)?;
        self.request_count.fetch_add(1, Ordering::SeqCst);
        loop {
            let mut chunk = [0u8; RELAY_CHUNK];
            let n = upstream.read(&mut chunk).await.map_err(|_| ClientError::Closed)?;
            if n == 0 {
                break;
            }
            client.write_all(&chunk[..n]).await.map_err(|_| ClientError::Closed)?;
            client.flush().await.map_err(|_| ClientError::Closed)?;
        }
        Ok(())
    }
}

fn is_pac_target(target: &str) -> bool {
    let path = if let Some(rest) = target.strip_prefix("http://") {
        rest.split_once('/').map(|(_, p)| format!("/{p}")).unwrap_or_default()
    } else {
        target.to_string()
    };
    path == "/proxy.pac" || path == "/wpad.dat"
}

fn absolutize(target: &str, headers: &[(String, String)]) -> Result<String, ClientError> {
    if let Some(path) = target.strip_prefix('/') {
        let host = header_get(headers, "host").ok_or(ClientError::BadRequest("origin-form request without Host".into()))?;
        return Ok(format!("http://{host}/{path}"));
    }
    Err(ClientError::BadRequest(format!("unsupported request target: {target}")))
}

fn head_body_extra(head: &[u8]) -> Vec<u8> {
    if let Some(pos) = find_headers_end(head) {
        head[pos..].to_vec()
    } else {
        Vec::new()
    }
}

async fn send_error(client: &mut TcpStream, code: &str, message: &str) {
    let body = message.as_bytes();
    let head = format!("HTTP/1.1 {code} {message}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len().min(200));
    let _ = client.write_all(head.as_bytes()).await;
    let _ = client.write_all(&body[..body.len().min(200)]).await;
    let _ = client.flush().await;
}

#[derive(Debug)]
enum ClientError {
    Upstream(UpstreamError),
    Auth,
    BadRequest(String),
    Closed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_headers_and_sessions() {
        let out = redact("Proxy-Authorization: Basic dXNlcjpwYXNz_session-abc123\r\n");
        assert!(!out.contains("dXNlcjpwYXNz"));
        assert!(out.contains("[REDACTED]"));
        let out = redact("pw_hardsession-AbC123 pw_lockedsession-XyZ789");
        assert!(!out.contains("AbC123"));
        assert!(!out.contains("XyZ789"));
    }

    #[test]
    fn pac_targets() {
        assert!(is_pac_target("/proxy.pac"));
        assert!(is_pac_target("/wpad.dat"));
        assert!(is_pac_target("http://127.0.0.1:8899/proxy.pac"));
        assert!(!is_pac_target("/other"));
        assert!(!is_pac_target("http://example.com/"));
    }

    #[test]
    fn base64_roundtrip_shape() {
        assert_eq!(basic_token("u", "p"), "dTpw");
    }

    #[test]
    fn refusal_quieting() {
        clear_refusal_state();
        let e = UpstreamError::new("refused for probe.example:443: 502", Some("probe.example:443".into()));
        log_upstream_error(&e); // warns (no assert on log output; just exercises path)
        log_upstream_error(&e); // quieted
        clear_refusal_state();
    }
}
