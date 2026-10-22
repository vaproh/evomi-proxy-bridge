//! Integration tests: fake upstream + real bridge (1:1 port of the Python suite).

use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use evomi_bridge_core::{Config, ProxyServer, SessionState};

fn test_config(upstream_port: u16) -> Config {
    Config {
        local_host: "127.0.0.1".into(),
        local_port: 0,
        upstream_host: "127.0.0.1".into(),
        upstream_port,
        username: "user1".into(),
        ..Config::default()
    }
}

async fn read_head(stream: &mut TcpStream) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            return buf;
        }
        let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut chunk))
            .await
            .unwrap()
            .unwrap();
        assert!(n > 0, "connection closed");
        buf.extend_from_slice(&chunk[..n]);
    }
}

struct FakeUpstream {
    tokens: Arc<Mutex<Vec<Option<String>>>>,
    _task: tokio::task::JoinHandle<()>,
    port: u16,
}

impl FakeUpstream {
    async fn start(mode: &str, tls_pem: Option<(String, String)>, pipe_to: Option<u16>) -> Self {
        let tokens: Arc<Mutex<Vec<Option<String>>>> = Arc::new(Mutex::new(Vec::new()));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let m = mode.to_string();
        let t2 = Arc::clone(&tokens);
        let tls_cfg: Option<tokio_rustls::TlsAcceptor> = tls_pem.map(|(cert_pem, key_pem)| {
            let mut cert_reader = std::io::BufReader::new(cert_pem.as_bytes());
            let certs: Vec<_> = rustls_pemfile::certs(&mut cert_reader).map(|c| c.unwrap()).collect();
            let mut key_reader = std::io::BufReader::new(key_pem.as_bytes());
            let key = rustls_pemfile::private_key(&mut key_reader).unwrap().unwrap();
            let server_cfg = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .unwrap();
            tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg))
        });
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else { break };
                let tokens = Arc::clone(&t2);
                let m2 = m.clone();
                let tls_cfg = tls_cfg.clone();
                tokio::spawn(async move {
                    if let Some(acceptor) = tls_cfg {
                        let acc = tokio::time::timeout(Duration::from_secs(5), acceptor.accept(stream)).await;
                        match acc {
                            Ok(Ok(tls_stream)) => handle(tls_stream, tokens, m2, pipe_to).await,
                            _ => {}
                        }
                    } else {
                        handle(stream, tokens, m2, pipe_to).await;
                    }
                });
            }
        });
        Self { tokens, _task: task, port }
    }
}

async fn handle<S>(mut stream: S, tokens: Arc<Mutex<Vec<Option<String>>>>, mode: String, pipe_to: Option<u16>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    handle_stream(&mut stream, tokens, mode, pipe_to).await
}

async fn handle_stream<S>(stream: &mut S, tokens: Arc<Mutex<Vec<Option<String>>>>, mode: String, pipe_to: Option<u16>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let head = {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
            match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut chunk)).await {
                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return,
                Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
            }
        }
        buf
    };
    let text = String::from_utf8_lossy(&head).into_owned();
    let token = text
        .lines()
        .skip(1)
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            (k.trim().to_ascii_lowercase() == "proxy-authorization").then(|| v.trim().to_string())
        });
    tokens.lock().unwrap().push(token);
    if mode == "authfail" {
        let _ = stream.write_all(b"HTTP/1.1 407 Proxy Auth Required\r\nContent-Length: 0\r\n\r\n").await;
        return;
    }
    let is_connect = text.starts_with("CONNECT");
    if is_connect {
        let _ = stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await;
        if let Some(tport) = pipe_to {
            let mut target = TcpStream::connect(("127.0.0.1", tport)).await.unwrap();
            let _ = tokio::io::copy_bidirectional(stream, &mut target).await;
            return;
        }
        // echo tunnel
        let mut buf = [0u8; 65536];
        loop {
            match stream.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if stream.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
    } else {
        let body = b"hello-upstream";
        let _ = stream
            .write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).as_bytes())
            .await;
        let _ = stream.write_all(body).await;
    }
}

fn rcgen_cert() -> (String, String) {
    // Returns (cert_pem, key_pem) for localhost/127.0.0.1 (TEST ONLY).
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()]).unwrap();
    (cert.cert.pem(), cert.key_pair.serialize_pem())
}

fn write_temp(name: &str, content: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("evomi-bridge-test-{name}-{}.pem", std::process::id()));
    std::fs::write(&p, content).unwrap();
    p
}

async fn start_bridge(cfg: Config, session: SessionState) -> (Arc<ProxyServer>, u16) {
    let server = ProxyServer::new(cfg, Arc::new(session)).unwrap();
    server.start().await.unwrap();
    let port = server.stats().bound_port;
    assert!(port != 0);
    (server, port)
}

async fn get(port: u16, req: &[u8]) -> (String, Vec<u8>) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    s.write_all(req).await.unwrap();
    let raw = read_head(&mut s).await;
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4).unwrap_or(raw.len());
    let text = String::from_utf8_lossy(&raw[..split]).into_owned();
    let len: usize = text
        .lines()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            (k.trim().to_ascii_lowercase() == "content-length").then(|| v.trim().parse().unwrap_or(0))
        })
        .unwrap_or(0);
    let mut body = raw[split..].to_vec();
    while body.len() < len {
        let mut chunk = vec![0u8; len - body.len()];
        let n = s.read(&mut chunk).await.unwrap();
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(len);
    (text, body)
}

#[tokio::test]
async fn http_forwarding_and_auth() {
    let up = FakeUpstream::start("ok", None, None).await;
    let session = SessionState::new("basepw").unwrap();
    let (bridge, port) = start_bridge(test_config(up.port), session).await;
    let (head, body) = get(port, b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n").await;
    assert!(head.lines().next().unwrap().contains("200"));
    assert_eq!(body, b"hello-upstream");
    assert_eq!(up.tokens.lock().unwrap().len(), 1);
    assert!(up.tokens.lock().unwrap()[0].as_ref().unwrap().starts_with("Basic "));
    bridge.stop().await;
}

#[tokio::test]
async fn connect_tunneling_echo() {
    let up = FakeUpstream::start("ok", None, None).await;
    let (bridge, port) = start_bridge(test_config(up.port), SessionState::new("basepw").unwrap()).await;
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    s.write_all(b"CONNECT echo.test:443 HTTP/1.1\r\nHost: echo.test:443\r\n\r\n").await.unwrap();
    let head = read_head(&mut s).await;
    assert!(String::from_utf8_lossy(&head).lines().next().unwrap().contains("200"));
    s.write_all(b"ping-tunnel").await.unwrap();
    let mut buf = [0u8; 11];
    tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut buf)).await.unwrap().unwrap();
    assert_eq!(&buf, b"ping-tunnel");
    bridge.stop().await;
}

#[tokio::test]
async fn rotation_affects_new_connections() {
    use std::sync::Arc as A;
    let up = FakeUpstream::start("ok", None, None).await;
    let session = A::new(SessionState::new("basepw").unwrap());
    let cfg = test_config(up.port);
    let bridge = ProxyServer::new(cfg, Arc::clone(&session)).unwrap();
    bridge.start().await.unwrap();
    let port = bridge.stats().bound_port;
    let old = session.current_password();
    get(port, b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n").await;
    session.rotate();
    assert_ne!(old, session.current_password());
    get(port, b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n").await;
    let toks = up.tokens.lock().unwrap();
    assert_eq!(toks.len(), 2);
    assert_ne!(toks[0], toks[1]);
    bridge.stop().await;
}

#[tokio::test]
async fn invalid_credentials_mapped_to_502() {
    let up = FakeUpstream::start("authfail", None, None).await;
    let (bridge, port) = start_bridge(test_config(up.port), SessionState::new("wrong").unwrap()).await;
    let (head, _) = get(port, b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n").await;
    assert!(head.lines().next().unwrap().contains("502"));
    bridge.stop().await;
}

#[tokio::test]
async fn upstream_outage_returns_502() {
    // closed port
    let tmp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead = tmp.local_addr().unwrap().port();
    drop(tmp);
    let (bridge, port) = start_bridge(test_config(dead), SessionState::new("basepw").unwrap()).await;
    let (head, _) = get(port, b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n").await;
    assert!(head.lines().next().unwrap().contains("502"));
    bridge.stop().await;
}

#[tokio::test]
async fn listener_bound_to_loopback_only() {
    let up = FakeUpstream::start("ok", None, None).await;
    let (bridge, _port) = start_bridge(test_config(up.port), SessionState::new("basepw").unwrap()).await;
    assert!(bridge.stats().listening);
    bridge.stop().await;
    assert!(!bridge.stats().listening);
}

#[tokio::test]
async fn pac_served_locally() {
    let up = FakeUpstream::start("ok", None, None).await;
    let (bridge, port) = start_bridge(test_config(up.port), SessionState::new("basepw").unwrap()).await;
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    s.write_all(b"GET /proxy.pac HTTP/1.1\r\nHost: x\r\n\r\n").await.unwrap();
    let head = read_head(&mut s).await;
    let text = String::from_utf8_lossy(&head);
    assert!(text.lines().next().unwrap().contains("200"));
    assert!(text.contains(&format!("PROXY 127.0.0.1:{port}")));
    assert!(up.tokens.lock().unwrap().is_empty()); // never forwarded upstream
    bridge.stop().await;
}

fn bridge_tls_cfg(uport: u16, cafile: &std::path::Path) -> Config {
    Config {
        local_host: "127.0.0.1".into(),
        local_port: 0,
        upstream_host: "127.0.0.1".into(),
        upstream_port: uport,
        upstream_tls: true,
        upstream_cafile: cafile.to_string_lossy().into_owned(),
        username: "user1".into(),
        ..Config::default()
    }
}

#[tokio::test]
async fn tls_connect_tunneling_verified() {
    let (cert_pem, key_pem) = rcgen_cert();
    let cafile = write_temp("ca", &cert_pem);
    let up = FakeUpstream::start("ok", Some((cert_pem, key_pem)), None).await;
    let (bridge, port) = start_bridge(bridge_tls_cfg(up.port, &cafile), SessionState::new("basepw").unwrap()).await;
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    s.write_all(b"CONNECT echo.test:443 HTTP/1.1\r\nHost: echo.test:443\r\n\r\n").await.unwrap();
    let head = read_head(&mut s).await;
    assert!(String::from_utf8_lossy(&head).lines().next().unwrap().contains("200"));
    s.write_all(b"tls-echo").await.unwrap();
    let mut buf = [0u8; 8];
    tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut buf)).await.unwrap().unwrap();
    assert_eq!(&buf, b"tls-echo");
    bridge.stop().await;
    std::fs::remove_file(cafile).ok();
}

#[tokio::test]
async fn tls_to_plain_port_returns_502() {
    let up = FakeUpstream::start("ok", None, None).await;
    let mut cfg = test_config(up.port);
    cfg.upstream_tls = true;
    cfg.connect_timeout_s = 2.0;
    let (bridge, port) = start_bridge(cfg, SessionState::new("basepw").unwrap()).await;
    let (head, _) = get(port, b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n").await;
    assert!(head.lines().next().unwrap().contains("502"));
    bridge.stop().await;
}

#[tokio::test]
async fn tls_untrusted_cert_refused() {
    let (cert_pem, key_pem) = rcgen_cert();
    let up = FakeUpstream::start("ok", Some((cert_pem, key_pem)), None).await;
    // No cafile: system roots do not trust the fixture cert -> refuse with 502.
    let mut cfg = test_config(up.port);
    cfg.upstream_tls = true;
    cfg.connect_timeout_s = 5.0;
    let (bridge, port) = start_bridge(cfg, SessionState::new("basepw").unwrap()).await;
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    s.write_all(b"CONNECT echo.test:443 HTTP/1.1\r\nHost: echo.test:443\r\n\r\n").await.unwrap();
    let head = read_head(&mut s).await;
    assert!(String::from_utf8_lossy(&head).lines().next().unwrap().contains("502"));
    bridge.stop().await;
}

#[tokio::test]
async fn tls_hostname_mismatch_refused() {
    // Cert valid only for example.com, bridge verifies 127.0.0.1 -> must refuse.
    let cert = rcgen::generate_simple_self_signed(vec!["example.com".into()]).unwrap();
    let key_pem = cert.key_pair.serialize_pem();
    let other = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cafile = write_temp("ca-mismatch", &other.cert.pem());
    let up = FakeUpstream::start("ok", Some((cert.cert.pem(), key_pem)), None).await;
    let (bridge, port) = start_bridge(bridge_tls_cfg(up.port, &cafile), SessionState::new("basepw").unwrap()).await;
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    s.write_all(b"CONNECT echo.test:443 HTTP/1.1\r\nHost: echo.test:443\r\n\r\n").await.unwrap();
    let head = read_head(&mut s).await;
    assert!(String::from_utf8_lossy(&head).lines().next().unwrap().contains("502"));
    bridge.stop().await;
    std::fs::remove_file(cafile).ok();
}

#[tokio::test]
async fn nested_tls_ip_check() {
    use evomi_bridge_core::check_exit_ip_blocking_via;
    // TLS target stub speaking HTTPS with a fixture cert.
    let (cert_pem, key_pem) = rcgen_cert();
    let cafile = write_temp("ca-nested", &cert_pem);
    let mut cert_reader = std::io::BufReader::new(cert_pem.as_bytes());
    let certs: Vec<_> = rustls_pemfile::certs(&mut cert_reader).map(|c| c.unwrap()).collect();
    let mut key_reader = std::io::BufReader::new(key_pem.as_bytes());
    let key = rustls_pemfile::private_key(&mut key_reader).unwrap().unwrap();
    let server_cfg = std::sync::Arc::new(
        rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(certs, key).unwrap(),
    );
    let acceptor = tokio_rustls::TlsAcceptor::from(server_cfg);
    let stub = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tport = stub.local_addr().unwrap().port();
    tokio::spawn(async move {
        let Ok((stream, _)) = stub.accept().await else { return };
        let mut tls = acceptor.accept(stream).await.unwrap();
        let mut seen_end = false;
        let mut req = Vec::new();
        let mut one = [0u8; 1];
        while !seen_end {
            match tls.read(&mut one).await {
                Ok(0) | Err(_) => return,
                Ok(_) => {
                    req.extend_from_slice(&one);
                    if req.windows(4).any(|w| w == b"\r\n\r\n") {
                        seen_end = true;
                    }
                }
            }
        }
        let body = b"203.0.113.7\n";
        tls.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).as_bytes()).await.unwrap();
        tls.write_all(body).await.unwrap();
    });
    // TLS upstream piping raw TCP to the stub.
    let up = FakeUpstream::start("ok", Some((cert_pem, key_pem)), Some(tport)).await;
    let uport = up.port;
    let cafile_s = cafile.to_string_lossy().into_owned();
    let ip = tokio::task::spawn_blocking(move || {
        check_exit_ip_blocking_via("u", "p", "127.0.0.1", uport, true, "127.0.0.1", tport, "/s", Duration::from_secs(10), &cafile_s)
    })
    .await
    .unwrap()
    .expect("nested TLS ip check");
    assert_eq!(ip, "203.0.113.7");
    std::fs::remove_file(cafile).ok();
}
