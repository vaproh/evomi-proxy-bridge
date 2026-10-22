//! Validated configuration: .env loading, proxy-URL parsing, value resolution.
//!
//! Precedence: explicit settings > .env file > built-in defaults.
//! Credentials are never logged.

use std::collections::HashMap;
use std::fmt;

pub const DEFAULT_LOCAL_HOST: &str = "127.0.0.1";
pub const DEFAULT_LOCAL_PORT: u16 = 8899;
pub const DEFAULT_UPSTREAM_HOST: &str = "rp.evomi.com";
pub const DEFAULT_UPSTREAM_PORT: u16 = 1000;
pub const DEFAULT_CONNECT_TIMEOUT_S: f64 = 10.0;
pub const DEFAULT_RELAY_TIMEOUT_S: f64 = 60.0;
pub const DEFAULT_MAX_CONNECTIONS: usize = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionType {
    Session,
    Hard,
    Locked,
}

impl SessionType {
    pub fn key(self) -> &'static str {
        match self {
            SessionType::Session => "session",
            SessionType::Hard => "hardsession",
            SessionType::Locked => "lockedsession",
        }
    }

    pub fn from_key(s: &str) -> Option<SessionType> {
        match s {
            "session" => Some(SessionType::Session),
            "hardsession" => Some(SessionType::Hard),
            "lockedsession" => Some(SessionType::Locked),
            _ => None,
        }
    }
}

impl fmt::Display for SessionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.key())
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub local_host: String,
    pub local_port: u16,
    pub upstream_host: String,
    pub upstream_port: u16,
    pub upstream_tls: bool,
    pub upstream_cafile: String,
    pub username: String,
    pub connect_timeout_s: f64,
    pub relay_timeout_s: f64,
    pub max_connections: usize,
    pub local_user: String,
    #[allow(dead_code)]
    pub local_pass: String,
    pub notify: bool,
    pub session_type: SessionType,
    /// Sticky lifetime minutes (None = default/unset). Only used with `session`.
    pub lifetime: Option<u32>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            local_host: DEFAULT_LOCAL_HOST.to_string(),
            local_port: DEFAULT_LOCAL_PORT,
            upstream_host: DEFAULT_UPSTREAM_HOST.to_string(),
            upstream_port: DEFAULT_UPSTREAM_PORT,
            upstream_tls: false,
            upstream_cafile: String::new(),
            username: String::new(),
            connect_timeout_s: DEFAULT_CONNECT_TIMEOUT_S,
            relay_timeout_s: DEFAULT_RELAY_TIMEOUT_S,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            local_user: String::new(),
            local_pass: String::new(),
            notify: true,
            session_type: SessionType::Session,
            lifetime: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError(pub String);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

impl Config {
    pub fn validate(&self) -> Result<(), ConfigError> {
        let err = |m: &str| ConfigError(m.to_string());
        if self.local_host != "127.0.0.1" {
            return Err(err("local_host must be 127.0.0.1 (loopback only)"));
        }
        if self.upstream_host.is_empty() || self.upstream_host.len() > 255 {
            return Err(err("invalid upstream_host"));
        }
        if self.upstream_port == 0 {
            return Err(err("invalid upstream_port"));
        }
        if self.username.is_empty() || self.username.len() > 128 {
            return Err(err("username must be 1-128 chars"));
        }
        if !(1.0..=60.0).contains(&self.connect_timeout_s) {
            return Err(err("connect_timeout must be 1-60s"));
        }
        if !(5.0..=600.0).contains(&self.relay_timeout_s) {
            return Err(err("relay_timeout must be 5-600s"));
        }
        if self.max_connections == 0 || self.max_connections > 1000 {
            return Err(err("max_connections must be 1-1000"));
        }
        if self.local_user.is_empty() != self.local_pass.is_empty() {
            return Err(err("local_user and local_pass must be given together"));
        }
        if let Some(l) = self.lifetime {
            if l == 0 || l > 1440 {
                return Err(err("lifetime must be 1-1440 minutes"));
            }
        }
        Ok(())
    }

    pub fn local_auth_enabled(&self) -> bool {
        !self.local_user.is_empty()
    }
}

/// Parse a dashboard proxy string.
/// Accepts `http(s)://user:pass_flags@host:port` and Evomi's
/// `http(s)://host:port:user:pass_flags` shape.
/// Returns (username, password, host, port, use_tls).
pub fn parse_proxy_url(text: &str) -> Option<(String, String, String, u16, bool)> {
    let text = text.trim();
    let (scheme, rest) = text.split_once("://")?;
    if scheme != "http" && scheme != "https" {
        return None;
    }
    let use_tls = scheme == "https";
    if let Some(at) = rest.rfind('@') {
        // standard shape user:pass@host:port
        let (userinfo, hostport) = (rest[..at].to_string(), &rest[at + 1..]);
        let (user, password) = userinfo.split_once(':')?;
        // hostport may be host:port or [v6]:port; keep it simple: split last ':'
        let (host, port_s) = hostport.rsplit_once(':')?;
        let host = host.trim().trim_matches(|c| c == '[' || c == ']').to_string();
        let port: u16 = port_s.trim().parse().ok()?;
        if user.is_empty() || password.is_empty() || host.is_empty() {
            return None;
        }
        return Some((
            percent_decode(user),
            percent_decode(password),
            host,
            port,
            use_tls,
        ));
    }
    // Evomi shape host:port:user:pass_flags
    let mut parts = rest.splitn(4, ':');
    let host = parts.next()?.trim().to_string();
    let port: u16 = parts.next()?.trim().parse().ok()?;
    let user = parts.next()?.trim().to_string();
    let password = parts.next()?.trim().to_string();
    if host.is_empty() || user.is_empty() || password.is_empty() {
        return None;
    }
    Some((percent_decode(&user), percent_decode(&password), host, port, use_tls))
}

fn percent_decode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push((h * 16 + l) as char);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Minimal .env reader: KEY=value, full-line # comments, optional `export`
/// prefix, optional matching single/double quotes. Missing file yields {}.
pub fn load_dotenv(path: &str) -> HashMap<String, String> {
    let mut values = HashMap::new();
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return values,
    };
    for raw in content.lines() {
        let mut line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("export ") {
            line = rest.trim();
        }
        let Some((key, mut value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        value = value.trim();
        if value.len() >= 2 {
            let b = value.as_bytes();
            if (b[0] == b'\'' || b[0] == b'"') && b[0] == b[value.len() - 1] {
                value = &value[1..value.len() - 1];
            }
        }
        if !key.is_empty() {
            values.insert(key.to_string(), value.to_string());
        }
    }
    values
}

/// True if the file exists and is readable beyond its owner (warn).
#[cfg(unix)]
pub fn dotenv_exposed(path: &str) -> bool {
    use std::os::unix::fs::MetadataExt;
    match std::fs::metadata(path) {
        Ok(m) => m.mode() & 0o077 != 0,
        Err(_) => false,
    }
}

#[cfg(not(unix))]
pub fn dotenv_exposed(_path: &str) -> bool {
    false
}

/// Merge explicit settings over .env over defaults.
/// `explicit` holds CLI/GUI-provided values (None = unset).
#[derive(Debug, Default)]
pub struct Explicit {
    pub local_port: Option<u16>,
    pub upstream_host: Option<String>,
    pub upstream_port: Option<u16>,
    pub upstream_tls: Option<bool>,
    pub username: Option<String>,
    pub connect_timeout_s: Option<f64>,
    pub max_connections: Option<usize>,
    pub local_user: Option<String>,
    pub local_pass: Option<String>,
    pub notify: Option<bool>,
    pub session_type: Option<SessionType>,
    pub lifetime: Option<Option<u32>>,
}

fn parse_bool_env(v: &str) -> Option<bool> {
    match v.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

pub fn resolve_config(env: &HashMap<String, String>, explicit: Explicit) -> Result<Config, ConfigError> {
    let err = |m: String| ConfigError(m);
    let mut env = env.clone();
    if let Some(url) = env.get("EVOMI_PROXY_URL").cloned() {
        let url = url.trim().to_string();
        if !url.is_empty() {
            let parts = parse_proxy_url(&url)
                .ok_or_else(|| err("invalid EVOMI_PROXY_URL".to_string()))?;
            env.entry("EVOMI_USERNAME".into()).or_insert(parts.0);
            env.entry("EVOMI_UPSTREAM_HOST".into()).or_insert(parts.2);
            env.entry("EVOMI_UPSTREAM_PORT".into()).or_insert(parts.3.to_string());
            if parts.4 {
                env.entry("EVOMI_UPSTREAM_TLS".into()).or_insert("true".into());
            }
        }
    }
    let get = |k: &str| env.get(k).map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let parse_u16 = |k: &str, v: &str| v.parse::<u16>().map_err(|_| err(format!("invalid {k}: {v:?}")));
    let cfg = Config {
        local_host: DEFAULT_LOCAL_HOST.to_string(),
        local_port: explicit.local_port.or(get("EVOMI_LOCAL_PORT").map(|v| v.parse().unwrap_or(DEFAULT_LOCAL_PORT))).unwrap_or(DEFAULT_LOCAL_PORT),
        upstream_host: explicit.upstream_host.or(get("EVOMI_UPSTREAM_HOST")).unwrap_or_else(|| DEFAULT_UPSTREAM_HOST.to_string()),
        upstream_port: explicit.upstream_port.or(get("EVOMI_UPSTREAM_PORT").map(|v| v.parse().unwrap_or(DEFAULT_UPSTREAM_PORT))).unwrap_or(DEFAULT_UPSTREAM_PORT),
        upstream_tls: explicit.upstream_tls.or(get("EVOMI_UPSTREAM_TLS").and_then(|v| parse_bool_env(&v))).unwrap_or(false),
        upstream_cafile: get("EVOMI_UPSTREAM_CAFILE").unwrap_or_default(),
        username: explicit.username.or(get("EVOMI_USERNAME")).unwrap_or_default(),
        connect_timeout_s: explicit.connect_timeout_s.or(get("EVOMI_CONNECT_TIMEOUT").and_then(|v| v.parse().ok())).unwrap_or(DEFAULT_CONNECT_TIMEOUT_S),
        relay_timeout_s: DEFAULT_RELAY_TIMEOUT_S,
        max_connections: explicit.max_connections.or(get("EVOMI_MAX_CONNECTIONS").and_then(|v| v.parse().ok())).unwrap_or(DEFAULT_MAX_CONNECTIONS),
        local_user: explicit.local_user.or(get("EVOMI_LOCAL_USER")).unwrap_or_default(),
        local_pass: explicit.local_pass.or_else(|| env.get("EVOMI_LOCAL_PASS").cloned()).unwrap_or_default(),
        notify: explicit.notify.or(get("EVOMI_NOTIFY").and_then(|v| parse_bool_env(&v))).unwrap_or(true),
        session_type: explicit.session_type.or(get("EVOMI_SESSION_TYPE").and_then(|v| SessionType::from_key(&v.to_ascii_lowercase()))).unwrap_or(SessionType::Session),
        lifetime: explicit.lifetime.flatten().or(get("EVOMI_LIFETIME").and_then(|v| v.parse().ok())),
    };
    let _ = parse_u16;
    cfg.validate()?;
    // strict port parsing (reject garbage instead of silently defaulting)
    if let Some(v) = get("EVOMI_UPSTREAM_PORT") {
        parse_u16("EVOMI_UPSTREAM_PORT", &v)?;
    }
    if let Some(v) = get("EVOMI_LOCAL_PORT") {
        let p: u16 = v.parse().map_err(|_| err(format!("invalid EVOMI_LOCAL_PORT: {v:?}")))?;
        let _ = p;
    }
    Ok(cfg)
}

/// Password (with flags) from EVOMI_PROXY_URL or EVOMI_PASSWORD, else "".
pub fn env_password(env: &HashMap<String, String>) -> String {
    if let Some(url) = env.get("EVOMI_PROXY_URL") {
        if let Some(parts) = parse_proxy_url(url.trim()) {
            return parts.1;
        }
    }
    env.get("EVOMI_PASSWORD").cloned().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_standard_shape() {
        let p = parse_proxy_url("http://user:pw@core-residential.evomi.com:1000").unwrap();
        assert_eq!(p, ("user".into(), "pw".into(), "core-residential.evomi.com".into(), 1000, false));
    }

    #[test]
    fn url_evomi_https_shape() {
        let p = parse_proxy_url(
            "https://core-residential.evomi-proxy.com:1001:vaproh4:BASE_country-GB,US_session-X_lifetime-15",
        )
        .unwrap();
        assert_eq!(p.0, "vaproh4");
        assert_eq!(p.2, "core-residential.evomi-proxy.com");
        assert_eq!(p.3, 1001);
        assert!(p.4);
        assert!(p.1.contains("_country-GB,US_"));
    }

    #[test]
    fn url_rejects_garbage() {
        assert!(parse_proxy_url("justausername").is_none());
        assert!(parse_proxy_url("http://nouserhost:1000").is_none());
        assert!(parse_proxy_url("ftp://u:p@h:1").is_none());
    }

    #[test]
    fn validate_loopback_only() {
        let mut c = Config::default();
        c.local_host = "0.0.0.0".into();
        c.username = "u".into();
        assert!(c.validate().is_err());
    }
}
