//! evomi-bridge-core: local HTTP proxy chaining to Evomi residential proxies.
//!
//! Stdlib-plus-tokio design mirroring the original Python bridge:
//! one upstream TCP connection per client request (`Connection: close`),
//! so session rotation is race-free for all newly created connections.

pub mod checks;
pub mod config;
pub mod logging;
pub mod pac;
pub mod proxy;
pub mod session;

pub use logging::{LogBuffer, LogEntry};

pub use checks::{check_exit_ip_blocking, check_exit_ip_blocking_via, check_geo_blocking, GeoInfo};
pub use config::{env_password, load_dotenv, parse_proxy_url, resolve_config, Config, Explicit, SessionType};
pub use proxy::{ProxyServer, ServerStats};
pub use session::SessionState;
