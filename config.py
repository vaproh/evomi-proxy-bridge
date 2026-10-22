"""Validated configuration for the Evomi proxy bridge (stdlib only)."""
from __future__ import annotations

import argparse
import re
import urllib.parse
from dataclasses import dataclass, field

DEFAULT_LOCAL_HOST = "127.0.0.1"
DEFAULT_LOCAL_PORT = 8899
DEFAULT_UPSTREAM_HOST = "rp.evomi.com"
DEFAULT_UPSTREAM_PORT = 1000
DEFAULT_TIMEOUT = 10.0
DEFAULT_MAX_CONNECTIONS = 100
IP_CHECK_HOST = "ip.evomi.com"
IP_CHECK_PORT = 443
IP_CHECK_PATH = "/s"

_HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.\-]{0,253}[A-Za-z0-9])?$")


def _check_host(value: str, name: str) -> str:
    value = value.strip()
    if not value or len(value) > 255 or not _HOST_RE.match(value):
        raise ValueError(f"invalid {name}: {value!r}")
    return value


def _check_port(value: int, name: str) -> int:
    if not 1 <= value <= 65535:
        raise ValueError(f"invalid {name}: {value!r} (must be 1-65535)")
    return value


def parse_proxy_url(text: str) -> tuple[str, str, str, int, bool] | None:
    """Parse dashboard proxy strings into (username, password, host, port, use_tls).

    Accepts standard `http(s)://user:pass_flags@host:port` and Evomi's
    `http(s)://host:port:user:pass_flags` shape. Password keeps every Evomi
    flag suffix untouched for SessionState. `use_tls` follows the scheme.
    """
    text = text.strip()
    if "://" not in text:
        return None
    try:
        scheme, _, rest = text.partition("://")
        if scheme not in ("http", "https"):
            return None
        if "@" in rest:
            # standard shape: user:pass@host:port
            parts = urllib.parse.urlsplit(text)
            host, port = parts.hostname, parts.port
            user = urllib.parse.unquote(parts.username or "")
            password = urllib.parse.unquote(parts.password or "")
        else:
            # Evomi shape: host:port:user:pass_flags
            chunks = rest.split(":", 3)
            if len(chunks) != 4:
                return None
            host, port_s, user, password = chunks
            host = host.strip()
            if not host or not port_s.strip().isdigit():
                return None
            port = int(port_s.strip())
            user = urllib.parse.unquote(user.strip())
            password = urllib.parse.unquote(password.strip())
    except ValueError:
        return None
    if not host or not port or not user or not password:
        return None
    return user, password, host, port, scheme == "https"


@dataclass
class Config:
    local_host: str = DEFAULT_LOCAL_HOST
    local_port: int = DEFAULT_LOCAL_PORT
    upstream_host: str = DEFAULT_UPSTREAM_HOST
    upstream_port: int = DEFAULT_UPSTREAM_PORT
    upstream_tls: bool = False  # True for https endpoints (e.g. *.evomi-proxy.com:1001)
    upstream_cafile: str = ""  # custom CA bundle for upstream TLS (rarely needed)
    session_type: str | None = None  # override: session | hardsession | lockedsession
    lifetime: int | None = None  # override: sticky minutes, 1-1440 (session type only)
    username: str = ""
    connect_timeout: float = DEFAULT_TIMEOUT
    relay_timeout: float = 60.0
    max_connections: int = DEFAULT_MAX_CONNECTIONS
    local_user: str = ""  # optional local auth; empty = disabled
    local_pass: str = field(default="", repr=False)
    notify: bool = True  # desktop notification on verified rotation (notify-send)

    def validate(self) -> None:
        if self.local_host != "127.0.0.1":
            raise ValueError("local_host must be 127.0.0.1 (loopback only, no LAN exposure)")
        if not 0 <= self.local_port <= 65535:
            raise ValueError(f"invalid local_port: {self.local_port!r} (must be 0-65535)")
        _check_host(self.upstream_host, "upstream_host")
        _check_port(self.upstream_port, "upstream_port")
        if not self.username or len(self.username) > 128:
            raise ValueError("username must be 1-128 chars")
        if not 1.0 <= self.connect_timeout <= 60.0:
            raise ValueError("connect_timeout must be 1-60s")
        if not 5.0 <= self.relay_timeout <= 600.0:
            raise ValueError("relay_timeout must be 5-600s")
        if not 1 <= self.max_connections <= 1000:
            raise ValueError("max_connections must be 1-1000")
        if self.session_type is not None and self.session_type not in (
                "session", "hardsession", "lockedsession"):
            raise ValueError("session_type must be session|hardsession|lockedsession")
        if self.lifetime is not None and not (1 <= self.lifetime <= 1440):
            raise ValueError("lifetime must be 1-1440 minutes")
        if bool(self.local_user) != bool(self.local_pass):
            raise ValueError("--local-user and --local-pass must be given together")


ENV_KEYS = {
    # .env key -> Config field
    "EVOMI_USERNAME": "username",
    "EVOMI_LOCAL_PORT": "local_port",
    "EVOMI_UPSTREAM_HOST": "upstream_host",
    "EVOMI_UPSTREAM_PORT": "upstream_port",
    "EVOMI_CONNECT_TIMEOUT": "connect_timeout",
    "EVOMI_MAX_CONNECTIONS": "max_connections",
    "EVOMI_LOCAL_USER": "local_user",
    "EVOMI_LOCAL_PASS": "local_pass",
    "EVOMI_SESSION_TYPE": "session_type",
    "EVOMI_LIFETIME": "lifetime",
}
_BOOL_TRUE = {"1", "true", "yes", "on"}
_BOOL_FALSE = {"0", "false", "no", "off"}


def load_dotenv(path: str) -> dict[str, str]:
    """Minimal .env reader (stdlib): KEY=value, full-line # comments,
    optional `export` prefix, optional matching single/double quotes.
    No escape processing; a missing file yields {}."""
    values: dict[str, str] = {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            lines = fh.read().splitlines()
    except FileNotFoundError:
        return {}
    except OSError as exc:
        raise ValueError(f"cannot read env file {path!r}: {exc}") from exc
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        if key:
            values[key] = value
    return values


def dotenv_exposed(path: str) -> bool:
    """True if the env file exists and is readable beyond its owner (warn)."""
    import os as _os
    import stat as _stat
    try:
        mode = _os.stat(path).st_mode
    except OSError:
        return False
    return bool(mode & (_stat.S_IRGRP | _stat.S_IROTH))


def _parse_bool(text: str, name: str) -> bool:
    low = text.strip().lower()
    if low in _BOOL_TRUE:
        return True
    if low in _BOOL_FALSE:
        return False
    raise ValueError(f"invalid {name}: {text!r} (expected true/false)")


def parse_args_with_env(argv: list[str] | None = None) -> tuple[Config, dict[str, str], str]:
    """Like parse_args, but also returns (.env mapping, env path) for password/prompt use."""
    p = argparse.ArgumentParser(description="Evomi proxy bridge: 127.0.0.1:8899 -> rp.evomi.com:1000")
    p.add_argument("--env-file", default=".env", help="dotenv file with proxy details (default: .env)")
    p.add_argument("--local-port", type=int, default=None)
    p.add_argument("--upstream-host", default=None)
    p.add_argument("--upstream-port", type=int, default=None)
    p.add_argument("--upstream-tls", action="store_true",
                   help="TLS to upstream (for https endpoints like *.evomi-proxy.com:1001)")
    p.add_argument("--session-type", default=None,
                   choices=["session", "hardsession", "lockedsession"],
                   help="override session type (default: from password, else session)")
    p.add_argument("--lifetime", type=int, default=None, metavar="MINUTES",
                   help="override sticky lifetime 1-1440 min (session type only)")
    p.add_argument("--username", default=None, help="Evomi username (else .env, else prompted)")
    p.add_argument("--connect-timeout", type=float, default=None)
    p.add_argument("--max-connections", type=int, default=None)
    p.add_argument("--local-user", default=None, help="optional local proxy username")
    p.add_argument("--local-pass", default=None, help="optional local proxy password")
    p.add_argument("--no-notify", action="store_true", help="no desktop notification on rotation")
    a = p.parse_args(argv)
    env = load_dotenv(a.env_file)

    url = (env.get("EVOMI_PROXY_URL") or "").strip()
    if url:
        parts = parse_proxy_url(url)
        if parts is None:
            raise ValueError(f"invalid EVOMI_PROXY_URL in {a.env_file}")
        env.setdefault("EVOMI_USERNAME", parts[0])
        env.setdefault("EVOMI_UPSTREAM_HOST", parts[2])
        env.setdefault("EVOMI_UPSTREAM_PORT", str(parts[3]))
        if parts[4]:
            env.setdefault("EVOMI_UPSTREAM_TLS", "true")

    def pick(field: str, cli, cast=str):
        if cli is not None:
            return cli
        if field in ENV_KEYS.values():
            key = next(k for k, v in ENV_KEYS.items() if v == field)
            if key in env and env[key] != "":
                try:
                    return cast(env[key])
                except ValueError:
                    raise ValueError(f"invalid {key} in {a.env_file}: {env[key]!r}")
        defaults = {"local_port": DEFAULT_LOCAL_PORT, "upstream_host": DEFAULT_UPSTREAM_HOST,
                    "upstream_port": DEFAULT_UPSTREAM_PORT, "username": "",
                    "connect_timeout": DEFAULT_TIMEOUT, "max_connections": DEFAULT_MAX_CONNECTIONS,
                    "local_user": "", "local_pass": "", "lifetime": None}
        return defaults[field]

    if a.no_notify:
        notify = False
    elif env.get("EVOMI_NOTIFY", "") != "":
        notify = _parse_bool(env["EVOMI_NOTIFY"], "EVOMI_NOTIFY")
    else:
        notify = True
    if a.upstream_tls:
        use_tls = True
    elif env.get("EVOMI_UPSTREAM_TLS", "") != "":
        use_tls = _parse_bool(env["EVOMI_UPSTREAM_TLS"], "EVOMI_UPSTREAM_TLS")
    else:
        use_tls = False
    cfg = Config(
        local_port=pick("local_port", a.local_port, int),
        upstream_host=pick("upstream_host", a.upstream_host),
        upstream_port=pick("upstream_port", a.upstream_port, int),
        upstream_tls=use_tls,
        username=(a.username.strip() if a.username is not None
                  else env.get("EVOMI_USERNAME", "").strip()),
        connect_timeout=pick("connect_timeout", a.connect_timeout, float),
        max_connections=pick("max_connections", a.max_connections, int),
        local_user=(a.local_user.strip() if a.local_user is not None
                    else env.get("EVOMI_LOCAL_USER", "").strip()),
        local_pass=(a.local_pass if a.local_pass is not None
                    else env.get("EVOMI_LOCAL_PASS", "")),
        notify=notify,
        session_type=(a.session_type if a.session_type is not None
                      else (env.get("EVOMI_SESSION_TYPE", "").strip().lower() or None)),
        lifetime=pick("lifetime", a.lifetime, int),
    )
    cfg.validate()
    return cfg, env, a.env_file


def parse_args(argv: list[str] | None = None) -> Config:
    cfg, _, _ = parse_args_with_env(argv)
    return cfg


def env_password(env: dict[str, str]) -> str:
    """Password (with flags) from EVOMI_PROXY_URL or EVOMI_PASSWORD, else ''."""
    url = (env.get("EVOMI_PROXY_URL") or "").strip()
    if url:
        parsed = parse_proxy_url(url)
        if parsed is None:
            raise ValueError("invalid EVOMI_PROXY_URL (expected http://user:pass@host:port)")
        return parsed[1]
    return (env.get("EVOMI_PASSWORD") or "")
