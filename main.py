"""CLI lifecycle, session controller, and terminal hotkey UI (stdlib only)."""
from __future__ import annotations

import asyncio
import getpass
import logging
import queue
import re
import secrets
import sys
import threading
import time

from config import Config, dotenv_exposed, env_password, parse_args_with_env, parse_proxy_url
from proxy_server import ProxyServer, UpstreamAuthError, check_exit_ip, check_geo, redact

log = logging.getLogger("proxy_bridge")

HELP = """\
hotkeys: [r]otate  [i]p info  [s]tatus  [q]uit
  r - new random session id (flags kept), verify exit IP, desktop-notify result
  i - session label, flags, lifetime + current exit IP and geo (through proxy)
  s - server status incl. flags, lifetime left, last known exit IP
  q - graceful shutdown (also Ctrl+C)
"""


class SessionState:
    """Thread-safe Evomi password holder with rotation and flag awareness.

    Accepts a base password OR a full dashboard string with flags, e.g.
    ``BASE_country-GB,US_session-Ab12Cd34_lifetime-15``. Rotation replaces
    only the session-id segment (same session key), preserving every other
    flag. Session id rule per Evomi docs: 6-10 alphanumerics; we generate
    8 hex chars via secrets.token_hex(4).
    """

    _SESS_RE = re.compile(r"_(hardsession|lockedsession|session)-([A-Za-z0-9]+)")

    def __init__(self, template: str) -> None:
        template = template.strip()
        if not template or len(template) > 512:
            raise ValueError("password must be 1-512 chars")
        self._lock = threading.Lock()
        self.generation = 0
        self.rotated_at = time.time()
        m = self._SESS_RE.search(template)
        if m:
            self._key = m.group(1)
            self._head = template[:m.start()]
            self._tail = template[m.end():]
            self._id = m.group(2)
        else:
            self._key = "session"
            self._head = template
            self._tail = ""
            self._id = secrets.token_hex(4)
        if not self.valid_session_id(self._id):
            # Pasted id outside Evomi's 6-10 alphanum rule: replace, keep flags.
            self._id = secrets.token_hex(4)

    def current_password(self) -> str:
        with self._lock:
            return f"{self._head}_{self._key}-{self._id}{self._tail}"

    def label(self) -> str:
        with self._lock:
            return f"{self._key}-{self._id} (gen {self.generation})"

    def session_type(self) -> str:
        with self._lock:
            return self._key

    def flags(self) -> list[str]:
        """Non-secret `_key-value` segments (base password never included)."""
        with self._lock:
            pw = f"{self._head}_{self._key}-{self._id}{self._tail}"
        parts = pw.split("_")
        out = [p for p in parts[1:] if "-" in p]
        return [p for p in out if not self._SESS_RE.fullmatch("_" + p)]

    def lifetime_minutes(self) -> int | None:
        for flag in self.flags():
            if flag.startswith("lifetime-"):
                try:
                    n = int(flag.split("-", 1)[1])
                except ValueError:
                    return None
                return n if 1 <= n <= 1440 else None
        return 30 if self.session_type() == "session" else None

    def expires_in(self) -> float | None:
        life = self.lifetime_minutes()
        if life is None:
            return None
        return max(0.0, self.rotated_at + life * 60 - time.time())

    def rotate(self) -> str:
        with self._lock:
            self._id = secrets.token_hex(4)
            self.generation += 1
            self.rotated_at = time.time()
            return f"{self._key}-{self._id} (gen {self.generation})"

    @staticmethod
    def valid_session_id(sid: str) -> bool:
        return bool(re.fullmatch(r"[A-Za-z0-9]{6,10}", sid))


def prompt_credentials(cfg: Config, env: dict) -> tuple[str, str]:
    env_pw = env_password(env)
    if cfg.username and env_pw:
        print("[*] credentials taken from env file (no prompt)")
        return cfg.username, env_pw
    first = (cfg.username or input("Evomi username (or paste full http://user:pass@host:port URL): ")).strip()
    if not first:
        raise SystemExit("username is required")
    parsed = parse_proxy_url(first)
    if parsed:
        user, password, host, port, use_tls = parsed
        cfg.username, cfg.upstream_host, cfg.upstream_port = user, host, port
        cfg.upstream_tls = cfg.upstream_tls or use_tls
        cfg.validate()
        print(f"[*] URL parsed: user + {'https' if cfg.upstream_tls else 'http'} upstream {host}:{port}, flags kept")
        return user, password
    password = getpass.getpass("Evomi password, flags allowed (hidden, never stored): ").strip()
    if not password:
        raise SystemExit("password is required")
    print("[*] tip: paste a full dashboard string incl. _country-.._session-.._lifetime-.. flags;")
    print("    rotation swaps only the session id and keeps the rest.")
    return first, password


def read_keys(stop: threading.Event, out: queue.Queue[str]) -> None:
    """Single-keypress reader for ordinary Linux terminals, no root needed.

    Uses termios raw mode when stdin is a TTY; falls back to line input.
    """
    try:
        import termios
        import tty
        import select
    except ImportError:
        while not stop.is_set():
            try:
                line = input()
            except EOFError:
                out.put("q")
                return
            if line.strip():
                out.put(line.strip()[0].lower())
        return

    if not sys.stdin.isatty():
        while not stop.is_set():
            try:
                line = input()
            except EOFError:
                out.put("q")
                return
            if line.strip():
                out.put(line.strip()[0].lower())
        return

    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd)
        while not stop.is_set():
            r, _, _ = select.select([sys.stdin], [], [], 0.2)
            if not r:
                continue
            ch = sys.stdin.read(1)
            if not ch:
                continue
            if ch == "\x03":  # Ctrl+C
                out.put("q")
                return
            if ch in ("\r", "\n"):
                continue
            out.put(ch.lower())
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


def format_flags(session: SessionState) -> str:
    flags = session.flags()
    return (" | ".join(flags)) if flags else "(no targeting flags)"


def format_lifetime(session: SessionState) -> str:
    life = session.lifetime_minutes()
    if life is None:
        return "lifetime: n/a (hardsession/lockedsession)"
    left = session.expires_in()
    assert left is not None
    return f"lifetime: {life} min (expires in ~{left / 60:.0f} min)"


async def desktop_notify(title: str, body: str) -> bool:
    """Linux desktop notification via notify-send. Returns False if unavailable."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "notify-send", title, body,
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
        await proc.wait()
        return proc.returncode == 0
    except (FileNotFoundError, OSError):
        return False


async def cmd_ip(cfg: Config, session: SessionState, state: dict) -> None:
    label = session.label()
    print(f"[*] {label} - checking exit IP through Evomi ...")
    print(f"[*] flags: {format_flags(session)}")
    print(f"[*] {format_lifetime(session)}")
    try:
        ip = await check_exit_ip(cfg.username, session.current_password(),
                                 cfg.upstream_host, cfg.upstream_port,
                                 upstream_tls=cfg.upstream_tls,
                                 cafile=cfg.upstream_cafile or None)
        state["last_ip"] = ip
        print(f"[+] exit IP: {ip}")
        print("    (independent check via CONNECT to ip.evomi.com through upstream)")
        try:
            geo = await check_geo(cfg.username, session.current_password(),
                                  cfg.upstream_host, cfg.upstream_port, ip,
                                  upstream_tls=cfg.upstream_tls)
        except Exception:
            geo = {}
        if geo:
            state["last_geo"] = geo
            loc = ", ".join(p for p in
                            (geo.get("city", ""), geo.get("regionName", ""),
                             f"{geo.get('country', '')} ({geo.get('countryCode', '')})") if p)
            print(f"[+] location: {loc or 'unknown'} | ISP: {geo.get('isp') or 'unknown'}")
        else:
            print("[*] location: unavailable (geo lookup failed or rate-limited)")
    except UpstreamAuthError:
        print("[-] upstream rejected credentials (407). Re-run and re-enter them.")
    except Exception as exc:
        print(f"[-] IP check failed: {redact(str(exc))}")


def cmd_status(server: ProxyServer, session: SessionState, state: dict) -> None:
    up = time.time() - server.started_at if server.started_at else 0
    print(f"[*] listening: {server.listening} (127.0.0.1:{server.config.local_port})")
    scheme = "https" if server.config.upstream_tls else "http"
    print(f"[*] upstream: {scheme}://{server.config.upstream_host}:{server.config.upstream_port}")
    print(f"[*] session: {session.label()}")
    print(f"[*] flags: {format_flags(session)}")
    print(f"[*] {format_lifetime(session)}")
    if state.get("last_ip"):
        print(f"[*] last exit IP: {state['last_ip']}")
    print(f"[*] uptime: {up:.0f}s  plain-requests: {server.request_count}  tunnels: {server.connect_count}")


async def verify_rotation(cfg: Config, session: SessionState, state: dict,
                          old_ip: str | None) -> None:
    """Post-rotation background check: confirm exit IP, notify on change."""
    try:
        ip = await check_exit_ip(cfg.username, session.current_password(),
                                 cfg.upstream_host, cfg.upstream_port,
                                 upstream_tls=cfg.upstream_tls,
                                 cafile=cfg.upstream_cafile or None)
    except Exception as exc:
        print(f"[-] post-rotation check failed: {redact(str(exc))}")
        return
    state["last_ip"] = ip
    loc = ""
    try:
        geo = await check_geo(cfg.username, session.current_password(),
                              cfg.upstream_host, cfg.upstream_port, ip,
                              upstream_tls=cfg.upstream_tls)
        if geo:
            state["last_geo"] = geo
            loc = f"{geo.get('city', '')}, {geo.get('country', '')}".strip(", ")
    except Exception:
        pass
    changed = old_ip is not None and ip != old_ip
    detail = f"{ip}" + (f" ({loc})" if loc else "")
    if old_ip is None:
        print(f"[+] current exit IP: {detail}")
    elif changed:
        print(f"[+] exit IP changed: {old_ip} -> {detail}")
    else:
        print(f"[*] exit IP unchanged: {detail} (Evomi may reuse peers; rotate again if needed)")
    if cfg.notify:
        title = "proxy-bridge: IP changed" if changed else "proxy-bridge: rotation verified"
        if not await desktop_notify(title, detail):
            print("[*] (install `notify-send` / libnotify to get desktop popups)")


async def async_main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    cfg_env = parse_args_with_env()
    cfg, env, env_path = cfg_env[0], cfg_env[1], cfg_env[2]
    if env and dotenv_exposed(env_path):
        print(f"[!] warning: {env_path} is readable by others; run `chmod 600 {env_path}`")
    username, password = prompt_credentials(cfg, env)
    cfg.username = username
    session = SessionState(password)
    del password  # keep only inside session object
    state: dict = {"last_ip": None, "last_geo": None}

    server = ProxyServer(cfg, session)
    await server.start()
    scheme = "https" if cfg.upstream_tls else "http"
    print(f"[+] bridge up: 127.0.0.1:{cfg.local_port} -> {scheme}://{cfg.upstream_host}:{cfg.upstream_port}")
    if cfg.upstream_tls and not cfg.upstream_host.endswith("evomi-proxy.com"):
        print("[!] warning: upstream TLS hostname is outside *.evomi-proxy.com;")
        print("    Evomi's certificate covers evomi-proxy.com, so verification may fail.")
        print("    Use an *.evomi-proxy.com host on port 1001 for HTTPS upstreams.")
    print(f"[*] initial {session.label()}")
    print(HELP, flush=True)

    stop = threading.Event()
    keys: queue.Queue[str] = queue.Queue()
    thread = threading.Thread(target=read_keys, args=(stop, keys), daemon=True)
    thread.start()

    try:
        while True:
            await asyncio.sleep(0.1)
            while not keys.empty():
                key = keys.get_nowait()
                if key == "r":
                    old_ip = state.get("last_ip")
                    label = session.rotate()
                    closed = server.retire_idle_upstreams()
                    print(f"[+] rotated to {label} (retired {closed} idle upstream socket(s))")
                    print("    New connections use the new session. Existing browser tabs/tunnels")
                    print("    may keep the old exit IP until they reconnect; verifying ...")
                    asyncio.ensure_future(verify_rotation(cfg, session, state, old_ip))
                elif key == "i":
                    await cmd_ip(cfg, session, state)
                elif key == "s":
                    cmd_status(server, session, state)
                elif key == "q":
                    print("[*] shutting down ...")
                    return 0
                elif key == "h":
                    print(HELP)
    except (KeyboardInterrupt, asyncio.CancelledError):
        print("\n[*] interrupted, shutting down ...")
        return 0
    finally:
        stop.set()
        await server.stop()
        print("[*] bridge stopped, sockets closed.")


def main() -> int:
    try:
        return asyncio.run(async_main())
    except SystemExit as exc:
        print(str(exc))
        return 2


if __name__ == "__main__":
    sys.exit(main())
