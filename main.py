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

import os as _os

_COLOR = sys.stdout.isatty() and _os.environ.get("NO_COLOR", "") == ""


class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    GREEN = "\033[32m"
    RED = "\033[31m"
    YELLOW = "\033[33m"
    CYAN = "\033[36m"
    MAGENTA = "\033[35m"


def paint(text: str, *codes: str) -> str:
    if _COLOR and codes:
        return "".join(codes) + text + C.RESET
    return text


def _ok(msg: str) -> str:
    return paint("[+]", C.GREEN, C.BOLD) + " " + msg


def _err(msg: str) -> str:
    return paint("[-]", C.RED, C.BOLD) + " " + msg


def _info(msg: str) -> str:
    return paint("[*]", C.CYAN) + " " + msg


def _warn(msg: str) -> str:
    return paint("[!]", C.YELLOW, C.BOLD) + " " + msg

def help_text() -> str:
    k = lambda c: paint(c, C.BOLD, C.MAGENTA)  # noqa: E731
    d = lambda s: paint(s, C.DIM)  # noqa: E731
    return (
        f"{paint('hotkeys', C.BOLD, C.CYAN)}  "
        f"[{k('r')}]otate  [{k('i')}]p info  [{k('s')}]tatus  [{k('q')}]uit\n"
        f"  {k('r')} - new random session id {d('(flags kept)')}, verify exit IP, desktop-notify\n"
        f"  {k('i')} - session, flags, lifetime + current exit IP and geo {d('(through proxy)')}\n"
        f"  {k('s')} - server status incl. flags, lifetime left, last known exit IP\n"
        f"  {k('q')} - graceful shutdown {d('(also Ctrl+C)')}\n"
    )


HELP = help_text()


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
        print(_info(paint("credentials taken from env file (no prompt)", C.DIM)))
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
        print(_info(f"URL parsed: user + {paint(('https' if cfg.upstream_tls else 'http') + f' upstream {host}:{port}', C.BOLD)}, flags kept"))
        return user, password
    password = getpass.getpass("Evomi password, flags allowed (hidden, never stored): ").strip()
    if not password:
        raise SystemExit("password is required")
    print(_info(paint("tip: paste a full dashboard string incl. _country-.._session-.._lifetime-.. flags;", C.DIM)))
    print(paint("    rotation swaps only the session id and keeps the rest.", C.DIM))
    return first, password


def read_keys(stop: threading.Event, out: queue.Queue[str]) -> None:
    """Single-keypress reader for ordinary terminals, no root needed.

    Windows: msvcrt (no Enter). Linux/macOS: termios raw mode on a TTY.
    Anything else: line input fallback.
    """
    if _os.name == "nt":
        _read_keys_windows(stop, out)
        return
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


def _read_keys_windows(stop: threading.Event, out: queue.Queue[str]) -> None:
    """Single-keypress reader for Windows consoles (msvcrt, no Enter needed)."""
    import msvcrt

    while not stop.is_set():
        try:
            if not msvcrt.kbhit():
                time.sleep(0.05)
                continue
            ch = msvcrt.getwch()
        except (KeyboardInterrupt, OSError):
            out.put("q")
            return
        if ch in ("", "\x00", "\xe0"):
            continue  # special-key prefix; ignore the sequence
        if ch in ("\x03", "\x1a"):  # Ctrl+C / Ctrl+Z
            out.put("q")
            return
        if ch in ("\r", "\n"):
            continue
        out.put(ch.lower())


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
    """Desktop notification. notify-send on Linux, WinRT toast on Windows."""
    if _os.name == "nt":
        return await _notify_windows(title, body)
    try:
        proc = await asyncio.create_subprocess_exec(
            "notify-send", title, body,
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
        await proc.wait()
        return proc.returncode == 0
    except (FileNotFoundError, OSError):
        return False


_WINDOWS_TOAST_PS = r"""$ErrorActionPreference = 'Stop'
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
$template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
$texts = $template.GetElementsByTagName('text')
$texts[0].AppendChild($template.CreateTextNode($args[0])) | Out-Null
$texts[1].AppendChild($template.CreateTextNode($args[1])) | Out-Null
$toast = [Windows.UI.Notifications.ToastNotification]::new($template)
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('proxy-bridge').Show($toast)
"""


async def _notify_windows(title: str, body: str) -> bool:
    """Best-effort Windows toast via PowerShell + WinRT. False when unavailable."""
    import shutil
    import tempfile

    shell = shutil.which("powershell") or shutil.which("pwsh")
    if shell is None:
        return False
    path = None
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".ps1", delete=False,
                                         encoding="utf-8-sig") as fh:
            fh.write(_WINDOWS_TOAST_PS)
            path = fh.name
        proc = await asyncio.wait_for(
            asyncio.create_subprocess_exec(
                shell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                "-File", path, title, body,
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL),
            timeout=20)
        await asyncio.wait_for(proc.wait(), timeout=20)
        return proc.returncode == 0
    except (OSError, asyncio.TimeoutError):
        return False
    finally:
        if path:
            try:
                _os.unlink(path)
            except OSError:
                pass


def _kv(key: str, value: str) -> str:
    return paint(key, C.DIM) + " " + paint(value, C.BOLD)


async def cmd_ip(cfg: Config, session: SessionState, state: dict) -> None:
    label = session.label()
    print(_info(f"{paint(label, C.BOLD)} {paint('- checking exit IP through Evomi ...', C.DIM)}"))
    print(_info(_kv("flags:", format_flags(session))))
    print(_info(_kv("lifetime:", format_lifetime(session).removeprefix("lifetime: "))))
    try:
        ip = await check_exit_ip(cfg.username, session.current_password(),
                                 cfg.upstream_host, cfg.upstream_port,
                                 upstream_tls=cfg.upstream_tls,
                                 cafile=cfg.upstream_cafile or None)
        state["last_ip"] = ip
        print(_ok(f"exit IP: {paint(ip, C.BOLD, C.GREEN)}"))
        print(paint("    (independent check via CONNECT to ip.evomi.com through upstream)", C.DIM))
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
            print(_ok(f"location: {paint(loc or 'unknown', C.BOLD)} | "
                        f"{paint('ISP:', C.DIM)} {geo.get('isp') or 'unknown'}"))
        else:
            print(_info("location: unavailable (geo lookup failed or rate-limited)"))
    except UpstreamAuthError:
        print(_err("upstream rejected credentials (407). Re-run and re-enter them."))
    except Exception as exc:
        print(_err(f"IP check failed: {redact(str(exc))}"))


def cmd_status(server: ProxyServer, session: SessionState, state: dict) -> None:
    up = time.time() - server.started_at if server.started_at else 0
    alive = paint("yes", C.GREEN, C.BOLD) if server.listening else paint("no", C.RED, C.BOLD)
    print(_info(f"listening: {alive} {paint(f'(127.0.0.1:{server.bound_port()})', C.DIM)}"))
    scheme = "https" if server.config.upstream_tls else "http"
    print(_info(f"upstream: {paint(f'{scheme}://{server.config.upstream_host}:{server.config.upstream_port}', C.BOLD)}"))
    print(_info(f"session: {paint(session.label(), C.BOLD, C.MAGENTA)}"))
    print(_info(_kv("flags:", format_flags(session))))
    life = format_lifetime(session).removeprefix("lifetime: ")
    print(_info(_kv("lifetime:", paint(life, C.YELLOW))))
    print(_info(f"auto-config URL: {paint(f'http://127.0.0.1:{server.bound_port()}/proxy.pac', C.BOLD)}"))
    if state.get("last_ip"):
        print(_info(f"last exit IP: {paint(state['last_ip'], C.BOLD, C.GREEN)}"))
    print(_info(f"uptime: {up:.0f}s  plain-requests: {server.request_count}  tunnels: {server.connect_count}"))


async def verify_rotation(cfg: Config, session: SessionState, state: dict,
                          old_ip: str | None) -> None:
    """Post-rotation background check: confirm exit IP, notify on change."""
    try:
        ip = await check_exit_ip(cfg.username, session.current_password(),
                                 cfg.upstream_host, cfg.upstream_port,
                                 upstream_tls=cfg.upstream_tls,
                                 cafile=cfg.upstream_cafile or None)
    except Exception as exc:
        print(_err(f"post-rotation check failed: {redact(str(exc))}"))
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
        print(_ok(f"current exit IP: {paint(detail, C.BOLD, C.GREEN)}"))
    elif changed:
        print(_ok(f"exit IP changed: {paint(old_ip, C.DIM)} -> {paint(detail, C.BOLD, C.GREEN)}"))
    else:
        print(_info(f"exit IP unchanged: {paint(detail, C.BOLD)} "
                    f"{paint('(Evomi may reuse peers; rotate again if needed)', C.DIM)}"))
    if cfg.notify:
        title = "proxy-bridge: IP changed" if changed else "proxy-bridge: rotation verified"
        if not await desktop_notify(title, detail):
            hint = ("install a notification daemon" if _os.name != "nt"
                    else "enable Windows notifications for this app")
            print(_info(paint(f"(no desktop popup: {hint})", C.DIM)))


async def async_main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    cfg_env = parse_args_with_env()
    cfg, env, env_path = cfg_env[0], cfg_env[1], cfg_env[2]
    if env and dotenv_exposed(env_path):
        print(_warn(f"{env_path} is readable by others; run `chmod 600 {env_path}`"))
    username, password = prompt_credentials(cfg, env)
    cfg.username = username
    session = SessionState(password)
    del password  # keep only inside session object
    state: dict = {"last_ip": None, "last_geo": None}

    server = ProxyServer(cfg, session)
    await server.start()
    scheme = "https" if cfg.upstream_tls else "http"
    rule = paint("\u2501" * 46, C.DIM)
    print(paint("\n  p r o x y - b r i d g e", C.BOLD, C.CYAN))
    print(rule)
    print(_kv("  listen  ", f"127.0.0.1:{server.bound_port()}"))
    print(_kv("  upstream", f"{scheme}://{cfg.upstream_host}:{cfg.upstream_port}"))
    print(_kv("  session ", session.label()))
    print(_kv("  auto-cfg", f"http://127.0.0.1:{server.bound_port()}/proxy.pac"))
    print(rule)
    if cfg.upstream_tls and not cfg.upstream_host.endswith("evomi-proxy.com"):
        print(_warn("upstream TLS hostname is outside *.evomi-proxy.com;"))
        print(paint("    Evomi's certificate covers evomi-proxy.com, so verification may fail.", C.DIM))
        print(paint("    Use an *.evomi-proxy.com host on port 1001 for HTTPS upstreams.", C.DIM))
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
                    print(_ok(f"rotated to {paint(label, C.BOLD, C.MAGENTA)} "
                              f"{paint(f'(retired {closed} idle upstream socket(s))', C.DIM)}"))
                    print(paint("    New connections use the new session. Old tunnels drain naturally;", C.DIM))
                    print(paint("    verifying new exit IP ...", C.DIM))
                    asyncio.ensure_future(verify_rotation(cfg, session, state, old_ip))
                elif key == "i":
                    await cmd_ip(cfg, session, state)
                elif key == "s":
                    cmd_status(server, session, state)
                elif key == "q":
                    print(_info("shutting down ..."))
                    return 0
                elif key == "h":
                    print(HELP)
    except (KeyboardInterrupt, asyncio.CancelledError):
        print(_info("\ninterrupted, shutting down ..."))
        return 0
    finally:
        stop.set()
        await server.stop()
        print(_info("bridge stopped, sockets closed."))


def main() -> int:
    try:
        return asyncio.run(async_main())
    except SystemExit as exc:
        print(str(exc))
        return 2


if __name__ == "__main__":
    sys.exit(main())
