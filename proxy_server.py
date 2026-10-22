"""Local HTTP proxy with CONNECT tunneling and authenticated upstream chaining.

Stdlib asyncio only. One upstream TCP connection per client request
(shortcut: no upstream keep-alive reuse, `Connection: close` is forced). This
makes session rotation trivially correct: every new request snapshots the
current session password, so rotation affects all newly created upstream
connections without credential races. Active CONNECT tunnels keep their old
credentials until the client closes them; rotation never kills mid-stream
tunnels (see README limitations).
"""
from __future__ import annotations

import asyncio
import base64
import logging
import re
import socket
import ssl
import time

from config import IP_CHECK_HOST, IP_CHECK_PATH, IP_CHECK_PORT

log = logging.getLogger("proxy_bridge")

MAX_HEADER_BYTES = 65536
RELAY_CHUNK = 65536

_HOP_HEADERS = {
    "proxy-authorization", "proxy-authenticate", "proxy-connection",
    "connection", "keep-alive", "transfer-encoding", "upgrade",
}


def redact(text: str) -> str:
    """Redact credential-bearing material before logging."""
    text = re.sub(r"(?i)(proxy-authorization:\s*)[^\r\n]+", r"\1[REDACTED]", text)
    text = re.sub(r"(?i)(authorization:\s*)[^\r\n]+", r"\1[REDACTED]", text)
    text = re.sub(r"_(?:hard|locked)?session-[A-Za-z0-9]+", "_session-[REDACTED]", text)
    return text


def basic_token(username: str, password: str) -> str:
    return base64.b64encode(f"{username}:{password}".encode()).decode()


def parse_head(raw: bytes) -> tuple[str, str, list[tuple[str, str]]]:
    try:
        head = raw.decode("latin-1")
    except UnicodeDecodeError as exc:
        raise ValueError("undecodable headers") from exc
    lines = head.split("\r\n")
    parts = lines[0].split(" ", 2)
    if len(parts) != 3:
        raise ValueError(f"bad request line: {lines[0][:80]!r}")
    method, target = parts[0].upper(), parts[1]
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if not line:
            continue
        if ":" not in line:
            raise ValueError(f"bad header line: {line[:80]!r}")
        name, _, value = line.partition(":")
        headers.append((name.strip(), value.strip()))
    return method, target, headers


def header_get(headers: list[tuple[str, str]], name: str) -> str | None:
    lname = name.lower()
    for k, v in headers:
        if k.lower() == lname:
            return v
    return None


async def read_head(reader: asyncio.StreamReader) -> bytes:
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = await reader.read(16384)
        if not chunk:
            break
        buf += chunk
        if len(buf) > MAX_HEADER_BYTES:
            raise ValueError("headers too large")
    if b"\r\n\r\n" not in buf:
        raise ValueError("incomplete headers")
    return buf


class UpstreamAuthError(Exception):
    pass


class UpstreamError(ConnectionError):
    """Upstream dial/refusal failed (mapped to 502; distinct from client aborts)."""


class ProxyServer:
    """Asyncio HTTP proxy bound to loopback, chaining to authenticated upstream."""

    def __init__(self, config, session_state) -> None:
        self.config = config
        self.session = session_state
        self.server: asyncio.AbstractServer | None = None
        self._tunnels: set[asyncio.Task] = set()
        self._upstreams: set[asyncio.StreamWriter] = set()
        self._sem: asyncio.Semaphore | None = None
        self.started_at: float = 0.0
        self.request_count = 0
        self.connect_count = 0

    @property
    def listening(self) -> bool:
        return self.server is not None and self.server.is_serving()

    def _track(self, writer: asyncio.StreamWriter) -> None:
        self._upstreams.add(writer)

    def _untrack(self, writer: asyncio.StreamWriter) -> None:
        self._upstreams.discard(writer)
        try:
            if not writer.is_closing():
                writer.close()
        except Exception:
            pass

    async def _open_upstream(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        cfg = self.config
        ctx = None
        if cfg.upstream_tls:
            ctx = ssl.create_default_context()
            if getattr(cfg, "upstream_cafile", None):
                ctx.load_verify_locations(cafile=cfg.upstream_cafile)
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(cfg.upstream_host, cfg.upstream_port,
                                        ssl=ctx, server_hostname=cfg.upstream_host if ctx else None),
                timeout=cfg.connect_timeout,
            )
        except ssl.CertificateError as exc:
            raise UpstreamError(f"upstream TLS hostname check failed: {redact(str(exc))}") from exc
        self._track(writer)
        return reader, writer

    async def start(self) -> None:
        cfg = self.config
        if cfg.local_host != "127.0.0.1":
            raise ValueError("refusing to bind non-loopback address")
        self._sem = asyncio.Semaphore(cfg.max_connections)
        self.server = await asyncio.start_server(
            self._handle_client, cfg.local_host, cfg.local_port
        )
        for sock in self.server.sockets or []:
            if sock.getsockname()[0] != "127.0.0.1":
                self.server.close()
                raise RuntimeError(f"listener not on loopback: {sock.getsockname()}")
        self.started_at = time.time()
        log.info("listening on 127.0.0.1:%d -> %s:%d",
                 cfg.local_port, cfg.upstream_host, cfg.upstream_port)

    async def stop(self) -> None:
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()
            self.server = None
        for task in list(self._tunnels):
            task.cancel()
        for writer in list(self._upstreams):
            try:
                writer.close()
            except Exception:
                pass
        self._upstreams.clear()

    def retire_idle_upstreams(self) -> int:
        """Close tracked upstream sockets after rotation.

        One-shot requests are already drained by rotation time; active CONNECT
        relays hold their own references and finish naturally. Returns count.
        """
        n = len(self._upstreams)
        for writer in list(self._upstreams):
            try:
                writer.close()
            except Exception:
                pass
        self._upstreams.clear()
        return n

    # -- client handling -------------------------------------------------
    async def _handle_client(self, reader: asyncio.StreamReader,
                             writer: asyncio.StreamWriter) -> None:
        assert self._sem is not None
        async with self._sem:
            try:
                await asyncio.wait_for(self._dispatch(reader, writer),
                                       timeout=self.config.relay_timeout)
            except asyncio.TimeoutError:
                await self._send_error(writer, "504", "Gateway Timeout")
            except UpstreamError as exc:
                log.warning("upstream error: %s", redact(str(exc)))
                await self._send_error(writer, "502", "Bad Gateway: upstream unreachable")
            except UpstreamAuthError:
                await self._send_error(
                    writer, "502", "Upstream auth failed: check Evomi username/password")
            except ValueError as exc:
                await self._send_error(writer, "400", f"Bad request: {redact(str(exc))}")
            except (ConnectionError, OSError, asyncio.IncompleteReadError):
                pass
            except Exception as exc:  # defensive: one client must not kill the proxy
                log.warning("client error: %s", redact(str(exc)))
                await self._send_error(writer, "502", "Bad Gateway")
            finally:
                try:
                    writer.close()
                except Exception:
                    pass

    async def _dispatch(self, reader, writer) -> None:
        raw = await read_head(reader)
        method, target, headers = parse_head(raw)
        extra = raw.split(b"\r\n\r\n", 1)[1]

        if self.config.local_user and not self._check_local_auth(headers):
            writer.write(b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                         b"Proxy-Authenticate: Basic realm=\"proxy-bridge\"\r\n"
                         b"Content-Length: 0\r\nConnection: close\r\n\r\n")
            await writer.drain()
            return

        if method == "CONNECT":
            await self._handle_connect(reader, writer, target)
        else:
            await self._handle_http(reader, writer, method, target, headers, extra)

    def _check_local_auth(self, headers) -> bool:
        got = header_get(headers, "proxy-authorization")
        want = "Basic " + base64.b64encode(
            f"{self.config.local_user}:{self.config.local_pass}".encode()).decode()
        return got == want

    # -- CONNECT tunneling (bytes relayed untouched, no TLS interception) --
    async def _handle_connect(self, c_r, c_w, target: str) -> None:
        if ":" not in target:
            raise ValueError("CONNECT target must be host:port")
        host, _, port_s = target.rpartition(":")
        if not host or not port_s.isdigit():
            raise ValueError("bad CONNECT target")
        password = self.session.current_password()  # atomic snapshot
        token = basic_token(self.config.username, password)
        try:
            up_r, up_w = await self._open_upstream()
        except UpstreamError:
            raise
        except (OSError, asyncio.TimeoutError) as exc:
            raise UpstreamError(f"upstream unreachable: {exc}") from exc
        try:
            up_w.write(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n"
                       f"Proxy-Authorization: Basic {token}\r\n"
                       f"Connection: close\r\n\r\n".encode())
            await asyncio.wait_for(up_w.drain(), timeout=self.config.connect_timeout)
            resp = await asyncio.wait_for(read_head(up_r), timeout=self.config.connect_timeout)
            code = _status_code(resp)
            if code == "407":
                raise UpstreamAuthError("upstream rejected credentials")
            if code != "200":
                raise UpstreamError(
                    f"upstream CONNECT refused: {redact(_status_line(resp))}")
            c_w.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await c_w.drain()
            self.connect_count += 1
            await self._relay_pair(c_r, c_w, up_r, up_w)
        finally:
            self._untrack(up_w)

    async def _relay_pair(self, c_r, c_w, u_r, u_w) -> None:
        async def fwd(src, dst) -> None:
            try:
                while True:
                    chunk = await src.read(RELAY_CHUNK)
                    if not chunk:
                        break
                    dst.write(chunk)
                    await dst.drain()
            except (ConnectionError, OSError, asyncio.CancelledError):
                pass
            except Exception as exc:
                log.warning("relay error: %s", redact(str(exc)))

        t1 = asyncio.ensure_future(fwd(c_r, u_w))
        t2 = asyncio.ensure_future(fwd(u_r, c_w))
        self._tunnels.update((t1, t2))
        try:
            await asyncio.wait((t1, t2), return_when=asyncio.FIRST_COMPLETED)
        finally:
            for t in (t1, t2):
                if not t.done():
                    t.cancel()
                self._tunnels.discard(t)

    # -- plain HTTP forwarding -------------------------------------------
    async def _handle_http(self, c_r, c_w, method, target, headers, extra) -> None:
        url = target if target.startswith("http://") else self._absolutize(target, headers)
        password = self.session.current_password()  # atomic snapshot
        token = basic_token(self.config.username, password)
        length = header_get(headers, "content-length")
        body = b""
        if length:
            try:
                n = int(length)
            except ValueError as exc:
                raise ValueError("bad Content-Length") from exc
            if not 0 <= n <= 32 * 1024 * 1024:
                raise ValueError("Content-Length out of range")
            body = extra[:n]
            while len(body) < n:
                chunk = await c_r.read(n - len(body))
                if not chunk:
                    raise ValueError("truncated body")
                body += chunk

        try:
            up_r, up_w = await self._open_upstream()
        except UpstreamError:
            raise
        except (OSError, asyncio.TimeoutError) as exc:
            raise UpstreamError(f"upstream unreachable: {exc}") from exc
        try:
            out = [f"{method} {url} HTTP/1.1"]
            for k, v in headers:
                if k.lower() in _HOP_HEADERS:
                    continue
                out.append(f"{k}: {v}")
            out.append(f"Proxy-Authorization: Basic {token}")
            out.append("Connection: close")
            up_w.write(("\r\n".join(out) + "\r\n\r\n").encode("latin-1") + body)
            await asyncio.wait_for(up_w.drain(), timeout=self.config.connect_timeout)
            resp_head = await asyncio.wait_for(
                read_head(up_r), timeout=self.config.connect_timeout)
            if _status_code(resp_head) == "407":
                raise UpstreamAuthError("upstream rejected credentials")
            c_w.write(resp_head)
            await c_w.drain()
            self.request_count += 1
            while True:
                chunk = await up_r.read(RELAY_CHUNK)
                if not chunk:
                    break
                c_w.write(chunk)
                await c_w.drain()
        finally:
            self._untrack(up_w)

    @staticmethod
    def _absolutize(target: str, headers) -> str:
        if target.startswith("/"):
            host = header_get(headers, "host")
            if not host:
                raise ValueError("origin-form request without Host")
            return f"http://{host}{target}"
        raise ValueError(f"unsupported request target: {target[:60]!r}")

    @staticmethod
    async def _send_error(writer, code: str, message: str) -> None:
        body = message.encode()[:200]
        try:
            writer.write(f"HTTP/1.1 {code} {message.split(':')[0]}\r\n"
                         f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode() + body)
            await writer.drain()
        except (ConnectionError, OSError):
            pass


def _status_line(resp_head: bytes) -> str:
    return resp_head.split(b"\r\n", 1)[0].decode("latin-1", "replace")


def _status_code(resp_head: bytes) -> str:
    parts = _status_line(resp_head).split(" ")
    return parts[1] if len(parts) > 1 else ""


def _blocking_get_via_upstream(username: str, password: str, upstream_host: str,
                               upstream_port: int, upstream_tls: bool,
                               target_host: str, target_port: int,
                               path: str, use_tls: bool, timeout: float,
                               cafile: str | None = None) -> bytes:
    """Blocking HTTP GET through the upstream via CONNECT. Runs in a thread.

    Returns the raw response body. Raises UpstreamAuthError / UpstreamError.
    The upstream leg itself is TLS-wrapped when upstream_tls is set.
    """
    token = basic_token(username, password)
    sock = socket.create_connection((upstream_host, upstream_port), timeout=timeout)
    try:
        sock.settimeout(timeout)
        if upstream_tls:
            ctx = ssl.create_default_context(cafile=cafile)
            try:
                sock = ctx.wrap_socket(sock, server_hostname=upstream_host)
            except ssl.CertificateError as exc:
                raise UpstreamError(
                    f"upstream TLS hostname check failed: {redact(str(exc))}") from exc
            sock.settimeout(timeout)
        sock.sendall(f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n"
                     f"Host: {target_host}:{target_port}\r\n"
                     f"Proxy-Authorization: Basic {token}\r\n\r\n".encode())
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = sock.recv(4096)
            if not chunk:
                break
            head += chunk
            if len(head) > MAX_HEADER_BYTES:
                raise UpstreamError("oversize CONNECT response")
        code = _status_code(head)
        if code == "407":
            raise UpstreamAuthError("upstream rejected credentials")
        if code != "200":
            raise UpstreamError(f"CONNECT refused: {redact(_status_line(head))}")
        if use_tls:
            ctx = ssl.create_default_context()
            sock = ctx.wrap_socket(sock, server_hostname=target_host)
            sock.settimeout(timeout)
        sock.sendall(f"GET {path} HTTP/1.1\r\nHost: {target_host}\r\n"
                     f"Connection: close\r\n\r\n".encode())
        data = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            if len(data) > 262144:
                break
        _, _, body = data.partition(b"\r\n\r\n")
        return body
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _blocking_ip_check(username: str, password: str, upstream_host: str,
                       upstream_port: int, upstream_tls: bool, timeout: float,
                       cafile: str | None = None) -> str:
    body = _blocking_get_via_upstream(
        username, password, upstream_host, upstream_port, upstream_tls,
        IP_CHECK_HOST, IP_CHECK_PORT, IP_CHECK_PATH, True, timeout, cafile)
    ip = body.decode("utf-8", "replace").strip().split()[0] if body.strip() else ""
    if not ip:
        raise UpstreamError("empty IP check response")
    return ip


def parse_geo_body(body: bytes) -> dict:
    """Parse ip-api.com JSON into a small geo dict; {} when unusable."""
    import json as _json
    try:
        info = _json.loads(body.decode("utf-8", "replace") or "{}")
    except ValueError:
        return {}
    if not isinstance(info, dict) or info.get("status") != "success":
        return {}
    return {k: info.get(k, "") for k in
            ("country", "countryCode", "regionName", "city", "isp", "org", "as", "query")}


def _blocking_geo_check(username: str, password: str, upstream_host: str,
                        upstream_port: int, upstream_tls: bool, ip: str, timeout: float) -> dict:
    """Best-effort geo lookup of the exit IP via free ip-api.com (through proxy).

    Returns {} on any failure; callers must treat geo as informational only.
    """
    import urllib.parse as _up
    path = "/json/" + _up.quote(ip, safe="") + (
        "?fields=status,message,country,countryCode,regionName,city,isp,org,as,query")
    try:
        body = _blocking_get_via_upstream(
            username, password, upstream_host, upstream_port, upstream_tls,
            "ip-api.com", 80, path, False, timeout)
    except (OSError, UpstreamAuthError, UpstreamError):
        return {}
    return parse_geo_body(body)


async def check_exit_ip(username: str, password: str, upstream_host: str,
                        upstream_port: int, timeout: float = 15.0,
                        upstream_tls: bool = False, cafile: str | None = None) -> str:
    """Public exit IP seen through the upstream (independent check, no creds logged)."""
    return await asyncio.to_thread(
        _blocking_ip_check, username, password, upstream_host, upstream_port,
        upstream_tls, timeout, cafile)


async def check_geo(username: str, password: str, upstream_host: str,
                    upstream_port: int, ip: str, timeout: float = 15.0,
                    upstream_tls: bool = False) -> dict:
    """Best-effort geo info for an exit IP ({} when unavailable). Runs in a thread."""
    return await asyncio.to_thread(
        _blocking_geo_check, username, password, upstream_host, upstream_port,
        upstream_tls, ip, timeout)
