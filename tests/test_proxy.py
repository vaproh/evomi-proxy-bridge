"""Unit tests: forwarding, CONNECT, auth, rotation, cleanup, errors (stdlib unittest)."""
from __future__ import annotations

import asyncio
import base64
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import Config, parse_proxy_url
from main import SessionState
from proxy_server import (
    ProxyServer,
    header_get,
    parse_geo_body,
    parse_head,
    read_head,
    redact,
)


async def read_http_response(reader: asyncio.StreamReader) -> tuple[str, bytes]:
    buf = await read_head(reader)
    head_raw, _, extra = buf.partition(b"\r\n\r\n")
    head = head_raw.decode("latin-1", "replace") + "\r\n\r\n"
    length = 0
    for line in head.split("\r\n"):
        if line.lower().startswith("content-length:"):
            length = int(line.split(":", 1)[1].strip())
    body = extra
    while len(body) < length:
        chunk = await reader.read(length - len(body))
        if not chunk:
            break
        body += chunk
    return head, body[:length]


class FakeUpstream:
    """Configurable fake Evomi upstream: records auth, canned responses."""

    def __init__(self, mode: str = "ok", delay: float = 0.0,
                 pipe_target: tuple[str, int] | None = None):
        self.mode = mode  # ok | authfail
        self.delay = delay
        # When set, CONNECT tunnels are piped as raw TCP to this target
        # (lets the test client handshake TLS end-to-end with the target).
        self.pipe_target = pipe_target
        self.seen_tokens: list[str | None] = []
        self.server: asyncio.AbstractServer | None = None

    async def start(self, tls_cert: str | None = None, tls_key: str | None = None,
                  ) -> tuple[str, int]:
        ctx = None
        if tls_cert:
            import ssl as _ssl
            ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(tls_cert, tls_key)
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0, ssl=ctx)
        sock = self.server.sockets[0]
        return sock.getsockname()[0], sock.getsockname()[1]

    @staticmethod
    async def _pipe_raw(c_r, c_w, host: str, port: int) -> None:
        t_r, t_w = await asyncio.open_connection(host, port)

        async def fwd(src, dst) -> None:
            try:
                while True:
                    chunk = await src.read(65536)
                    if not chunk:
                        break
                    dst.write(chunk)
                    await dst.drain()
            except (ConnectionError, OSError):
                pass

        t1 = asyncio.ensure_future(fwd(c_r, t_w))
        t2 = asyncio.ensure_future(fwd(t_r, c_w))
        try:
            await asyncio.wait((t1, t2), return_when=asyncio.FIRST_COMPLETED)
        finally:
            for t in (t1, t2):
                if not t.done():
                    t.cancel()
            try:
                t_w.close()
            except Exception:
                pass

    async def stop(self) -> None:
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()

    async def _handle(self, reader, writer) -> None:
        try:
            head = await read_head(reader)
            try:
                method, target, headers = parse_head(head)
            except ValueError:
                writer.write(b"HTTP/1.1 400 Bad\x0d\x0aContent-Length: 0\x0d\x0a\x0d\x0a")
                await writer.drain()
                return
            token = header_get(headers, "proxy-authorization")
            self.seen_tokens.append(token)
            if self.delay:
                await asyncio.sleep(self.delay)
            if self.mode == "authfail":
                writer.write(b"HTTP/1.1 407 Proxy Auth Required\r\nContent-Length: 0\r\n\r\n")
                await writer.drain()
                return
            if method == "CONNECT":
                writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                await writer.drain()
                if self.pipe_target:
                    await self._pipe_raw(reader, writer, *self.pipe_target)
                    return
                # echo tunnel
                while True:
                    chunk = await reader.read(65536)
                    if not chunk:
                        break
                    writer.write(chunk)
                    await writer.drain()
            else:
                body = b"hello-upstream"
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n"
                             % len(body) + body)
                await writer.drain()
        except (ConnectionError, OSError, asyncio.IncompleteReadError):
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass


FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


def make_cfg(upstream_port: int, **over) -> Config:
    cfg = Config(local_port=0, upstream_host="127.0.0.1", upstream_port=upstream_port,
                 username="user1", **over)
    cfg.validate()
    return cfg


async def start_bridge(cfg: Config, session: SessionState) -> tuple[ProxyServer, int]:
    server = ProxyServer(cfg, session)
    await server.start()
    port = server.server.sockets[0].getsockname()[1]  # type: ignore[union-attr]
    return server, port


class ProxyTests(unittest.IsolatedAsyncioTestCase):
    async def test_http_forwarding_and_auth(self):
        up = FakeUpstream()
        host, uport = await up.start()
        self.assertEqual(host, "127.0.0.1")
        try:
            session = SessionState("basepw")
            cfg = make_cfg(uport)
            bridge, port = await start_bridge(cfg, session)
            try:
                r, w = await asyncio.open_connection("127.0.0.1", port)
                w.write(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
                await w.drain()
                head, body = await read_http_response(r)
                self.assertIn("200", head.split("\r\n")[0])
                self.assertEqual(body, b"hello-upstream")
                want = "Basic " + base64.b64encode(
                    f"user1:basepw_session-{session.label().split()[0].split('-')[1]}".encode()).decode()
                self.assertEqual(up.seen_tokens[-1], want)
                w.close()
            finally:
                await bridge.stop()
        finally:
            await up.stop()

    async def test_connect_tunneling_echo(self):
        up = FakeUpstream()
        _, uport = await up.start()
        try:
            session = SessionState("basepw")
            bridge, port = await start_bridge(make_cfg(uport), session)
            try:
                r, w = await asyncio.open_connection("127.0.0.1", port)
                w.write(b"CONNECT echo.test:443 HTTP/1.1\r\nHost: echo.test:443\r\n\r\n")
                await w.drain()
                head = await read_head(r)
                self.assertIn("200", head.decode().split("\r\n")[0])
                w.write(b"ping-tunnel")
                await w.drain()
                echo = await asyncio.wait_for(r.read(11), timeout=5)
                self.assertEqual(echo, b"ping-tunnel")
                w.close()
            finally:
                await bridge.stop()
        finally:
            await up.stop()

    async def test_rotation_affects_new_connections(self):
        up = FakeUpstream()
        _, uport = await up.start()
        try:
            session = SessionState("basepw")
            bridge, port = await start_bridge(make_cfg(uport), session)
            try:
                old_pw = session.current_password()

                async def one_request():
                    r, w = await asyncio.open_connection("127.0.0.1", port)
                    w.write(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
                    await w.drain()
                    await read_http_response(r)
                    w.close()

                await one_request()
                session.rotate()
                new_pw = session.current_password()
                self.assertNotEqual(old_pw, new_pw)
                await one_request()
                toks = up.seen_tokens
                self.assertEqual(len(toks), 2)
                self.assertNotEqual(toks[0], toks[1])
                self.assertIn(base64.b64encode(f"user1:{new_pw}".encode()).decode(), toks[1])
            finally:
                await bridge.stop()
        finally:
            await up.stop()

    async def test_retire_idle_upstreams(self):
        up = FakeUpstream()
        _, uport = await up.start()
        try:
            session = SessionState("basepw")
            bridge, port = await start_bridge(make_cfg(uport), session)
            try:
                r, w = await asyncio.open_connection("127.0.0.1", port)
                w.write(b"CONNECT echo.test:443 HTTP/1.1\r\nHost: echo.test:443\r\n\r\n")
                await w.drain()
                await read_head(r)
                # tunnel active: at least one tracked upstream or tunnel task
                self.assertTrue(len(bridge._upstreams) >= 1 or len(bridge._tunnels) >= 1)
                w.close()
                await asyncio.sleep(0.3)
                n = bridge.retire_idle_upstreams()
                self.assertGreaterEqual(n, 0)
                self.assertEqual(len(bridge._upstreams), 0)
            finally:
                await bridge.stop()
        finally:
            await up.stop()

    async def test_invalid_credentials_mapped_to_502(self):
        up = FakeUpstream(mode="authfail")
        _, uport = await up.start()
        try:
            bridge, port = await start_bridge(make_cfg(uport), SessionState("wrong"))
            try:
                r, w = await asyncio.open_connection("127.0.0.1", port)
                w.write(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
                await w.drain()
                head, _ = await read_http_response(r)
                self.assertIn("502", head.split("\r\n")[0])
                w.close()
            finally:
                await bridge.stop()
        finally:
            await up.stop()

    async def test_upstream_outage_returns_502(self):
        # closed port: nothing listening
        tmp = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
        dead_port = tmp.sockets[0].getsockname()[1]
        tmp.close()
        await tmp.wait_closed()
        bridge, port = await start_bridge(make_cfg(dead_port), SessionState("basepw"))
        try:
            r, w = await asyncio.open_connection("127.0.0.1", port)
            w.write(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
            await w.drain()
            head, _ = await read_http_response(r)
            self.assertIn("502", head.split("\r\n")[0])
            w.close()
        finally:
            await bridge.stop()

    async def test_graceful_shutdown_and_loopback(self):
        up = FakeUpstream()
        _, uport = await up.start()
        try:
            bridge, port = await start_bridge(make_cfg(uport), SessionState("basepw"))
            for sock in bridge.server.sockets:  # type: ignore[union-attr]
                self.assertEqual(sock.getsockname()[0], "127.0.0.1")
            self.assertTrue(bridge.listening)
            await bridge.stop()
            self.assertFalse(bridge.listening)
        finally:
            await up.stop()

    async def test_local_auth_optional(self):
        up = FakeUpstream()
        _, uport = await up.start()
        try:
            session = SessionState("basepw")
            cfg = make_cfg(uport, local_user="me", local_pass="secret")
            bridge, port = await start_bridge(cfg, session)
            try:
                # no credentials -> 407
                r, w = await asyncio.open_connection("127.0.0.1", port)
                w.write(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
                await w.drain()
                head, _ = await read_http_response(r)
                self.assertIn("407", head.split("\r\n")[0])
                w.close()
                # correct credentials -> forwarded
                import base64 as _b64
                tok = _b64.b64encode(b"me:secret").decode()
                r, w = await asyncio.open_connection("127.0.0.1", port)
                w.write(f"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n"
                        f"Proxy-Authorization: Basic {tok}\r\n\r\n".encode())
                await w.drain()
                head, body = await read_http_response(r)
                self.assertIn("200", head.split("\r\n")[0])
                self.assertEqual(body, b"hello-upstream")
                w.close()
            finally:
                await bridge.stop()
        finally:
            await up.stop()

    def test_redaction(self):
        sample = ("Proxy-Authorization: Basic dXNlcjpwYXNz_session-abc123\r\n"
                  "GET http://x/ HTTP/1.1 password_session-zzz")
        out = redact(sample)
        self.assertNotIn("dXNlcjpwYXNz", out)
        self.assertNotIn("abc123", out)
        self.assertIn("[REDACTED]", out)

    def test_session_format_valid(self):
        for _ in range(20):
            s = SessionState("pw")
            sid = s.current_password().rsplit("_session-", 1)[1]
            self.assertTrue(SessionState.valid_session_id(sid), sid)
            self.assertEqual(len(sid), 8)

    def test_full_flag_template_preserved_on_rotate(self):
        s = SessionState("XXXXXXXXXXXXXXXXXX_country-GB,US,AE,DE,FR,IT_session-B4KINYMKS_lifetime-15")
        self.assertEqual(s.session_type(), "session")
        self.assertIn("country-GB,US,AE,DE,FR,IT", s.flags())
        self.assertIn("lifetime-15", s.flags())
        self.assertEqual(s.lifetime_minutes(), 15)
        old = s.current_password()
        s.rotate()
        new = s.current_password()
        self.assertNotEqual(old, new)
        self.assertIn("_country-GB,US,AE,DE,FR,IT_", new)
        self.assertTrue(new.endswith("_lifetime-15"))
        self.assertEqual(new.count("_session-"), 1)  # replaced, not duplicated
        self.assertNotIn("B4KINYMKS", new)

    def test_plain_base_gets_session_appended(self):
        s = SessionState("justbase")
        self.assertTrue(s.current_password().startswith("justbase_session-"))
        self.assertEqual(s.lifetime_minutes(), 30)  # Evomi default for `session`

    def test_hardsession_kept_and_no_lifetime(self):
        s = SessionState("BASE_hardsession-JS9nsq2n")
        self.assertEqual(s.session_type(), "hardsession")
        s.rotate()
        pw = s.current_password()
        self.assertIn("_hardsession-", pw)
        self.assertNotIn("_session-", pw.replace("_hardsession-", ""))
        self.assertIsNone(s.lifetime_minutes())
        self.assertNotIn("JS9nsq2n", pw)

    def test_flags_hide_base_and_session_id(self):
        s = SessionState("SECRETBASE_country-GB_session-Ab12Cd34_lifetime-15")
        flags = s.flags()
        self.assertNotIn("SECRETBASE", " ".join(flags))
        self.assertFalse(any("Ab12Cd34" in f for f in flags))
        self.assertIn("country-GB", flags)

    def test_invalid_pasted_session_id_replaced(self):
        s = SessionState("BASE_session-waytoolongforthisformat")
        self.assertTrue(SessionState.valid_session_id(
            s.current_password().rsplit("_session-", 1)[1]))

    def test_redact_hard_and_locked_sessions(self):
        out = redact("pw_hardsession-AbC123 pw_lockedsession-XyZ789 pw_session-QwE123")
        self.assertNotIn("AbC123", out)
        self.assertNotIn("XyZ789", out)
        self.assertNotIn("QwE123", out)

    def test_parse_proxy_url(self):
        got = parse_proxy_url(
            "http://exampleuser:XXXXXXXXXXXXXXXXXX_country-GB,US,AE,DE,FR,IT_session-B4KINYMKS_lifetime-15"
            "@core-residential.evomi.com:1000")
        assert got is not None
        user, password, host, port, use_tls = got
        self.assertEqual(user, "exampleuser")
        self.assertEqual(host, "core-residential.evomi.com")
        self.assertEqual(port, 1000)
        self.assertFalse(use_tls)
        self.assertIn("_country-GB,US", password)
        self.assertIsNone(parse_proxy_url("justausername"))
        self.assertIsNone(parse_proxy_url("http://nouserhost:1000"))

    def test_parse_geo_body(self):
        body = (b'{"status":"success","country":"Germany","countryCode":"DE",'
                b'"regionName":"Bavaria","city":"Munich","isp":"ExampleNet",'
                b'"org":"ExampleOrg","as":"AS123 Example","query":"1.2.3.4"}')
        geo = parse_geo_body(body)
        self.assertEqual(geo["country"], "Germany")
        self.assertEqual(geo["city"], "Munich")
        self.assertEqual(parse_geo_body(b'{"status":"fail","message":"reserved"}'), {})
        self.assertEqual(parse_geo_body(b"not json"), {})

    def test_dotenv_parser(self):
        import tempfile
        from config import load_dotenv
        content = (
            "# comment line\n"
            "EVOMI_USERNAME=bob\n"
            "EVOMI_PASSWORD='base_country-GB_lifetime-15'\n"
            'export EVOMI_UPSTREAM_HOST="core-residential.evomi.com"\n'
            "EVOMI_UPSTREAM_PORT=1000\n"
            "EMPTY=\n"
            "NOEQUALS IGNORED\n"
        )
        with tempfile.NamedTemporaryFile("w", suffix=".env", delete=False) as fh:
            fh.write(content)
            path = fh.name
        try:
            got = load_dotenv(path)
        finally:
            import os
            os.unlink(path)
        self.assertEqual(got["EVOMI_USERNAME"], "bob")
        self.assertEqual(got["EVOMI_PASSWORD"], "base_country-GB_lifetime-15")
        self.assertEqual(got["EVOMI_UPSTREAM_HOST"], "core-residential.evomi.com")
        self.assertEqual(got["EVOMI_UPSTREAM_PORT"], "1000")
        self.assertEqual(got["EMPTY"], "")
        self.assertNotIn("NOEQUALS IGNORED", got)
        self.assertEqual(load_dotenv("/nonexistent-xyz-123.env"), {})

    def test_dotenv_merge_precedence(self):
        import tempfile
        from config import env_password, parse_args_with_env
        content = (
            "EVOMI_USERNAME=envuser\n"
            "EVOMI_PASSWORD=envbase_country-DE_lifetime-20\n"
            "EVOMI_UPSTREAM_HOST=env-host.example\n"
            "EVOMI_UPSTREAM_PORT=1001\n"
            "EVOMI_NOTIFY=false\n"
        )
        with tempfile.NamedTemporaryFile("w", suffix=".env", delete=False) as fh:
            fh.write(content)
            path = fh.name
        try:
            cfg, env, _ = parse_args_with_env(["--env-file", path])
            self.assertEqual(cfg.username, "envuser")
            self.assertEqual(cfg.upstream_host, "env-host.example")
            self.assertEqual(cfg.upstream_port, 1001)
            self.assertFalse(cfg.notify)
            self.assertEqual(env_password(env), "envbase_country-DE_lifetime-20")
            # CLI beats .env
            cfg2, _, _ = parse_args_with_env(
                ["--env-file", path, "--upstream-host", "cli-host.example", "--username", "cliuser"])
            self.assertEqual(cfg2.upstream_host, "cli-host.example")
            self.assertEqual(cfg2.username, "cliuser")
            self.assertEqual(cfg2.upstream_port, 1001)  # .env kept where CLI silent
            # bad int in .env raises
            with open(path, "w") as fh2:
                fh2.write("EVOMI_USERNAME=u\nEVOMI_UPSTREAM_PORT=banana\n")
            with self.assertRaises(ValueError):
                parse_args_with_env(["--env-file", path])
        finally:
            import os
            os.unlink(path)

    def test_dotenv_proxy_url(self):
        import tempfile
        from config import env_password, parse_args_with_env
        url = ("http://exampleuser:XXXXXXXXXXXXXXXXXX_country-GB,US_session-B4KINYMKS_lifetime-15"
               "@core-residential.evomi.com:1000")
        with tempfile.NamedTemporaryFile("w", suffix=".env", delete=False) as fh:
            fh.write(f"EVOMI_PROXY_URL={url}\n")
            path = fh.name
        try:
            cfg, env, _ = parse_args_with_env(["--env-file", path])
            self.assertEqual(cfg.username, "exampleuser")
            self.assertEqual(cfg.upstream_host, "core-residential.evomi.com")
            self.assertEqual(cfg.upstream_port, 1000)
            pw = env_password(env)
            self.assertIn("_country-GB,US_", pw)
            # explicit keys override URL parts
            with open(path, "w") as fh2:
                fh2.write(f"EVOMI_PROXY_URL={url}\nEVOMI_UPSTREAM_PORT=1002\n")
            cfg2, _, _ = parse_args_with_env(["--env-file", path])
            self.assertEqual(cfg2.upstream_port, 1002)
            with open(path, "w") as fh3:
                fh3.write("EVOMI_PROXY_URL=http://bad\n")
            with self.assertRaises(ValueError):
                parse_args_with_env(["--env-file", path])
        finally:
            import os
            os.unlink(path)

    def test_config_rejects_non_loopback(self):
        cfg = Config(local_host="0.0.0.0", username="u")
        with self.assertRaises(ValueError):
            cfg.validate()


    def test_parse_evomi_https_shape(self):
        got = parse_proxy_url(
            "https://core-residential.evomi-proxy.com:1001:exampleuser:"
            "EXAMPLEBASEPASS00_country-GB,US,AE,DE,FR,IT_session-K7M2PQX4Z_lifetime-15")
        assert got is not None
        user, password, host, port, use_tls = got
        self.assertEqual(user, "exampleuser")
        self.assertEqual(host, "core-residential.evomi-proxy.com")
        self.assertEqual(port, 1001)
        self.assertTrue(use_tls)
        self.assertIn("_country-GB,US,AE,DE,FR,IT_", password)
        s = SessionState(password)
        self.assertIn("country-GB,US,AE,DE,FR,IT", s.flags())
        self.assertEqual(s.lifetime_minutes(), 15)

    def test_upstream_tls_flag_and_env(self):
        import os as _os
        from config import parse_args
        # os.devnull reads as an empty env file: isolates tests from ./.env
        cfg = parse_args(["--username", "u", "--upstream-tls", "--env-file", _os.devnull])
        self.assertTrue(cfg.upstream_tls)
        cfg = parse_args(["--username", "u", "--env-file", _os.devnull])
        self.assertFalse(cfg.upstream_tls)
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".env", delete=False) as fh:
            fh.write("EVOMI_USERNAME=u\nEVOMI_UPSTREAM_TLS=yes\n")
            path = fh.name
        try:
            cfg = parse_args(["--env-file", path])
            self.assertTrue(cfg.upstream_tls)
        finally:
            import os
            os.unlink(path)

    def test_tls_connect_tunneling_verified(self):
        import asyncio
        import os as _os

        async def go():
            up = FakeUpstream()
            crt = _os.path.join(FIXTURES, "localhost.crt")
            key = _os.path.join(FIXTURES, "localhost.key")
            _, uport = await up.start(tls_cert=crt, tls_key=key)
            try:
                session = SessionState("basepw")
                bridge, port = await start_bridge(
                    make_cfg(uport, upstream_tls=True, upstream_cafile=crt), session)
                try:
                    r, w = await asyncio.open_connection("127.0.0.1", port)
                    w.write(b"CONNECT echo.test:443 HTTP/1.1\r\nHost: echo.test:443\r\n\r\n")
                    await w.drain()
                    head = await read_head(r)
                    self.assertIn("200", head.decode().split("\r\n")[0])
                    w.write(b"tls-echo")
                    await w.drain()
                    self.assertEqual(await asyncio.wait_for(r.read(8), timeout=5), b"tls-echo")
                    w.close()
                finally:
                    await bridge.stop()
            finally:
                await up.stop()
        asyncio.get_event_loop_policy().new_event_loop().run_until_complete(go())

    def test_tls_to_plain_port_returns_502(self):
        import asyncio

        async def go():
            up = FakeUpstream()  # plain TCP, no TLS
            _, uport = await up.start()
            try:
                bridge, port = await start_bridge(
                    make_cfg(uport, upstream_tls=True, connect_timeout=2.0),
                    SessionState("basepw"))
                try:
                    r, w = await asyncio.open_connection("127.0.0.1", port)
                    w.write(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
                    await w.drain()
                    head, _ = await read_http_response(r)
                    self.assertIn("502", head.split("\r\n")[0])
                    w.close()
                finally:
                    await bridge.stop()
            finally:
                await up.stop()
        asyncio.get_event_loop_policy().new_event_loop().run_until_complete(go())

    def test_tls_untrusted_cert_refused(self):
        import asyncio
        import os as _os

        async def go():
            up = FakeUpstream()
            crt = _os.path.join(FIXTURES, "localhost.crt")
            key = _os.path.join(FIXTURES, "localhost.key")
            _, uport = await up.start(tls_cert=crt, tls_key=key)
            try:
                # system CAs do not trust the fixture cert -> must refuse
                cfg = make_cfg(uport, upstream_tls=True)
                from proxy_server import ProxyServer, UpstreamError
                server = ProxyServer(cfg, SessionState("basepw"))
                with self.assertRaises(UpstreamError):
                    await asyncio.wait_for(server._open_upstream(), timeout=10)
            finally:
                await up.stop()
        asyncio.get_event_loop_policy().new_event_loop().run_until_complete(go())

    async def test_nested_tls_ip_check(self):
        # TLS upstream + TLS target: outer handshake must run via BIO pump
        # (double wrap_socket cannot stack; regression test for UNEXPECTED_MESSAGE).
        import os as _os
        import ssl as _ssl
        from proxy_server import _blocking_get_via_upstream

        async def https_stub(reader, writer) -> None:
            try:
                await read_head(reader)
                body = b"203.0.113.7\n"
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n"
                             b"Connection: close\r\n\r\n" + body)
                await writer.drain()
            except (ConnectionError, OSError):
                pass
            finally:
                try:
                    writer.close()
                except Exception:
                    pass

        crt = _os.path.join(FIXTURES, "localhost.crt")
        key = _os.path.join(FIXTURES, "localhost.key")
        server_ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
        server_ctx.load_cert_chain(crt, key)
        stub = await asyncio.start_server(https_stub, "127.0.0.1", 0, ssl=server_ctx)
        tport = stub.sockets[0].getsockname()[1]
        up = FakeUpstream(pipe_target=("127.0.0.1", tport))
        _, uport = await up.start(tls_cert=crt, tls_key=key)
        try:
            body = await asyncio.to_thread(
                _blocking_get_via_upstream,
                "u", "p", "127.0.0.1", uport, True,
                "localhost", tport, "/s", True, 10.0, crt)
            self.assertIn(b"203.0.113.7", body)
        finally:
            await up.stop()
            stub.close()
            await stub.wait_closed()

    def test_paint_respects_color_switch(self):
        import main as _main
        old, _main._COLOR = _main._COLOR, False
        try:
            self.assertEqual(_main.paint("hi", _main.C.BOLD), "hi")
            self.assertEqual(_main._ok("x"), "[+] x")
        finally:
            _main._COLOR = old

    def test_paint_emits_ansi_when_enabled(self):
        import main as _main
        old, _main._COLOR = _main._COLOR, True
        try:
            out = _main.paint("hi", _main.C.BOLD, _main.C.GREEN)
            self.assertTrue(out.startswith("\033["))
            self.assertTrue(out.endswith("\033[0m"))
            self.assertIn("hi", out)
        finally:
            _main._COLOR = old

if __name__ == "__main__":
    unittest.main()
