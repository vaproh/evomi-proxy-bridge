"""Live integration test: real Evomi credentials, opt-in only.

Run: EVOMI_LIVE_TEST=1 EVOMI_USER=... EVOMI_PASS=... python3 -m unittest tests.test_live -v
Skipped by default so ordinary installs/tests never touch the network.
"""
from __future__ import annotations

import asyncio
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import Config, DEFAULT_UPSTREAM_HOST, DEFAULT_UPSTREAM_PORT
from main import SessionState
from proxy_server import ProxyServer, check_exit_ip

LIVE = os.environ.get("EVOMI_LIVE_TEST") == "1"


@unittest.skipUnless(LIVE, "opt-in live test (set EVOMI_LIVE_TEST=1)")
class LiveTests(unittest.IsolatedAsyncioTestCase):
    async def test_live_ip_check_and_bridge_forward(self):
        user = os.environ.get("EVOMI_USER", "")
        pw = os.environ.get("EVOMI_PASS", "")
        if not user or not pw:
            self.skipTest("EVOMI_USER/EVOMI_PASS not set")
        session = SessionState(pw)
        ip = await check_exit_ip(user, session.current_password(),
                                 DEFAULT_UPSTREAM_HOST, DEFAULT_UPSTREAM_PORT, timeout=25)
        self.assertTrue(ip, "empty exit IP")
        cfg = Config(local_port=18999, upstream_host=DEFAULT_UPSTREAM_HOST,
                     upstream_port=DEFAULT_UPSTREAM_PORT, username=user)
        cfg.validate()
        bridge = ProxyServer(cfg, session)
        await bridge.start()
        try:
            self.assertTrue(bridge.listening)
            r, w = await asyncio.open_connection("127.0.0.1", 18999)
            w.write(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n"
                    b"Connection: close\r\n\r\n")
            await w.drain()
            data = await asyncio.wait_for(r.read(65536), timeout=25)
            self.assertIn(b"200", data.split(b"\r\n", 1)[0])
            w.close()
        finally:
            await bridge.stop()


if __name__ == "__main__":
    unittest.main()
