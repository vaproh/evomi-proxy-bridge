# Evomi Proxy Bridge

Local HTTP proxy on `127.0.0.1:8899` that chains Mullvad Browser (or any app)
to Evomi residential proxies (`rp.evomi.com:1000`), with terminal-hotkey
session rotation. Stdlib only, no runtime dependencies.

Verified against Evomi docs (Oct 2026): sessions are password suffixes like
`basepassword_country-US_session-<id>`; session ids are 6-10 alphanumerics
(this bridge uses 8 hex chars via `secrets.token_hex(4)`); the `session` type
may change IP for stability; exit-IP check endpoint is `https://ip.evomi.com/s`.

## Install & run

```bash
cd proxy-bridge
python3 -m venv .venv && source .venv/bin/activate   # or: uv venv && source .venv/bin/activate
pip install -r requirements.txt   # runtime needs nothing; file pins test tooling only
python3 main.py
```

You will be prompted for your Evomi username and password (hidden input,
kept in process memory only, never written to disk or shown in `ps`/history).
Two input styles are accepted at the password prompt:

- a base password, or
- a full dashboard string with Evomi flags, e.g.
  `XXXXXXXXXXXXXXXXXX_country-GB,US,AE,DE,FR,IT_session-B4KINYMKS_lifetime-15`
  (session id, `hardsession-`/`lockedsession-`, `lifetime-N`, geo flags, ...).

Rotation (`r`) swaps only the session id and keeps every other flag.
Alternatively, paste a complete proxy URL at the username prompt:

```bash
http://exampleuser:XXXX_country-GB,US_session-Ab12Cd34_lifetime-15@core-residential.evomi.com:1000
```

and user, password, upstream host and port are all taken from it. Then:

```bash
python3 main.py --help
python3 main.py --username myuser --upstream-host rp.evomi.com --upstream-port 1000
```

Hotkeys (single keypress, no Enter, no root): `r` rotate+verify+notify,
`i` proxy info (flags, lifetime, exit IP, geo), `s` status, `q` quit.
Ctrl+C also shuts down cleanly.

## HTTPS upstream (e.g. `*.evomi-proxy.com:1001`)

Paste your `https://host:port:user:pass_flags` string (or set
`EVOMI_PROXY_URL`, or `--upstream-host ... --upstream-port 1001 --upstream-tls`).
The bridge wraps the upstream leg in TLS and verifies the certificate hostname
against the configured host (plain Python `ssl`, no custom code); a mismatch
or untrusted cert fails the request with 502 instead of sending credentials.
Per Evomi's docs the TLS certificate covers `evomi-proxy.com`, so an
`https://` host outside `*.evomi-proxy.com` prints a warning at startup.
The browser-to-bridge hop stays plain HTTP on loopback (`127.0.0.1`), which is
correct: loopback is trusted and browsers speak plain HTTP to local proxies.

## `.env` file (optional)

Proxy details can live in a `.env` file instead of prompts/flags:

```bash
cp .env.example .env && chmod 600 .env
${EDITOR:-nano} .env
python3 main.py            # picks up .env automatically
python3 main.py --env-file /path/to/other.env
```

Supported keys: `EVOMI_PROXY_URL` (full `http://user:pass_flags@host:port`),
`EVOMI_USERNAME`, `EVOMI_PASSWORD` (flags allowed), `EVOMI_UPSTREAM_HOST`,
`EVOMI_UPSTREAM_PORT`, `EVOMI_UPSTREAM_TLS` (`true` for `https://` endpoints), `EVOMI_LOCAL_PORT`, `EVOMI_LOCAL_USER`,
`EVOMI_LOCAL_PASS`, `EVOMI_CONNECT_TIMEOUT`, `EVOMI_MAX_CONNECTIONS`,
`EVOMI_NOTIFY`. Precedence: CLI flags > `.env` > defaults; anything still
missing (username/password) is prompted. Quoting, `export ` prefixes and
full-line `#` comments are accepted; no escape processing is done.

Security: `.env` holds your password on disk, so the bridge warns if it is
readable by anyone but you, `.env.example` ships with empty values, and
`.gitignore` excludes `.env`. Prefer prompts on shared machines.

After each rotation the bridge re-checks the exit IP in the background and
pops a Linux desktop notification (`notify-send` from libnotify, no extra
Python deps) with the new IP and location; `--no-notify` disables this.
Geo info is a best-effort lookup via free ip-api.com through the same proxy
tunnel and may occasionally be unavailable or rate-limited.

Optional local auth (off by default; the loopback listener otherwise accepts
any local process — see Limitations):

```bash
python3 main.py --local-user me --local-pass 'long-random-string'
```

## Mullvad Browser setup

Mullvad Browser is Firefox-based, so proxy setup follows the Firefox UI. No
startup flags or custom profiles are used or needed; I did not verify the
exact menu labels of your installed version, so names below may differ
slightly (Settings → search "proxy" if lost).

1. Open Mullvad Browser → Settings → Network Settings → **Settings…** →
   **Manual proxy configuration**.
2. HTTP Proxy: `127.0.0.1`, Port: `8899`.
3. Tick **"Also use this proxy for HTTPS"**.
4. Leave SOCKS empty. Keep DNS-over-HTTPS as-is (HTTP(S) proxying resolves
   hostnames at the proxy; see leak test below). Do not change the user
   agent or fingerprinting settings.

Test it: press `i` in the bridge terminal (independent check through the same
upstream, plus geo) or visit `https://ip.evomi.com/s` in the browser. Then compare against a
leak test such as `https://www.dnsleaktest.com`: with the proxy active, the
shown IP/country should match the Evomi exit IP, not your ISP. A mismatch
between the page and your real ISP address means proxying works; identical
ISP values mean a direct connection or DNS leak — recheck steps 1-3 and that
the bridge terminal shows request counts growing (press `s`).

## Browser-session vs proxy-session (two workflows)

Rotating the proxy session (`r`) changes only the upstream exit IP used by
**new** connections. It does not clear cookies, cache, localStorage, or site
data, and it does not reset browser identity. Two options:

- **Keep the browser open, press `r`**: subsequent new connections use the new
  session. Fast, but existing tabs/keep-alive connections and all stored site
  data persist — sites can still recognize you by cookies/fingerprint.
- **Close Mullvad Browser, press `r`, reopen (New Identity if offered)**:
  full reset — new exit IP *and* clean browser state. Use this when you need
  sites to see a fresh visitor.

## Troubleshooting

- **407 / "Upstream auth failed"**: wrong Evomi username or base password,
  or a typo at the prompt. Restart and re-enter. The bridge never logs
  credentials; check the Evomi dashboard that the account has balance.
- **Exit IP unchanged after `r`**: expected sometimes — Evomi may reassign
  the same peer, and existing keep-alive tunnels/websockets keep the old IP
  until they reconnect. Press `i` twice (before/after) for an independent
  check; open a fresh tab or restart the browser if a tab reuses a tunnel.
- **CONNECT failures / pages hang on HTTPS**: upstream port 1000 may be
  blocked on your network, or `rp.evomi.com` fails to resolve. Try the
  alternate HTTPS endpoint: `--upstream-host rp.evomi-proxy.com
  --upstream-port 1001` (same credentials). Check status.evomi.com.
- **Location shows "unavailable"**: geo comes from free ip-api.com through
  the proxy tunnel and can be rate-limited; the exit IP itself is authoritative
  (it comes from Evomi). Your configured `country-...` targeting flags are
  always shown by `i`/`s` regardless.
- **Port 8899 in use**: stop the other program or pass `--local-port 8900`
  and update the browser port to match.
- **Nothing loads, bridge shows no requests**: browser is not using the
  proxy (recheck Manual configuration) or another profile/window bypasses it.

## Limitations (honest)

- A new session id does **not** guarantee a new exit IP; only the `i` check
  (or `ip.evomi.com/s` in-browser) confirms a change.
- Persistent browser connections (keep-alive, websockets, downloads) opened
  before rotation keep the old exit IP until closed. The bridge never kills
  active tunnels mid-stream; rotation retires idle sockets only.
- One upstream TCP connection per request (`Connection: close`, no
  keep-alive reuse): slightly more handshake overhead, deliberately traded
  for rotation correctness.
- Local listener has **no authentication by default**; any local process can
  use it. It binds `127.0.0.1` only (never LAN), and `--local-user/--local-pass`
  enables Basic auth if you want it.
- Plain-HTTP forwarding only relays `http://` absolute URIs; exotic methods
  with bodies over 32 MiB are rejected. CONNECT tunnels carry anything
  (including HTTPS) byte-for-byte without interception — TLS is never
  decrypted.

## Tests

```bash
python3 -m unittest discover -s tests -v        # offline unit tests
EVOMI_LIVE_TEST=1 EVOMI_USER=... EVOMI_PASS=... python3 -m unittest tests.test_live -v  # opt-in real-credential test
```

Never runs real proxy traffic unless you explicitly opt in via `EVOMI_LIVE_TEST=1`.
