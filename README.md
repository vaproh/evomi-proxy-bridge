# Evomi Bridge (Tauri GUI)

A floating desktop window that chains your browser to Evomi residential proxies:
loopback HTTP proxy (`127.0.0.1:8899`) with CONNECT tunneling, authenticated
upstream (plain or TLS with hostname verification), one-click session rotation,
exit-IP + geo verification, PAC auto-config, and a live log view.

Rust core (`crates/bridge`, 27 tests) + Tauri shell + vanilla HTML/CSS/JS UI.
Windows and Linux. No Python, no Docker, no paid dependencies.

## Run it

**Linux dev:**
```bash
just dev        # debug window (needs webkit2gtk dev libs)
just build      # .deb + .rpm in target/release/bundle/
```

> Local note: this machine has no ayatana-appindicator dev package (no sudo),
> so a shimmed `.pc` lives at `~/.local/lib/pkgconfig` (picked up by the
> justfile). CI installs the real dev packages.

**From a release:** install the `.deb`/`.rpm` (Linux) or `.msi`/`.exe`
(Windows), launch "Evomi Bridge".

## First run

1. Open **Settings**, enter your Evomi username and password (or paste a full
   `http://user:pass_flags@host:port` / `https://host:port:user:pass` string -
   either field accepts it). HTTPS upstream? Tick **https upstream** and use
   port 1001 with an `*.evomi-proxy.com` host.
2. **Save & restart** - credentials are stored in `.env` under the app config
   dir (`~/.config/evomi-proxy-bridge/` on Linux), `chmod 600`.
3. The bridge starts automatically. Point Mullvad Browser at it (below), then
   hit **Rotate** and **Check IP** on the Status tab.

## Mullvad Browser setup

Settings → Network Settings → Manual proxy configuration:

- HTTP Proxy `127.0.0.1`, port `8899`, tick **"Also use this proxy for HTTPS"**.
- Or fully automatic: set the browser's **Automatic proxy configuration URL**
  to the PAC address shown on the Status tab
  (`http://127.0.0.1:8899/proxy.pac`).

Verify: visit `https://ip.evomi.com/s`, or press **Check IP** - the exit IP,
country, and ISP appear in the window and in a desktop notification after
each rotation. Compare against a leak test (e.g. dnsleaktest.com): with the
proxy active you should see the Evomi exit, never your ISP.

## What each control does

- **Power button / tray Start-Stop**: starts or stops the local listener.
- **Rotate**: new random session id (all other password flags kept), old
  tunnels drain, then the exit IP is re-verified and a desktop notification
  shows the new IP + location. A new id does **not** guarantee a new IP -
  only the check confirms it.
- **Type chips (session/hard/locked)**: Evomi sticky-session modes; switching
  mints a fresh id. Hard/locked drop the lifetime flag.
- **Lifetime**: sticky minutes (1-1440, default 30 for `session`); the ring
  counts down to expiry. `0` clears it.
- **Logs tab**: live bridge log (follows, keeps last ~400 lines on screen).
- **Tray**: show/hide, rotate, check IP, start/stop, quit. Closing the window
  hides to tray; the bridge keeps running. Tooltip shows the current exit IP.

## Troubleshooting

- **Upstream auth failed (407)**: wrong username/password - re-enter in Settings.
- **Upstream 502 for some sites, others fine**: comes from Evomi's side for that
  specific target (exit peer can't route to it). Rotate and retry; repeats for
  the same target log once per 10 minutes (repeats go to debug) so probe
  hosts don't spam the Logs tab - the browser still gets the 502.
- **Exit IP unchanged after Rotate**: Evomi may reuse the peer; rotate again.
  Persistent browser tabs keep old tunnels until they reconnect.
- **TLS hostname failure**: the HTTPS certificate covers `*.evomi-proxy.com` -
  an `https://` host outside it warns at startup and fails closed (502, no
  credentials sent).

## Build system

Every `v*` tag push runs `.github/workflows/release.yml`: Rust tests, then
Tauri builds for Linux + Windows, attached to a GitHub release with
auto-generated notes. `git tag vX.Y.Z && git push origin vX.Y.Z`.

## Layout

```
crates/bridge/   core proxy: server, CONNECT, TLS, checks, sessions, PAC, logs
src-tauri/       Tauri shell: commands, tray, notifications, window config
ui/              static frontend: index.html, styles.css, app.js (no build step)
```
