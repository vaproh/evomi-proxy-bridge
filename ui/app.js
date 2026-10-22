// Evomi Bridge UI: polls backend, animates changes, no build step.
const $ = (id) => document.getElementById(id);
const invoke = (cmd, args = {}) => window.__TAURI__.core.invoke(cmd, args);

const QUIPS = [
  "sipping bandwidth, not chugging it",
  "your IP called in sick today",
  "fresh exit, who dis?",
  "tunnels dug, all quiet",
  "geo? never met her",
  "rotating like it's laundry day",
  "the proxy goblins approve",
  "same browser, brand-new accent",
];
let quipTimer = null;

const state = { lastIp: null, lastLogId: 0, unreadLogs: 0, pollers: [] };

function toast(msg, ms = 4500) {
  const t = $("toast");
  t.textContent = msg;
  t.classList.remove("hidden");
  clearTimeout(t._h);
  t._h = setTimeout(() => t.classList.add("hidden"), ms);
}

async function copyPac() {
  try {
    await navigator.clipboard.writeText($("pac-url").textContent);
    toast("PAC url copied - paste it as the browser's automatic-config URL");
  } catch {
    toast("copy failed - select the URL manually");
  }
}
async function call(cmd, args, what) {
  try {
    return await invoke(cmd, args);
  } catch (e) {
    toast(`${what || cmd} failed: ${e}`);
    throw e;
  }
}

function fmtUptime(s) {
  s = Math.floor(s || 0);
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60);
  return h > 0 ? `${h}h ${m}m` : `${m}m ${s % 60}s`;
}

function renderStatus(s) {
  const running = !!s.running;
  $("status-dot").className = "dot" + (running ? " running" : " stopped");
  const power = $("power");
  power.className = "power " + (running ? "on" : "off");
  $("state-line").textContent = running ? "protected" : "stopped";

  const ip = s.last_ip || "—";
  if (ip !== state.lastIp) {
    const el = $("exit-ip");
    el.textContent = ip;
    el.classList.remove("flip");
    void el.offsetWidth;
    el.classList.add("flip");
    state.lastIp = ip;
  }
  $("geo").textContent = s.last_geo || (running ? "press check to verify" : "bridge stopped");
  let note = $("check-note");
  if (!note) {
    note = document.createElement("div");
    note.id = "check-note";
    note.className = "check-note";
    $("geo").after(note);
  }
  note.textContent = s.last_check_note || "";
  note.classList.toggle("bad", /fail/i.test(s.last_check_note || ""));

  $("session-label").textContent = s.session_label || "—";
  document.querySelectorAll("#type-row .chip").forEach((c) => {
    const label = c.dataset.type === "hard" ? "hardsession" : c.dataset.type === "locked" ? "lockedsession" : "session";
    c.classList.toggle("active", label === s.session_type);
  });
  $("flags").textContent = s.flags || "—";

  const lifeMin = s.lifetime_min;
  const left = s.expires_in_s;
  const ring = $("ring-fg");
  if (lifeMin && left != null) {
    const total = lifeMin * 60;
    const frac = Math.max(0, Math.min(1, left / total));
    ring.style.strokeDashoffset = String(113 * (1 - frac));
    ring.style.stroke = frac < 0.15 ? "var(--red)" : frac < 0.4 ? "var(--amber)" : "var(--green)";
    $("lifetime").textContent = `lifetime ${lifeMin} min (expires in ~${Math.ceil(left / 60)} min)`;
  } else {
    ring.style.strokeDashoffset = "0";
    ring.style.stroke = "var(--dim)";
    $("lifetime").textContent = s.session_type === "session" ? "lifetime —" : "lifetime n/a (sticky)";
  }

  $("upstream").textContent = s.upstream || "—";
  $("listening").textContent = s.listening ? `yes (127.0.0.1:${s.bound_port})` : "no";
  $("counts").textContent = `${s.request_count} / ${s.connect_count} · up ${fmtUptime(s.uptime_s)}`;
  $("pac-url").textContent = s.pac_url || "—";

  $("btn-rotate").disabled = !running;
  $("btn-check").disabled = !running;
}

function renderLogs(entries) {
  const list = $("log-list");
  const follow = $("autoscroll").checked;
  const nearBottom = list.scrollHeight - list.scrollTop - list.clientHeight < 60;
  for (const e of entries) {
    const div = document.createElement("div");
    div.className = `log-line ${e.level}`;
    const lv = document.createElement("span");
    lv.className = "lv";
    lv.textContent = e.level;
    div.appendChild(lv);
    div.appendChild(document.createTextNode(e.message));
    list.appendChild(div);
    while (list.children.length > 400) list.removeChild(list.firstChild);
    state.lastLogId = Math.max(state.lastLogId, e.id);
  }
  if (entries.length && !$("tab-logs").classList.contains("active")) {
    state.unreadLogs += entries.length;
    const b = $("log-badge");
    b.textContent = state.unreadLogs > 99 ? "99+" : state.unreadLogs;
    b.classList.remove("hidden");
  }
  if (follow && (nearBottom || entries.length)) list.scrollTop = list.scrollHeight;
}

async function pollStatus() {
  try {
    renderStatus(await invoke("get_status"));
  } catch { /* backend starting */ }
}

async function pollLogs() {
  try {
    const entries = await invoke("get_logs", { since: state.lastLogId });
    if (entries.length) renderLogs(entries);
  } catch { /* ignore */ }
}

async function refreshSettings() {
  const s = await call("get_settings", {}, "Load settings");
  if (!s) return;
  $("set-username").value = s.username || "";
  $("set-host").value = s.upstream_host || "";
  $("set-port").value = s.upstream_port || "";
  $("set-tls").checked = !!s.upstream_tls;
  $("set-local-port").value = s.local_port ?? "";
  $("set-local-user").value = s.local_user || "";
  $("set-notify").checked = !!s.notify;
  const st = (s.session_type || "session").replace("hard", "hard").replace("lockedsession", "locked").replace("hardsession", "hard");
  $("set-type").value = st === "session" ? "session" : st;
  $("set-lifetime").value = s.lifetime ?? "";
  $("env-path").textContent = s.env_path ? `stored in ${s.env_path}` : "";
}

function startPollers() {
  stopPollers();
  pollStatus();
  pollLogs();
  state.pollers = [setInterval(pollStatus, 2000), setInterval(pollLogs, 1000)];
  quipTimer = setInterval(() => {
    $("quip").textContent = "“" + QUIPS[Math.floor(Math.random() * QUIPS.length)] + "”";
  }, 8000);
  $("quip").textContent = "“" + QUIPS[Math.floor(Math.random() * QUIPS.length)] + "”";
}
function stopPollers() {
  state.pollers.forEach(clearInterval);
  state.pollers = [];
  if (quipTimer) clearInterval(quipTimer);
}

function bindTabs() {
  document.querySelectorAll(".tab").forEach((t) => {
    t.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach((x) => x.classList.remove("active"));
      document.querySelectorAll(".pane").forEach((x) => x.classList.remove("active"));
      t.classList.add("active");
      $("tab-" + t.dataset.tab).classList.add("active");
      if (t.dataset.tab === "logs") {
        state.unreadLogs = 0;
        $("log-badge").classList.add("hidden");
      }
      if (t.dataset.tab === "settings") refreshSettings();
    });
  });
}

function bindActions() {
  $("power").addEventListener("click", async () => {
    const on = $("power").classList.contains("on");
    await call(on ? "stop_bridge" : "start_bridge", {}, on ? "Stop" : "Start").catch(() => {});
    pollStatus();
  });
  $("btn-rotate").addEventListener("click", async () => {
    await call("rotate_session", {}, "Rotate").catch(() => {});
    setTimeout(pollStatus, 300);
  });
  $("btn-check").addEventListener("click", async () => {
    await call("check_ip", {}, "Check IP").catch(() => {});
    setTimeout(pollStatus, 300);
  });
  document.querySelectorAll("#type-row .chip").forEach((c) => {
    c.addEventListener("click", async () => {
      await call("set_session_type", { session_type: c.dataset.type }, "Session type").catch(() => {});
      setTimeout(pollStatus, 300);
    });
  });
  $("btn-lifetime").addEventListener("click", async () => {
    const v = parseInt($("lifetime-input").value, 10);
    if (Number.isNaN(v) || v < 0 || v > 1440) return toast("lifetime must be 0-1440 (0 clears)");
    await call("set_lifetime", { minutes: v }, "Lifetime").catch(() => {});
    $("lifetime-input").value = "";
    setTimeout(pollStatus, 300);
  });
  $("btn-pac").addEventListener("click", copyPac);
  document.querySelectorAll(".copyable").forEach((el) => {
    el.addEventListener("click", async () => {
      const text = el.textContent;
      if (!text || text === "—") return;
      try {
        await navigator.clipboard.writeText(text);
        toast("copied to clipboard");
      } catch {
        toast("copy failed - select the text manually");
      }
    });
  });
  $("btn-clear-logs").addEventListener("click", () => {
    $("log-list").innerHTML = "";
  });
  $("btn-save").addEventListener("click", async () => {
    const lt = $("set-lifetime").value === "" ? null : parseInt($("set-lifetime").value, 10);
    const payload = {
      username: $("set-username").value,
      password: $("set-password").value,
      upstream_host: $("set-host").value,
      upstream_port: parseInt($("set-port").value, 10),
      upstream_tls: $("set-tls").checked,
      local_port: parseInt($("set-local-port").value, 10),
      local_user: $("set-local-user").value,
      local_pass: $("set-local-pass").value,
      session_type: $("set-type").value,
      lifetime: lt,
      notify: $("set-notify").checked,
    };
    if (!payload.username) return toast("username is required");
    if (Number.isNaN(payload.upstreamPort) || Number.isNaN(payload.localPort)) return toast("ports must be numbers");
    await call("save_settings", payload, "Save").catch(() => {});
    $("set-password").value = "";
    pollStatus();
  });
}

document.addEventListener("DOMContentLoaded", () => {
  bindTabs();
  bindActions();
  startPollers();
});
