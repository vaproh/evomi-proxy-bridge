//! Evomi Bridge desktop app: Tauri shell around evomi-bridge-core.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use evomi_bridge_core::{
    check_exit_ip_blocking, check_geo_blocking, env_password, load_dotenv, resolve_config,
    Config, Explicit, LogBuffer, ProxyServer, SessionState, SessionType,
};
use tauri::Manager;

const LOG_CAPACITY: usize = 2000;
const CHECK_TIMEOUT_S: u64 = 20;

struct Core {
    config: Config,
    env_path: String,
    password: String,
    session: Option<Arc<SessionState>>,
    server: Option<Arc<ProxyServer>>,
    running: bool,
    last_ip: Option<String>,
    last_geo: String,
    last_check_note: String,
}

impl Core {
    fn status_snapshot(&self) -> serde_json::Value {
        let (session_label, session_type, flags, lifetime_min, expires_in) = match &self.session {
            Some(s) => (
                s.label(),
                s.session_type().to_string(),
                s.flags().join(" | "),
                s.lifetime_minutes().map(|m| m as u64),
                s.expires_in_s(),
            ),
            None => ("-".into(), "-".into(), String::new(), None, None),
        };
        let stats = self.server.as_ref().map(|s| s.stats());
        serde_json::json!({
            "running": self.running,
            "listening": stats.as_ref().map(|s| s.listening).unwrap_or(false),
            "local_port": self.config.local_port,
            "bound_port": stats.as_ref().map(|s| s.bound_port).unwrap_or(self.config.local_port),
            "upstream": format!("{}://{}:{}",
                if self.config.upstream_tls { "https" } else { "http" },
                self.config.upstream_host, self.config.upstream_port),
            "upstream_tls": self.config.upstream_tls,
            "username": self.config.username,
            "has_password": !self.password.is_empty(),
            "session_label": session_label,
            "session_type": session_type,
            "flags": flags,
            "lifetime_min": lifetime_min,
            "expires_in_s": expires_in,
            "last_ip": self.last_ip,
            "last_geo": self.last_geo,
            "last_check_note": self.last_check_note,
            "request_count": stats.as_ref().map(|s| s.request_count).unwrap_or(0),
            "connect_count": stats.as_ref().map(|s| s.connect_count).unwrap_or(0),
            "uptime_s": stats.as_ref().map(|s| s.uptime_s).unwrap_or(0),
            "pac_url": format!("http://127.0.0.1:{}/proxy.pac",
                stats.as_ref().map(|s| s.bound_port).unwrap_or(self.config.local_port)),
            "notify": self.config.notify,
        })
    }
}

struct AppState {
    core: Mutex<Core>,
    logs: Arc<LogBuffer>,
}

impl AppState {
    fn new(config: Config, env_path: String, password: String, logs: Arc<LogBuffer>) -> Self {
        AppState {
            core: Mutex::new(Core {
                config,
                env_path,
                password,
                session: None,
                server: None,
                running: false,
                last_ip: None,
                last_geo: String::new(),
                last_check_note: String::new(),
            }),
            logs,
        }
    }
}

fn install_logger(logs: &Arc<LogBuffer>) {
    struct Forward(Arc<LogBuffer>);
    impl log::Log for Forward {
        fn enabled(&self, m: &log::Metadata) -> bool {
            m.level() <= log::Level::Info
        }
        fn log(&self, r: &log::Record) {
            if self.enabled(r.metadata()) {
                self.0.push(r.level().as_str(), r.args().to_string());
            }
        }
        fn flush(&self) {}
    }
    let logger: &'static Forward = Box::leak(Box::new(Forward(Arc::clone(logs))));
    let _ = log::set_logger(logger);
    log::set_max_level(log::LevelFilter::Info);
}

/// Resolve the .env location: app config dir, seeded from ./.env on first run.
fn resolve_env_path(app: &tauri::AppHandle) -> String {
    let dir = app
        .path()
        .app_config_dir()
        .unwrap_or_else(|_| std::path::PathBuf::from("."));
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join(".env");
    if !path.exists() {
        if let Ok(seed) = std::fs::read_to_string("./.env") {
            let _ = std::fs::write(&path, seed);
        }
    }
    path.to_string_lossy().into_owned()
}

fn write_env_file(path: &str, updates: &HashMap<String, String>) {
    let mut lines: Vec<String> = std::fs::read_to_string(path).unwrap_or_default().lines().map(|s| s.to_string()).collect();
    for (k, v) in updates {
        let mut done = false;
        for line in lines.iter_mut() {
            let t = line.trim();
            if t.starts_with('#') || t.starts_with("export ") {
                continue;
            }
            if let Some((kk, _)) = t.split_once('=') {
                if kk.trim() == *k {
                    *line = format!("{k}={v}");
                    done = true;
                    break;
                }
            }
        }
        if !done {
            lines.push(format!("{k}={v}"));
        }
    }
    let mut out = lines.join("\n");
    if !out.is_empty() {
        out.push('\n');
    }
    let _ = std::fs::write(path, out);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(md) = std::fs::metadata(path) {
            let mut perm = md.permissions();
            perm.set_mode(0o600);
            let _ = std::fs::set_permissions(path, perm);
        }
    }
}

fn initial_session(config: &Config, password: &str) -> Option<Arc<SessionState>> {
    if password.is_empty() {
        return None;
    }
    let session = Arc::new(SessionState::new(password).ok()?);
    session.set_session_type(config.session_type);
    if let Some(l) = config.lifetime {
        let _ = session.set_lifetime(Some(l));
    }
    // Otherwise any lifetime flag already present in the pasted template stays.
    Some(session)
}

#[tauri::command]
async fn get_status(state: tauri::State<'_, AppState>) -> Result<serde_json::Value, String> {
    Ok(state.core.lock().unwrap().status_snapshot())
}

#[tauri::command]
async fn get_logs(state: tauri::State<'_, AppState>, since: u64) -> Result<Vec<serde_json::Value>, String> {
    Ok(state
        .logs
        .since(since)
        .into_iter()
        .map(|e| serde_json::json!({"id": e.id, "level": e.level, "message": e.message}))
        .collect())
}

#[tauri::command]
async fn start_bridge(state: tauri::State<'_, AppState>) -> Result<serde_json::Value, String> {
    let (config, session) = {
        let mut core = state.core.lock().unwrap();
        if core.running {
            return Ok(core.status_snapshot());
        }
        if core.password.is_empty() || core.config.username.is_empty() {
            return Err("Set username and password in Settings first.".into());
        }
        if core.session.is_none() {
            core.session = initial_session(&core.config, &core.password);
        }
        let session = core.session.clone().ok_or("Could not init session.")?;
        (core.config.clone(), session)
    };
    let server = ProxyServer::new(config.clone(), session).map_err(|e| e.to_string())?;
    server.start().await.map_err(|e| e.to_string())?;
    {
        let mut core = state.core.lock().unwrap();
        core.server = Some(server);
        core.running = true;
        log::info!(
            "bridge up on 127.0.0.1:{} -> {}:{}",
            config.local_port, config.upstream_host, config.upstream_port
        );
        if config.upstream_tls && !config.upstream_host.ends_with("evomi-proxy.com") {
            log::warn!("upstream TLS host outside *.evomi-proxy.com; verification may fail");
        }
        Ok(core.status_snapshot())
    }
}

#[tauri::command]
async fn stop_bridge(state: tauri::State<'_, AppState>) -> Result<serde_json::Value, String> {
    let server = {
        let mut core = state.core.lock().unwrap();
        core.running = false;
        core.server.take()
    };
    if let Some(server) = server {
        server.stop().await;
    }
    log::info!("bridge stopped");
    Ok(state.core.lock().unwrap().status_snapshot())
}

fn spawn_verify(app: tauri::AppHandle, old_ip: Option<String>) {
    tauri::async_runtime::spawn(async move {
        let state: tauri::State<AppState> = app.state();
        let (username, password, host, port, tls, cafile) = {
            let core = state.core.lock().unwrap();
            (
                core.config.username.clone(),
                core.password.clone(),
                core.config.upstream_host.clone(),
                core.config.upstream_port,
                core.config.upstream_tls,
                core.config.upstream_cafile.clone(),
            )
        };
        let cafile = if cafile.is_empty() { None } else { Some(cafile) };
        let geo_args = (username.clone(), password.clone(), host.clone(), port, tls);
        let res = tokio::task::spawn_blocking(move || {
            check_exit_ip_blocking(&username, &password, &host, port, tls, Duration::from_secs(CHECK_TIMEOUT_S), cafile.as_deref().unwrap_or(""))
        })
        .await;
        let (ip, geo_text) = match res {
            Ok(Ok(ip)) => {
                let (u, p, h, pt, t) = geo_args;
                let ip_for_geo = ip.clone();
                let geo = tokio::task::spawn_blocking(move || {
                    check_geo_blocking(&u, &p, &h, pt, t, &ip_for_geo, Duration::from_secs(CHECK_TIMEOUT_S))
                })
                .await
                .unwrap_or_default();
                let g = if geo.country.is_empty() {
                    String::new()
                } else {
                    format!("{}, {}", geo.city, geo.country)
                };
                (Some(ip), g)
            }
            Ok(Err(e)) => {
                log::warn!("IP check failed: {e}");
                (None, String::new())
            }
            Err(e) => {
                log::warn!("IP check task failed: {e}");
                (None, String::new())
            }
        };
        let notify_enabled;
        let detail;
        {
            let mut core = state.core.lock().unwrap();
            notify_enabled = core.config.notify;
            if let Some(ip) = ip.clone() {
                core.last_ip = Some(ip.clone());
                core.last_geo = geo_text.clone();
                core.last_check_note = "verified just now".to_string();
            }
            let changed = match (&old_ip, &ip) {
                (Some(o), Some(n)) => o != n,
                _ => false,
            };
            detail = match (&old_ip, &ip) {
                (_, Some(n)) if changed => format!("{o} -> {n} ({geo_text})", o = old_ip.as_deref().unwrap_or(""), n = n, geo_text = geo_text.trim_matches(|c| c == ' ' || c == ',').trim_end_matches(',').trim()),
                (_, Some(n)) if old_ip.is_none() => format!("{n} ({geo_text})"),
                (_, Some(n)) => format!("{n} (unchanged)"),
                _ => "check failed".to_string(),
            };
            if old_ip.is_some() {
                log::info!("verify: {detail}");
            }
        }
        if notify_enabled {
            use tauri_plugin_notification::NotificationExt;
            let _ = app.notification().builder().title(if detail.contains("->") { "Evomi Bridge: IP changed" } else { "Evomi Bridge" }).body(detail.clone()).show();
        }
        update_tray_tooltip(&app);
    });
}

fn update_tray_tooltip(app: &tauri::AppHandle) {
    if let Some(tray) = app.tray_by_id("main") {
        let tip = {
            let state: tauri::State<AppState> = app.state();
            let core = state.core.lock().unwrap();
            match (&core.running, &core.last_ip) {
                (true, Some(ip)) => format!("Evomi Bridge: {ip}"),
                (true, None) => "Evomi Bridge: running".to_string(),
                _ => "Evomi Bridge: stopped".to_string(),
            }
        };
        let _ = tray.set_tooltip(Some(&tip));
    }
}

#[tauri::command]
async fn rotate_session(app: tauri::AppHandle, state: tauri::State<'_, AppState>) -> Result<serde_json::Value, String> {
    let old_ip = {
        let mut core = state.core.lock().unwrap();
        let session = core.session.clone().ok_or("No session (set credentials first).")?;
        let label = session.rotate();
        let retired = core.server.as_ref().map(|s| s.retire_idle_upstreams()).unwrap_or(0);
        log::info!("rotated to {label} (retired {retired} tracked relay(s))");
        core.last_check_note = "verifying new exit IP ...".to_string();
        core.last_ip.clone()
    };
    spawn_verify(app, old_ip);
    Ok(state.core.lock().unwrap().status_snapshot())
}

#[tauri::command]
async fn check_ip(app: tauri::AppHandle, state: tauri::State<'_, AppState>) -> Result<serde_json::Value, String> {
    let old_ip = state.core.lock().unwrap().last_ip.clone();
    spawn_verify(app, old_ip);
    Ok(state.core.lock().unwrap().status_snapshot())
}

#[tauri::command]
async fn set_session_type(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    session_type: String,
) -> Result<serde_json::Value, String> {
    let key = SessionType::from_key(&session_type.to_ascii_lowercase())
        .ok_or("unknown session type (session|hard|locked)")?;
    let old_ip = {
        let mut core = state.core.lock().unwrap();
        let session = core.session.clone().ok_or("No session (set credentials first).")?;
        session.set_session_type(key);
        core.config.session_type = key;
        log::info!("session type -> {}", key);
        core.last_ip.clone()
    };
    spawn_verify(app, old_ip);
    Ok(state.core.lock().unwrap().status_snapshot())
}

#[tauri::command]
async fn set_lifetime(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    minutes: u32,
) -> Result<serde_json::Value, String> {
    let old_ip = {
        let mut core = state.core.lock().unwrap();
        let session = core.session.clone().ok_or("No session (set credentials first).")?;
        if minutes == 0 {
            session.set_lifetime(None).map_err(|e| e)?;
            core.config.lifetime = None;
            log::info!("lifetime cleared");
        } else {
            session.set_lifetime(Some(minutes)).map_err(|e| e)?;
            core.config.lifetime = Some(minutes);
            log::info!("lifetime -> {minutes} min");
        }
        core.last_ip.clone()
    };
    spawn_verify(app, old_ip);
    Ok(state.core.lock().unwrap().status_snapshot())
}

#[tauri::command]
async fn get_settings(state: tauri::State<'_, AppState>) -> Result<serde_json::Value, String> {
    let core = state.core.lock().unwrap();
    Ok(serde_json::json!({
        "username": core.config.username,
        "has_password": !core.password.is_empty(),
        "upstream_host": core.config.upstream_host,
        "upstream_port": core.config.upstream_port,
        "upstream_tls": core.config.upstream_tls,
        "local_port": core.config.local_port,
        "local_user": core.config.local_user,
        "session_type": core.config.session_type.to_string(),
        "lifetime": core.config.lifetime,
        "notify": core.config.notify,
        "env_path": core.env_path,
    }))
}

#[allow(clippy::too_many_arguments)]
#[tauri::command]
async fn save_settings(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    username: String,
    password: String,
    upstream_host: String,
    upstream_port: u16,
    upstream_tls: bool,
    local_port: u16,
    local_user: String,
    local_pass: String,
    session_type: String,
    lifetime: Option<u32>,
    notify: bool,
) -> Result<serde_json::Value, String> {
    let key = SessionType::from_key(&session_type.to_ascii_lowercase())
        .ok_or("unknown session type (session|hard|locked)")?;
    if let Some(l) = lifetime {
        if l == 0 || l > 1440 {
            return Err("lifetime must be 1-1440".into());
        }
    }
    {
        let old_server = state.core.lock().unwrap().server.take();
        if let Some(server) = old_server {
            server.stop().await;
        }
    }
    {
        let mut core = state.core.lock().unwrap();
        core.running = false;
        core.config.username = username.trim().to_string();
        core.config.upstream_host = upstream_host.trim().to_string();
        core.config.upstream_port = upstream_port;
        core.config.upstream_tls = upstream_tls;
        core.config.local_port = local_port;
        core.config.local_user = local_user.trim().to_string();
        core.config.local_pass = local_pass;
        core.config.session_type = key;
        core.config.lifetime = lifetime;
        core.config.notify = notify;
        core.config.validate().map_err(|e| e.0)?;
        if !password.is_empty() {
            core.password = password.trim().to_string();
        }
        if core.config.username.is_empty() || core.password.is_empty() {
            return Err("username and password are required".into());
        }
        core.session = None; // rebuild on next start with new template
        let mut updates = HashMap::new();
        updates.insert("EVOMI_USERNAME".into(), core.config.username.clone());
        updates.insert("EVOMI_PASSWORD".into(), core.password.clone());
        updates.insert("EVOMI_UPSTREAM_HOST".into(), core.config.upstream_host.clone());
        updates.insert("EVOMI_UPSTREAM_PORT".into(), core.config.upstream_port.to_string());
        updates.insert("EVOMI_UPSTREAM_TLS".into(), core.config.upstream_tls.to_string());
        updates.insert("EVOMI_LOCAL_PORT".into(), core.config.local_port.to_string());
        updates.insert("EVOMI_LOCAL_USER".into(), core.config.local_user.clone());
        updates.insert("EVOMI_SESSION_TYPE".into(), key.to_string());
        if let Some(l) = lifetime {
            updates.insert("EVOMI_LIFETIME".into(), l.to_string());
        }
        if !core.config.local_pass.is_empty() {
            updates.insert("EVOMI_LOCAL_PASS".into(), core.config.local_pass.clone());
        }
        updates.insert("EVOMI_NOTIFY".into(), notify.to_string());
        let env_path = core.env_path.clone();
        write_env_file(&env_path, &updates);
        log::info!("settings saved to {env_path}; restarting bridge");
    }
    // Auto-start so new settings take effect immediately.
    start_bridge(app.state()).await
}

#[tauri::command]
async fn quit_app(app: tauri::AppHandle) {
    app.exit(0);
}

fn build_tray(app: &tauri::AppHandle) -> tauri::Result<()> {
    use tauri::menu::{Menu, MenuItem};
    use tauri::tray::TrayIconBuilder;
    let show = MenuItem::with_id(app, "show", "Show window", true, None::<&str>)?;
    let rotate = MenuItem::with_id(app, "rotate", "Rotate session", true, None::<&str>)?;
    let check = MenuItem::with_id(app, "check", "Check exit IP", true, None::<&str>)?;
    let toggle = MenuItem::with_id(app, "toggle", "Start / Stop bridge", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&show, &rotate, &check, &toggle, &quit])?;
    let icon = {
        let png = include_bytes!("../icons/32x32.png");
        let img = image::load_from_memory(png).map_err(|e| tauri::Error::Anyhow(e.into()))?.to_rgba8();
        let (w, h) = img.dimensions();
        tauri::image::Image::new_owned(img.into_raw(), w, h)
    };
    let _tray = TrayIconBuilder::with_id("main")
        .icon(icon)
        .menu(&menu)
        .tooltip("Evomi Bridge")
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "show" => {
                if let Some(w) = app.get_webview_window("main") {
                    let _ = w.show();
                    let _ = w.set_focus();
                }
            }
            "rotate" => {
                let app = app.clone();
                tauri::async_runtime::spawn(async move {
                    let state: tauri::State<AppState> = app.state();
                    let _ = rotate_session(app.clone(), state).await;
                });
            }
            "check" => {
                let app = app.clone();
                tauri::async_runtime::spawn(async move {
                    let state: tauri::State<AppState> = app.state();
                    let _ = check_ip(app.clone(), state).await;
                });
            }
            "toggle" => {
                let app = app.clone();
                tauri::async_runtime::spawn(async move {
                    let state: tauri::State<AppState> = app.state();
                    let running = state.core.lock().unwrap().running;
                    if running {
                        let _ = stop_bridge(state).await;
                    } else {
                        let _ = start_bridge(state).await;
                    }
                    update_tray_tooltip(&app);
                });
            }
            "quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            use tauri::tray::TrayIconEvent;
            if matches!(event, TrayIconEvent::DoubleClick { .. }) {
                let app = tray.app_handle();
                if let Some(w) = app.get_webview_window("main") {
                    let _ = w.show();
                    let _ = w.set_focus();
                }
            }
        })
        .build(app)?;
    Ok(())
}

pub fn run() {
    let logs = LogBuffer::new(LOG_CAPACITY);
    install_logger(&logs);
    // Config load needs an AppHandle for the config dir; do a first pass with
    // ./.env so the state exists before setup re-resolves it.
    let pre_env = load_dotenv("./.env");
    let (pre_config, pre_password, _) = {
        let mut explicit = Explicit::default();
        if let Some(u) = pre_env.get("EVOMI_USERNAME") {
            if !u.trim().is_empty() {
                explicit.username = Some(u.trim().to_string());
            }
        }
        let mut config = resolve_config(&pre_env, explicit).unwrap_or_default();
        if config.username.is_empty() {
            config.username = pre_env.get("EVOMI_USERNAME").cloned().unwrap_or_default();
        }
        (config, env_password(&pre_env), "./.env".to_string())
    };

    tauri::Builder::default()
        .plugin(tauri_plugin_notification::init())
        .manage(AppState::new(pre_config, "./.env".to_string(), pre_password, logs))
        .setup(|app| {
            // Re-resolve env path to the app config dir (seeded from ./.env).
            let env_path = resolve_env_path(app.handle());
            let env = load_dotenv(&env_path);
            let (config, password, _) = {
                let mut explicit = Explicit::default();
                if let Some(u) = env.get("EVOMI_USERNAME") {
                    if !u.trim().is_empty() {
                        explicit.username = Some(u.trim().to_string());
                    }
                }
                let mut c = resolve_config(&env, explicit).unwrap_or_default();
                if c.username.is_empty() {
                    c.username = env.get("EVOMI_USERNAME").cloned().unwrap_or_default();
                }
                (c, env_password(&env), env_path.clone())
            };
            {
                let state: tauri::State<AppState> = app.state();
                let mut core = state.core.lock().unwrap();
                core.config = config;
                core.env_path = env_path;
                core.password = password;
            }
            // Hide-on-close -> tray.
            if let Some(window) = app.get_webview_window("main") {
                let handle = app.handle().clone();
                window.on_window_event(move |event| {
                    if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                        api.prevent_close();
                        if let Some(w) = handle.get_webview_window("main") {
                            let _ = w.hide();
                        }
                    }
                });
            }
            build_tray(app.handle())?;
            // Autostart the bridge if credentials exist.
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                let state: tauri::State<AppState> = handle.state();
                let ready = {
                    let core = state.core.lock().unwrap();
                    !core.config.username.is_empty() && !core.password.is_empty()
                };
                if ready {
                    match start_bridge(state).await {
                        Ok(_) => {
                            let state: tauri::State<AppState> = handle.state();
                            let old = state.core.lock().unwrap().last_ip.clone();
                            spawn_verify(handle.clone(), old);
                        }
                        Err(e) => log::warn!("autostart failed: {e}"),
                    }
                } else {
                    log::info!("no credentials yet - configure them in Settings");
                }
                update_tray_tooltip(&handle);
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_status,
            get_logs,
            start_bridge,
            stop_bridge,
            rotate_session,
            check_ip,
            set_session_type,
            set_lifetime,
            get_settings,
            save_settings,
            quit_app,
        ])
        .run(tauri::generate_context!())
        .expect("error while running evomi bridge");
}

fn main() {
    run();
}
