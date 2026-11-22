mod apple_intents;
mod commands;
mod events;
mod notifications;

use comail_core::config::Paths;
use comail_core::Core;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{Emitter, Manager};

pub(crate) fn show_main(app: &tauri::AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

/// True for a `mailto:` deep link (case-insensitive, tolerant of leading space).
fn is_mailto(s: &str) -> bool {
    s.trim_start().to_ascii_lowercase().starts_with("mailto:")
}

/// First `mailto:` argument in a process arg list, if any.
fn mailto_from_args<I: IntoIterator<Item = String>>(args: I) -> Option<String> {
    args.into_iter().find(|a| is_mailto(a))
}

/// What the webview may do with a requested navigation.
#[derive(Debug, PartialEq, Eq)]
enum NavDecision {
    /// The app's own origins may load in the webview.
    Allow,
    /// External web/mailto targets go to the OS handler; the in-app
    /// navigation itself is cancelled.
    OpenExternal,
    /// Everything else is refused (`data:`, `file:`, `javascript:`, other
    /// localhost ports, unknown schemes).
    Deny,
}

/// Strict allowlist for webview navigations, mirroring
/// `AppManager::get_app_url`: the configured `devUrl` under `cfg(dev)` (the
/// same flag tauri-build and `get_app_url` use, not just a debug build), or a
/// `frontendDist` of the `Url` form otherwise. Falling back, the real app
/// origins per `tauri_protocol_url` are `tauri://localhost` (everywhere the
/// custom scheme registers - macOS/iOS/Linux, and Windows under the
/// dev-server proxy) and `http(s)://tauri.localhost` (Windows/Android);
/// both must match exactly with no explicit port. `about:` is limited to
/// exactly `about:blank`/`about:srcdoc` because wry does not filter the
/// callback to the main frame: on macOS it hooks
/// `decidePolicyForNavigationAction`, which WKWebView raises for any frame,
/// so the subframe loads of the sandboxed email-body iframe report here too
/// (WebView2's `NavigationStarting` is main-frame only).
fn nav_decision(
    url: &tauri::Url,
    dev_url: Option<&tauri::Url>,
    dist_url: Option<&tauri::Url>,
) -> NavDecision {
    // The app URL the platform may actually load, mirroring `get_app_url`:
    // devUrl under cfg(dev), else a URL-form frontendDist.
    let configured = if cfg!(dev) { dev_url } else { dist_url };
    let app_url = match url.scheme() {
        "tauri" => url.host_str() == Some("localhost") && url.port().is_none(),
        "about" => matches!(url.path(), "blank" | "srcdoc") && url.host_str().is_none(),
        "http" | "https" => {
            (url.host_str() == Some("tauri.localhost") && url.port().is_none())
                || configured.is_some_and(|d| url.origin() == d.origin())
        }
        _ => false,
    };
    if app_url {
        return NavDecision::Allow;
    }
    if matches!(url.scheme(), "http" | "https" | "mailto") {
        return NavDecision::OpenExternal;
    }
    NavDecision::Deny
}

/// Bring the window forward and hand a `mailto:` link to the frontend (which
/// opens a prefilled composer). De-duplicated because the same link can arrive
/// twice on a cold start (launch argv *and* the deep-link plugin's callback).
pub(crate) fn forward_mailto(app: &tauri::AppHandle, url: &str) {
    if !is_mailto(url) {
        return;
    }
    static LAST: std::sync::LazyLock<std::sync::Mutex<Option<(String, std::time::Instant)>>> =
        std::sync::LazyLock::new(|| std::sync::Mutex::new(None));
    {
        let mut last = LAST.lock().unwrap();
        let now = std::time::Instant::now();
        if let Some((u, t)) = last.as_ref() {
            if u == url && now.duration_since(*t) < std::time::Duration::from_millis(1500) {
                return;
            }
        }
        *last = Some((url.to_string(), now));
    }
    show_main(app);
    let _ = app.emit("deeplink:mailto", url);
}

/// Resolve a persisted language setting ("system" | a code) to a concrete code.
/// Tauri menus have no built-in i18n, so the tray labels are localized here.
fn resolve_lang(setting: &str) -> String {
    if setting.is_empty() || setting == "system" {
        return std::env::var("LANG")
            .ok()
            .and_then(|l| l.split(['_', '.', '-']).next().map(str::to_string))
            .filter(|l| !l.is_empty())
            .unwrap_or_else(|| "en".into());
    }
    setting.to_string()
}

/// Localized tray menu labels: (open, quit). "Comail" is a proper noun and stays.
/// Add a match arm per language as catalogs are added on the frontend.
fn tray_labels(lang: &str) -> (String, String) {
    let (open, quit) = match lang {
        "es" => ("Abrir", "Salir"),
        "fr" => ("Ouvrir", "Quitter"),
        "zh" => ("打开", "退出"),
        "vi" => ("Mở", "Thoát"),
        _ => ("Open", "Quit"),
    };
    (format!("{open} Comail"), format!("{quit} Comail"))
}

pub struct AppState {
    pub core: Core,
}

/// Detect the GPU/session and choose a WebKitGTK renderer that actually works,
/// so a single Linux binary runs correctly on any hardware without the user
/// picking a launch script.
///
/// WebKitGTK's DMABUF renderer is broken on many Linux GPU and Wayland setups
/// and quietly drops the webview to software compositing (~100% CPU, laggy
/// scrolling). Turning it off is the safe default and is right for Intel, AMD,
/// nouveau, and anything on X11. The one case where the DMABUF path is both
/// working and faster is the proprietary NVIDIA driver under Wayland, once it
/// is pointed at NVIDIA's GBM backend. We detect that and configure it instead.
///
/// Every variable is only set when the user has not already set it, so an
/// explicit override from the environment always wins.
#[cfg(target_os = "linux")]
fn configure_linux_renderer() {
    use std::path::Path;

    // An explicit choice from the environment beats auto-detection.
    if std::env::var_os("WEBKIT_DISABLE_DMABUF_RENDERER").is_some() {
        return;
    }

    let wayland = std::env::var_os("WAYLAND_DISPLAY").is_some()
        || std::env::var("XDG_SESSION_TYPE")
            .map(|s| s == "wayland")
            .unwrap_or(false);
    // The proprietary driver exposes this file; nouveau does not.
    let nvidia_proprietary = Path::new("/proc/driver/nvidia/version").exists();

    if wayland && nvidia_proprietary {
        // NVIDIA on Wayland: keep DMABUF on and route it through NVIDIA's GBM
        // backend, which is the fast path on RTX + Wayland machines.
        std::env::set_var("WEBKIT_DISABLE_DMABUF_RENDERER", "0");
        if std::env::var_os("GBM_BACKEND").is_none() {
            std::env::set_var("GBM_BACKEND", "nvidia-drm");
        }
        if std::env::var_os("__GLX_VENDOR_LIBRARY_NAME").is_none() {
            std::env::set_var("__GLX_VENDOR_LIBRARY_NAME", "nvidia");
        }
        tracing::info!("linux renderer: NVIDIA + Wayland, DMABUF via nvidia-drm GBM backend");
    } else {
        // Intel, AMD, nouveau, or any X11 session: the DMABUF path is
        // unreliable, so disable it and use the plain GL renderer.
        std::env::set_var("WEBKIT_DISABLE_DMABUF_RENDERER", "1");
        tracing::info!("linux renderer: DMABUF disabled (safe default)");
    }
}

/// Log to stderr (dev) and to `<data_dir>/logs/comail.log` (packaged builds,
/// where stderr goes nowhere). The file is rotated once to `.1` when it
/// crosses 5 MB so it can't grow unbounded, and is readable by the user only.
/// `RUST_LOG` overrides the filter (e.g. `RUST_LOG=info,comail_core=debug`).
fn init_logging() {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    use tracing_subscriber::Layer;

    // `info` by default: debug output names correspondents and subjects, so it
    // is opt-in. `html5ever`/`markup5ever` (pulled in via `ammonia` to sanitize
    // HTML email bodies) log a WARN for every message that contains malformed
    // HTML ("foster parenting not implemented" and friends). That's routine for
    // real email and nothing we can act on, so quiet those targets by default.
    let filter = || {
        tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| "info,html5ever=off,markup5ever=off".into())
    };

    let file = (|| {
        let dir = Paths::default_dirs().data_dir.join("logs");
        std::fs::create_dir_all(&dir).ok()?;
        let path = dir.join("comail.log");
        let rotated = dir.join("comail.log.1");
        if std::fs::metadata(&path).is_ok_and(|m| m.len() > 5 * 1024 * 1024) {
            let _ = std::fs::rename(&path, &rotated);
        }
        let mut options = std::fs::OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            options.mode(0o600);
            // `mode` only applies on create; tighten logs written before.
            for p in [&path, &rotated] {
                let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600));
            }
        }
        options.open(path).ok()
    })();

    let registry =
        tracing_subscriber::registry().with(tracing_subscriber::fmt::layer().with_filter(filter()));
    match file {
        Some(f) => registry
            .with(
                tracing_subscriber::fmt::layer()
                    .with_ansi(false)
                    .with_writer(std::sync::Mutex::new(f))
                    .with_filter(filter()),
            )
            .init(),
        None => registry.init(),
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    init_logging();
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        os = std::env::consts::OS,
        "comail starting"
    );

    // Pick a WebKitGTK rendering path that suits this machine's GPU. Must run
    // before the webview is created.
    #[cfg(target_os = "linux")]
    configure_linux_renderer();

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        // Backstop for external links the in-webview JS interception didn't catch
        // (email-body links in the sandboxed iframe, AI-answer links): open
        // external web/mailto targets in the OS default browser and cancel the
        // in-app navigation so the SPA is never replaced. Internal app
        // navigations (tauri://, localhost, about:, data:) proceed untouched.
        .plugin(
            // Pin the (unused) plugin-config type to `()`; only the runtime is
            // inferred. Without this the config type param can't be resolved.
            tauri::plugin::Builder::<_, ()>::new("comail-external-links")
                .on_navigation(|webview, url| {
                    let build = &webview.config().build;
                    let dist_url = match build.frontend_dist.as_ref() {
                        Some(tauri::utils::config::FrontendDist::Url(u)) => Some(u),
                        _ => None,
                    };
                    match nav_decision(url, build.dev_url.as_ref(), dist_url) {
                        NavDecision::Allow => true,
                        NavDecision::OpenExternal => {
                            let _ = tauri_plugin_opener::open_url(url.as_str(), None::<&str>);
                            false
                        }
                        NavDecision::Deny => false,
                    }
                })
                .build(),
        )
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        // Remember the main window's geometry across restarts. VISIBLE is
        // deliberately left out of the flags: the window launches hidden
        // (tauri.conf `visible: false`) and the frontend reveals it, so a
        // restored "hidden" state would keep it invisible forever. The intro's
        // cinema backdrop is a transient full-screen window and must never be
        // saved or restored.
        .plugin(
            tauri_plugin_window_state::Builder::new()
                .with_state_flags(
                    tauri_plugin_window_state::StateFlags::SIZE
                        | tauri_plugin_window_state::StateFlags::POSITION
                        | tauri_plugin_window_state::StateFlags::MAXIMIZED
                        | tauri_plugin_window_state::StateFlags::FULLSCREEN,
                )
                .with_denylist(&["cinema-backdrop"])
                .build(),
        )
        // Single-instance must be registered before deep-link so a mailto click
        // while the app runs focuses the existing window instead of spawning a
        // second copy; the forwarded argv carries the link on Linux/Windows.
        .plugin(tauri_plugin_single_instance::init(|app, args, _cwd| {
            if let Some(win) = app.get_webview_window("main") {
                let _ = win.set_focus();
            }
            if let Some(url) = mailto_from_args(args) {
                forward_mailto(app, &url);
            }
        }))
        .plugin(tauri_plugin_deep_link::init())
        .setup(|app| {
            {
                use tauri_plugin_deep_link::DeepLinkExt;
                // Register as a mailto handler at runtime (needed for dev and for
                // Linux/Windows); bundled installers also declare it via the
                // deep-link `schemes` in tauri.conf.json.
                #[cfg(any(target_os = "linux", target_os = "windows"))]
                let _ = app.deep_link().register("mailto");
                // macOS delivers links via this callback; on Linux/Windows it
                // carries cold-start argv links too.
                let dl_handle = app.handle().clone();
                app.deep_link().on_open_url(move |event| {
                    for url in event.urls() {
                        forward_mailto(&dl_handle, url.as_str());
                    }
                });
            }
            // Cold start: a mailto passed straight on the command line.
            if let Some(url) = mailto_from_args(std::env::args()) {
                forward_mailto(&app.handle(), &url);
            }
            let handle = app.handle().clone();
            // Expose the bundle resource dir to comail-core (which is Tauri-free)
            // so it can copy the bundled default embedding model on first run.
            if let Ok(res) = handle.path().resource_dir() {
                std::env::set_var("COMAIL_RESOURCE_DIR", res);
            }
            let lang = tauri::async_runtime::block_on(async move {
                let core = Core::start(Paths::default_dirs())
                    .await
                    .expect("failed to start comail core");
                events::spawn_forwarder(handle.clone(), core.bus.subscribe());
                let lang = resolve_lang(&core.settings().await.unwrap_or_default().language);
                handle.manage(AppState { core: core.clone() });
                apple_intents::install(&handle);
                notifications::spawn_dispatcher(handle.clone(), core);
                lang
            });

            // Startup-show failsafes. The main window launches hidden
            // (tauri.conf `visible: false`, no white flash) and the frontend
            // reveals it; if that wiring ever fails, force it visible after a
            // grace period. And the intro's cinema backdrop must never
            // outlive the show, whatever happens in the webviews.
            {
                let handle = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                    if let Some(main) = handle.get_webview_window("main") {
                        if !main.is_visible().unwrap_or(true) {
                            tracing::warn!("main window still hidden after 10s; forcing show");
                            let _ = main.show();
                            let _ = main.set_focus();
                        }
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(80)).await;
                    if let Some(backdrop) = handle.get_webview_window("cinema-backdrop") {
                        tracing::warn!("cinema backdrop still open after 90s; forcing close");
                        let _ = backdrop.close();
                    }
                });
            }

            // Tray: closing the window hides it; sync keeps running.
            let (open_label, quit_label) = tray_labels(&lang);
            let open = MenuItem::with_id(app, "open", &open_label, true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", &quit_label, true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&open, &quit])?;
            // macOS menu bar wants a monochrome template image (the system
            // tints it for light/dark/highlighted); elsewhere use the app icon.
            #[cfg(target_os = "macos")]
            let tray_icon =
                tauri::image::Image::from_bytes(include_bytes!("../icons/tray-template.png"))?;
            #[cfg(not(target_os = "macos"))]
            let tray_icon = app.default_window_icon().expect("window icon").clone();
            TrayIconBuilder::with_id("comail-tray")
                .icon(tray_icon)
                .icon_as_template(cfg!(target_os = "macos"))
                .tooltip("Comail")
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "open" => show_main(app),
                    "quit" => app.exit(0),
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    // Left click opens (works where the platform delivers
                    // click events; Linux appindicators are menu-only).
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        show_main(tray.app_handle());
                    }
                })
                .build(app)?;
            Ok(())
        })
        .on_window_event(|window, event| {
            // Only the main window hides-to-tray on close; auxiliary windows
            // (e.g. the intro's cinema backdrop) must close normally.
            if window.label() == "main" {
                if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                    let _ = window.hide();
                    api.prevent_close();
                }
            }
        })
        // Register OS file drops on the Rust side. This is what makes a drop a
        // real user gesture: the webview's own drag/drop events still fire
        // (this listener is additive - the built-in emission runs first), but
        // `claim_dropped_attachments` only mints tokens for paths observed
        // here, so the webview can't nominate files it claims were dropped.
        .on_webview_event(|webview, event| {
            if let tauri::WebviewEvent::DragDrop(tauri::DragDropEvent::Drop { paths, .. }) = event {
                if let Some(state) = webview.try_state::<AppState>() {
                    state.core.record_os_drop(paths);
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::ui_ready,
            commands::cinema_close,
            commands::list_accounts,
            commands::add_account_password,
            commands::test_connection,
            commands::set_account_display_name,
            commands::remove_account,
            commands::start_oauth,
            commands::reauth_account,
            commands::cancel_oauth,
            commands::list_threads,
            commands::get_thread,
            commands::get_body,
            commands::thread_unsubscribe_message,
            commands::unsubscribe_message,
            commands::get_attachment,
            commands::open_attachment,
            commands::save_attachment,
            commands::open_logs_dir,
            commands::focus_main_window,
            commands::preview_attachment,
            commands::list_folders,
            commands::perform_action,
            commands::undo_last,
            commands::cancel_send,
            commands::send_now,
            commands::pick_draft_attachments,
            commands::claim_dropped_attachments,
            commands::prepare_forward_attachment,
            commands::save_draft,
            commands::get_draft,
            commands::delete_draft,
            commands::queue_send,
            commands::list_contacts,
            commands::suggest_contacts,
            commands::search,
            commands::warm_search_embedding,
            commands::explain_search,
            commands::record_search_open,
            commands::clear_search_history,
            commands::list_snippets,
            commands::save_snippet,
            commands::delete_snippet,
            commands::use_snippet,
            commands::list_splits,
            commands::save_split,
            commands::delete_split,
            commands::preview_rule_change,
            commands::find_matching_split,
            commands::explain_route,
            commands::preview_split_condition,
            commands::reorder_tabs,
            commands::list_labels,
            commands::save_label,
            commands::delete_label,
            commands::restore_auto_labels,
            commands::sync_now,
            commands::get_sync_status,
            commands::unread_counts,
            commands::tab_totals,
            commands::relabel_auto,
            commands::reroute_all,
            commands::get_settings,
            commands::sender_avatar,
            commands::set_settings,
            commands::mcp_status,
            commands::mcp_get_token,
            commands::mcp_regenerate_token,
            commands::mcp_activity,
            commands::mcp_list_clients,
            commands::mcp_client_snippet,
            commands::mcp_install_client,
            commands::list_events,
            commands::events_for_message,
            commands::create_event,
            commands::rsvp_event,
            commands::update_event,
            commands::delete_event,
            commands::connect_calendar,
            commands::create_teams_meeting,
            commands::disconnect_calendar,
            commands::list_calendars,
            commands::set_calendar_enabled,
            commands::set_calendar_color,
            commands::set_default_calendar,
            commands::calendar_sync_now,
            commands::connect_contacts,
            commands::disconnect_contacts,
            commands::list_contact_servers,
            commands::set_address_book_enabled,
            commands::contacts_sync_now,
            commands::get_contact_card,
            commands::list_calendar_logins,
            commands::ai_status,
            commands::latest_verification_code,
            commands::ai_list_models,
            commands::ai_usage_stats,
            commands::email_stats,
            commands::ai_plan_automation,
            commands::set_ai_key,
            commands::set_oauth_client_secret,
            commands::set_decision_key,
            commands::test_decision_provider,
            commands::create_category,
            commands::ai_command,
            commands::ai_search_filter,
            commands::ai_summarize,
            commands::ai_quick_replies,
            commands::ai_draft,
            commands::ai_draft_actions,
            commands::ai_proofread,
            commands::ai_signature,
            commands::ai_learn_voice,
            commands::ai_ask,
            commands::embedding_status,
            commands::semantic_reindex,
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|_app, _event| {
            // macOS reactivation (Dock-icon click, and clicking a notification
            // that activates the app) fires Reopen with the window hidden to the
            // tray - re-show it so the app actually appears.
            #[cfg(target_os = "macos")]
            if let tauri::RunEvent::Reopen { .. } = _event {
                show_main(_app);
            }
        });
}

#[cfg(test)]
mod tests {
    use super::{nav_decision, NavDecision};
    use tauri::Url;

    const DEV: &str = "http://localhost:1420";

    fn decision(url: &str) -> NavDecision {
        nav_decision(
            &Url::parse(url).unwrap(),
            Some(&Url::parse(DEV).unwrap()),
            None,
        )
    }

    /// The devUrl arm is compiled under cfg(dev) - the same flag tauri-build
    /// and get_app_url use. A plain `cargo test` build has it off.
    fn dev_expected() -> NavDecision {
        if cfg!(dev) {
            NavDecision::Allow
        } else {
            NavDecision::OpenExternal
        }
    }

    /// A prod-style frontendDist URL is the app origin when devUrl is not in
    /// play.
    fn decision_dist(url: &str) -> NavDecision {
        nav_decision(
            &Url::parse(url).unwrap(),
            Some(&Url::parse(DEV).unwrap()),
            Some(&Url::parse("https://app.example.com").unwrap()),
        )
    }

    fn dist_expected() -> NavDecision {
        if cfg!(dev) {
            NavDecision::OpenExternal
        } else {
            NavDecision::Allow
        }
    }

    #[test]
    fn navigation_allowlist() {
        for (url, expected) in [
            // App origins per platform (exact host, no explicit port).
            ("tauri://localhost", NavDecision::Allow),
            ("tauri://localhost/", NavDecision::Allow),
            ("tauri://localhost/index.html", NavDecision::Allow),
            ("tauri://localhost:1234", NavDecision::Deny),
            ("http://tauri.localhost", NavDecision::Allow),
            ("https://tauri.localhost/", NavDecision::Allow),
            ("https://tauri.localhost/index.html", NavDecision::Allow),
            ("http://tauri.localhost:8080", NavDecision::OpenExternal),
            ("https://tauri.localhost:444", NavDecision::OpenExternal),
            // Only the two subframe documents an iframe may load.
            ("about:blank", NavDecision::Allow),
            ("about:srcdoc", NavDecision::Allow),
            ("about:blank?x=1", NavDecision::Allow),
            ("about:config", NavDecision::Deny),
            ("about://blank", NavDecision::Deny),
            // External web and mailto links go to the OS handler.
            ("https://example.com", NavDecision::OpenExternal),
            ("http://example.com/path?q=1", NavDecision::OpenExternal),
            ("mailto:a@b.c", NavDecision::OpenExternal),
            // Nothing else navigates, in particular:
            ("data:text/html,<h1>x</h1>", NavDecision::Deny),
            ("file:///etc/passwd", NavDecision::Deny),
            ("javascript:alert(1)", NavDecision::Deny),
            ("cid:logo@x", NavDecision::Deny),
            ("ws://localhost:1420", NavDecision::Deny),
            ("custom-scheme://x", NavDecision::Deny),
            // Lookalike app origins that are not the app.
            ("tauri://localhost.evil.com", NavDecision::Deny),
            ("http://tauri.localhost.evil.com", NavDecision::OpenExternal),
            (
                "https://evil.com/@tauri.localhost",
                NavDecision::OpenExternal,
            ),
            // Other localhost ports are never "the app".
            ("http://localhost:9999", NavDecision::OpenExternal),
            ("http://127.0.0.1:1420", NavDecision::OpenExternal),
            ("http://foo.localhost", NavDecision::OpenExternal),
            ("http://localhost", NavDecision::OpenExternal),
        ] {
            assert_eq!(decision(url), expected, "url: {url}");
        }
    }

    #[test]
    fn dev_server_url_is_allowed_only_in_dev() {
        assert_eq!(decision(DEV), dev_expected());
        assert_eq!(decision("http://localhost:1420/"), dev_expected());
        // A different port on the same host is not the dev server.
        assert_eq!(decision("http://localhost:1421"), NavDecision::OpenExternal);
    }

    #[test]
    fn frontend_dist_url_is_app_origin_outside_dev() {
        assert_eq!(decision_dist("https://app.example.com"), dist_expected());
        assert_eq!(
            decision_dist("https://app.example.com/index.html"),
            dist_expected()
        );
        // The dist URL's origin only - a different port or host is not it.
        assert_eq!(
            decision_dist("https://app.example.com:8443"),
            NavDecision::OpenExternal
        );
        assert_eq!(
            decision_dist("https://cdn.example.com"),
            NavDecision::OpenExternal
        );
    }

    #[test]
    fn no_configured_dev_url_means_no_localhost() {
        let url = Url::parse(DEV).unwrap();
        assert_eq!(nav_decision(&url, None, None), NavDecision::OpenExternal);
    }
}
