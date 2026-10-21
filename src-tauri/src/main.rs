//! AEGIS VAULT desktop shell. All cryptography lives in `aegis-core`; this crate only
//! wires it to the WebView through a narrow command surface (THREAT_MODEL boundary B1).

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
// `deny`, not `forbid`: the single Win32 call in `os_lock::session_locked` opts out.
#![deny(unsafe_code)]

mod clipboard;
mod commands;
mod os_lock;
mod state;
mod webview;

use std::time::Duration;

use tauri::{Emitter, Manager, RunEvent, WindowEvent};

use crate::os_lock::{SessionLockDetector, SuspendDetector};
use crate::state::AppState;

const VAULT_FILE: &str = "vault.aegis";
const SWEEP_INTERVAL: Duration = Duration::from_secs(1);

/// Background enforcement of auto-lock, lock on suspend / session lock (AC-L1, L-9) and
/// clipboard clearing (threat 11).
fn spawn_sweeper(app: tauri::AppHandle) {
    std::thread::spawn(move || {
        let mut suspend = SuspendDetector::new();
        let mut session_lock = SessionLockDetector::new();
        loop {
            std::thread::sleep(SWEEP_INTERVAL);
            // Checked every sweep, even while locked, so the detectors' state stays current.
            let suspended = suspend.check();
            let session_locked = session_lock.check();
            let state = app.state::<AppState>();
            let reason = {
                let mut s = state.session();
                let reason = if s.vault.is_none() {
                    None
                } else if suspended {
                    Some("suspend")
                } else if session_locked {
                    Some("session-lock")
                } else if s.idle_expired() {
                    Some("inactivity")
                } else {
                    None
                };
                if reason.is_some() {
                    s.lock();
                }
                reason
            };
            match reason {
                Some(reason) => {
                    state.clipboard.clear_now();
                    let _ = app.emit("vault-locked", reason);
                }
                None => state.clipboard.sweep(),
            }
        }
    });
}

fn lock_everything(app: &tauri::AppHandle) {
    let state = app.state::<AppState>();
    state.session().lock();
    state.clipboard.clear_now();
}

fn main() {
    let app = tauri::Builder::default()
        // Must be the first plugin: a second launch focuses the running window and exits.
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            if let Some(w) = app.get_webview_window("main") {
                let _ = w.unminimize();
                let _ = w.set_focus();
            }
        }))
        // Used from Rust only (commands::file_dialog); no dialog permission is granted to the WebView.
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let dir = app.path().app_data_dir()?;
            app.manage(AppState::new(dir.join(VAULT_FILE)));
            if let Some(w) = app.get_webview_window("main") {
                webview::harden(&w);
            }
            spawn_sweeper(app.handle().clone());
            Ok(())
        })
        .on_window_event(|window, event| {
            if matches!(event, WindowEvent::CloseRequested { .. } | WindowEvent::Destroyed) {
                lock_everything(window.app_handle());
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::vault_status,
            commands::create_vault,
            commands::unlock,
            commands::unlock_with_recovery_key,
            commands::lock,
            commands::touch,
            commands::vault_overview,
            commands::get_item,
            commands::get_item_for_edit,
            commands::reveal_field,
            commands::item_history,
            commands::copy_field,
            commands::copy_generated,
            commands::create_item,
            commands::update_item,
            commands::delete_item,
            commands::set_favorite,
            commands::create_folder,
            commands::rename_folder,
            commands::delete_folder,
            commands::set_settings,
            commands::generate_password,
            commands::generate_passphrase,
            commands::estimate_strength,
            commands::change_password,
            commands::set_password_after_recovery,
            commands::regenerate_recovery_key,
            commands::rotate_vault_key,
            commands::export_backup,
            commands::import_file,
        ])
        .build(tauri::generate_context!());
    let app = match app {
        Ok(app) => app,
        Err(e) => {
            eprintln!("AEGIS VAULT failed to start: {e}"); // log-ok: startup error, no vault data loaded yet
            std::process::exit(1);
        }
    };
    app.run(|handle, event| {
        if let RunEvent::Exit = event {
            lock_everything(handle);
        }
    });
}
