//! Hardens the embedded browser engine beyond what Tauri configures.
//!
//! WebView2 enables general form autofill by default: it remembers text typed into inputs
//! (usernames, notes, field values) in its profile folder, outside the encrypted vault. That
//! is turned off here, together with password autosave and browser shortcuts (print, reload,
//! find, zoom, developer tools). Editing shortcuts (copy, paste, undo) keep working, and key
//! events still reach the page.

/// Applies the settings to the main window's WebView. Runs asynchronously on the UI thread,
/// before the user can type anything.
#[cfg(windows)]
pub fn harden(window: &tauri::WebviewWindow) {
    let result = window.with_webview(|wv| {
        if apply(&wv.controller()).is_err() {
            // Autofill would stay on; refuse to run rather than leak typed values to disk.
            eprintln!("AEGIS VAULT: could not harden the WebView, exiting"); // log-ok: no vault data involved
            std::process::exit(1);
        }
    });
    if result.is_err() {
        eprintln!("AEGIS VAULT: WebView unavailable, exiting"); // log-ok: no vault data involved
        std::process::exit(1);
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn apply(
    controller: &webview2_com::Microsoft::Web::WebView2::Win32::ICoreWebView2Controller,
) -> windows_core::Result<()> {
    use webview2_com::Microsoft::Web::WebView2::Win32::{ICoreWebView2Settings3, ICoreWebView2Settings4};
    use windows_core::Interface;

    // SAFETY: COM calls on live interfaces owned by the WebView, made on its UI thread
    // (`with_webview` guarantees both). No raw pointers are passed.
    unsafe {
        let settings = controller.CoreWebView2()?.Settings()?;
        let s4: ICoreWebView2Settings4 = settings.cast()?;
        s4.SetIsGeneralAutofillEnabled(false)?;
        s4.SetIsPasswordAutosaveEnabled(false)?;
        let s3: ICoreWebView2Settings3 = settings.cast()?;
        s3.SetAreBrowserAcceleratorKeysEnabled(false)?;
        settings.SetIsStatusBarEnabled(false)?;
    }
    Ok(())
}

/// Other platforms' WebViews do not autofill app pages; nothing to change yet.
#[cfg(not(windows))]
pub fn harden(_window: &tauri::WebviewWindow) {}
