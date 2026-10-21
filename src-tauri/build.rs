// Every IPC command must be listed here *and* granted in capabilities/default.json.
// Anything not listed cannot be invoked from the WebView (AC-U2).
const COMMANDS: &[&str] = &[
    "vault_status",
    "create_vault",
    "unlock",
    "unlock_with_recovery_key",
    "lock",
    "touch",
    "vault_overview",
    "get_item",
    "get_item_for_edit",
    "reveal_field",
    "item_history",
    "copy_field",
    "copy_generated",
    "create_item",
    "update_item",
    "delete_item",
    "set_favorite",
    "create_folder",
    "rename_folder",
    "delete_folder",
    "set_settings",
    "generate_password",
    "generate_passphrase",
    "estimate_strength",
    "change_password",
    "set_password_after_recovery",
    "regenerate_recovery_key",
    "rotate_vault_key",
    "export_backup",
    "import_file",
];

fn main() {
    let attrs = tauri_build::Attributes::new().app_manifest(tauri_build::AppManifest::new().commands(COMMANDS));
    if let Err(e) = tauri_build::try_build(attrs) {
        panic!("tauri-build failed: {e:#}");
    }
}
