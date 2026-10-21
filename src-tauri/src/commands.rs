//! IPC commands (boundary B1). Rules:
//! * no command ever returns key material;
//! * list/detail views carry no secret field values — those cross only on explicit
//!   reveal or edit;
//! * every mutation is persisted immediately with an atomic write;
//! * after a Recovery-Key unlock, nothing but setting a new password (or locking) is allowed.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aegis_core::backup::BACKUP_EXTENSION;
use aegis_core::generator::{self, Generated, PassphraseOptions, PasswordOptions};
use aegis_core::import::{self, ImportSource, Skipped, MAX_IMPORT_BYTES};
use aegis_core::item::{Field, HistoryEntry, ItemInput, ItemKind, ItemSummary, ItemView};
use aegis_core::kdf::{KdfParams, DEFAULT_TARGET};
use aegis_core::recovery::RecoveryKey;
use aegis_core::storage::{backup_path, read_vault, write_file_atomic, write_vault_atomic};
use aegis_core::strength::{self, StrengthReport};
use aegis_core::vault::{Folder, ImportReport, Settings, UnlockedVault};
use aegis_core::{Error, SecretString};
use serde::Serialize;
use tauri::{AppHandle, Manager, State};
use tauri_plugin_dialog::{DialogExt, FileDialogBuilder};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::state::{AppState, Session};

// ---- Errors -------------------------------------------------------------------------

/// Error sent to the UI. Carries a stable code and a message that contains no secrets.
#[derive(Debug, Serialize)]
pub struct CmdError {
    code: &'static str,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    retry_after: Option<u64>,
}

impl CmdError {
    pub fn new(code: &'static str, message: &str) -> Self {
        Self { code, message: message.to_owned(), retry_after: None }
    }

    fn locked() -> Self {
        Self::new("locked", "the vault is locked")
    }
}

impl From<Error> for CmdError {
    fn from(e: Error) -> Self {
        let code = match &e {
            Error::InvalidCredentials => "invalid_credentials",
            Error::Integrity(_) => "integrity",
            Error::Format(_) => "format",
            Error::KdfParams(_) => "kdf_params",
            Error::Crypto => "crypto",
            Error::Policy(_) => "policy",
            Error::Validation(_) => "validation",
            Error::NotFound => "not_found",
            Error::Io(_) => "io",
        };
        Self { code, message: e.to_string(), retry_after: None }
    }
}

type CmdResult<T> = Result<T, CmdError>;

// ---- Helpers --------------------------------------------------------------------------

fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn persist(state: &AppState, vault: &mut UnlockedVault) -> CmdResult<()> {
    let file = vault.seal_to_file()?;
    write_vault_atomic(&state.vault_path, &file)?;
    Ok(())
}

/// Runs `f` on the unlocked vault (read-only access), counting as user activity.
fn read<T>(state: &AppState, f: impl FnOnce(&UnlockedVault) -> CmdResult<T>) -> CmdResult<T> {
    let mut s = state.session();
    s.touch();
    let v = s.vault.as_ref().ok_or_else(CmdError::locked)?;
    if v.must_change_password() {
        return Err(CmdError::new("must_change_password", "set a new master password first"));
    }
    f(v)
}

/// Runs `f` on the unlocked vault and saves the result.
fn write<T>(state: &AppState, f: impl FnOnce(&mut UnlockedVault) -> CmdResult<T>) -> CmdResult<T> {
    let mut s = state.session();
    s.touch();
    let v = s.vault.as_mut().ok_or_else(CmdError::locked)?;
    if v.must_change_password() {
        return Err(CmdError::new("must_change_password", "set a new master password first"));
    }
    let out = f(v)?;
    persist(state, v)?;
    Ok(out)
}

/// Like [`write`], for credential changes. If saving fails, the in-memory vault (new key
/// slots the user was told failed) must never reach disk with a later save, so we lock
/// and the file on disk stays authoritative.
fn write_credentials<T>(state: &AppState, f: impl FnOnce(&mut UnlockedVault) -> CmdResult<T>) -> CmdResult<T> {
    let mut s = state.session();
    s.touch();
    let v = s.vault.as_mut().ok_or_else(CmdError::locked)?;
    let out = f(v)?;
    if let Err(e) = persist(state, v) {
        s.lock();
        return Err(e);
    }
    Ok(out)
}

// ---- Status & lifecycle ---------------------------------------------------------------------

#[derive(Serialize)]
pub struct Status {
    exists: bool,
    unlocked: bool,
    must_change_password: bool,
}

fn status_of(state: &AppState, s: &Session) -> Status {
    Status {
        exists: state.vault_path.exists(),
        unlocked: s.vault.is_some(),
        must_change_password: s.vault.as_ref().is_some_and(UnlockedVault::must_change_password),
    }
}

#[tauri::command]
pub fn vault_status(state: State<'_, AppState>) -> Status {
    let s = state.session();
    status_of(&state, &s)
}

/// Creates the vault and returns the Recovery Key — the only time it is ever shown.
#[tauri::command]
pub async fn create_vault(state: State<'_, AppState>, password: SecretString) -> CmdResult<SecretString> {
    let mut s = state.session();
    if state.vault_path.exists() {
        return Err(CmdError::new("exists", "a vault already exists"));
    }
    strength::check_master_password_policy(password.expose())?;
    let kdf = KdfParams::calibrate(DEFAULT_TARGET)?;
    let (mut vault, rk) = UnlockedVault::create(&password, kdf)?;
    persist(&state, &mut vault)?;
    s.vault = Some(vault);
    s.register_success();
    s.touch();
    Ok(rk.encode())
}

fn attempt_unlock(
    state: &AppState,
    open: impl FnOnce(&aegis_core::format::VaultFile) -> aegis_core::Result<UnlockedVault>,
) -> CmdResult<Status> {
    let mut s = state.session();
    if let Some(secs) = s.retry_after() {
        return Err(CmdError {
            code: "rate_limited",
            message: format!("too many attempts — try again in {secs} s"),
            retry_after: Some(secs),
        });
    }
    let file = read_vault(&state.vault_path)?;
    match open(&file) {
        Ok(v) => {
            s.vault = Some(v);
            s.register_success();
            s.touch();
            Ok(status_of(state, &s))
        }
        Err(e) => {
            if e == Error::InvalidCredentials {
                s.register_failure();
            }
            Err(e.into())
        }
    }
}

#[tauri::command]
pub async fn unlock(state: State<'_, AppState>, password: SecretString) -> CmdResult<Status> {
    attempt_unlock(&state, |f| UnlockedVault::unlock_with_password(f, &password))
}

#[tauri::command]
pub async fn unlock_with_recovery_key(state: State<'_, AppState>, recovery_key: SecretString) -> CmdResult<Status> {
    let rk = RecoveryKey::parse(recovery_key.expose())?;
    attempt_unlock(&state, |f| UnlockedVault::unlock_with_recovery_key(f, &rk))
}

#[tauri::command]
pub fn lock(state: State<'_, AppState>) {
    state.session().lock();
    state.clipboard.clear_now();
}

/// UI activity heartbeat (throttled by the UI); keeps auto-lock from firing while in use.
#[tauri::command]
pub fn touch(state: State<'_, AppState>) {
    let mut s = state.session();
    if s.vault.is_some() {
        s.touch();
    }
}

// ---- Reading ----------------------------------------------------------------------------------

#[derive(Serialize)]
pub struct Overview {
    items: Vec<ItemSummary>,
    folders: Vec<Folder>,
    settings: Settings,
    has_recovery_key: bool,
}

#[tauri::command]
pub fn vault_overview(state: State<'_, AppState>) -> CmdResult<Overview> {
    read(&state, |v| {
        Ok(Overview {
            items: v.summaries(),
            folders: v.folders().to_vec(),
            settings: v.settings(),
            has_recovery_key: v.has_recovery_key(),
        })
    })
}

#[tauri::command]
pub fn get_item(state: State<'_, AppState>, id: Uuid) -> CmdResult<ItemView> {
    read(&state, |v| Ok(v.item(&id)?.masked_view()))
}

/// Full item for the edit form (includes secret values; excludes history).
#[derive(Serialize)]
pub struct EditableItem {
    id: Uuid,
    kind: ItemKind,
    title: String,
    folder_id: Option<Uuid>,
    tags: Vec<String>,
    favorite: bool,
    fields: Vec<Field>,
    notes: String,
}

#[tauri::command]
pub fn get_item_for_edit(state: State<'_, AppState>, id: Uuid) -> CmdResult<EditableItem> {
    read(&state, |v| {
        let i = v.item(&id)?;
        Ok(EditableItem {
            id: i.id,
            kind: i.kind,
            title: i.title.clone(),
            folder_id: i.folder_id,
            tags: i.tags.clone(),
            favorite: i.favorite,
            fields: i.fields.clone(),
            notes: i.notes.clone(),
        })
    })
}

#[tauri::command]
pub fn reveal_field(state: State<'_, AppState>, item_id: Uuid, field_id: Uuid) -> CmdResult<SecretString> {
    read(&state, |v| {
        let f = v.item(&item_id)?.field(&field_id).ok_or(Error::NotFound)?;
        Ok(SecretString::from(f.value.as_str()))
    })
}

#[tauri::command]
pub fn item_history(state: State<'_, AppState>, id: Uuid) -> CmdResult<Vec<HistoryEntry>> {
    read(&state, |v| Ok(v.item(&id)?.history.clone()))
}

/// Copies a field value straight from Rust to the clipboard. Returns the clear timeout.
#[tauri::command]
pub fn copy_field(state: State<'_, AppState>, item_id: Uuid, field_id: Uuid) -> CmdResult<u32> {
    read(&state, |v| {
        let f = v.item(&item_id)?.field(&field_id).ok_or(Error::NotFound)?;
        let secs = v.settings().clipboard_clear_seconds;
        state.clipboard.copy(&f.value, Duration::from_secs(u64::from(secs)))?;
        Ok(secs)
    })
}

/// Copies a generator result (already visible in the UI) with the same clearing rules.
#[tauri::command]
pub fn copy_generated(state: State<'_, AppState>, value: SecretString) -> CmdResult<u32> {
    let secs = {
        let s = state.session();
        s.vault.as_ref().map_or(Settings::default().clipboard_clear_seconds, |v| v.settings().clipboard_clear_seconds)
    };
    state.clipboard.copy(value.expose(), Duration::from_secs(u64::from(secs)))?;
    Ok(secs)
}

// ---- Items & folders ---------------------------------------------------------------------

#[tauri::command]
pub fn create_item(state: State<'_, AppState>, input: ItemInput) -> CmdResult<Uuid> {
    write(&state, |v| Ok(v.create_item(&input, now())?))
}

#[tauri::command]
pub fn update_item(state: State<'_, AppState>, id: Uuid, input: ItemInput) -> CmdResult<()> {
    write(&state, |v| Ok(v.update_item(&id, &input, now())?))
}

#[tauri::command]
pub fn delete_item(state: State<'_, AppState>, id: Uuid) -> CmdResult<()> {
    write(&state, |v| Ok(v.delete_item(&id)?))
}

#[tauri::command]
pub fn set_favorite(state: State<'_, AppState>, id: Uuid, favorite: bool) -> CmdResult<()> {
    write(&state, |v| Ok(v.set_favorite(&id, favorite)?))
}

#[tauri::command]
pub fn create_folder(state: State<'_, AppState>, name: String) -> CmdResult<Folder> {
    write(&state, |v| Ok(v.create_folder(&name)?))
}

#[tauri::command]
pub fn rename_folder(state: State<'_, AppState>, id: Uuid, name: String) -> CmdResult<()> {
    write(&state, |v| Ok(v.rename_folder(&id, &name)?))
}

#[tauri::command]
pub fn delete_folder(state: State<'_, AppState>, id: Uuid) -> CmdResult<()> {
    write(&state, |v| Ok(v.delete_folder(&id)?))
}

#[tauri::command]
pub fn set_settings(state: State<'_, AppState>, settings: Settings) -> CmdResult<()> {
    write(&state, |v| Ok(v.set_settings(settings)?))
}

// ---- Generator & strength (no vault needed) ---------------------------------------------------

#[tauri::command]
pub fn generate_password(options: PasswordOptions) -> CmdResult<Generated> {
    Ok(generator::generate_password(&options)?)
}

#[tauri::command]
pub fn generate_passphrase(options: PassphraseOptions) -> CmdResult<Generated> {
    Ok(generator::generate_passphrase(&options)?)
}

#[tauri::command]
pub fn estimate_strength(password: SecretString) -> StrengthReport {
    strength::estimate(password.expose())
}

// ---- Credentials (re-authentication required, AC-L3) -----------------------------------------------

#[tauri::command]
pub async fn change_password(state: State<'_, AppState>, current: SecretString, new: SecretString) -> CmdResult<()> {
    strength::check_master_password_policy(new.expose())?;
    let kdf = KdfParams::calibrate(DEFAULT_TARGET)?;
    write_credentials(&state, |v| Ok(v.change_password(&current, &new, kdf)?))
}

#[tauri::command]
pub async fn set_password_after_recovery(state: State<'_, AppState>, new: SecretString) -> CmdResult<()> {
    strength::check_master_password_policy(new.expose())?;
    let kdf = KdfParams::calibrate(DEFAULT_TARGET)?;
    write_credentials(&state, |v| Ok(v.set_password_after_recovery(&new, kdf)?))
}

#[tauri::command]
pub async fn regenerate_recovery_key(state: State<'_, AppState>, current: SecretString) -> CmdResult<SecretString> {
    write_credentials(&state, |v| Ok(v.regenerate_recovery_key(&current)?.encode()))
}

#[tauri::command]
pub async fn rotate_vault_key(state: State<'_, AppState>, current: SecretString) -> CmdResult<SecretString> {
    write_credentials(&state, |v| Ok(v.rotate_vault_key(&current)?.encode()))
}

// ---- Import & export (Phase 3) ------------------------------------------------------------------
//
// File dialogs are opened here, in Rust: the WebView never chooses a path and never sees the
// contents of a plaintext import file. Dialogs are shown without holding the session lock, so
// auto-lock and clipboard clearing keep running while the user browses.

fn file_dialog(app: &AppHandle) -> FileDialogBuilder<tauri::Wry> {
    let d = app.dialog().file();
    match app.get_webview_window("main") {
        Some(w) => d.set_parent(&w),
        None => d,
    }
}

fn picked_path(p: tauri_plugin_dialog::FilePath) -> CmdResult<PathBuf> {
    p.into_path().map_err(|_| CmdError::new("io", "unsupported file location"))
}

/// True if `a` and `b` are the same existing file.
fn same_file(a: &Path, b: &Path) -> bool {
    matches!((a.canonicalize(), b.canonicalize()), (Ok(x), Ok(y)) if x == y)
}

/// Writes an encrypted backup to a location the user picks. Returns the file name, or
/// `None` if the user cancelled the dialog.
#[tauri::command]
pub async fn export_backup(
    app: AppHandle,
    state: State<'_, AppState>,
    current: SecretString,
    passphrase: SecretString,
) -> CmdResult<Option<String>> {
    // Encrypt first, so a wrong master password fails before any dialog is shown.
    let backup = read(&state, |v| Ok(v.export_backup(&current, &passphrase, now())?))?;
    drop((current, passphrase));
    let data = backup.to_json()?;
    let Some(path) = file_dialog(&app)
        .set_title("Save encrypted backup")
        .set_file_name(format!("AEGIS VAULT backup.{BACKUP_EXTENSION}"))
        .add_filter("AEGIS VAULT backup", &[BACKUP_EXTENSION])
        .blocking_save_file()
    else {
        return Ok(None);
    };
    let path = picked_path(path)?;
    if same_file(&path, &state.vault_path) || same_file(&path, &backup_path(&state.vault_path)) {
        return Err(CmdError::new("validation", "choose a different file: that is your vault"));
    }
    write_file_atomic(&path, &data)?;
    Ok(Some(path.file_name().map_or_else(String::new, |n| n.to_string_lossy().into_owned())))
}

#[derive(Serialize)]
pub struct ImportResult {
    #[serde(flatten)]
    report: ImportReport,
    skipped: Vec<Skipped>,
}

/// Imports a file the user picks. `None` if the dialog was cancelled.
#[tauri::command]
pub async fn import_file(
    app: AppHandle,
    state: State<'_, AppState>,
    source: ImportSource,
    passphrase: Option<SecretString>,
) -> CmdResult<Option<ImportResult>> {
    // Fail fast (locked, or a new password is due) before showing a dialog.
    read(&state, |_| Ok(()))?;
    let (name, exts): (&str, &[&str]) = match source {
        ImportSource::AegisBackup => ("AEGIS VAULT backup", &[BACKUP_EXTENSION]),
        ImportSource::BitwardenJson => ("Bitwarden export (.json)", &["json"]),
        ImportSource::BitwardenCsv | ImportSource::BrowserCsv | ImportSource::OnePasswordCsv => ("CSV export", &["csv"]),
    };
    let Some(path) = file_dialog(&app).set_title("Choose a file to import").add_filter(name, exts).blocking_pick_file()
    else {
        return Ok(None);
    };
    let path = picked_path(path)?;
    if std::fs::metadata(&path).map_err(Error::from)?.len() > MAX_IMPORT_BYTES as u64 {
        return Err(CmdError::new("format", "the file is too large to import"));
    }
    let bytes = Zeroizing::new(std::fs::read(&path).map_err(Error::from)?);
    let parsed = import::parse(source, &bytes, passphrase.as_ref(), now())?;
    drop((bytes, passphrase));
    let report = write(&state, |v| Ok(v.import(&parsed.entries, now())?))?;
    Ok(Some(ImportResult { report, skipped: parsed.skipped.clone() }))
}
