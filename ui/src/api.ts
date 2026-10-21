// Typed wrappers around the Rust commands (src-tauri/src/commands.rs).
// Struct fields are snake_case (serde defaults); top-level command arguments are camelCase (Tauri).
import { invoke } from "@tauri-apps/api/core";

export type ItemKind =
  | "login"
  | "secure_note"
  | "recovery_codes"
  | "api_key"
  | "wifi"
  | "software_license"
  | "custom";

export type FieldKind = "text" | "username" | "email" | "url" | "password" | "concealed";

export const isSecret = (k: FieldKind) => k === "password" || k === "concealed";

export interface Status {
  exists: boolean;
  unlocked: boolean;
  must_change_password: boolean;
}

export interface ItemSummary {
  id: string;
  kind: ItemKind;
  title: string;
  subtitle: string;
  url: string | null;
  folder_id: string | null;
  tags: string[];
  favorite: boolean;
  has_secret: boolean;
  updated_at: number;
}

export interface Folder {
  id: string;
  name: string;
}

export interface Settings {
  auto_lock_minutes: number;
  clipboard_clear_seconds: number;
}

export interface Overview {
  items: ItemSummary[];
  folders: Folder[];
  settings: Settings;
  has_recovery_key: boolean;
}

export interface FieldView {
  id: string;
  label: string;
  kind: FieldKind;
  value: string | null; // null for secret fields
  has_value: boolean;
}

export interface ItemView {
  id: string;
  kind: ItemKind;
  title: string;
  folder_id: string | null;
  tags: string[];
  favorite: boolean;
  fields: FieldView[];
  notes: string;
  history_count: number;
  created_at: number;
  updated_at: number;
}

export interface Field {
  id: string;
  label: string;
  kind: FieldKind;
  value: string;
}

export interface EditableItem {
  id: string;
  kind: ItemKind;
  title: string;
  folder_id: string | null;
  tags: string[];
  favorite: boolean;
  fields: Field[];
  notes: string;
}

export interface FieldInput {
  id: string | null;
  label: string;
  kind: FieldKind;
  value: string;
}

export interface ItemInput {
  kind: ItemKind;
  title: string;
  folder_id: string | null;
  tags: string[];
  favorite: boolean;
  fields: FieldInput[];
  notes: string;
}

export interface HistoryEntry {
  field_label: string;
  value: string;
  replaced_at: number;
}

export interface Generated {
  value: string;
  entropy_bits: number;
}

export interface PasswordOptions {
  length: number;
  lowercase: boolean;
  uppercase: boolean;
  digits: boolean;
  symbols: boolean;
  exclude_ambiguous: boolean;
}

export interface PassphraseOptions {
  words: number;
  separator: string;
  capitalize: boolean;
  include_number: boolean;
}

export interface StrengthReport {
  score: number;
  guesses_log10: number;
  warning: string | null;
  suggestions: string[];
}

export type ImportSource = "aegis_backup" | "bitwarden_json" | "bitwarden_csv" | "browser_csv" | "one_password_csv";

export interface ImportResult {
  imported: number;
  duplicates: number;
  invalid: number;
  folders_created: number;
  skipped: { row: number; reason: string }[];
}

/** Error shape returned by every command (CmdError in Rust). */
export interface ApiError {
  code: string;
  message: string;
  retry_after?: number;
}

export function errorMessage(e: unknown): string {
  if (e && typeof e === "object" && "message" in e) return String((e as ApiError).message);
  return String(e);
}

export function errorCode(e: unknown): string | undefined {
  return e && typeof e === "object" && "code" in e ? (e as ApiError).code : undefined;
}

export const api = {
  vaultStatus: () => invoke<Status>("vault_status"),
  createVault: (password: string) => invoke<string>("create_vault", { password }),
  unlock: (password: string) => invoke<Status>("unlock", { password }),
  unlockWithRecoveryKey: (recoveryKey: string) => invoke<Status>("unlock_with_recovery_key", { recoveryKey }),
  lock: () => invoke<void>("lock"),
  touch: () => invoke<void>("touch"),

  overview: () => invoke<Overview>("vault_overview"),
  getItem: (id: string) => invoke<ItemView>("get_item", { id }),
  getItemForEdit: (id: string) => invoke<EditableItem>("get_item_for_edit", { id }),
  revealField: (itemId: string, fieldId: string) => invoke<string>("reveal_field", { itemId, fieldId }),
  itemHistory: (id: string) => invoke<HistoryEntry[]>("item_history", { id }),
  copyField: (itemId: string, fieldId: string) => invoke<number>("copy_field", { itemId, fieldId }),
  copyGenerated: (value: string) => invoke<number>("copy_generated", { value }),

  createItem: (input: ItemInput) => invoke<string>("create_item", { input }),
  updateItem: (id: string, input: ItemInput) => invoke<void>("update_item", { id, input }),
  deleteItem: (id: string) => invoke<void>("delete_item", { id }),
  setFavorite: (id: string, favorite: boolean) => invoke<void>("set_favorite", { id, favorite }),

  createFolder: (name: string) => invoke<Folder>("create_folder", { name }),
  renameFolder: (id: string, name: string) => invoke<void>("rename_folder", { id, name }),
  deleteFolder: (id: string) => invoke<void>("delete_folder", { id }),
  setSettings: (settings: Settings) => invoke<void>("set_settings", { settings }),

  generatePassword: (options: PasswordOptions) => invoke<Generated>("generate_password", { options }),
  generatePassphrase: (options: PassphraseOptions) => invoke<Generated>("generate_passphrase", { options }),
  estimateStrength: (password: string) => invoke<StrengthReport>("estimate_strength", { password }),

  changePassword: (current: string, next: string) => invoke<void>("change_password", { current, new: next }),
  setPasswordAfterRecovery: (next: string) => invoke<void>("set_password_after_recovery", { new: next }),
  regenerateRecoveryKey: (current: string) => invoke<string>("regenerate_recovery_key", { current }),
  rotateVaultKey: (current: string) => invoke<string>("rotate_vault_key", { current }),

  // Both open a native file dialog in Rust; null means the user cancelled it.
  exportBackup: (current: string, passphrase: string) => invoke<string | null>("export_backup", { current, passphrase }),
  importFile: (source: ImportSource, passphrase: string | null) => invoke<ImportResult | null>("import_file", { source, passphrase }),
};

export const KIND_LABELS: Record<ItemKind, string> = {
  login: "Login",
  secure_note: "Secure note",
  recovery_codes: "Recovery codes",
  api_key: "API key",
  wifi: "Wi-Fi",
  software_license: "Software license",
  custom: "Custom",
};

/** Default fields for a new item of each kind. */
export function templateFields(kind: ItemKind): FieldInput[] {
  const f = (label: string, k: FieldKind): FieldInput => ({ id: null, label, kind: k, value: "" });
  switch (kind) {
    case "login":
      return [f("Username", "username"), f("Password", "password"), f("Website", "url")];
    case "secure_note":
      return [];
    case "recovery_codes":
      return [f("Service", "text"), f("Codes", "concealed")];
    case "api_key":
      return [f("Service", "text"), f("Key ID", "text"), f("Secret", "concealed")];
    case "wifi":
      return [f("Network name", "text"), f("Password", "password")];
    case "software_license":
      return [f("Product", "text"), f("Licensed to", "text"), f("License key", "concealed")];
    case "custom":
      return [f("Field", "text")];
  }
}

export function formatDate(secs: number): string {
  return new Date(secs * 1000).toLocaleString();
}
