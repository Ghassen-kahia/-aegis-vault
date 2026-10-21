//! Import from other password managers and from AEGIS backups.
//!
//! Parsers turn a file into [`ImportEntry`] values; [`crate::vault::UnlockedVault::import`]
//! then adds them to the vault in one step. Parsers never fail on a single bad row: the row
//! is skipped and reported by number (never by content).

mod bitwarden;
pub mod csv;
mod header_csv;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::backup::BackupFile;
use crate::error::{Error, Result};
use crate::item::{FieldInput, FieldKind, HistoryEntry, ItemInput, ItemKind, MAX_LABEL, MAX_TITLE};
use crate::secret::SecretString;

/// Import files are plaintext exports of a whole vault; refuse anything implausibly large.
pub const MAX_IMPORT_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportSource {
    AegisBackup,
    BitwardenJson,
    BitwardenCsv,
    /// Chrome, Edge, Brave, Firefox and Safari password CSV exports.
    BrowserCsv,
    OnePasswordCsv,
}

/// One item to import. Wiped on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ImportEntry {
    /// `folder_id` is ignored; the folder is given by name.
    pub input: ItemInput,
    pub folder: Option<String>,
    pub history: Vec<HistoryEntry>,
    #[zeroize(skip)]
    pub created_at: Option<i64>,
    #[zeroize(skip)]
    pub updated_at: Option<i64>,
}

impl std::fmt::Debug for ImportEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ImportEntry(<redacted>)")
    }
}

/// A source row that could not be imported. Carries a position and a fixed reason only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Skipped {
    /// 1-based data row (CSV, header excluded) or item index (JSON).
    pub row: usize,
    pub reason: &'static str,
}

#[derive(Debug, Default)]
pub struct Parsed {
    pub entries: Vec<ImportEntry>,
    pub skipped: Vec<Skipped>,
}

/// Parses `bytes` as `source`. `passphrase` is required for (and only used by) AEGIS backups.
pub fn parse(source: ImportSource, bytes: &[u8], passphrase: Option<&SecretString>, now: i64) -> Result<Parsed> {
    if bytes.len() > MAX_IMPORT_BYTES {
        return Err(Error::Format("file too large".into()));
    }
    let text = || std::str::from_utf8(bytes).map_err(|_| Error::Format("the file is not UTF-8 text".into()));
    match source {
        ImportSource::AegisBackup => {
            let passphrase = passphrase.ok_or_else(|| Error::Validation("the backup passphrase is required".into()))?;
            let entries = BackupFile::from_json(bytes)?.open(passphrase)?;
            Ok(Parsed { entries, skipped: Vec::new() })
        }
        ImportSource::BitwardenJson => bitwarden::parse_json(text()?, now),
        ImportSource::BitwardenCsv => bitwarden::parse_csv(text()?),
        ImportSource::BrowserCsv => header_csv::parse(text()?, header_csv::Flavor::Browser),
        ImportSource::OnePasswordCsv => header_csv::parse(text()?, header_csv::Flavor::OnePassword),
    }
}

// ---- Helpers shared by the parsers ----------------------------------------------------------

/// Builds entries field by field, dropping empty values.
pub(crate) struct EntryBuilder {
    kind: ItemKind,
    title: String,
    fields: Vec<FieldInput>,
    notes: String,
    tags: Vec<String>,
    favorite: bool,
    folder: Option<String>,
    history: Vec<HistoryEntry>,
}

impl EntryBuilder {
    pub fn new(kind: ItemKind, title: &str) -> Self {
        Self {
            kind,
            title: title.trim().to_owned(),
            fields: Vec::new(),
            notes: String::new(),
            tags: Vec::new(),
            favorite: false,
            folder: None,
            history: Vec::new(),
        }
    }

    pub fn field(&mut self, label: &str, kind: FieldKind, value: &str) -> &mut Self {
        let value = if kind.is_secret() { value } else { value.trim() };
        if !value.trim().is_empty() {
            self.fields.push(FieldInput {
                id: None,
                label: truncate(label.trim(), MAX_LABEL),
                kind,
                value: value.to_owned(),
            });
        }
        self
    }

    pub fn notes(&mut self, notes: &str) -> &mut Self {
        self.notes = notes.trim_end().to_owned();
        self
    }

    pub fn tag(&mut self, tag: &str) -> &mut Self {
        let tag = tag.trim();
        if !tag.is_empty() {
            self.tags.push(truncate(tag, crate::item::MAX_TAG));
        }
        self
    }

    pub fn favorite(&mut self, favorite: bool) -> &mut Self {
        self.favorite = favorite;
        self
    }

    pub fn folder(&mut self, folder: &str) -> &mut Self {
        let folder = folder.trim();
        self.folder = (!folder.is_empty()).then(|| folder.to_owned());
        self
    }

    pub fn history(&mut self, label: &str, value: &str, replaced_at: i64) -> &mut Self {
        if !value.is_empty() {
            self.history.push(HistoryEntry { field_label: label.to_owned(), value: value.to_owned(), replaced_at });
        }
        self
    }

    pub fn has_content(&self) -> bool {
        !self.fields.is_empty() || !self.notes.trim().is_empty()
    }

    /// Finishes the entry. An empty title falls back to the website's host, then the
    /// username, then "Untitled".
    pub fn build(&mut self) -> ImportEntry {
        let mut title = std::mem::take(&mut self.title);
        if title.is_empty() {
            let first = |k: FieldKind| self.fields.iter().find(|f| f.kind == k).map(|f| f.value.as_str());
            title = first(FieldKind::Url)
                .map(host_of)
                .filter(|h| !h.is_empty())
                .or_else(|| first(FieldKind::Username).or_else(|| first(FieldKind::Email)).map(str::to_owned))
                .unwrap_or_else(|| "Untitled".to_owned());
        }
        ImportEntry {
            input: ItemInput {
                kind: self.kind,
                title: truncate(&title, MAX_TITLE),
                folder_id: None,
                tags: std::mem::take(&mut self.tags),
                favorite: self.favorite,
                fields: std::mem::take(&mut self.fields),
                notes: std::mem::take(&mut self.notes),
            },
            folder: self.folder.take(),
            history: std::mem::take(&mut self.history),
            created_at: None,
            updated_at: None,
        }
    }
}

fn truncate(s: &str, max_chars: usize) -> String {
    s.chars().take(max_chars).collect()
}

/// "https://www.example.com:8443/login?x" → "www.example.com". Returns "" if there is no host.
pub(crate) fn host_of(url: &str) -> String {
    let rest = url.trim().split_once("://").map_or(url.trim(), |(_, r)| r);
    let rest = rest.rsplit_once('@').map_or(rest, |(_, r)| r);
    rest.split(['/', '?', '#', ':']).next().unwrap_or("").to_owned()
}

/// "true"/"1"/"yes" (any case) → true.
pub(crate) fn truthy(s: &str) -> bool {
    matches!(s.trim().to_ascii_lowercase().as_str(), "true" | "1" | "yes" | "y")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_extraction() {
        assert_eq!(host_of("https://www.example.test:8443/login?x=1"), "www.example.test");
        assert_eq!(host_of("example.test/path"), "example.test");
        assert_eq!(host_of("ftp://user@files.example.test"), "files.example.test");
        assert_eq!(host_of(""), "");
    }

    #[test]
    fn builder_title_fallbacks_and_empty_fields() {
        let mut b = EntryBuilder::new(ItemKind::Login, "  ");
        b.field("Username", FieldKind::Username, "synthetic-user")
            .field("Website", FieldKind::Url, "https://login.example.test/")
            .field("Password", FieldKind::Password, "");
        let e = b.build();
        assert_eq!(e.input.title, "login.example.test");
        assert_eq!(e.input.fields.len(), 2, "empty values are dropped");

        let mut b = EntryBuilder::new(ItemKind::Login, "");
        b.field("Username", FieldKind::Username, "synthetic-user");
        assert_eq!(b.build().input.title, "synthetic-user");
        assert_eq!(EntryBuilder::new(ItemKind::SecureNote, "").build().input.title, "Untitled");
    }

    #[test]
    fn secret_values_keep_their_whitespace() {
        let mut b = EntryBuilder::new(ItemKind::Login, "t");
        b.field("Password", FieldKind::Password, " padded ").field("Username", FieldKind::Username, " u ");
        let e = b.build();
        assert_eq!(e.input.fields[0].value, " padded ");
        assert_eq!(e.input.fields[1].value, "u");
    }

    #[test]
    fn backup_requires_passphrase_and_size_is_capped() {
        assert!(matches!(parse(ImportSource::AegisBackup, b"{}", None, 0), Err(Error::Validation(_))));
        let big = vec![b' '; MAX_IMPORT_BYTES + 1];
        assert!(matches!(parse(ImportSource::BrowserCsv, &big, None, 0), Err(Error::Format(_))));
        assert!(matches!(parse(ImportSource::BrowserCsv, &[0xff, 0xfe], None, 0), Err(Error::Format(_))));
    }
}
