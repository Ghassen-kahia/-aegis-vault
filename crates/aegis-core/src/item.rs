//! Decrypted item model. Items only exist in this form inside an unlocked vault and are
//! wiped on drop.
//!
//! Three views cross to the UI:
//! * [`ItemSummary`] — list rows, **no secret field values**;
//! * [`ItemView`] — detail page, secret values masked (revealed one at a time on request);
//! * the full [`Item`] — only for the edit form.

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Error, Result};

pub const MAX_TITLE: usize = 256;
pub const MAX_FIELDS: usize = 64;
pub const MAX_LABEL: usize = 128;
pub const MAX_VALUE: usize = 64 * 1024;
pub const MAX_NOTES: usize = 256 * 1024;
pub const MAX_TAGS: usize = 32;
pub const MAX_TAG: usize = 64;
pub const MAX_HISTORY: usize = 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemKind {
    Login,
    SecureNote,
    RecoveryCodes,
    ApiKey,
    Wifi,
    SoftwareLicense,
    Custom,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldKind {
    Text,
    Username,
    Email,
    Url,
    /// A password: masked, generator-capable, tracked in history and (Phase 4) audited.
    Password,
    /// Any other secret (API key, license key, recovery codes…): masked and tracked in history.
    Concealed,
}

impl FieldKind {
    pub fn is_secret(self) -> bool {
        matches!(self, FieldKind::Password | FieldKind::Concealed)
    }
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Field {
    #[zeroize(skip)]
    pub id: Uuid,
    pub label: String,
    #[zeroize(skip)]
    pub kind: FieldKind,
    pub value: String,
}

/// A previous value of a secret field (encrypted item history).
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct HistoryEntry {
    pub field_label: String,
    pub value: String,
    pub replaced_at: i64,
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Item {
    #[zeroize(skip)]
    pub id: Uuid,
    #[zeroize(skip)]
    pub kind: ItemKind,
    pub title: String,
    #[zeroize(skip)]
    pub folder_id: Option<Uuid>,
    pub tags: Vec<String>,
    pub favorite: bool,
    pub fields: Vec<Field>,
    pub notes: String,
    pub history: Vec<HistoryEntry>,
    pub created_at: i64,
    pub updated_at: i64,
}

impl std::fmt::Debug for Item {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Item")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

/// Field as submitted by the edit form. `id == None` means a new field.
#[derive(Clone, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct FieldInput {
    #[zeroize(skip)]
    pub id: Option<Uuid>,
    pub label: String,
    #[zeroize(skip)]
    pub kind: FieldKind,
    pub value: String,
}

#[derive(Clone, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ItemInput {
    #[zeroize(skip)]
    pub kind: ItemKind,
    pub title: String,
    #[zeroize(skip)]
    pub folder_id: Option<Uuid>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub favorite: bool,
    #[serde(default)]
    pub fields: Vec<FieldInput>,
    #[serde(default)]
    pub notes: String,
}

impl std::fmt::Debug for ItemInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ItemInput(<redacted>)")
    }
}

impl ItemInput {
    pub fn validate(&self) -> Result<()> {
        let v = |m: &str| Err(Error::Validation(m.to_owned()));
        let title = self.title.trim();
        if title.is_empty() {
            return v("title is required");
        }
        if title.chars().count() > MAX_TITLE {
            return v("title is too long");
        }
        if self.fields.len() > MAX_FIELDS {
            return v("too many fields");
        }
        for f in &self.fields {
            if f.label.chars().count() > MAX_LABEL {
                return v("field label is too long");
            }
            if f.value.len() > MAX_VALUE {
                return v("field value is too long");
            }
        }
        if self.notes.len() > MAX_NOTES {
            return v("notes are too long");
        }
        if self.tags.len() > MAX_TAGS {
            return v("too many tags");
        }
        if self.tags.iter().any(|t| t.trim().is_empty() || t.chars().count() > MAX_TAG) {
            return v("invalid tag");
        }
        Ok(())
    }
}

impl Item {
    pub fn from_input(input: &ItemInput, now: i64) -> Result<Self> {
        input.validate()?;
        Ok(Self {
            id: Uuid::new_v4(),
            kind: input.kind,
            title: input.title.trim().to_owned(),
            folder_id: input.folder_id,
            tags: normalize_tags(&input.tags),
            favorite: input.favorite,
            fields: input
                .fields
                .iter()
                .map(|f| Field {
                    id: Uuid::new_v4(),
                    label: f.label.trim().to_owned(),
                    kind: f.kind,
                    value: f.value.clone(),
                })
                .collect(),
            notes: input.notes.clone(),
            history: Vec::new(),
            created_at: now,
            updated_at: now,
        })
    }

    /// Applies an edit, moving replaced or removed secret values into the history.
    pub fn apply_update(&mut self, input: &ItemInput, now: i64) -> Result<()> {
        input.validate()?;
        let mut new_fields = Vec::with_capacity(input.fields.len());
        for f in &input.fields {
            let id = match f.id {
                Some(id) if self.fields.iter().any(|old| old.id == id) => id,
                _ => Uuid::new_v4(),
            };
            new_fields.push(Field {
                id,
                label: f.label.trim().to_owned(),
                kind: f.kind,
                value: f.value.clone(),
            });
        }
        for old in self.fields.iter().filter(|f| f.kind.is_secret() && !f.value.is_empty()) {
            let unchanged = new_fields.iter().any(|n| n.id == old.id && n.value == old.value);
            if !unchanged {
                self.history.push(HistoryEntry {
                    field_label: old.label.clone(),
                    value: old.value.clone(),
                    replaced_at: now,
                });
            }
        }
        if self.history.len() > MAX_HISTORY {
            let excess = self.history.len() - MAX_HISTORY;
            self.history.drain(..excess);
        }
        self.kind = input.kind;
        self.title = input.title.trim().to_owned();
        self.folder_id = input.folder_id;
        self.tags = normalize_tags(&input.tags);
        self.favorite = input.favorite;
        self.fields = new_fields;
        self.notes = input.notes.clone();
        self.updated_at = now;
        Ok(())
    }

    pub fn field(&self, field_id: &Uuid) -> Option<&Field> {
        self.fields.iter().find(|f| &f.id == field_id)
    }

    pub fn summary(&self) -> ItemSummary {
        let first = |kinds: &[FieldKind]| {
            self.fields
                .iter()
                .find(|f| kinds.contains(&f.kind) && !f.value.is_empty())
                .map(|f| f.value.clone())
        };
        ItemSummary {
            id: self.id,
            kind: self.kind,
            title: self.title.clone(),
            subtitle: first(&[FieldKind::Username, FieldKind::Email])
                .or_else(|| first(&[FieldKind::Text]))
                .unwrap_or_default(),
            url: first(&[FieldKind::Url]),
            folder_id: self.folder_id,
            tags: self.tags.clone(),
            favorite: self.favorite,
            has_secret: self.fields.iter().any(|f| f.kind.is_secret() && !f.value.is_empty()),
            updated_at: self.updated_at,
        }
    }

    /// Detail view with every secret value removed.
    pub fn masked_view(&self) -> ItemView {
        ItemView {
            id: self.id,
            kind: self.kind,
            title: self.title.clone(),
            folder_id: self.folder_id,
            tags: self.tags.clone(),
            favorite: self.favorite,
            fields: self
                .fields
                .iter()
                .map(|f| FieldView {
                    id: f.id,
                    label: f.label.clone(),
                    kind: f.kind,
                    value: if f.kind.is_secret() { None } else { Some(f.value.clone()) },
                    has_value: !f.value.is_empty(),
                })
                .collect(),
            notes: self.notes.clone(),
            history_count: self.history.len(),
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

fn normalize_tags(tags: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for t in tags {
        let t = t.trim().to_owned();
        if !out.iter().any(|o| o.eq_ignore_ascii_case(&t)) {
            out.push(t);
        }
    }
    out
}

/// List row. Contains no secret field values.
#[derive(Clone, Debug, Serialize)]
pub struct ItemSummary {
    pub id: Uuid,
    pub kind: ItemKind,
    pub title: String,
    pub subtitle: String,
    pub url: Option<String>,
    pub folder_id: Option<Uuid>,
    pub tags: Vec<String>,
    pub favorite: bool,
    pub has_secret: bool,
    pub updated_at: i64,
}

#[derive(Clone, Debug, Serialize)]
pub struct FieldView {
    pub id: Uuid,
    pub label: String,
    pub kind: FieldKind,
    /// `None` for secret fields.
    pub value: Option<String>,
    pub has_value: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct ItemView {
    pub id: Uuid,
    pub kind: ItemKind,
    pub title: String,
    pub folder_id: Option<Uuid>,
    pub tags: Vec<String>,
    pub favorite: bool,
    pub fields: Vec<FieldView>,
    pub notes: String,
    pub history_count: usize,
    pub created_at: i64,
    pub updated_at: i64,
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn login_input(title: &str, password: &str) -> ItemInput {
        ItemInput {
            kind: ItemKind::Login,
            title: title.into(),
            folder_id: None,
            tags: vec!["work".into()],
            favorite: false,
            fields: vec![
                FieldInput { id: None, label: "Username".into(), kind: FieldKind::Username, value: "synthetic.user@example.test".into() },
                FieldInput { id: None, label: "Password".into(), kind: FieldKind::Password, value: password.into() },
                FieldInput { id: None, label: "Website".into(), kind: FieldKind::Url, value: "https://example.test".into() },
            ],
            notes: String::new(),
        }
    }

    fn edit_input(item: &Item) -> ItemInput {
        ItemInput {
            kind: item.kind,
            title: item.title.clone(),
            folder_id: item.folder_id,
            tags: item.tags.clone(),
            favorite: item.favorite,
            fields: item
                .fields
                .iter()
                .map(|f| FieldInput { id: Some(f.id), label: f.label.clone(), kind: f.kind, value: f.value.clone() })
                .collect(),
            notes: item.notes.clone(),
        }
    }

    #[test]
    fn summary_and_masked_view_contain_no_secrets() {
        let item = Item::from_input(&login_input("Example", "S3cret-Synthetic-Value"), 1).unwrap();
        let s = serde_json::to_string(&item.summary()).unwrap();
        let v = serde_json::to_string(&item.masked_view()).unwrap();
        assert!(!s.contains("S3cret-Synthetic-Value"));
        assert!(!v.contains("S3cret-Synthetic-Value"));
        assert!(v.contains("synthetic.user@example.test"));
        assert_eq!(item.summary().subtitle, "synthetic.user@example.test");
        assert!(item.summary().has_secret);
        assert!(!format!("{item:?}").contains("S3cret"));
    }

    #[test]
    fn history_records_changed_and_removed_secrets() {
        let mut item = Item::from_input(&login_input("Example", "old-password-1"), 1).unwrap();
        // Unchanged edit: no history.
        item.apply_update(&edit_input(&item), 2).unwrap();
        assert!(item.history.is_empty());
        // Change the password.
        let mut input = edit_input(&item);
        input.fields[1].value = "new-password-2".into();
        item.apply_update(&input, 3).unwrap();
        assert_eq!(item.history.len(), 1);
        assert_eq!(item.history[0].value, "old-password-1");
        assert_eq!(item.history[0].replaced_at, 3);
        // Remove the password field entirely.
        let mut input = edit_input(&item);
        input.fields.remove(1);
        item.apply_update(&input, 4).unwrap();
        assert_eq!(item.history.len(), 2);
        assert_eq!(item.history[1].value, "new-password-2");
    }

    #[test]
    fn history_is_capped() {
        let mut item = Item::from_input(&login_input("Example", "p0"), 0).unwrap();
        for i in 1..=30 {
            let mut input = edit_input(&item);
            input.fields[1].value = format!("p{i}");
            item.apply_update(&input, i).unwrap();
        }
        assert_eq!(item.history.len(), MAX_HISTORY);
        assert_eq!(item.history.last().unwrap().value, "p29");
    }

    #[test]
    fn validation() {
        let mut i = login_input("  ", "x");
        assert!(i.validate().is_err());
        i.title = "a".repeat(MAX_TITLE + 1);
        assert!(i.validate().is_err());
        i.title = "ok".into();
        i.tags = vec![" ".into()];
        assert!(i.validate().is_err());
        i.tags = vec!["Tag".into(), "tag".into()];
        let item = Item::from_input(&i, 0).unwrap();
        assert_eq!(item.tags, vec!["Tag".to_string()]);
    }

    #[test]
    fn unknown_field_ids_get_fresh_ids() {
        let mut item = Item::from_input(&login_input("Example", "pw"), 0).unwrap();
        let mut input = edit_input(&item);
        let forged = Uuid::new_v4();
        input.fields[0].id = Some(forged);
        item.apply_update(&input, 1).unwrap();
        assert!(item.fields.iter().all(|f| f.id != forged));
    }
}
