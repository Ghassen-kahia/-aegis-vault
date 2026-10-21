//! Bitwarden unencrypted exports: `.json` (all item types, folders, custom fields, password
//! history) and `.csv` (logins and secure notes only). Encrypted / password-protected
//! Bitwarden exports are refused with a clear message.

use serde::Deserialize;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::item::{FieldKind, ItemKind};

use super::csv::{self, cell, Header};
use super::{truthy, EntryBuilder, Parsed, Skipped};

// ---- JSON -------------------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Export {
    #[serde(default)]
    encrypted: bool,
    #[serde(default)]
    folders: Vec<BwFolder>,
    items: Option<Vec<BwItem>>,
}

#[derive(Deserialize)]
struct BwFolder {
    id: String,
    name: String,
}

// Absent and `null` values both become `None` / empty via `Option` + `default`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BwItem {
    #[serde(rename = "type")]
    kind: u8,
    name: Option<String>,
    notes: Option<String>,
    #[serde(default)]
    favorite: bool,
    folder_id: Option<String>,
    fields: Option<Vec<BwField>>,
    login: Option<BwLogin>,
    card: Option<BwCard>,
    identity: Option<BwIdentity>,
    ssh_key: Option<BwSshKey>,
    password_history: Option<Vec<BwHistory>>,
}

#[derive(Deserialize)]
struct BwField {
    name: Option<String>,
    value: Option<String>,
    #[serde(rename = "type")]
    kind: u8,
}

#[derive(Deserialize)]
struct BwLogin {
    username: Option<String>,
    password: Option<String>,
    totp: Option<String>,
    uris: Option<Vec<BwUri>>,
}

#[derive(Deserialize)]
struct BwUri {
    uri: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BwCard {
    cardholder_name: Option<String>,
    brand: Option<String>,
    number: Option<String>,
    exp_month: Option<String>,
    exp_year: Option<String>,
    code: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BwIdentity {
    title: Option<String>,
    first_name: Option<String>,
    middle_name: Option<String>,
    last_name: Option<String>,
    company: Option<String>,
    email: Option<String>,
    phone: Option<String>,
    username: Option<String>,
    address1: Option<String>,
    address2: Option<String>,
    address3: Option<String>,
    city: Option<String>,
    state: Option<String>,
    postal_code: Option<String>,
    country: Option<String>,
    ssn: Option<String>,
    passport_number: Option<String>,
    license_number: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BwSshKey {
    private_key: Option<String>,
    public_key: Option<String>,
    key_fingerprint: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BwHistory {
    last_used_date: Option<String>,
    password: Option<String>,
}

fn s(v: &Option<String>) -> &str {
    v.as_deref().unwrap_or("")
}

pub fn parse_json(text: &str, now: i64) -> Result<Parsed> {
    // The parsed tree holds every secret; serde_json's own buffers are released when this
    // function returns. The text itself is owned (and wiped) by the caller.
    let export: Export = serde_json::from_str(text).map_err(|_| Error::Format("not a Bitwarden .json export".into()))?;
    if export.encrypted {
        return Err(Error::Format(
            "this Bitwarden export is encrypted; export again choosing \".json\" (not \".json (Encrypted)\")".into(),
        ));
    }
    let items = export.items.ok_or_else(|| Error::Format("not a Bitwarden .json export".into()))?;
    let folder_name = |id: &Option<String>| {
        id.as_ref().and_then(|id| export.folders.iter().find(|f| &f.id == id)).map(|f| f.name.as_str())
    };

    let mut parsed = Parsed::default();
    for (i, it) in items.iter().enumerate() {
        let kind = match it.kind {
            1 => ItemKind::Login,
            2 => ItemKind::SecureNote,
            3..=5 => ItemKind::Custom,
            _ => {
                parsed.skipped.push(Skipped { row: i + 1, reason: "unsupported item type" });
                continue;
            }
        };
        let mut b = EntryBuilder::new(kind, s(&it.name));
        b.notes(s(&it.notes)).favorite(it.favorite).folder(folder_name(&it.folder_id).unwrap_or(""));

        if let Some(l) = &it.login {
            b.field("Username", FieldKind::Username, s(&l.username)).field("Password", FieldKind::Password, s(&l.password));
            for (n, u) in l.uris.iter().flatten().enumerate() {
                b.field(if n == 0 { "Website" } else { "Other website" }, FieldKind::Url, s(&u.uri));
            }
            b.field("One-time password (TOTP)", FieldKind::Concealed, s(&l.totp));
        }
        if let Some(c) = &it.card {
            let expiry = match (s(&c.exp_month), s(&c.exp_year)) {
                ("", y) => y.to_owned(),
                (m, "") => m.to_owned(),
                (m, y) => format!("{m:0>2}/{y}"),
            };
            b.field("Cardholder name", FieldKind::Text, s(&c.cardholder_name))
                .field("Brand", FieldKind::Text, s(&c.brand))
                .field("Card number", FieldKind::Concealed, s(&c.number))
                .field("Expiry", FieldKind::Text, &expiry)
                .field("Security code", FieldKind::Concealed, s(&c.code));
        }
        if let Some(d) = &it.identity {
            let name = [&d.title, &d.first_name, &d.middle_name, &d.last_name]
                .iter()
                .map(|p| s(p).trim())
                .filter(|p| !p.is_empty())
                .collect::<Vec<_>>()
                .join(" ");
            let address = [&d.address1, &d.address2, &d.address3, &d.city, &d.state, &d.postal_code, &d.country]
                .iter()
                .map(|p| s(p).trim())
                .filter(|p| !p.is_empty())
                .collect::<Vec<_>>()
                .join(", ");
            b.field("Name", FieldKind::Text, &name)
                .field("Company", FieldKind::Text, s(&d.company))
                .field("Email", FieldKind::Email, s(&d.email))
                .field("Phone", FieldKind::Text, s(&d.phone))
                .field("Username", FieldKind::Username, s(&d.username))
                .field("Address", FieldKind::Text, &address)
                .field("Social security number", FieldKind::Concealed, s(&d.ssn))
                .field("Passport number", FieldKind::Concealed, s(&d.passport_number))
                .field("License number", FieldKind::Concealed, s(&d.license_number));
        }
        if let Some(k) = &it.ssh_key {
            b.field("Private key", FieldKind::Concealed, s(&k.private_key))
                .field("Public key", FieldKind::Text, s(&k.public_key))
                .field("Fingerprint", FieldKind::Text, s(&k.key_fingerprint));
        }
        for f in it.fields.iter().flatten() {
            let kind = match f.kind {
                0 | 2 => FieldKind::Text,
                1 => FieldKind::Concealed,
                _ => continue, // 3 = linked field: a reference, not a value
            };
            b.field(s(&f.name), kind, s(&f.value));
        }
        for h in it.password_history.iter().flatten() {
            let when = h.last_used_date.as_deref().and_then(parse_rfc3339_utc).unwrap_or(now);
            b.history("Password", s(&h.password), when);
        }
        if b.has_content() || !s(&it.name).trim().is_empty() {
            parsed.entries.push(b.build());
        } else {
            parsed.skipped.push(Skipped { row: i + 1, reason: "empty item" });
        }
    }
    Ok(parsed)
}

/// "2024-05-06T07:08:09.123Z" → Unix seconds. UTC (`Z`) timestamps only.
fn parse_rfc3339_utc(t: &str) -> Option<i64> {
    let t = t.strip_suffix('Z')?;
    let (date, time) = t.split_once('T')?;
    let mut d = date.splitn(3, '-').map(|p| p.parse::<i64>().ok());
    let (y, m, day) = (d.next()??, d.next()??, d.next()??);
    let time = time.split('.').next()?;
    let mut c = time.splitn(3, ':').map(|p| p.parse::<i64>().ok());
    let (hh, mm, ss) = (c.next()??, c.next()??, c.next()??);
    if !(1..=12).contains(&m) || !(1..=31).contains(&day) || hh > 23 || mm > 59 || ss > 60 {
        return None;
    }
    // Days from civil (Howard Hinnant's algorithm).
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + hh * 3_600 + mm * 60 + ss)
}

// ---- CSV --------------------------------------------------------------------------------------

/// Columns: folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp
pub fn parse_csv(text: &str) -> Result<Parsed> {
    let rows = csv::parse(text)?;
    let Some((head, data)) = rows.split_first() else {
        return Err(Error::Format("the file is empty".into()));
    };
    let h = Header::new(head);
    let col = |n: &str| h.find(&[n]);
    let (kind, name) = (col("type"), col("name"));
    if kind.is_none() || name.is_none() || col("login_password").is_none() {
        return Err(Error::Format("not a Bitwarden .csv export".into()));
    }
    let (folder, fav, notes, fields) = (col("folder"), col("favorite"), col("notes"), col("fields"));
    let (uri, user, pass, totp) = (col("login_uri"), col("login_username"), col("login_password"), col("login_totp"));

    let mut parsed = Parsed::default();
    for (i, row) in data.iter().enumerate() {
        let get = |c| cell(row, c);
        let item_kind = match get(kind).trim() {
            "login" => ItemKind::Login,
            "note" => ItemKind::SecureNote,
            _ => {
                parsed.skipped.push(Skipped { row: i + 1, reason: "unsupported item type" });
                continue;
            }
        };
        let mut b = EntryBuilder::new(item_kind, get(name));
        b.folder(get(folder)).favorite(truthy(get(fav))).notes(get(notes));
        b.field("Username", FieldKind::Username, get(user)).field("Password", FieldKind::Password, get(pass));
        // Several URIs are joined with ','.
        for (n, u) in get(uri).split(',').filter(|u| !u.trim().is_empty()).enumerate() {
            b.field(if n == 0 { "Website" } else { "Other website" }, FieldKind::Url, u);
        }
        b.field("One-time password (TOTP)", FieldKind::Concealed, get(totp));
        // Custom fields: one "name: value" per line. Their hidden/text type is not in the
        // CSV, so all are imported as concealed to be safe.
        let custom = Zeroizing::new(get(fields).to_owned());
        for line in custom.lines() {
            let (label, value) = line.split_once(": ").unwrap_or(("Field", line));
            b.field(label, FieldKind::Concealed, value);
        }
        if b.has_content() || !get(name).trim().is_empty() {
            parsed.entries.push(b.build());
        } else {
            parsed.skipped.push(Skipped { row: i + 1, reason: "empty row" });
        }
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const JSON: &str = r#"{
      "encrypted": false,
      "folders": [{ "id": "f1", "name": "Work" }],
      "items": [
        { "type": 1, "name": "Example", "notes": null, "favorite": true, "folderId": "f1",
          "fields": [{ "name": "PIN", "value": "1234", "type": 1 }, { "name": "linked", "value": null, "type": 3 }],
          "login": { "username": "synthetic-user", "password": "synthetic-pass",
                     "totp": null, "uris": [{ "uri": "https://example.test" }, { "uri": "https://alt.example.test" }] },
          "passwordHistory": [{ "lastUsedDate": "2024-01-02T03:04:05.000Z", "password": "older-pass" }] },
        { "type": 2, "name": "Note", "notes": "synthetic note", "secureNote": { "type": 0 } },
        { "type": 3, "name": "Card", "card": { "cardholderName": "A B", "brand": "Visa",
          "number": "4111111111111111", "expMonth": "1", "expYear": "2030", "code": "123" } },
        { "type": 4, "name": "Me", "identity": { "firstName": "A", "lastName": "B", "city": "X", "country": "Y",
          "ssn": "000-00-0000" } },
        { "type": 9, "name": "Future type" },
        { "type": 1, "name": "", "login": { "username": null, "password": null, "uris": [] } }
      ]
    }"#;

    #[test]
    fn json_export_maps_every_type() {
        let p = parse_json(JSON, 99).unwrap();
        assert_eq!(p.entries.len(), 4);
        assert_eq!(
            p.skipped,
            [Skipped { row: 5, reason: "unsupported item type" }, Skipped { row: 6, reason: "empty item" }]
        );

        let login = &p.entries[0];
        assert_eq!(login.input.kind, ItemKind::Login);
        assert!(login.input.favorite);
        assert_eq!(login.folder.as_deref(), Some("Work"));
        let labels: Vec<_> = login.input.fields.iter().map(|f| (f.label.as_str(), f.kind)).collect();
        assert_eq!(
            labels,
            [
                ("Username", FieldKind::Username),
                ("Password", FieldKind::Password),
                ("Website", FieldKind::Url),
                ("Other website", FieldKind::Url),
                ("PIN", FieldKind::Concealed),
            ]
        );
        assert_eq!(login.history.len(), 1);
        assert_eq!(login.history[0].value, "older-pass");
        assert_eq!(login.history[0].replaced_at, 1_704_164_645);

        assert_eq!(p.entries[1].input.kind, ItemKind::SecureNote);
        assert_eq!(p.entries[1].input.notes, "synthetic note");

        let card = &p.entries[2].input;
        assert!(card.fields.iter().any(|f| f.label == "Expiry" && f.value == "01/2030"));
        assert!(card.fields.iter().any(|f| f.label == "Card number" && f.kind == FieldKind::Concealed));

        let id = &p.entries[3].input;
        assert!(id.fields.iter().any(|f| f.label == "Name" && f.value == "A B"));
        assert!(id.fields.iter().any(|f| f.label == "Address" && f.value == "X, Y"));
    }

    #[test]
    fn encrypted_and_foreign_json_are_refused() {
        let e = parse_json(r#"{"encrypted": true, "encKeyValidation_DO_NOT_EDIT": "x", "data": "y"}"#, 0);
        assert!(matches!(e, Err(Error::Format(m)) if m.contains("encrypted")));
        assert!(parse_json(r#"{"something": 1}"#, 0).is_err());
        assert!(parse_json("not json", 0).is_err());
    }

    #[test]
    fn rfc3339() {
        assert_eq!(parse_rfc3339_utc("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_rfc3339_utc("2000-03-01T00:00:00.5Z"), Some(951_868_800));
        assert_eq!(parse_rfc3339_utc("2024-01-02T03:04:05+01:00"), None);
        assert_eq!(parse_rfc3339_utc("2024-13-02T03:04:05Z"), None);
    }

    #[test]
    fn csv_export() {
        let p = parse_csv(
            "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n\
             Work,1,login,Example,,\"PIN: 1234\nQuestion: blue\",0,\"https://example.test,https://alt.example.test\",synthetic-user,synthetic-pass,\n\
             ,,note,Note,synthetic note,,0,,,,\n\
             ,,card,Card,,,0,,,,\n",
        )
        .unwrap();
        assert_eq!(p.entries.len(), 2);
        assert_eq!(p.skipped, [Skipped { row: 3, reason: "unsupported item type" }]);
        let e = &p.entries[0];
        assert!(e.input.favorite);
        assert_eq!(e.folder.as_deref(), Some("Work"));
        let fields: Vec<_> = e.input.fields.iter().map(|f| (f.label.as_str(), f.value.as_str())).collect();
        assert_eq!(
            fields,
            [
                ("Username", "synthetic-user"),
                ("Password", "synthetic-pass"),
                ("Website", "https://example.test"),
                ("Other website", "https://alt.example.test"),
                ("PIN", "1234"),
                ("Question", "blue"),
            ]
        );
        assert_eq!(p.entries[1].input.kind, ItemKind::SecureNote);
        assert!(parse_csv("name,url\nx,y\n").is_err());
    }
}
