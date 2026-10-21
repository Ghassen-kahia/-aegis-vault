//! CSV exports identified by their header row: browsers (Chrome, Edge, Brave, Firefox,
//! Safari) and 1Password. Columns are matched by name, so column order does not matter
//! and unknown columns are ignored.

use crate::error::{Error, Result};
use crate::item::{FieldKind, ItemKind};

use super::csv::{self, cell, Header};
use super::{truthy, EntryBuilder, Parsed, Skipped};

#[derive(Clone, Copy)]
pub enum Flavor {
    Browser,
    OnePassword,
}

const TITLE: &[&str] = &["title", "name"];
const URL: &[&str] = &["url", "website", "urls", "login_uri", "login url"];
const USERNAME: &[&str] = &["username", "login", "user", "login_username", "email"];
const PASSWORD: &[&str] = &["password", "login_password"];
const OTP: &[&str] = &["otpauth", "one-time password", "totp"];
const NOTES: &[&str] = &["notes", "note", "notesplain", "comment"];
const TAGS: &[&str] = &["tags"];
const FAVORITE: &[&str] = &["favorite", "favourite"];
const ARCHIVED: &[&str] = &["archived"];

pub fn parse(text: &str, flavor: Flavor) -> Result<Parsed> {
    let rows = csv::parse(text)?;
    let Some((head, data)) = rows.split_first() else {
        return Err(Error::Format("the file is empty".into()));
    };
    let h = Header::new(head);
    let col = |aliases| h.find(aliases);
    let (title, url, user, pass) = (col(TITLE), col(URL), col(USERNAME), col(PASSWORD));
    if pass.is_none() || (url.is_none() && title.is_none()) {
        return Err(Error::Format(match flavor {
            Flavor::Browser => "not a browser password export (expected url, username and password columns)".into(),
            Flavor::OnePassword => "not a 1Password CSV export (expected title, url, username and password columns)".into(),
        }));
    }
    let (otp, notes, tags, fav, archived) = (col(OTP), col(NOTES), col(TAGS), col(FAVORITE), col(ARCHIVED));

    let mut parsed = Parsed::default();
    for (i, row) in data.iter().enumerate() {
        let get = |c| cell(row, c);
        let is_login = [user, pass, url].iter().any(|&c| !get(c).trim().is_empty());
        let mut b = EntryBuilder::new(if is_login { ItemKind::Login } else { ItemKind::SecureNote }, get(title));
        b.field("Username", FieldKind::Username, get(user))
            .field("Password", FieldKind::Password, get(pass))
            .field("Website", FieldKind::Url, get(url))
            .field("One-time password (TOTP)", FieldKind::Concealed, get(otp))
            .notes(get(notes))
            .favorite(truthy(get(fav)));
        // 1Password separates tags with ';' or ','.
        for t in get(tags).split([';', ',']) {
            b.tag(t);
        }
        if truthy(get(archived)) {
            b.tag("archived");
        }
        if b.has_content() {
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

    fn values(p: &Parsed, i: usize) -> Vec<(String, String)> {
        p.entries[i].input.fields.iter().map(|f| (f.label.clone(), f.value.clone())).collect()
    }

    #[test]
    fn chrome_export() {
        let p = parse(
            "name,url,username,password,note\n\
             example.test,https://example.test/login,synthetic-user,synthetic-pass-1,a note\n\
             ,https://other.example.test/,u2,p2,\n",
            Flavor::Browser,
        )
        .unwrap();
        assert_eq!(p.entries.len(), 2);
        let e = &p.entries[0];
        assert_eq!(e.input.kind, ItemKind::Login);
        assert_eq!(e.input.title, "example.test");
        assert_eq!(e.input.notes, "a note");
        assert_eq!(
            values(&p, 0),
            [
                ("Username".into(), "synthetic-user".into()),
                ("Password".into(), "synthetic-pass-1".into()),
                ("Website".into(), "https://example.test/login".into()),
            ]
        );
        assert_eq!(p.entries[1].input.title, "other.example.test");
    }

    #[test]
    fn firefox_export_has_no_name_column() {
        let p = parse(
            "\"url\",\"username\",\"password\",\"httpRealm\",\"formActionOrigin\",\"guid\",\"timeCreated\"\n\
             \"https://example.test\",\"synthetic-user\",\"synthetic-pass\",,\"https://example.test\",\"{x}\",\"1\"\n",
            Flavor::Browser,
        )
        .unwrap();
        assert_eq!(p.entries[0].input.title, "example.test");
        assert_eq!(values(&p, 0).len(), 3);
    }

    #[test]
    fn safari_export_keeps_totp() {
        let p = parse(
            "Title,URL,Username,Password,Notes,OTPAuth\n\
             Example,https://example.test,u,p,,otpauth://totp/x?secret=SYNTHETIC\n",
            Flavor::Browser,
        )
        .unwrap();
        let otp = p.entries[0].input.fields.iter().find(|f| f.kind == FieldKind::Concealed).unwrap();
        assert_eq!(otp.value, "otpauth://totp/x?secret=SYNTHETIC");
    }

    #[test]
    fn onepassword_export_with_tags_favorite_archived() {
        let p = parse(
            "Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes\n\
             Bank,https://bank.example.test,u,p,,true,false,finance;personal,\n\
             Old,https://old.example.test,u,p,,false,true,,\n\
             Wifi note,,,,,false,false,,the code is on the router\n\
             ,,,,,,,,\n",
            Flavor::OnePassword,
        )
        .unwrap();
        assert_eq!(p.entries.len(), 3);
        assert!(p.entries[0].input.favorite);
        assert_eq!(p.entries[0].input.tags, ["finance", "personal"]);
        assert_eq!(p.entries[1].input.tags, ["archived"]);
        assert_eq!(p.entries[2].input.kind, ItemKind::SecureNote);
        assert_eq!(p.skipped, [Skipped { row: 4, reason: "empty row" }]);
    }

    #[test]
    fn wrong_file_is_rejected() {
        assert!(parse("a,b,c\n1,2,3\n", Flavor::Browser).is_err());
        assert!(parse("", Flavor::OnePassword).is_err());
    }
}
