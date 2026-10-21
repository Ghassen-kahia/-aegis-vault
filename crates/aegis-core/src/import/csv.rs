//! Minimal RFC 4180 reader. Every cell lives in zeroize-on-drop memory, which a general-purpose
//! CSV crate's internal buffers would not guarantee.

use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::format::MAX_ITEMS;

/// Rows of cells, wiped on drop.
pub type Rows = Zeroizing<Vec<Vec<String>>>;

/// Parses CSV text: `,` separators, `"` quoting with `""` escapes, CRLF or LF line ends,
/// quoted cells may span lines. A leading UTF-8 BOM is skipped. Blank lines are dropped.
pub fn parse(text: &str) -> Result<Rows> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut rows: Rows = Zeroizing::new(Vec::new());
    let mut row: Zeroizing<Vec<String>> = Zeroizing::new(Vec::new());
    let mut cell = Zeroizing::new(String::new());
    let mut in_quotes = false;
    let mut chars = text.chars().peekable();

    let end_row = |row: &mut Zeroizing<Vec<String>>, rows: &mut Rows| -> Result<()> {
        let blank = row.len() == 1 && row[0].is_empty();
        if !blank {
            if rows.len() > MAX_ITEMS {
                return Err(Error::Format("too many rows".into()));
            }
            rows.push(std::mem::take(&mut **row));
        } else {
            row.clear();
        }
        Ok(())
    };

    while let Some(c) = chars.next() {
        if in_quotes {
            match c {
                '"' if chars.peek() == Some(&'"') => {
                    chars.next();
                    cell.push('"');
                }
                '"' => in_quotes = false,
                _ => cell.push(c),
            }
            continue;
        }
        match c {
            '"' if cell.is_empty() => in_quotes = true,
            ',' => row.push(std::mem::take(&mut *cell)),
            '\r' if chars.peek() == Some(&'\n') => {}
            '\n' | '\r' => {
                row.push(std::mem::take(&mut *cell));
                end_row(&mut row, &mut rows)?;
            }
            _ => cell.push(c),
        }
    }
    if in_quotes {
        return Err(Error::Format("unterminated quoted field".into()));
    }
    if !cell.is_empty() || !row.is_empty() {
        row.push(std::mem::take(&mut *cell));
        end_row(&mut row, &mut rows)?;
    }
    Ok(rows)
}

/// Column lookup by header name (case-insensitive, trimmed).
pub struct Header {
    names: Vec<String>,
}

impl Header {
    pub fn new(row: &[String]) -> Self {
        Self { names: row.iter().map(|h| h.trim().to_ascii_lowercase()).collect() }
    }

    /// Index of the first column whose name is one of `aliases` (given in lowercase).
    pub fn find(&self, aliases: &[&str]) -> Option<usize> {
        aliases.iter().find_map(|a| self.names.iter().position(|n| n == a))
    }
}

/// The cell at `col` in `row`, or "" if the column is absent or the row is short.
pub fn cell(row: &[String], col: Option<usize>) -> &str {
    col.and_then(|c| row.get(c)).map_or("", |s| s.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting_escapes_and_line_ends() {
        let rows = parse("\u{feff}a,b,c\r\n\"x, y\",\"he said \"\"hi\"\"\",\"multi\nline\"\n\n1,,3").unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0], ["a", "b", "c"]);
        assert_eq!(rows[1], ["x, y", "he said \"hi\"", "multi\nline"]);
        assert_eq!(rows[2], ["1", "", "3"]);
    }

    #[test]
    fn trailing_newline_and_empty_last_cell() {
        assert_eq!(*parse("a,\n").unwrap(), vec![vec!["a".to_string(), String::new()]]);
        assert!(parse("").unwrap().is_empty());
    }

    #[test]
    fn unterminated_quote_is_rejected() {
        assert!(parse("a,\"b\nc").is_err());
    }

    #[test]
    fn header_lookup_is_case_insensitive() {
        let h = Header::new(&[" URL ".into(), "Username".into()]);
        assert_eq!(h.find(&["website", "url"]), Some(0));
        assert_eq!(h.find(&["username"]), Some(1));
        assert_eq!(h.find(&["password"]), None);
        assert_eq!(cell(&["a".into()], Some(3)), "");
    }
}
