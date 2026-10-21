//! Atomic vault persistence: temp file + fsync + rename, keeping the last good version as `.bak`.

use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::format::{VaultFile, MAX_FILE_BYTES};

fn sibling(path: &Path, ext: &str) -> PathBuf {
    let mut s: OsString = path.as_os_str().to_owned();
    s.push(".");
    s.push(ext);
    PathBuf::from(s)
}

pub fn backup_path(path: &Path) -> PathBuf {
    sibling(path, "bak")
}

pub fn read_vault(path: &Path) -> Result<VaultFile> {
    if fs::metadata(path)?.len() > MAX_FILE_BYTES as u64 {
        return Err(Error::Format("file too large".into()));
    }
    VaultFile::from_json(&fs::read(path)?)
}

fn write_synced(path: &Path, data: &[u8]) -> Result<()> {
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(data)?;
    f.sync_all()?;
    Ok(())
}

/// Writes any file atomically (temp file + fsync + rename), owner-only on Unix.
pub fn write_file_atomic(path: &Path, data: &[u8]) -> Result<()> {
    let tmp = sibling(path, "tmp");
    write_synced(&tmp, data)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

pub fn write_vault_atomic(path: &Path, file: &VaultFile) -> Result<()> {
    let data = file.to_json()?;
    // Never persist something we could not read back.
    VaultFile::from_json(&data)?;
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let tmp = sibling(path, "tmp");
    write_synced(&tmp, &data)?;
    // Back up the current file only if it is itself a structurally valid vault, so a
    // corrupted file can never overwrite the last good backup.
    if let Ok(current) = fs::read(path) {
        if VaultFile::from_json(&current).is_ok() {
            let bak_tmp = sibling(path, "bak.tmp");
            write_synced(&bak_tmp, &current)?;
            fs::rename(&bak_tmp, backup_path(path))?;
        }
    }
    fs::rename(&tmp, path)?;
    Ok(())
}
