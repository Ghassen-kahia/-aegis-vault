import { FormEvent, useState } from "react";
import { api, errorMessage, ImportResult, ImportSource } from "../api";
import { ErrorBanner, Modal, PasswordInput, StrengthMeter } from "../components/common";

/** Encrypted backup: master password (AC-L3) plus a separate backup passphrase. */
export function ExportBackup({ onClose }: { onClose: () => void }) {
  const [current, setCurrent] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [savedAs, setSavedAs] = useState<string | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const name = await api.exportBackup(current, passphrase);
      if (name !== null) {
        setSavedAs(name);
        setCurrent("");
        setPassphrase("");
        setConfirm("");
      }
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal title="Export encrypted backup" onClose={busy ? undefined : onClose}>
      {savedAs ? (
        <>
          <p>
            Backup saved as <strong>{savedAs}</strong>.
          </p>
          <p className="muted">
            Keep the backup passphrase somewhere safe and separate from the file. Without it the backup cannot be
            restored. Your master password and Recovery Key do not open it.
          </p>
          <button type="button" className="primary" onClick={onClose}>Done</button>
        </>
      ) : (
        <form autoComplete="off" onSubmit={submit}>
          <p className="lead">
            Saves every item and folder to one file, encrypted with a backup passphrase you choose now. You can restore
            it into any AEGIS VAULT, even if you lose this vault, your master password and your Recovery Key.
          </p>
          <PasswordInput label="Current master password" value={current} onChange={setCurrent} autoFocus autoComplete="current-password" />
          <PasswordInput label="Backup passphrase" value={passphrase} onChange={setPassphrase} autoComplete="new-password" />
          <StrengthMeter password={passphrase} minScore={3} />
          <PasswordInput label="Confirm backup passphrase" value={confirm} onChange={setConfirm} autoComplete="new-password" />
          {confirm && passphrase !== confirm && <div className="hint warn">The passphrases don't match.</div>}
          {passphrase && passphrase === current && <div className="hint warn">Use a passphrase that differs from your master password.</div>}
          <ErrorBanner message={error} />
          <button
            type="submit"
            className="primary"
            disabled={busy || !current || passphrase.length < 12 || passphrase !== confirm || passphrase === current}
          >
            {busy ? "Encrypting…" : "Choose where to save…"}
          </button>
        </form>
      )}
    </Modal>
  );
}

const SOURCES: { value: ImportSource; label: string; help: string }[] = [
  { value: "aegis_backup", label: "AEGIS VAULT backup (.aegisbackup)", help: "An encrypted backup made with Export. You need its backup passphrase." },
  {
    value: "bitwarden_json",
    label: "Bitwarden (.json)",
    help: "In Bitwarden: Tools → Export vault → File format \".json\" (not the encrypted one). Includes cards, identities, custom fields and password history.",
  },
  { value: "bitwarden_csv", label: "Bitwarden (.csv)", help: "In Bitwarden: Tools → Export vault → \".csv\". Logins and notes only." },
  {
    value: "browser_csv",
    label: "Browser (Chrome, Edge, Brave, Firefox, Safari)",
    help: "Export saved passwords to CSV from the browser's password settings.",
  },
  { value: "one_password_csv", label: "1Password (.csv)", help: "In 1Password: File → Export → choose the CSV format." },
];

export function ImportData({ onClose, onImported }: { onClose: () => void; onImported: () => void }) {
  const [source, setSource] = useState<ImportSource>("aegis_backup");
  const [passphrase, setPassphrase] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ImportResult | null>(null);
  const isBackup = source === "aegis_backup";
  const info = SOURCES.find((s) => s.value === source);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const r = await api.importFile(source, isBackup ? passphrase : null);
      if (r !== null) {
        setResult(r);
        setPassphrase("");
        onImported();
      }
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  if (result) {
    const skipped = result.skipped.length;
    return (
      <Modal title="Import finished" onClose={onClose}>
        <ul className="stack">
          <li>
            <strong>{result.imported}</strong> item{result.imported === 1 ? "" : "s"} imported
            {result.folders_created > 0 && `, ${result.folders_created} folder${result.folders_created === 1 ? "" : "s"} created`}.
          </li>
          {result.duplicates > 0 && <li>{result.duplicates} already in your vault and skipped.</li>}
          {result.invalid > 0 && <li>{result.invalid} could not be imported (a value was too long or a title was missing).</li>}
          {skipped > 0 && (
            <li>
              {skipped} row{skipped === 1 ? "" : "s"} skipped:{" "}
              {result.skipped
                .slice(0, 10)
                .map((s) => `#${s.row} (${s.reason})`)
                .join(", ")}
              {skipped > 10 && "…"}
            </li>
          )}
        </ul>
        {!isBackup && (
          <div className="notice">
            The file you imported holds your passwords in plain text. Delete it now, and empty the recycle bin.
          </div>
        )}
        <button type="button" className="primary" onClick={onClose}>Done</button>
      </Modal>
    );
  }

  return (
    <Modal title="Import" onClose={busy ? undefined : onClose}>
      <form autoComplete="off" onSubmit={submit}>
        <div className="field">
          <label htmlFor="import-source">Import from</label>
          <select id="import-source" value={source} onChange={(e) => setSource(e.target.value as ImportSource)}>
            {SOURCES.map((s) => (
              <option key={s.value} value={s.value}>{s.label}</option>
            ))}
          </select>
        </div>
        <p className="muted">{info?.help}</p>
        {isBackup && <PasswordInput label="Backup passphrase" value={passphrase} onChange={setPassphrase} autoFocus autoComplete="off" />}
        <p className="muted">Items already in your vault are skipped, so importing the same file twice is safe.</p>
        <ErrorBanner message={error} />
        <button type="submit" className="primary" disabled={busy || (isBackup && !passphrase)}>
          {busy ? "Importing…" : "Choose file…"}
        </button>
      </form>
    </Modal>
  );
}
