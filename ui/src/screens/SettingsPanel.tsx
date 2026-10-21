import { FormEvent, useState } from "react";
import { api, errorMessage, Settings } from "../api";
import { ErrorBanner, Modal, PasswordInput, RecoveryKeyPanel, StrengthMeter } from "../components/common";
import { ExportBackup, ImportData } from "./ImportExport";

type Action = "change" | "recovery" | "rotate";
type Transfer = "export" | "import";

const ACTION_COPY: Record<Action, { title: string; body: string; submit: string }> = {
  change: {
    title: "Change master password",
    body: "Your vault is re-protected with the new password. Your Recovery Key keeps working.",
    submit: "Change password",
  },
  recovery: {
    title: "New Recovery Key",
    body: "A new Recovery Key is issued and your current one stops working immediately.",
    submit: "Issue new Recovery Key",
  },
  rotate: {
    title: "Rotate vault key",
    body: "Generates a new encryption key and re-encrypts every item. Do this if you suspect an old copy of your vault file was exposed. Your current Recovery Key stops working and a new one is issued.",
    submit: "Rotate key",
  },
};

/** Sensitive operations: all require the current master password (AC-L3). */
function CredentialAction({ action, onClose }: { action: Action; onClose: () => void }) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);
  const [recoveryKey, setRecoveryKey] = useState<string | null>(null);
  const copy = ACTION_COPY[action];

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      if (action === "change") {
        await api.changePassword(current, next);
        setDone(true);
      } else {
        setRecoveryKey(action === "recovery" ? await api.regenerateRecoveryKey(current) : await api.rotateVaultKey(current));
      }
      setCurrent("");
      setNext("");
      setConfirm("");
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  if (recoveryKey) {
    return (
      <Modal title="Your new Recovery Key">
        <RecoveryKeyPanel recoveryKey={recoveryKey} onDone={onClose} doneLabel="Done" />
      </Modal>
    );
  }

  return (
    <Modal title={copy.title} onClose={busy ? undefined : onClose}>
      {done ? (
        <>
          <p>Your master password has been changed.</p>
          <button type="button" className="primary" onClick={onClose}>Done</button>
        </>
      ) : (
        <form autoComplete="off" onSubmit={submit}>
          <p className="lead">{copy.body}</p>
          <PasswordInput label="Current master password" value={current} onChange={setCurrent} autoFocus autoComplete="current-password" />
          {action === "change" && (
            <>
              <PasswordInput label="New master password" value={next} onChange={setNext} autoComplete="new-password" />
              <StrengthMeter password={next} minScore={3} />
              <PasswordInput label="Confirm new master password" value={confirm} onChange={setConfirm} autoComplete="new-password" />
              {confirm && next !== confirm && <div className="hint warn">The passwords don't match.</div>}
            </>
          )}
          <ErrorBanner message={error} />
          <button
            type="submit"
            className={action === "rotate" ? "danger" : "primary"}
            disabled={busy || !current || (action === "change" && (next.length < 12 || next !== confirm))}
          >
            {busy ? "Working…" : copy.submit}
          </button>
        </form>
      )}
    </Modal>
  );
}

export function SettingsPanel({ settings, onClose, onSaved }: { settings: Settings; onClose: () => void; onSaved: () => void }) {
  const [draft, setDraft] = useState(settings);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const [action, setAction] = useState<Action | null>(null);
  const [transfer, setTransfer] = useState<Transfer | null>(null);

  async function save(e: FormEvent) {
    e.preventDefault();
    try {
      await api.setSettings(draft);
      setError(null);
      setSaved(true);
      onSaved();
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  if (action) return <CredentialAction action={action} onClose={() => setAction(null)} />;
  if (transfer === "export") return <ExportBackup onClose={() => setTransfer(null)} />;
  if (transfer === "import") return <ImportData onClose={() => setTransfer(null)} onImported={onSaved} />;

  return (
    <Modal title="Settings" onClose={onClose}>
      <form autoComplete="off" onSubmit={save}>
        <h3>Security timers</h3>
        <div className="grid2">
          <div className="field">
            <label htmlFor="autolock">Auto-lock after inactivity (minutes)</label>
            <input autoComplete="off"
              id="autolock"
              type="number"
              min={1}
              max={480}
              value={draft.auto_lock_minutes}
              onChange={(e) => {
                setSaved(false);
                setDraft({ ...draft, auto_lock_minutes: Number(e.target.value) });
              }}
            />
          </div>
          <div className="field">
            <label htmlFor="clip">Clear clipboard after (seconds)</label>
            <input autoComplete="off"
              id="clip"
              type="number"
              min={5}
              max={600}
              value={draft.clipboard_clear_seconds}
              onChange={(e) => {
                setSaved(false);
                setDraft({ ...draft, clipboard_clear_seconds: Number(e.target.value) });
              }}
            />
          </div>
        </div>
        <ErrorBanner message={error} />
        <div className="row">
          <button type="submit" className="primary">Save</button>
          {saved && <span className="muted">Saved.</span>}
        </div>
      </form>

      <h3>Master password & keys</h3>
      <div className="stack">
        <button type="button" className="secondary" onClick={() => setAction("change")}>Change master password…</button>
        <button type="button" className="secondary" onClick={() => setAction("recovery")}>Issue a new Recovery Key…</button>
        <button type="button" className="secondary" onClick={() => setAction("rotate")}>Rotate vault encryption key…</button>
      </div>

      <h3>Backup & import</h3>
      <div className="stack">
        <button type="button" className="secondary" onClick={() => setTransfer("export")}>Export encrypted backup…</button>
        <button type="button" className="secondary" onClick={() => setTransfer("import")}>Import from a backup or another password manager…</button>
      </div>
    </Modal>
  );
}
