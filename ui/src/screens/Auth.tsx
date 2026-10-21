import { FormEvent, useEffect, useState } from "react";
import { api, errorCode, errorMessage, Status } from "../api";
import { ErrorBanner, Icon, PasswordInput, RecoveryKeyPanel, StrengthMeter } from "../components/common";

const MIN_CHARS = 12;
const MIN_SCORE = 3;

// Reasons sent with the Rust "vault-locked" event.
const LOCK_NOTICES: Record<string, string> = {
  inactivity: "Locked after a period of inactivity.",
  suspend: "Locked because the computer went to sleep.",
  "session-lock": "Locked because your session was locked.",
};

function Shell({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="auth">
      <div className="auth-card">
        <div className="brand">
          <Icon name="shield" size={28} />
          <span>AEGIS VAULT</span>
        </div>
        <h1>{title}</h1>
        {children}
      </div>
    </div>
  );
}

/** Choosing a master password, with policy feedback. Shared by setup and post-recovery reset. */
function NewPasswordForm({ submitLabel, busyLabel, onSubmit }: { submitLabel: string; busyLabel: string; onSubmit: (pw: string) => Promise<void> }) {
  const [pw, setPw] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const mismatch = confirm.length > 0 && pw !== confirm;
  const canSubmit = pw.length >= MIN_CHARS && pw === confirm && !busy;

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!canSubmit) return;
    setBusy(true);
    setError(null);
    try {
      await onSubmit(pw);
    } catch (err) {
      setError(errorMessage(err));
      setBusy(false);
    }
  }

  return (
    <form autoComplete="off" onSubmit={submit}>
      <PasswordInput label="Master password" value={pw} onChange={setPw} autoFocus autoComplete="new-password" />
      <StrengthMeter password={pw} minScore={MIN_SCORE} />
      <PasswordInput label="Confirm master password" value={confirm} onChange={setConfirm} autoComplete="new-password" />
      {mismatch && <div className="hint warn">The passwords don't match.</div>}
      <p className="hint">
        At least {MIN_CHARS} characters. A passphrase of four or more random words works well. There is <strong>no way to reset</strong> it
        without your Recovery Key.
      </p>
      <ErrorBanner message={error} />
      <button className="primary" type="submit" disabled={!canSubmit}>
        {busy ? busyLabel : submitLabel}
      </button>
    </form>
  );
}

export function Setup({ onReady }: { onReady: () => void }) {
  const [recoveryKey, setRecoveryKey] = useState<string | null>(null);
  if (recoveryKey) {
    return (
      <Shell title="Save your Recovery Key">
        <RecoveryKeyPanel recoveryKey={recoveryKey} onDone={onReady} doneLabel="Open my vault" />
      </Shell>
    );
  }
  return (
    <Shell title="Create your vault">
      <p className="lead">Everything is encrypted on this device with a key derived from your master password.</p>
      <NewPasswordForm
        submitLabel="Create vault"
        busyLabel="Creating vault…"
        onSubmit={async (pw) => setRecoveryKey(await api.createVault(pw))}
      />
    </Shell>
  );
}

export function Unlock({ onUnlocked, lockReason }: { onUnlocked: (s: Status) => void; lockReason: string | null }) {
  const [mode, setMode] = useState<"password" | "recovery">("password");
  const [secret, setSecret] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [retryAfter, setRetryAfter] = useState(0);

  useEffect(() => {
    if (retryAfter <= 0) return;
    const t = setTimeout(() => setRetryAfter(retryAfter - 1), 1000);
    return () => clearTimeout(t);
  }, [retryAfter]);

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!secret || busy || retryAfter > 0) return;
    setBusy(true);
    setError(null);
    try {
      const status = mode === "password" ? await api.unlock(secret) : await api.unlockWithRecoveryKey(secret);
      setSecret("");
      onUnlocked(status);
    } catch (err) {
      const code = errorCode(err);
      if (code === "rate_limited") {
        setRetryAfter((err as { retry_after?: number }).retry_after ?? 1);
      }
      setError(
        code === "invalid_credentials"
          ? mode === "password" ? "Incorrect master password." : "That Recovery Key does not unlock this vault."
          : code === "integrity"
            ? "The vault file failed its integrity check. It may be corrupted or have been tampered with. A backup is kept next to it as vault.aegis.bak."
            : errorMessage(err),
      );
    } finally {
      setBusy(false);
    }
  }

  function switchMode() {
    setMode(mode === "password" ? "recovery" : "password");
    setSecret("");
    setError(null);
  }

  return (
    <Shell title={mode === "password" ? "Unlock your vault" : "Unlock with Recovery Key"}>
      {lockReason && LOCK_NOTICES[lockReason] && <div className="notice">{LOCK_NOTICES[lockReason]}</div>}
      <form autoComplete="off" onSubmit={submit}>
        {mode === "password" ? (
          <PasswordInput label="Master password" value={secret} onChange={setSecret} autoFocus autoComplete="current-password" />
        ) : (
          <div className="field">
            <label htmlFor="rk">Recovery Key</label>
            <textarea autoComplete="off"
              id="rk"
              className="mono"
              rows={3}
              value={secret}
              onChange={(e) => setSecret(e.target.value)}
              autoFocus
              spellCheck={false}
              placeholder="XXXXX-XXXXX-XXXXX-…"
            />
            <div className="hint">You will be asked to choose a new master password.</div>
          </div>
        )}
        <ErrorBanner message={retryAfter > 0 ? `Too many attempts. Try again in ${retryAfter} s.` : error} />
        <button className="primary" type="submit" disabled={!secret || busy || retryAfter > 0}>
          {busy ? "Unlocking…" : "Unlock"}
        </button>
      </form>
      <button type="button" className="link" onClick={switchMode}>
        {mode === "password" ? "Forgot your master password? Use your Recovery Key" : "Use master password instead"}
      </button>
    </Shell>
  );
}

export function ResetAfterRecovery({ onDone, onCancel }: { onDone: () => void; onCancel: () => void }) {
  return (
    <Shell title="Choose a new master password">
      <p className="lead">You unlocked with your Recovery Key. Set a new master password to continue. Your Recovery Key keeps working.</p>
      <NewPasswordForm
        submitLabel="Set password and open vault"
        busyLabel="Saving…"
        onSubmit={async (pw) => {
          await api.setPasswordAfterRecovery(pw);
          onDone();
        }}
      />
      <button type="button" className="link" onClick={onCancel}>Lock instead</button>
    </Shell>
  );
}
