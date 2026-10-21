import { ReactNode, useEffect, useId, useState } from "react";
import { createPortal } from "react-dom";
import { api, StrengthReport } from "../api";

// ---- Icons (inlined, no icon library) ---------------------------------------------------

const paths = {
  eye: "M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12Zm10 3a3 3 0 1 0 0-6 3 3 0 0 0 0 6Z",
  eyeOff: "M3 3l18 18M10.6 5.1A10.9 10.9 0 0 1 12 5c6.4 0 10 7 10 7a17 17 0 0 1-3.1 3.9M6.6 6.6C3.9 8.4 2 12 2 12s3.6 7 10 7a9.7 9.7 0 0 0 5.4-1.6M9.9 9.9a3 3 0 0 0 4.2 4.2",
  copy: "M9 9h11v11H9zM5 15H4V4h11v1",
  star: "M12 3l2.8 5.7 6.2.9-4.5 4.4 1 6.2L12 17.3 6.5 20.2l1-6.2L3 9.6l6.2-.9L12 3Z",
  lock: "M6 11h12v10H6zM8 11V7a4 4 0 0 1 8 0v4",
  plus: "M12 5v14M5 12h14",
  gear: "M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6Zm7.4-3a7.4 7.4 0 0 0-.1-1.3l2-1.6-2-3.4-2.4 1a7.5 7.5 0 0 0-2.2-1.3L14.4 3h-4l-.4 2.4a7.5 7.5 0 0 0-2.2 1.3l-2.4-1-2 3.4 2 1.6a7.4 7.4 0 0 0 0 2.6l-2 1.6 2 3.4 2.4-1a7.5 7.5 0 0 0 2.2 1.3l.4 2.4h4l.4-2.4a7.5 7.5 0 0 0 2.2-1.3l2.4 1 2-3.4-2-1.6c.1-.4.1-.9.1-1.3Z",
  dice: "M4 4h16v16H4zM8.5 8.5h.01M15.5 15.5h.01M15.5 8.5h.01M8.5 15.5h.01M12 12h.01",
  trash: "M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13",
  edit: "M4 20h4L19 9l-4-4L4 16v4Z",
  folder: "M3 6h6l2 2h10v11H3z",
  refresh: "M20 11a8 8 0 1 0-2.3 5.7M20 5v6h-6",
  shield: "M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6l8-3Z",
  close: "M6 6l12 12M18 6L6 18",
  history: "M3 12a9 9 0 1 0 3-6.7M3 4v5h5M12 7v5l3 3",
};

export type IconName = keyof typeof paths;

export function Icon({ name, size = 16 }: { name: IconName; size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d={paths[name]} />
    </svg>
  );
}

export function IconButton({ icon, label, onClick, active, disabled }: { icon: IconName; label: string; onClick: () => void; active?: boolean; disabled?: boolean }) {
  return (
    <button type="button" className={`icon-btn${active ? " active" : ""}`} title={label} aria-label={label} onClick={onClick} disabled={disabled}>
      <Icon name={icon} />
    </button>
  );
}

// ---- Inputs --------------------------------------------------------------------------------

export function PasswordInput(props: {
  value: string;
  onChange: (v: string) => void;
  label: string;
  autoFocus?: boolean;
  placeholder?: string;
  autoComplete?: string;
}) {
  const [shown, setShown] = useState(false);
  const id = useId();
  return (
    <div className="field">
      <label htmlFor={id}>{props.label}</label>
      <div className="input-row">
        <input
          id={id}
          type={shown ? "text" : "password"}
          value={props.value}
          onChange={(e) => props.onChange(e.target.value)}
          autoFocus={props.autoFocus}
          placeholder={props.placeholder}
          autoComplete={props.autoComplete ?? "off"}
          spellCheck={false}
          autoCapitalize="off"
          autoCorrect="off"
        />
        <IconButton icon={shown ? "eyeOff" : "eye"} label={shown ? "Hide" : "Show"} onClick={() => setShown(!shown)} />
      </div>
    </div>
  );
}

const SCORE_LABELS = ["Very weak", "Weak", "Fair", "Strong", "Very strong"];

/** Live zxcvbn estimate, computed in Rust. Debounced so we don't send every keystroke. */
export function StrengthMeter({ password, minScore }: { password: string; minScore?: number }) {
  const [report, setReport] = useState<StrengthReport | null>(null);
  useEffect(() => {
    if (!password) {
      setReport(null);
      return;
    }
    let live = true;
    const t = setTimeout(() => {
      api.estimateStrength(password).then((r) => live && setReport(r), () => {});
    }, 200);
    return () => {
      live = false;
      clearTimeout(t);
    };
  }, [password]);
  if (!report) return <div className="strength empty" />;
  const ok = minScore === undefined || report.score >= minScore;
  return (
    <div className={`strength s${report.score}`}>
      <div className="bars">
        {[0, 1, 2, 3, 4].map((i) => (
          <span key={i} className={i <= report.score ? "on" : ""} />
        ))}
      </div>
      <div className="strength-text">
        <strong>{SCORE_LABELS[report.score]}</strong>
        {!ok && <span> — not strong enough for a master password</span>}
        {report.warning && <div className="muted">{report.warning}</div>}
        {report.suggestions.slice(0, 2).map((s) => (
          <div key={s} className="muted">{s}</div>
        ))}
      </div>
    </div>
  );
}

// ---- Layout pieces --------------------------------------------------------------------------

/** Rendered into <body> so a modal opened from inside a form is not part of that form. */
export function Modal({ title, onClose, children, wide }: { title: string; onClose?: () => void; children: ReactNode; wide?: boolean }) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose?.();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
  return createPortal(
    <div className="modal-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose?.()}>
      <div className={`modal${wide ? " wide" : ""}`} role="dialog" aria-modal="true" aria-label={title}>
        <header>
          <h2>{title}</h2>
          {onClose && <IconButton icon="close" label="Close" onClick={onClose} />}
        </header>
        <div className="modal-body">{children}</div>
      </div>
    </div>,
    document.body,
  );
}

export function ErrorBanner({ message }: { message: string | null }) {
  if (!message) return null;
  return <div className="error" role="alert">{message}</div>;
}

/** Shows a freshly issued Recovery Key once, and requires acknowledgement. */
export function RecoveryKeyPanel({ recoveryKey, onDone, doneLabel = "Continue" }: { recoveryKey: string; onDone: () => void; doneLabel?: string }) {
  const [saved, setSaved] = useState(false);
  const [copied, setCopied] = useState<number | null>(null);
  return (
    <div className="recovery">
      <p>
        This is your <strong>Recovery Key</strong>. It is the only way back into your vault if you forget your master
        password. It is shown <strong>once</strong> and is not stored anywhere by AEGIS VAULT.
      </p>
      <p>Write it down on paper or store it somewhere offline and safe.</p>
      <code className="recovery-key">{recoveryKey}</code>
      <div className="row">
        <button
          type="button"
          className="secondary"
          onClick={() => api.copyGenerated(recoveryKey).then(setCopied, () => {})}
        >
          <Icon name="copy" /> Copy
        </button>
        {copied !== null && <span className="muted">Copied — the clipboard clears in {copied} s.</span>}
      </div>
      <label className="check">
        <input autoComplete="off" type="checkbox" checked={saved} onChange={(e) => setSaved(e.target.checked)} />
        I have saved my Recovery Key somewhere safe.
      </label>
      <button type="button" className="primary" disabled={!saved} onClick={onDone}>
        {doneLabel}
      </button>
    </div>
  );
}

export function Toast({ message, onDone }: { message: string; onDone: () => void }) {
  useEffect(() => {
    const t = setTimeout(onDone, 2500);
    return () => clearTimeout(t);
  }, [message, onDone]);
  return <div className="toast" role="status">{message}</div>;
}
