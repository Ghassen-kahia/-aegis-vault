import { useCallback, useEffect, useState } from "react";
import { api, errorMessage, Generated, PassphraseOptions, PasswordOptions } from "../api";
import { ErrorBanner, Icon, IconButton, Modal } from "../components/common";

const DEFAULT_PASSWORD: PasswordOptions = { length: 20, lowercase: true, uppercase: true, digits: true, symbols: true, exclude_ambiguous: false };
const DEFAULT_PASSPHRASE: PassphraseOptions = { words: 6, separator: "-", capitalize: false, include_number: false };

function strengthLabel(bits: number) {
  if (bits < 50) return "weak";
  if (bits < 80) return "good";
  if (bits < 110) return "strong";
  return "excellent";
}

/** Generator in Rust (OS CSPRNG). With `onUse`, it fills a field in the item editor. */
export function Generator({ onClose, onUse }: { onClose: () => void; onUse?: (v: string) => void }) {
  const [mode, setMode] = useState<"password" | "passphrase">("password");
  const [pw, setPw] = useState(DEFAULT_PASSWORD);
  const [pp, setPp] = useState(DEFAULT_PASSPHRASE);
  const [result, setResult] = useState<Generated | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState<number | null>(null);

  const generate = useCallback(async () => {
    setCopied(null);
    try {
      setResult(mode === "password" ? await api.generatePassword(pw) : await api.generatePassphrase(pp));
      setError(null);
    } catch (e) {
      setResult(null);
      setError(errorMessage(e));
    }
  }, [mode, pw, pp]);

  useEffect(() => {
    generate();
  }, [generate]);

  const toggle = (k: keyof Omit<PasswordOptions, "length">) => (
    <label className="check" key={k}>
      <input autoComplete="off" type="checkbox" checked={pw[k]} onChange={(e) => setPw({ ...pw, [k]: e.target.checked })} />
      {{ lowercase: "a–z", uppercase: "A–Z", digits: "0–9", symbols: "!@#$", exclude_ambiguous: "Avoid look-alikes (0/O, 1/l)" }[k]}
    </label>
  );

  return (
    <Modal title="Password generator" onClose={onClose}>
      <div className="tabs">
        <button type="button" className={mode === "password" ? "active" : ""} onClick={() => setMode("password")}>Password</button>
        <button type="button" className={mode === "passphrase" ? "active" : ""} onClick={() => setMode("passphrase")}>Passphrase</button>
      </div>

      <div className="generated">
        <code>{result?.value ?? ""}</code>
        <IconButton icon="refresh" label="Regenerate" onClick={generate} />
      </div>
      {result && (
        <div className="muted">
          ≈ {Math.round(result.entropy_bits)} bits of entropy · {strengthLabel(result.entropy_bits)}
        </div>
      )}
      <ErrorBanner message={error} />

      {mode === "password" ? (
        <div className="options">
          <label className="range">
            Length <strong>{pw.length}</strong>
            <input autoComplete="off" type="range" min={8} max={128} value={pw.length} onChange={(e) => setPw({ ...pw, length: Number(e.target.value) })} />
          </label>
          <div className="checks">{(["lowercase", "uppercase", "digits", "symbols", "exclude_ambiguous"] as const).map(toggle)}</div>
        </div>
      ) : (
        <div className="options">
          <label className="range">
            Words <strong>{pp.words}</strong>
            <input autoComplete="off" type="range" min={3} max={20} value={pp.words} onChange={(e) => setPp({ ...pp, words: Number(e.target.value) })} />
          </label>
          <div className="checks">
            <label className="check">
              Separator
              <input autoComplete="off" className="tiny" value={pp.separator} maxLength={3} onChange={(e) => setPp({ ...pp, separator: e.target.value })} />
            </label>
            <label className="check">
              <input autoComplete="off" type="checkbox" checked={pp.capitalize} onChange={(e) => setPp({ ...pp, capitalize: e.target.checked })} />
              Capitalize
            </label>
            <label className="check">
              <input autoComplete="off" type="checkbox" checked={pp.include_number} onChange={(e) => setPp({ ...pp, include_number: e.target.checked })} />
              Add a digit
            </label>
          </div>
        </div>
      )}

      <div className="row">
        {onUse && (
          <button type="button" className="primary" disabled={!result} onClick={() => result && onUse(result.value)}>
            Use this
          </button>
        )}
        <button
          type="button"
          className={onUse ? "secondary" : "primary"}
          disabled={!result}
          onClick={() => result && api.copyGenerated(result.value).then(setCopied, (e) => setError(errorMessage(e)))}
        >
          <Icon name="copy" /> Copy
        </button>
        {copied !== null && <span className="muted">Copied — clears in {copied} s</span>}
      </div>
    </Modal>
  );
}
