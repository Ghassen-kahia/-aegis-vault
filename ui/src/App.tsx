import { useCallback, useEffect, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { api, errorMessage, Status } from "./api";
import { ErrorBanner } from "./components/common";
import { ResetAfterRecovery, Setup, Unlock } from "./screens/Auth";
import { VaultScreen } from "./screens/VaultScreen";

/** How often UI activity is reported to Rust, which owns the auto-lock timer. */
const HEARTBEAT_MS = 15_000;

export function App() {
  const [status, setStatus] = useState<Status | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [lockReason, setLockReason] = useState<string | null>(null);
  // Bumped on every lock so the whole vault tree (and any revealed secret in it) unmounts.
  const [session, setSession] = useState(0);

  const loadStatus = useCallback(() => {
    api.vaultStatus().then(setStatus, (e) => setError(errorMessage(e)));
  }, []);

  useEffect(loadStatus, [loadStatus]);

  // Rust locks on inactivity and tells us.
  useEffect(() => {
    const off = listen<string>("vault-locked", (e) => {
      setLockReason(e.payload);
      setSession((n) => n + 1);
      loadStatus();
    });
    return () => {
      off.then((f) => f());
    };
  }, [loadStatus]);

  // Report activity (throttled). The timeout itself is enforced in Rust.
  useEffect(() => {
    if (!status?.unlocked) return;
    let last = 0;
    const onActivity = () => {
      const now = Date.now();
      if (now - last > HEARTBEAT_MS) {
        last = now;
        api.touch().catch(() => {});
      }
    };
    const events = ["mousemove", "mousedown", "keydown", "wheel"] as const;
    events.forEach((e) => window.addEventListener(e, onActivity, { passive: true }));
    return () => events.forEach((e) => window.removeEventListener(e, onActivity));
  }, [status?.unlocked]);

  // A command answering "locked" means Rust locked underneath us: resync.
  useEffect(() => {
    const onRejection = (e: PromiseRejectionEvent) => {
      if ((e.reason as { code?: string })?.code === "locked") loadStatus();
    };
    window.addEventListener("unhandledrejection", onRejection);
    return () => window.removeEventListener("unhandledrejection", onRejection);
  }, [loadStatus]);

  const lock = useCallback(async () => {
    await api.lock().catch(() => {});
    setLockReason(null);
    setSession((n) => n + 1);
    loadStatus();
  }, [loadStatus]);

  if (error) return <div className="pane-empty"><ErrorBanner message={error} /></div>;
  if (!status) return null;
  if (!status.exists) return <Setup onReady={loadStatus} />;
  if (!status.unlocked) {
    return (
      <Unlock
        lockReason={lockReason}
        onUnlocked={(s) => {
          setLockReason(null);
          setStatus(s);
        }}
      />
    );
  }
  if (status.must_change_password) return <ResetAfterRecovery onDone={loadStatus} onCancel={lock} />;
  return <VaultScreen key={session} onLock={lock} />;
}
