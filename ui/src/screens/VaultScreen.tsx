import { FormEvent, useCallback, useEffect, useMemo, useState } from "react";
import { api, errorMessage, Folder, ItemSummary, KIND_LABELS, Overview } from "../api";
import { ErrorBanner, Icon, IconButton, Modal, Toast } from "../components/common";
import { Generator } from "./Generator";
import { ItemDetail } from "./ItemDetail";
import { ItemEditor } from "./ItemEditor";
import { SettingsPanel } from "./SettingsPanel";

type Filter = { kind: "all" } | { kind: "favorites" } | { kind: "folder"; id: string };
type Pane = { mode: "view"; id: string } | { mode: "edit"; id: string } | { mode: "new" } | { mode: "none" };

function matches(item: ItemSummary, q: string) {
  if (!q) return true;
  const hay = [item.title, item.subtitle, item.url ?? "", ...item.tags].join(" ").toLowerCase();
  return q.toLowerCase().split(/\s+/).every((w) => hay.includes(w));
}

function FolderDialog({ folder, onClose, onDone }: { folder: Folder | null; onClose: () => void; onDone: () => void }) {
  const [name, setName] = useState(folder?.name ?? "");
  const [error, setError] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    try {
      if (folder) await api.renameFolder(folder.id, name);
      else await api.createFolder(name);
      onDone();
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  async function remove() {
    try {
      await api.deleteFolder(folder!.id);
      onDone();
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  return (
    <Modal title={folder ? "Edit folder" : "New folder"} onClose={onClose}>
      <form autoComplete="off" onSubmit={submit}>
        <div className="field">
          <label htmlFor="fname">Name</label>
          <input autoComplete="off" id="fname" value={name} onChange={(e) => setName(e.target.value)} autoFocus maxLength={64} />
        </div>
        <ErrorBanner message={error} />
        <div className="row">
          <button type="submit" className="primary" disabled={!name.trim()}>Save</button>
          {folder && !confirmDelete && (
            <button type="button" className="secondary" onClick={() => setConfirmDelete(true)}>Delete folder…</button>
          )}
        </div>
        {confirmDelete && (
          <div className="confirm">
            <span>Delete this folder? Its items are kept and moved to “No folder”.</span>
            <button type="button" className="danger" onClick={remove}>Delete</button>
            <button type="button" className="secondary" onClick={() => setConfirmDelete(false)}>Cancel</button>
          </div>
        )}
      </form>
    </Modal>
  );
}

export function VaultScreen({ onLock }: { onLock: () => void }) {
  const [overview, setOverview] = useState<Overview | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<Filter>({ kind: "all" });
  const [query, setQuery] = useState("");
  const [pane, setPane] = useState<Pane>({ mode: "none" });
  const [version, setVersion] = useState(0);
  const [toast, setToast] = useState<string | null>(null);
  const [modal, setModal] = useState<"generator" | "settings" | { folder: Folder | null } | null>(null);

  const refresh = useCallback(async () => {
    try {
      setOverview(await api.overview());
      setVersion((v) => v + 1);
      setError(null);
    } catch (e) {
      setError(errorMessage(e));
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  // If the selected folder was deleted, fall back to "All items".
  useEffect(() => {
    if (overview && filter.kind === "folder" && !overview.folders.some((f) => f.id === filter.id)) {
      setFilter({ kind: "all" });
    }
  }, [overview, filter]);

  // Ctrl+L locks; Ctrl+N creates; Ctrl+F focuses search.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (!e.ctrlKey) return;
      const k = e.key.toLowerCase();
      if (k === "l") {
        e.preventDefault();
        onLock();
      } else if (k === "n") {
        e.preventDefault();
        setPane({ mode: "new" });
      } else if (k === "f") {
        e.preventDefault();
        document.getElementById("search")?.focus();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onLock]);

  const items = useMemo(() => {
    if (!overview) return [];
    return overview.items.filter((i) => {
      if (filter.kind === "favorites" && !i.favorite) return false;
      if (filter.kind === "folder" && i.folder_id !== filter.id) return false;
      return matches(i, query.trim());
    });
  }, [overview, filter, query]);

  if (!overview) {
    return <div className="pane-empty"><ErrorBanner message={error} /></div>;
  }

  const notify = (m: string) => setToast(m);
  const count = (f: Filter) =>
    overview.items.filter((i) => (f.kind === "favorites" ? i.favorite : f.kind === "folder" ? i.folder_id === f.id : true)).length;
  const isActive = (f: Filter) => filter.kind === f.kind && (f.kind !== "folder" || (filter.kind === "folder" && filter.id === f.id));
  const selectedId = pane.mode === "view" || pane.mode === "edit" ? pane.id : null;

  const nav = (f: Filter, label: React.ReactNode) => (
    <button type="button" className={`nav${isActive(f) ? " active" : ""}`} onClick={() => setFilter(f)}>
      <span>{label}</span>
      <span className="count">{count(f)}</span>
    </button>
  );

  return (
    <div className="vault">
      <aside className="sidebar">
        <div className="brand">
          <Icon name="shield" size={20} />
          <span>AEGIS VAULT</span>
        </div>
        <button type="button" className="primary block" onClick={() => setPane({ mode: "new" })}>
          <Icon name="plus" /> New item
        </button>
        <nav>
          {nav({ kind: "all" }, "All items")}
          {nav({ kind: "favorites" }, "Favorites")}
          <div className="nav-heading">
            <span>Folders</span>
            <IconButton icon="plus" label="New folder" onClick={() => setModal({ folder: null })} />
          </div>
          {overview.folders.map((f) => (
            <div className="nav-folder" key={f.id}>
              {nav({ kind: "folder", id: f.id }, <><Icon name="folder" size={14} /> {f.name}</>)}
              <IconButton icon="edit" label={`Edit ${f.name}`} onClick={() => setModal({ folder: f })} />
            </div>
          ))}
        </nav>
        <div className="sidebar-footer">
          <button type="button" className="nav" onClick={() => setModal("generator")}><span><Icon name="dice" /> Generator</span></button>
          <button type="button" className="nav" onClick={() => setModal("settings")}><span><Icon name="gear" /> Settings</span></button>
          <button type="button" className="nav" onClick={onLock} title="Ctrl+L"><span><Icon name="lock" /> Lock</span></button>
          {!overview.has_recovery_key && <div className="hint warn">No Recovery Key is set. Issue one in Settings.</div>}
        </div>
      </aside>

      <section className="list">
        <div className="search">
          <input autoComplete="off" id="search" type="search" placeholder="Search (Ctrl+F)" value={query} onChange={(e) => setQuery(e.target.value)} />
        </div>
        <ErrorBanner message={error} />
        <ul>
          {items.map((i) => (
            <li key={i.id}>
              <button type="button" className={`row-item${selectedId === i.id ? " selected" : ""}`} onClick={() => setPane({ mode: "view", id: i.id })}>
                <div className="avatar">{i.title.slice(0, 1).toUpperCase()}</div>
                <div className="row-text">
                  <div className="row-title">{i.title}{i.favorite && <span className="fav"><Icon name="star" size={12} /></span>}</div>
                  <div className="row-sub">{i.subtitle || KIND_LABELS[i.kind]}</div>
                </div>
              </button>
            </li>
          ))}
        </ul>
        {items.length === 0 && (
          <div className="list-empty">
            {overview.items.length === 0 ? "Your vault is empty. Create your first item." : "Nothing matches."}
          </div>
        )}
      </section>

      <main className="pane">
        {pane.mode === "view" && (
          <ItemDetail
            itemId={pane.id}
            folders={overview.folders}
            version={version}
            notify={notify}
            onEdit={() => setPane({ mode: "edit", id: pane.id })}
            onChanged={refresh}
            onDeleted={() => {
              setPane({ mode: "none" });
              notify("Item deleted");
              refresh();
            }}
          />
        )}
        {(pane.mode === "edit" || pane.mode === "new") && (
          <ItemEditor
            key={pane.mode === "edit" ? pane.id : "new"}
            itemId={pane.mode === "edit" ? pane.id : null}
            defaultFolder={filter.kind === "folder" ? filter.id : null}
            folders={overview.folders}
            onCancel={() => setPane(pane.mode === "edit" ? { mode: "view", id: pane.id } : { mode: "none" })}
            onSaved={(id) => {
              setPane({ mode: "view", id });
              notify("Saved");
              refresh();
            }}
          />
        )}
        {pane.mode === "none" && (
          <div className="pane-empty">
            <Icon name="shield" size={48} />
            <p className="muted">Select an item, or press Ctrl+N to create one.</p>
          </div>
        )}
      </main>

      {modal === "generator" && <Generator onClose={() => setModal(null)} />}
      {modal === "settings" && <SettingsPanel settings={overview.settings} onClose={() => setModal(null)} onSaved={refresh} />}
      {modal && typeof modal === "object" && (
        <FolderDialog
          folder={modal.folder}
          onClose={() => setModal(null)}
          onDone={() => {
            setModal(null);
            refresh();
          }}
        />
      )}
      {toast && <Toast message={toast} onDone={() => setToast(null)} />}
    </div>
  );
}
