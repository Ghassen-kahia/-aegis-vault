import { useEffect, useState } from "react";
import { api, errorMessage, FieldView, Folder, formatDate, HistoryEntry, isSecret, ItemView, KIND_LABELS } from "../api";
import { ErrorBanner, Icon, IconButton, Modal } from "../components/common";

function FieldRow({ itemId, field, notify }: { itemId: string; field: FieldView; notify: (m: string) => void }) {
  const secret = isSecret(field.kind);
  // Revealed values live only in this component and are dropped when it unmounts or on hide.
  const [revealed, setRevealed] = useState<string | null>(null);

  async function toggleReveal() {
    if (revealed !== null) return setRevealed(null);
    try {
      setRevealed(await api.revealField(itemId, field.id));
    } catch (e) {
      notify(errorMessage(e));
    }
  }

  async function copy() {
    try {
      const secs = await api.copyField(itemId, field.id);
      notify(secret ? `${field.label} copied — clipboard clears in ${secs} s` : `${field.label} copied`);
    } catch (e) {
      notify(errorMessage(e));
    }
  }

  const value = secret ? (revealed ?? "••••••••••••") : field.value ?? "";
  return (
    <div className="detail-field">
      <div className="detail-label">{field.label || "Untitled"}</div>
      <div className="detail-value-row">
        <div className={`detail-value${secret ? " mono" : ""}${secret && revealed === null ? " masked" : ""}`}>
          {field.kind === "url" && value ? <span className="url">{value}</span> : value || <span className="muted">—</span>}
        </div>
        {field.has_value && (
          <div className="actions">
            {secret && <IconButton icon={revealed !== null ? "eyeOff" : "eye"} label={revealed !== null ? "Hide" : "Reveal"} onClick={toggleReveal} />}
            <IconButton icon="copy" label="Copy" onClick={copy} />
          </div>
        )}
      </div>
    </div>
  );
}

function HistoryModal({ itemId, onClose }: { itemId: string; onClose: () => void }) {
  const [entries, setEntries] = useState<HistoryEntry[] | null>(null);
  const [shown, setShown] = useState<Set<number>>(new Set());
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    api.itemHistory(itemId).then((h) => setEntries([...h].reverse()), (e) => setError(errorMessage(e)));
  }, [itemId]);
  return (
    <Modal title="Previous values" onClose={onClose}>
      <ErrorBanner message={error} />
      {entries?.length === 0 && <p className="muted">No previous values.</p>}
      <ul className="history">
        {entries?.map((h, i) => (
          <li key={i}>
            <div>
              <div className="detail-label">{h.field_label} · replaced {formatDate(h.replaced_at)}</div>
              <div className={`mono${shown.has(i) ? "" : " masked"}`}>{shown.has(i) ? h.value : "••••••••••••"}</div>
            </div>
            <IconButton
              icon={shown.has(i) ? "eyeOff" : "eye"}
              label={shown.has(i) ? "Hide" : "Reveal"}
              onClick={() => {
                const next = new Set(shown);
                if (next.has(i)) next.delete(i);
                else next.add(i);
                setShown(next);
              }}
            />
          </li>
        ))}
      </ul>
    </Modal>
  );
}

export function ItemDetail(props: {
  itemId: string;
  folders: Folder[];
  version: number;
  onEdit: () => void;
  onDeleted: () => void;
  onChanged: () => void;
  notify: (m: string) => void;
}) {
  const [item, setItem] = useState<ItemView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [history, setHistory] = useState(false);

  useEffect(() => {
    setConfirmDelete(false);
    api.getItem(props.itemId).then(setItem, (e) => setError(errorMessage(e)));
  }, [props.itemId, props.version]);

  if (error) return <div className="pane-empty"><ErrorBanner message={error} /></div>;
  if (!item) return <div className="pane-empty" />;

  const folder = props.folders.find((f) => f.id === item.folder_id);

  async function toggleFavorite() {
    try {
      await api.setFavorite(item!.id, !item!.favorite);
      props.onChanged();
    } catch (e) {
      props.notify(errorMessage(e));
    }
  }

  async function remove() {
    try {
      await api.deleteItem(item!.id);
      props.onDeleted();
    } catch (e) {
      props.notify(errorMessage(e));
    }
  }

  return (
    <div className="detail">
      <header className="detail-header">
        <div>
          <div className="kind-chip">{KIND_LABELS[item.kind]}</div>
          <h2>{item.title}</h2>
          {folder && <div className="muted"><Icon name="folder" size={13} /> {folder.name}</div>}
        </div>
        <div className="actions">
          <IconButton icon="star" label={item.favorite ? "Remove from favorites" : "Add to favorites"} active={item.favorite} onClick={toggleFavorite} />
          <IconButton icon="edit" label="Edit" onClick={props.onEdit} />
          <IconButton icon="trash" label="Delete" onClick={() => setConfirmDelete(true)} />
        </div>
      </header>

      {confirmDelete && (
        <div className="confirm">
          <span>Delete “{item.title}”? This cannot be undone.</span>
          <button type="button" className="danger" onClick={remove}>Delete</button>
          <button type="button" className="secondary" onClick={() => setConfirmDelete(false)}>Cancel</button>
        </div>
      )}

      <section>
        {item.fields.map((f) => (
          <FieldRow key={f.id} itemId={item.id} field={f} notify={props.notify} />
        ))}
      </section>

      {item.notes && (
        <section>
          <div className="detail-label">Notes</div>
          <pre className="notes">{item.notes}</pre>
        </section>
      )}

      {item.tags.length > 0 && (
        <div className="tags">
          {item.tags.map((t) => <span key={t} className="tag">{t}</span>)}
        </div>
      )}

      <footer className="detail-meta">
        <span>Created {formatDate(item.created_at)}</span>
        <span>Updated {formatDate(item.updated_at)}</span>
        {item.history_count > 0 && (
          <button type="button" className="link" onClick={() => setHistory(true)}>
            <Icon name="history" size={13} /> {item.history_count} previous value{item.history_count === 1 ? "" : "s"}
          </button>
        )}
      </footer>

      {history && <HistoryModal itemId={item.id} onClose={() => setHistory(false)} />}
    </div>
  );
}
