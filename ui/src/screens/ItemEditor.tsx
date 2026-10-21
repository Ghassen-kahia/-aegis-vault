import { FormEvent, useEffect, useState } from "react";
import { api, errorMessage, FieldInput, FieldKind, Folder, isSecret, ItemInput, ItemKind, KIND_LABELS, templateFields } from "../api";
import { ErrorBanner, IconButton } from "../components/common";
import { Generator } from "./Generator";

const FIELD_KINDS: { value: FieldKind; label: string }[] = [
  { value: "text", label: "Text" },
  { value: "username", label: "Username" },
  { value: "email", label: "Email" },
  { value: "url", label: "URL" },
  { value: "password", label: "Password" },
  { value: "concealed", label: "Hidden" },
];

interface Draft extends Omit<ItemInput, "tags"> {
  tags: string;
}

function emptyDraft(kind: ItemKind, folderId: string | null): Draft {
  return { kind, title: "", folder_id: folderId, tags: "", favorite: false, fields: templateFields(kind), notes: "" };
}

function SecretValueInput({ value, onChange, onGenerate }: { value: string; onChange: (v: string) => void; onGenerate: () => void }) {
  const [shown, setShown] = useState(false);
  return (
    <div className="input-row">
      <input className="mono" type={shown ? "text" : "password"} value={value} onChange={(e) => onChange(e.target.value)} spellCheck={false} autoComplete="off" />
      <IconButton icon={shown ? "eyeOff" : "eye"} label={shown ? "Hide" : "Show"} onClick={() => setShown(!shown)} />
      <IconButton icon="dice" label="Generate" onClick={onGenerate} />
    </div>
  );
}

/** Create (itemId = null) or edit an item. */
export function ItemEditor(props: {
  itemId: string | null;
  defaultFolder: string | null;
  folders: Folder[];
  onSaved: (id: string) => void;
  onCancel: () => void;
}) {
  const [draft, setDraft] = useState<Draft | null>(props.itemId ? null : emptyDraft("login", props.defaultFolder));
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [generatorFor, setGeneratorFor] = useState<number | null>(null);

  useEffect(() => {
    if (!props.itemId) return;
    api.getItemForEdit(props.itemId).then(
      (i) => setDraft({ ...i, tags: i.tags.join(", "), fields: i.fields.map((f) => ({ ...f })) }),
      (e) => setError(errorMessage(e)),
    );
  }, [props.itemId]);

  if (!draft) return <div className="pane-empty"><ErrorBanner message={error} /></div>;

  const set = (patch: Partial<Draft>) => setDraft({ ...draft, ...patch });
  const setField = (i: number, patch: Partial<FieldInput>) =>
    set({ fields: draft.fields.map((f, j) => (j === i ? { ...f, ...patch } : f)) });

  function changeKind(kind: ItemKind) {
    // On a new item with untouched template fields, swap in the new template.
    const untouched = draft!.fields.every((f) => !f.value);
    set({ kind, fields: !props.itemId && untouched ? templateFields(kind) : draft!.fields });
  }

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    const input: ItemInput = {
      ...draft!,
      tags: draft!.tags.split(",").map((t) => t.trim()).filter(Boolean),
    };
    try {
      if (props.itemId) {
        await api.updateItem(props.itemId, input);
        props.onSaved(props.itemId);
      } else {
        props.onSaved(await api.createItem(input));
      }
    } catch (err) {
      setError(errorMessage(err));
      setBusy(false);
    }
  }

  return (
    <form autoComplete="off" className="editor" onSubmit={submit}>
      <header className="detail-header">
        <h2>{props.itemId ? "Edit item" : "New item"}</h2>
      </header>

      <div className="grid2">
        <div className="field">
          <label htmlFor="kind">Type</label>
          <select id="kind" value={draft.kind} onChange={(e) => changeKind(e.target.value as ItemKind)}>
            {Object.entries(KIND_LABELS).map(([k, l]) => <option key={k} value={k}>{l}</option>)}
          </select>
        </div>
        <div className="field">
          <label htmlFor="folder">Folder</label>
          <select id="folder" value={draft.folder_id ?? ""} onChange={(e) => set({ folder_id: e.target.value || null })}>
            <option value="">No folder</option>
            {props.folders.map((f) => <option key={f.id} value={f.id}>{f.name}</option>)}
          </select>
        </div>
      </div>

      <div className="field">
        <label htmlFor="title">Title</label>
        <input autoComplete="off" id="title" value={draft.title} onChange={(e) => set({ title: e.target.value })} autoFocus maxLength={256} />
      </div>

      <fieldset>
        <legend>Fields</legend>
        {draft.fields.map((f, i) => (
          <div className="field-edit" key={f.id ?? `new-${i}`}>
            <input autoComplete="off" className="label-input" value={f.label} placeholder="Label" onChange={(e) => setField(i, { label: e.target.value })} maxLength={128} />
            <select value={f.kind} onChange={(e) => setField(i, { kind: e.target.value as FieldKind })}>
              {FIELD_KINDS.map((k) => <option key={k.value} value={k.value}>{k.label}</option>)}
            </select>
            {isSecret(f.kind) ? (
              <SecretValueInput value={f.value} onChange={(v) => setField(i, { value: v })} onGenerate={() => setGeneratorFor(i)} />
            ) : (
              <input autoComplete="off" value={f.value} onChange={(e) => setField(i, { value: e.target.value })} spellCheck={false} />
            )}
            <IconButton icon="trash" label="Remove field" onClick={() => set({ fields: draft.fields.filter((_, j) => j !== i) })} />
          </div>
        ))}
        <button
          type="button"
          className="secondary small"
          onClick={() => set({ fields: [...draft.fields, { id: null, label: "", kind: "text", value: "" }] })}
        >
          Add field
        </button>
      </fieldset>

      <div className="field">
        <label htmlFor="notes">Notes</label>
        <textarea autoComplete="off" id="notes" rows={5} value={draft.notes} onChange={(e) => set({ notes: e.target.value })} />
      </div>

      <div className="field">
        <label htmlFor="tags">Tags (comma-separated)</label>
        <input autoComplete="off" id="tags" value={draft.tags} onChange={(e) => set({ tags: e.target.value })} />
      </div>

      <label className="check">
        <input autoComplete="off" type="checkbox" checked={draft.favorite} onChange={(e) => set({ favorite: e.target.checked })} />
        Favorite
      </label>

      <ErrorBanner message={error} />
      <div className="row">
        <button type="submit" className="primary" disabled={busy}>{busy ? "Saving…" : "Save"}</button>
        <button type="button" className="secondary" onClick={props.onCancel}>Cancel</button>
      </div>

      {generatorFor !== null && (
        <Generator
          onClose={() => setGeneratorFor(null)}
          onUse={(v) => {
            setField(generatorFor, { value: v });
            setGeneratorFor(null);
          }}
        />
      )}
    </form>
  );
}
