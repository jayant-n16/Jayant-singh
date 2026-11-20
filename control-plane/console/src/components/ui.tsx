import { useEffect, useId, useRef, useState, type FormEvent, type ReactNode } from "react";

import { ApiError } from "../api";

const TONE: Record<string, string> = {
  PENDING: "warn", SCHEDULED: "warn", ESCALATING: "warn", EXECUTING: "warn", OPEN: "danger",
  APPROVED: "info", ACTIVE: "info", DRY_RUN: "info",
  EXECUTED: "ok", ESCALATED: "ok", CLOSED: "ok", RESOLVED: "ok", REVOKED: "muted",
  REJECTED: "muted", EXPIRED: "muted", CANCELLED: "muted", NONE: "muted",
  FAILED: "danger", GRANT_FAILED: "danger",
  HEALTHY: "ok", UNHEALTHY: "danger", AVAILABLE: "ok", FAILING: "danger",
  OK: "ok", CONFIGURED: "info", ERROR: "danger", NOT_CONFIGURED: "muted",
  CONNECTED: "ok", UNREACHABLE: "danger", CONSISTENT: "ok", DRIFT: "danger",
  RUNNING: "ok", STOPPED: "muted", TERMINATED: "muted", STOPPING: "warn", STARTING: "warn",
};

export function Badge({ value }: { value: string }) {
  return <span className={`badge badge-${TONE[value] ?? "muted"}`}>{value.replace(/_/g, " ")}</span>;
}

export function errorMessage(e: unknown): string {
  if (e instanceof ApiError) {
    if (e.status === 403) return `Not allowed: ${e.detail}`;
    if (e.status === 423) return `Blocked by the kill switch: ${e.detail}`;
    if (e.status === 503) return `Not configured on this control plane: ${e.detail}`;
    if (e.status === 0) return e.detail;
    return `${e.detail} (HTTP ${e.status})`;
  }
  return e instanceof Error ? e.message : String(e);
}

export function ErrorNote({ error }: { error: unknown }) {
  if (error === undefined || error === null) return null;
  return (
    <div className="note note-danger" role="alert">
      {errorMessage(error)}
    </div>
  );
}

export function Loading({ what }: { what: string }) {
  return (
    <p className="muted" role="status">
      Loading {what}…
    </p>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="empty">{children}</p>;
}

export function PageHeader({ title, intro, actions }: { title: string; intro?: ReactNode; actions?: ReactNode }) {
  return (
    <header className="page-header">
      <div>
        <h1>{title}</h1>
        {intro ? <p className="muted">{intro}</p> : null}
      </div>
      {actions ? <div className="actions">{actions}</div> : null}
    </header>
  );
}

export function TableWrap({ children, label }: { children: ReactNode; label: string }) {
  return (
    <div className="table-wrap" role="region" aria-label={label} tabIndex={0}>
      <table>{children}</table>
    </div>
  );
}

export function JsonBlock({ value }: { value: unknown }) {
  return <pre className="json">{value === null || value === undefined ? "—" : JSON.stringify(value, null, 2)}</pre>;
}

export interface Field {
  name: string;
  label: string;
  kind: "text" | "textarea" | "number" | "select" | "checkbox" | "radio";
  required?: boolean;
  minLength?: number;
  maxLength?: number;
  min?: number;
  max?: number;
  options?: { value: string; label: string }[];
  initial?: string | boolean;
  help?: string;
}

/**
 * An in-page confirmation dialog with optional fields. Runs `onSubmit`; on failure the error is
 * shown inside the dialog and the dialog stays open; on success it closes.
 */
export function ActionDialog({
  title, description, fields = [], confirmLabel, danger = false, onSubmit, onClose,
}: {
  title: string;
  description?: ReactNode;
  fields?: Field[];
  confirmLabel: string;
  danger?: boolean;
  onSubmit: (values: Record<string, string | boolean>) => Promise<void>;
  onClose: () => void;
}) {
  const [values, setValues] = useState<Record<string, string | boolean>>(() =>
    Object.fromEntries(fields.map((f) => [f.name, f.initial ?? (f.kind === "checkbox" ? false : "")])),
  );
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(undefined);
  const titleId = useId();
  const first = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const el = first.current?.querySelector<HTMLElement>("input, textarea, select, button");
    el?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !busy) onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [busy, onClose]);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(undefined);
    try {
      await onSubmit(values);
      onClose();
    } catch (err) {
      setError(err);
      setBusy(false);
    }
  }

  const set = (name: string, v: string | boolean) => setValues((s) => ({ ...s, [name]: v }));

  return (
    <div className="overlay" onMouseDown={(e) => e.target === e.currentTarget && !busy && onClose()}>
      <div className="dialog" role="dialog" aria-modal="true" aria-labelledby={titleId} ref={first}>
        <form onSubmit={submit}>
          <h2 id={titleId}>{title}</h2>
          {description ? <div className="muted dialog-desc">{description}</div> : null}
          {fields.map((f) => {
            const id = `${titleId}-${f.name}`;
            const v = values[f.name];
            if (f.kind === "checkbox")
              return (
                <label key={f.name} className="check" htmlFor={id}>
                  <input id={id} type="checkbox" checked={v === true} onChange={(e) => set(f.name, e.target.checked)} />
                  {f.label}
                </label>
              );
            if (f.kind === "radio")
              return (
                <fieldset key={f.name}>
                  <legend>{f.label}</legend>
                  {(f.options ?? []).map((o) => (
                    <label key={o.value} className="check">
                      <input type="radio" name={id} value={o.value} required={f.required}
                        checked={v === o.value} onChange={() => set(f.name, o.value)} />
                      {o.label}
                    </label>
                  ))}
                </fieldset>
              );
            return (
              <div key={f.name} className="field">
                <label htmlFor={id}>{f.label}</label>
                {f.kind === "textarea" ? (
                  <textarea id={id} rows={3} required={f.required} minLength={f.minLength} maxLength={f.maxLength}
                    value={String(v ?? "")} onChange={(e) => set(f.name, e.target.value)} />
                ) : f.kind === "select" ? (
                  <select id={id} required={f.required} value={String(v ?? "")} onChange={(e) => set(f.name, e.target.value)}>
                    <option value="" disabled>
                      Choose…
                    </option>
                    {(f.options ?? []).map((o) => (
                      <option key={o.value} value={o.value}>
                        {o.label}
                      </option>
                    ))}
                  </select>
                ) : (
                  <input id={id} type={f.kind} required={f.required} minLength={f.minLength} maxLength={f.maxLength}
                    min={f.min} max={f.max} value={String(v ?? "")} onChange={(e) => set(f.name, e.target.value)} />
                )}
                {f.help ? <small className="muted">{f.help}</small> : null}
              </div>
            );
          })}
          {error !== undefined ? <ErrorNote error={error} /> : null}
          <div className="dialog-actions">
            <button type="button" className="btn" onClick={onClose} disabled={busy}>
              Cancel
            </button>
            <button type="submit" className={danger ? "btn btn-danger" : "btn btn-primary"} disabled={busy}>
              {busy ? "Working…" : confirmLabel}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
