import type { ReactNode } from "react";

import { ActionDialog, type Field } from "../components/ui";
import type { IntegrationSettings, SettingField } from "../types";

/** Form value shown for a setting's current value. */
export function initialValue(f: SettingField): string | boolean {
  if (f.kind === "bool") return f.value === true;
  if (f.value === null || f.value === undefined) return "";
  if (f.kind === "list") return Array.isArray(f.value) ? f.value.join("\n") : String(f.value);
  if (f.kind === "json") return typeof f.value === "string" ? f.value : JSON.stringify(f.value, null, 2);
  return String(f.value);
}

const SOURCE: Record<SettingField["source"], string> = {
  applied: "set in the console",
  environment: "from the environment",
  default: "built-in default",
};

export function settingFields(item: IntegrationSettings, secretsWritable: boolean): Field[] {
  const fields: Field[] = item.fields.map((f) => ({
    name: `v:${f.key}`,
    label: `${f.label} (${f.key})`,
    kind: f.kind === "bool" ? "checkbox" : f.kind === "choice" ? "select" : f.kind === "list" || f.kind === "json" ? "textarea" : "text",
    options: f.kind === "choice" ? f.options.map((o) => ({ value: o, label: o })) : undefined,
    initial: initialValue(f),
    help: [f.kind === "list" ? "One entry per line." : "", f.help, `Now: ${SOURCE[f.source]}.`,
      f.source === "applied" ? "Clear it to go back to the environment value." : ""].filter(Boolean).join(" "),
  }));
  if (secretsWritable)
    for (const s of item.secrets)
      fields.push({
        name: `s:${s.name}`,
        label: `Secret ${s.name}`,
        kind: "password",
        help: `${s.present ? "A value exists." : "Not set."} Leave empty to keep it. Write-only: stored only in Vault, never shown again.`,
      });
  fields.push({ name: "reason", label: "Reason", kind: "textarea", required: true, minLength: 10, maxLength: 1000 });
  return fields;
}

export interface SettingsChange {
  values: Record<string, unknown>;
  secrets: Record<string, string>;
  reason: string;
}

/** Only what changed is sent. Throws with a readable message for invalid JSON. */
export function buildChange(item: IntegrationSettings, form: Record<string, string | boolean>): SettingsChange {
  const values: Record<string, unknown> = {};
  for (const f of item.fields) {
    const raw = form[`v:${f.key}`];
    if (raw === initialValue(f)) continue;
    if (f.kind === "bool") {
      values[f.key] = raw === true;
      continue;
    }
    const text = String(raw ?? "").trim();
    if (!text) {
      if (f.source === "applied") values[f.key] = null; // back to the environment / default
      continue;
    }
    if (f.kind === "list") values[f.key] = text.split("\n").map((l) => l.trim()).filter(Boolean);
    else if (f.kind === "json") {
      try {
        values[f.key] = JSON.parse(text);
      } catch {
        throw new Error(`${f.label}: not valid JSON`);
      }
    } else values[f.key] = text;
  }
  const secrets: Record<string, string> = {};
  for (const s of item.secrets) {
    const v = form[`s:${s.name}`];
    if (typeof v === "string" && v !== "") secrets[s.name] = v;
  }
  if (!Object.keys(values).length && !Object.keys(secrets).length) throw new Error("Nothing was changed.");
  return { values, secrets, reason: String(form.reason ?? "") };
}

export function SettingsDialog({
  item, secretsWritable, vaultNote, onSubmit, onClose,
}: {
  item: IntegrationSettings;
  secretsWritable: boolean;
  vaultNote: string;
  onSubmit: (change: SettingsChange) => Promise<void>;
  onClose: () => void;
}) {
  const description: ReactNode = (
    <>
      <p>
        The change becomes a proposal: another approver must approve it and an operator executes it. Values set here
        take precedence over environment variables. Workers, CronJobs and other API replicas use them after a restart.
      </p>
      {item.note ? <p>{item.note}</p> : null}
      {item.secrets.length && !secretsWritable ? <p className="note note-danger">{vaultNote}</p> : null}
    </>
  );
  return (
    <ActionDialog
      title={`Settings: ${item.name}`}
      description={description}
      fields={settingFields(item, secretsWritable)}
      confirmLabel="Propose change"
      onClose={onClose}
      onSubmit={async (form) => onSubmit(buildChange(item, form))}
    />
  );
}
