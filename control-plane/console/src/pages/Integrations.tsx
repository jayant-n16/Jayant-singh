import { useState } from "react";
import { Link } from "react-router";

import { ActionDialog, Badge, ErrorNote, Loading, PageHeader, TableWrap } from "../components/ui";
import { fmtTime } from "../format";
import { useResource, useSession } from "../session";
import type { IntegrationSettings, IntegrationStatus, Proposal, SettingsCatalog } from "../types";
import { SettingsDialog } from "./IntegrationSettings";

const CATEGORY: Record<string, string> = {
  cloud: "Clouds", cicd: "CI/CD", identity: "Identity providers", alerting: "Alerting", secrets: "Secrets", "sign-in": "Console sign-in",
};
const ORDER = ["cloud", "cicd", "identity", "alerting", "secrets", "sign-in"];

export default function Integrations() {
  const { api, me } = useSession();
  const list = useResource(() => api.get<IntegrationStatus[]>("/integrations"), [api]);
  const [test, setTest] = useState<IntegrationStatus | null>(null);
  const [result, setResult] = useState<{ name: string; ok: boolean; text: string } | null>(null);
  const catalog = useResource(
    () => (me.can.approve ? api.get<SettingsCatalog>("/settings/integrations") : Promise.resolve(null)),
    [api, me.can.approve],
  );
  const [editing, setEditing] = useState<IntegrationSettings | null>(null);
  const [proposed, setProposed] = useState<Proposal | null>(null);
  const settingsFor = (name: string) => catalog.data?.integrations.find((i) => i.name === name);

  return (
    <>
      <PageHeader
        title="Integrations"
        intro="Live read-only status of every connection OPLIA uses. Secret values are never shown — only whether the named secret exists."
        actions={
          <>
            {settingsFor("databases") ? (
              <button className="btn" onClick={() => setEditing(settingsFor("databases") ?? null)}>Database list…</button>
            ) : null}
            <button className="btn" onClick={list.reload} disabled={list.loading}>{list.loading ? "Checking…" : "Re-check all"}</button>
          </>
        }
      />
      {me.can.approve ? <ErrorNote error={catalog.error} /> : null}
      {catalog.data ? (
        <p className="muted small">
          Approvers can change each integration&apos;s settings. Precedence: {catalog.data.precedence}.
          {catalog.data.secrets_writable ? " Secrets are written only to Vault." : ` ${catalog.data.vault_note}`}
        </p>
      ) : null}
      {proposed ? (
        <div className="note" role="status">
          Settings change proposed for {String((proposed.payload as { integration?: string }).integration ?? "")}:{" "}
          <Link to={`/proposals/${proposed.id}`}>open the proposal</Link>. Another approver must approve it and an operator
          executes it; the proposal then shows the integration&apos;s re-checked status.
        </div>
      ) : null}
      <ErrorNote error={list.error} />
      {result ? <div className={result.ok ? "note" : "note note-danger"} role="status">{result.name}: {result.text}</div> : null}
      {list.loading && !list.data ? <Loading what="integration status (each one is contacted, this can take a few seconds)" /> : null}
      {list.data ? ORDER.filter((c) => list.data!.some((i) => i.category === c)).map((cat) => (
        <section key={cat}>
          <h2>{CATEGORY[cat]}</h2>
          <TableWrap label={CATEGORY[cat] ?? cat}>
            <thead><tr><th>Integration</th><th>Status</th><th>Target</th><th>Detail</th><th>Secrets (names)</th><th>Checked</th><th /></tr></thead>
            <tbody>
              {list.data!.filter((i) => i.category === cat).map((i) => (
                <tr key={i.name}>
                  <td className="mono">{i.name}</td>
                  <td><Badge value={i.status === "not_configured" ? "NOT_CONFIGURED" : i.status.toUpperCase()} /></td>
                  <td className="wrap small">{i.target || "—"}</td>
                  <td className="wrap small">{i.detail}</td>
                  <td className="mono small wrap">{i.secrets.join(", ") || "—"}</td>
                  <td className="small">{fmtTime(i.checked_at)}<div className="muted">{i.latency_ms} ms</div></td>
                  <td>
                    <div className="row-actions">
                      {i.can_test_notification && me.can.approve ? <button className="btn" onClick={() => setTest(i)}>Send test…</button> : null}
                      {settingsFor(i.name) ? (
                        <button className="btn" aria-label={`Edit settings of ${i.name}`} onClick={() => setEditing(settingsFor(i.name) ?? null)}>Settings…</button>
                      ) : null}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </TableWrap>
        </section>
      )) : null}
      {editing && catalog.data ? (
        <SettingsDialog
          item={editing}
          secretsWritable={catalog.data.secrets_writable}
          vaultNote={catalog.data.vault_note}
          onClose={() => setEditing(null)}
          onSubmit={async (change) => {
            const body: Record<string, unknown> = { values: change.values, reason: change.reason };
            if (Object.keys(change.secrets).length) body.secrets = change.secrets;
            setProposed(await api.post<Proposal>(`/settings/integrations/${encodeURIComponent(editing.name)}`, body));
            catalog.reload();
          }}
        />
      ) : null}
      {test ? (
        <ActionDialog
          title={`Send a test notification to ${test.name}`}
          description={test.name === "pagerduty" ? "Triggers an info-severity test event and resolves it immediately. Depending on your PagerDuty service rules this may still notify on-call." : "Sends one clearly labelled test message. Recorded in the audit log."}
          confirmLabel="Send test"
          onClose={() => setTest(null)}
          onSubmit={async () => {
            const r = await api.post<{ ok: boolean; detail: string; error: string | null }>(`/integrations/${encodeURIComponent(test.name)}/test`);
            setResult({ name: test.name, ok: r.ok, text: r.ok ? r.detail : `failed — ${r.error}` });
          }}
        />
      ) : null}
    </>
  );
}
