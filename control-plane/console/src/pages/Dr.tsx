import { useState } from "react";

import { ActionDialog, Badge, Empty, ErrorNote, JsonBlock, Loading, PageHeader, TableWrap } from "../components/ui";
import { fmtTime, shortId } from "../format";
import { useResource, useSession } from "../session";
import type { Breaker, Incident } from "../types";

export default function Dr() {
  const { api, me } = useSession();
  const breakers = useResource(() => api.get<Breaker[]>("/dr/breakers"), [api]);
  const incidents = useResource(() => api.get<Incident[]>("/dr/incidents", { limit: 50 }), [api]);
  const [dialog, setDialog] = useState<{ kind: "trip" | "reset"; stream: string } | null>(null);
  const reload = () => { breakers.reload(); incidents.reload(); };

  return (
    <>
      <PageHeader
        title="DR circuit breakers"
        intro="Each breaker inspects one replication stream. When it trips, the DR copy stops receiving changes until an approver decides."
        actions={<button className="btn" onClick={reload}>Refresh</button>}
      />
      <ErrorNote error={breakers.error} />
      {breakers.loading && !breakers.data ? <Loading what="breakers" /> : null}
      {breakers.data ? (
        <TableWrap label="Breakers">
          <thead><tr><th>Stream</th><th>State</th><th>Incident</th><th>Pending decision</th><th /></tr></thead>
          <tbody>
            {breakers.data.map((b) => (
              <tr key={b.stream}>
                <td className="mono">{b.stream}</td>
                <td><Badge value={b.state} /></td>
                <td className="mono">{shortId(b.incident_id)}</td>
                <td>{b.pending_decision ?? "—"}</td>
                <td className="row-actions">
                  {me.can.approve && b.state === "CLOSED" ? (
                    <button className="btn btn-danger" onClick={() => setDialog({ kind: "trip", stream: b.stream })}>Trip</button>
                  ) : null}
                  {me.can.approve && b.state === "OPEN" ? (
                    <button className="btn btn-primary" onClick={() => setDialog({ kind: "reset", stream: b.stream })}>Reset…</button>
                  ) : null}
                </td>
              </tr>
            ))}
          </tbody>
        </TableWrap>
      ) : null}

      <h2>Incidents</h2>
      <ErrorNote error={incidents.error} />
      {incidents.data && incidents.data.length === 0 ? <Empty>No incidents.</Empty> : null}
      {(incidents.data ?? []).map((i) => (
        <details key={i.id} className="incident">
          <summary>
            <span className="mono">{shortId(i.id)}</span> · {fmtTime(i.opened_at)} · <strong>{i.trigger}</strong> · {i.summary}{" "}
            {i.resolved_at ? <Badge value="RESOLVED" /> : <Badge value="OPEN" />}
          </summary>
          <dl className="details">
            <div><dt>Dump SHA-256</dt><dd className="mono wrap">{i.dump_sha256 ?? "—"}</dd></div>
            <div><dt>Resolved</dt><dd>{i.resolved_at ? `${fmtTime(i.resolved_at)} by ${i.resolved_by}` : "—"}</dd></div>
          </dl>
          <h3>Findings</h3>
          <JsonBlock value={i.findings} />
          <h3>Actions taken</h3>
          <JsonBlock value={i.actions} />
          {i.resolution ? (<><h3>Resolution</h3><JsonBlock value={i.resolution} /></>) : null}
        </details>
      ))}

      {dialog?.kind === "trip" ? (
        <ActionDialog
          title={`Trip breaker ${dialog.stream}`}
          description="Stops forwarding to the DR copy, quarantines the held changes, alerts on-call and locks the DR targets read-only."
          fields={[{ name: "reason", label: "Reason", kind: "textarea", required: true, minLength: 5, maxLength: 2000 }]}
          confirmLabel="Trip breaker"
          danger
          onClose={() => setDialog(null)}
          onSubmit={async (v) => {
            await api.post(`/dr/breakers/${encodeURIComponent(dialog.stream)}/trip`, { reason: String(v.reason) });
            reload();
          }}
        />
      ) : null}
      {dialog?.kind === "reset" ? (
        <ActionDialog
          title={`Reset breaker ${dialog.stream}`}
          description="Choose what happens to the held changes. Unlocking returns exactly the targets that were locked to read-write."
          fields={[
            { name: "decision", label: "Held changes", kind: "radio", required: true, options: [
              { value: "release", label: "Release — forward them to the DR copy (they were legitimate)" },
              { value: "discard", label: "Discard — skip them (they were the incident)" },
            ] },
            { name: "unlock_targets", label: "Unlock the DR targets", kind: "checkbox" },
            { name: "note", label: "Note (recorded in the audit log)", kind: "textarea", required: true, minLength: 5, maxLength: 2000 },
          ]}
          confirmLabel="Reset breaker"
          onClose={() => setDialog(null)}
          onSubmit={async (v) => {
            await api.post(`/dr/breakers/${encodeURIComponent(dialog.stream)}/reset`, {
              decision: String(v.decision), unlock_targets: v.unlock_targets === true, note: String(v.note),
            });
            reload();
          }}
        />
      ) : null}
    </>
  );
}
