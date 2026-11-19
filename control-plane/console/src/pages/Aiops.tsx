import { useState } from "react";
import { useSearchParams } from "react-router";

import { ActionDialog, Badge, Empty, ErrorNote, Loading, PageHeader, TableWrap } from "../components/ui";
import { fmtTime } from "../format";
import { useResource, useSession } from "../session";
import type { Prediction } from "../types";

const STATUSES = ["SCHEDULED", "ESCALATING", "ESCALATED", "FAILED", "EXPIRED", "CANCELLED"];

export default function Aiops() {
  const { api } = useSession();
  const [params, setParams] = useSearchParams();
  const status = params.get("status") ?? "";
  const list = useResource(() => api.get<Prediction[]>("/aiops/predictions", { status_filter: status || undefined, limit: 200 }), [api, status]);
  const [cancel, setCancel] = useState<Prediction | null>(null);

  return (
    <>
      <PageHeader
        title="AIOps predictions"
        intro="Predicted incidents are escalated to on-call before they are expected to happen."
        actions={
          <>
            <label htmlFor="as" className="inline-label">Status</label>
            <select id="as" value={status} onChange={(e) => setParams(e.target.value ? { status: e.target.value } : {})}>
              <option value="">All</option>
              {STATUSES.map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
            <button className="btn" onClick={list.reload}>Refresh</button>
          </>
        }
      />
      <ErrorNote error={list.error} />
      {list.loading && !list.data ? <Loading what="predictions" /> : null}
      {list.data && !list.data.length ? <Empty>No predictions.</Empty> : null}
      {list.data && list.data.length ? (
        <TableWrap label="Predictions">
          <thead><tr><th>Service</th><th>Severity</th><th>Probability</th><th>Expected</th><th>Notify at</th><th>Channels</th><th>Status</th><th>Summary</th><th /></tr></thead>
          <tbody>
            {list.data.map((p) => (
              <tr key={p.id}>
                <td>{p.service}</td><td>{p.severity}</td><td>{Math.round(p.probability * 100)} %</td>
                <td>{fmtTime(p.predicted_at)}</td><td>{fmtTime(p.notify_at)}</td><td>{p.channels.join(", ")}</td>
                <td><Badge value={p.status} />{p.last_error ? <div className="small muted">{p.last_error}</div> : null}</td>
                <td className="wrap">{p.summary}</td>
                <td>{p.status === "SCHEDULED" ? <button className="btn" onClick={() => setCancel(p)}>Cancel…</button> : null}</td>
              </tr>
            ))}
          </tbody>
        </TableWrap>
      ) : null}
      {cancel ? (
        <ActionDialog
          title={`Cancel prediction for ${cancel.service}`}
          description="No escalation will be sent for it."
          fields={[{ name: "note", label: "Why (recorded)", kind: "textarea", maxLength: 2000 }]}
          confirmLabel="Cancel prediction"
          danger
          onClose={() => setCancel(null)}
          onSubmit={async (v) => {
            await api.post(`/aiops/predictions/${encodeURIComponent(cancel.id)}/cancel`, { note: String(v.note ?? "") });
            list.reload();
          }}
        />
      ) : null}
    </>
  );
}
