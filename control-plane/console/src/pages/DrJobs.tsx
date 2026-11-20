import { useState } from "react";
import { useNavigate } from "react-router";

import { ActionDialog, Badge, Empty, ErrorNote, Loading, PageHeader, TableWrap } from "../components/ui";
import { fmtTime } from "../format";
import { useResource, useSession } from "../session";
import type { DrJob, DrJobModule, DrJobsStatus, Proposal } from "../types";

function detail(j: DrJob): string {
  const st = j.state;
  const parts: string[] = [];
  if (typeof st.verdict === "string") parts.push(`verdict ${st.verdict}`);
  if (typeof st.boot_seconds === "number") parts.push(`booted in ${st.boot_seconds}s`);
  if (Array.isArray(st.checks)) {
    for (const c of st.checks as { passed: boolean; detail: string }[]) parts.push(`${c.passed ? "✓" : "✗"} ${c.detail}`);
  }
  if (st.torn_down === true) parts.push("torn down");
  if (typeof st.cleanup_error === "string") parts.push(`cleanup error: ${st.cleanup_error}`);
  return parts.join(" · ");
}

/** Every persisted-step DR module (restore drills, registry copies, backups, ...) from GET /dr/jobs. */
export default function DrJobs() {
  const { api } = useSession();
  const navigate = useNavigate();
  const st = useResource(() => api.get<DrJobsStatus>("/dr/jobs"), [api]);
  const [open, setOpen] = useState<DrJobModule | null>(null);

  return (
    <>
      <PageHeader
        title="DR jobs and restore drills"
        intro="Long-running DR jobs run by the oplia-dr-job-worker CronJob one persisted step at a time. Starting one creates a proposal: another approver approves, an operator executes, then the worker takes over."
        actions={<button className="btn" onClick={st.reload} disabled={st.loading}>{st.loading ? "Reading…" : "Refresh"}</button>}
      />
      <ErrorNote error={st.error} />
      {st.loading && !st.data ? <Loading what="DR jobs" /> : null}
      {st.data?.modules.map((m) => (
        <section key={m.kind} aria-label={m.title}>
          <h2>{m.title}</h2>
          <div className="actions">
            <button className="btn" onClick={() => setOpen(m)}>Propose {m.title.toLowerCase()}…</button>
            <span className="small muted mono">{Object.entries(m.summary).map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(", ") : String(v)}`).join(" · ")}</span>
          </div>
          {m.jobs.length === 0 ? <Empty>No jobs yet.</Empty> : (
            <TableWrap label={`${m.title} jobs`}>
              <thead><tr><th>Target</th><th>Status</th><th>Step</th><th>Requested</th><th>Updated</th><th>Detail</th></tr></thead>
              <tbody>{m.jobs.map((j) => (
                <tr key={j.id}>
                  <td className="mono small wrap">{j.target}</td>
                  <td><Badge value={j.status} /></td>
                  <td className="mono small">{j.step}</td>
                  <td className="small">{j.requested_by}</td>
                  <td className="small">{fmtTime(j.updated_at)}</td>
                  <td className="small wrap">{j.error ? <div className="danger">{j.error}</div> : null}{detail(j)}</td>
                </tr>
              ))}</tbody>
            </TableWrap>
          )}
        </section>
      ))}
      {open ? (
        <ActionDialog title={`Propose: ${open.title}`} confirmLabel="Create proposal"
          fields={[...open.fields, { name: "reason", label: "Reason (recorded)", kind: "textarea", required: true, minLength: 5, maxLength: 2000 }]}
          onClose={() => setOpen(null)}
          onSubmit={async (v) => {
            const { reason, ...params } = v;
            const p = await api.post<Proposal>(`/dr/jobs/${encodeURIComponent(open.kind)}`, { params, reason: String(reason) });
            navigate(`/proposals/${p.id}`);
          }} />
      ) : null}
    </>
  );
}
