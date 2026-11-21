import { useState } from "react";
import { useNavigate } from "react-router";

import { ActionDialog, Badge, Empty, ErrorNote, Loading, PageHeader, TableWrap } from "../components/ui";
import { fmtTime } from "../format";
import { useResource, useSession } from "../session";
import type { DrJob, DrJobModule, DrJobsStatus, Proposal } from "../types";

export const MIGRATION_KINDS = ["schema_synthesis", "schema_change", "schema_contract", "cdc_pipeline",
  "cdc_lag_probe", "parity_check", "cutover", "failback"];

type Obj = Record<string, unknown>;

function detail(j: DrJob): string {
  const st = j.state;
  const parts: string[] = [];
  const res = (st.result ?? {}) as Obj;
  if (typeof res.p99_ms === "number") parts.push(`lag p50 ${String(res.p50_ms)} ms · p99 ${res.p99_ms} ms (${String(res.samples)} samples)`);
  if (typeof res.applied_ms === "number") parts.push(`switch applied in ${res.applied_ms} ms`);
  if (typeof res.verdict === "string") parts.push(String(res.verdict));
  if (typeof res.status === "string") parts.push(`parity ${res.status}`);
  if (typeof st.rows_backfilled === "number") parts.push(`${st.rows_backfilled} rows backfilled`);
  if (st.awaiting_contract === true) parts.push("expanded: contract is a separate approval");
  const design = st.design as Obj | undefined;
  if (design) parts.push(`${(design.ddl as unknown[]).length} DDL statement(s) · ${(design.warnings as unknown[]).length} warning(s)`);
  const val = st.validation as Obj | undefined;
  if (val) parts.push(`validated on ${String(val.database)}: ${String(val.failed)} failed of ${String(val.statements)}`);
  if (typeof st.verdict === "string") parts.push(`verdict ${st.verdict}`);
  if (typeof st.boot_seconds === "number") parts.push(`booted in ${st.boot_seconds}s`);
  if (Array.isArray(st.checks)) {
    for (const c of st.checks as { passed: boolean; detail: string }[]) parts.push(`${c.passed ? "✓" : "✗"} ${c.detail}`);
  }
  if (st.torn_down === true) parts.push("torn down");
  if (typeof st.cleanup_error === "string") parts.push(`cleanup error: ${st.cleanup_error}`);
  return parts.join(" · ");
}

const DR_INTRO = "Long-running DR jobs run by the oplia-dr-job-worker CronJob one persisted step at a time. Starting one creates a proposal: another approver approves, an operator executes, then the worker takes over.";

/** Persisted-step job modules from GET /dr/jobs: DR modules (default) or the migration engine (``migration``). */
export default function DrJobs({ migration = false }: { migration?: boolean }) {
  const { api } = useSession();
  const navigate = useNavigate();
  const st = useResource(() => api.get<DrJobsStatus>("/dr/jobs"), [api]);
  const [open, setOpen] = useState<DrJobModule | null>(null);
  const modules = (st.data?.modules ?? []).filter((m) => MIGRATION_KINDS.includes(m.kind) === migration);

  return (
    <>
      <PageHeader
        title={migration ? "Zero-downtime migration" : "DR jobs and restore drills"}
        intro={migration
          ? "Schema synthesis, online schema changes, CDC pipelines, lag and parity evidence, cutover and failback. Every step that changes something is a proposal: another approver approves, an operator executes, then the worker runs it one persisted step at a time."
          : DR_INTRO}
        actions={<button className="btn" onClick={st.reload} disabled={st.loading}>{st.loading ? "Reading…" : "Refresh"}</button>}
      />
      <ErrorNote error={st.error} />
      {st.loading && !st.data ? <Loading what={migration ? "migration jobs" : "DR jobs"} /> : null}
      {st.data && modules.length === 0 ? <Empty>No {migration ? "migration" : "DR job"} module is configured on this control plane.</Empty> : null}
      {modules.map((m) => (
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
