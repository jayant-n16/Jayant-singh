import { useState } from "react";
import { useNavigate } from "react-router";

import { ActionDialog, Badge, Empty, ErrorNote, Loading, PageHeader, TableWrap } from "../components/ui";
import { fmtTime } from "../format";
import { useResource, useSession } from "../session";
import type { DrJob, DrJobModule, DrJobsStatus, Proposal } from "../types";

export const MIGRATION_KINDS = ["schema_synthesis", "schema_change", "schema_contract", "cdc_pipeline",
  "cdc_lag_probe", "parity_check", "cutover", "failback"];

type Obj = Record<string, unknown>;

/** Restore drills report {check: {...}, passed, detail}; online schema changes report {check: "what", offending_rows, passed}. */
export interface CheckRow { check?: unknown; passed?: boolean; detail?: string; offending_rows?: number }

export function checkText(c: CheckRow): string {
  const rows = typeof c.offending_rows === "number" ? c.offending_rows : undefined;
  const passed = typeof c.passed === "boolean" ? c.passed : rows === 0;
  const label = typeof c.check === "string" ? c.check : (c.detail ?? "check");
  const extra = rows !== undefined && rows > 0 ? ` (${rows} offending row${rows === 1 ? "" : "s"})` : "";
  return `${passed ? "✓" : "✗"} ${label}${extra}`;
}

function detail(j: DrJob): string {
  const st = j.state;
  const parts: string[] = [];
  const res = (st.result ?? {}) as Obj;
  if (typeof res.p99_ms === "number") parts.push(`lag p50 ${String(res.p50_ms)} ms · p99 ${res.p99_ms} ms (${String(res.samples)} samples)`);
  if (typeof res.applied_ms === "number") parts.push(`switch applied in ${res.applied_ms} ms`);
  if (typeof res.verdict === "string") parts.push(String(res.verdict));
  if (res.status === "MATCH" || res.status === "DIFF") {
    const tables = (res.tables ?? {}) as Record<string, Obj>;
    const differing = Object.entries(tables).filter(([, t]) => t.status === "DIFF").map(([n]) => n);
    const schema = Array.isArray(res.schema) ? (res.schema as Obj[]) : [];
    const bits = [`parity verdict ${res.status}`];
    if (differing.length) bits.push(`tables differing: ${differing.join(", ")}`);
    for (const i of schema) bits.push(`schema: ${String(i.table)} ${String(i.issue)}${Array.isArray(i.columns) ? ` (${i.columns.join(", ")})` : ""}`);
    parts.push(bits.join(" · "));
  }
  if (typeof st.rows_backfilled === "number") parts.push(`${st.rows_backfilled} rows backfilled`);
  if (st.awaiting_contract === true) parts.push("expanded: contract is a separate approval");
  const design = st.design as Obj | undefined;
  if (design) parts.push(`${(design.ddl as unknown[]).length} DDL statement(s) · ${(design.warnings as unknown[]).length} warning(s)`);
  const val = st.validation as Obj | undefined;
  if (val) parts.push(`validated on ${String(val.database)}: ${String(val.failed)} failed of ${String(val.statements)}`);
  if (typeof st.verdict === "string") parts.push(`verdict ${st.verdict}`);
  if (typeof st.boot_seconds === "number") parts.push(`booted in ${st.boot_seconds}s`);
  if (Array.isArray(st.checks)) for (const c of st.checks as CheckRow[]) parts.push(checkText(c));
  if (st.torn_down === true) parts.push("torn down");
  if (typeof st.cleanup_error === "string") parts.push(`cleanup error: ${st.cleanup_error}`);
  return parts.join(" · ");
}

/** The comparison verdict of a parity job (MATCH or DIFF), shown next to the job status. */
export function verdictOf(j: DrJob): string | null {
  const r = (j.state.result ?? {}) as Obj;
  return j.kind === "parity_check" && (r.status === "MATCH" || r.status === "DIFF") ? r.status : null;
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
                  <td>
                    <Badge value={j.status} />
                    {verdictOf(j) ? <> <Badge value={verdictOf(j)!} /></> : null}
                  </td>
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
