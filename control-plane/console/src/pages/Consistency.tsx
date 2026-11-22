import { useState } from "react";
import { Link } from "react-router";

import { Badge, Empty, ErrorNote, Loading, TableWrap, errorMessage } from "../components/ui";
import { fmtTime, shortId } from "../format";
import { useResource, useSession } from "../session";
import type { ConsistencyRun, DatabaseEntry } from "../types";

export default function Consistency() {
  const { api } = useSession();
  const dbs = useResource(() => api.get<DatabaseEntry[]>("/databases"), [api]);
  const runs = useResource(() => api.get<ConsistencyRun[]>("/databases/consistency", { limit: 100 }), [api]);
  const [busy, setBusy] = useState<string | null>(null);
  const [runError, setRunError] = useState<unknown>(undefined);
  const [open, setOpen] = useState<string | null>(null);

  const pairs = (dbs.data ?? []).filter((d) => d.dr_of);
  const latest = (pair: string) => (runs.data ?? []).find((r) => r.pair === pair);

  async function run(pair: string) {
    setBusy(pair);
    setRunError(undefined);
    try {
      await api.post(`/databases/${encodeURIComponent(pair)}/consistency`);
      runs.reload();
    } catch (e) {
      setRunError(e);
    } finally {
      setBusy(null);
    }
  }

  return (
    <section role="tabpanel" aria-label="DR consistency">
      <p className="muted">
        Compares each DR copy with its source: schema, row counts, chunked checksums (same engine, primary key) and replication lag.
        Differences are re-checked once before they count. Drift raises a resync proposal (PostgreSQL, MySQL, CockroachDB, MongoDB;
        a repeat of the same drift reuses the open one); nothing changes without approval. SQL Server and Oracle pairs are
        checked only: repair them through their own replication.
      </p>
      <ErrorNote error={dbs.error ?? runs.error} />
      {runError ? <div className="note note-danger" role="alert">Check could not run: {errorMessage(runError)}</div> : null}
      {(dbs.loading && !dbs.data) || (runs.loading && !runs.data) ? <Loading what="consistency runs" /> : null}
      {dbs.data && !pairs.length ? <Empty>No DR copies configured (OPLIA_DATABASES entries with dr_of).</Empty> : null}
      {pairs.length ? (
        <TableWrap label="DR pairs">
          <thead><tr><th>DR copy</th><th>Source</th><th>Last result</th><th>Summary</th><th>Lag</th><th>Checked</th><th>Proposal</th><th /></tr></thead>
          <tbody>
            {pairs.map((d) => {
              const r = latest(d.name);
              return (
                <tr key={d.name}>
                  <td className="mono">{d.name}</td>
                  <td className="mono">{d.dr_of}</td>
                  <td>{r ? <Badge value={r.status} /> : <span className="muted">never run</span>}</td>
                  <td className="wrap">{r?.summary ?? "—"}</td>
                  <td>{typeof r?.report.lag_seconds === "number" ? `${r.report.lag_seconds.toFixed(1)} s` : "—"}</td>
                  <td>{r ? <>{fmtTime(r.finished_at)}<div className="small muted">{r.triggered_by}</div></> : "—"}</td>
                  <td>{r?.proposal_id ? <Link className="mono" to={`/proposals/${r.proposal_id}`}>{shortId(r.proposal_id)}</Link>
                    : r?.status === "DRIFT" && r.report.resync_supported === false ? <span className="small muted">no automatic resync</span> : "—"}</td>
                  <td className="row-actions">
                    <button className="btn" disabled={busy !== null} onClick={() => void run(d.name)}>{busy === d.name ? "Checking…" : "Run check"}</button>
                    {r ? <button className="btn btn-small" aria-expanded={open === r.id} onClick={() => setOpen(open === r.id ? null : r.id)}>Report</button> : null}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </TableWrap>
      ) : null}
      {open ? <Report run={(runs.data ?? []).find((r) => r.id === open)} /> : null}
    </section>
  );
}

function Report({ run }: { run: ConsistencyRun | undefined }) {
  if (!run) return null;
  const tables = Object.entries(run.report.tables ?? {});
  return (
    <div className="panel">
      <h2>Report: {run.report.source} → {run.report.target}</h2>
      {run.report.error ? <div className="note note-danger">{run.report.error}</div> : null}
      {run.report.dr_breaker ? <p>DR breaker for stream <span className="mono">{run.report.dr_breaker.stream}</span>: <Badge value={run.report.dr_breaker.state} /></p> : null}
      {run.report.schema?.length ? (
        <>
          <h3>Schema differences</h3>
          <ul>{run.report.schema.map((s) => <li key={s.table}><span className="mono">{s.table}</span>: {s.issue}</li>)}</ul>
        </>
      ) : null}
      {tables.length ? (
        <TableWrap label="Tables">
          <thead><tr><th>Table</th><th>Source rows</th><th>DR rows</th><th>Checksum</th><th>Compared on</th><th>Result</th></tr></thead>
          <tbody>
            {tables.map(([name, t]) => (
              <tr key={name}>
                <td className="mono">{name}</td><td>{t.source_rows}</td><td>{t.target_rows}</td>
                <td className="small">{t.checksum ?? "—"}{t.rechecked ? " (re-checked)" : ""}</td>
                <td className="small">{t.compared_columns ? `common columns: ${t.compared_columns.join(", ")}` : "all columns"}</td>
                <td>{t.match ? <Badge value="CONSISTENT" /> : <Badge value="DRIFT" />}</td>
              </tr>
            ))}
          </tbody>
        </TableWrap>
      ) : null}
    </div>
  );
}
