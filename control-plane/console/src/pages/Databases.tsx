import { useState } from "react";
import { useSearchParams } from "react-router";

import Consistency from "./Consistency";

import { Badge, Empty, ErrorNote, JsonBlock, Loading, PageHeader, TableWrap, errorMessage } from "../components/ui";
import { fmtTime } from "../format";
import { useResource, useSession } from "../session";
import type { DatabaseEntry } from "../types";

const ENGINE: Record<string, string> = { postgres: "PostgreSQL", mysql: "MySQL", mongodb: "MongoDB", cockroachdb: "CockroachDB" };

function lagOf(e: DatabaseEntry): string {
  const rep = e.last_check?.detail.replication as Record<string, unknown> | undefined;
  if (!rep) return "—";
  const direct = rep.lag_seconds ?? rep.replay_lag_seconds;
  if (typeof direct === "number") return `${direct.toFixed(1)} s`;
  const feeds = rep.changefeeds as { lag_seconds: number | null }[] | undefined;
  if (feeds?.length) {
    const worst = Math.max(...feeds.map((f) => f.lag_seconds ?? 0));
    return `${worst.toFixed(1)} s (changefeed)`;
  }
  return "—";
}

export default function Databases() {
  const { me } = useSession();
  const [params, setParams] = useSearchParams();
  const tab = params.get("tab") === "consistency" && me.features.consistency ? "consistency" : "health";
  return (
    <>
      <PageHeader
        title="Databases"
        intro="Source and DR databases from configuration: health of each, and whether every DR copy matches its source."
      />
      <div className="tabs" role="tablist" aria-label="Database views">
        <button role="tab" aria-selected={tab === "health"} className={tab === "health" ? "tab active" : "tab"} onClick={() => setParams({})}>Health</button>
        {me.features.consistency ? (
          <button role="tab" aria-selected={tab === "consistency"} className={tab === "consistency" ? "tab active" : "tab"}
            onClick={() => setParams({ tab: "consistency" })}>DR consistency</button>
        ) : null}
      </div>
      {tab === "consistency" ? <Consistency /> : <Health />}
    </>
  );
}

function Health() {
  const { api } = useSession();
  const list = useResource(() => api.get<DatabaseEntry[]>("/databases"), [api]);
  const [busy, setBusy] = useState<string | null>(null);
  const [checkError, setCheckError] = useState<unknown>(undefined);
  const [open, setOpen] = useState<string | null>(null);

  async function check(name: string) {
    setBusy(name);
    setCheckError(undefined);
    try {
      await api.post(`/databases/${encodeURIComponent(name)}/check`);
      list.reload();
    } catch (e) {
      setCheckError(e);
    } finally {
      setBusy(null);
    }
  }

  return (
    <>
      <p className="muted">Latest read-only health check (connection, version, role, read-only, replication lag). <button className="btn btn-small" onClick={list.reload}>Refresh</button></p>
      <ErrorNote error={list.error} />
      {checkError ? <div className="note note-danger" role="alert">Check failed to run: {errorMessage(checkError)}</div> : null}
      {list.loading && !list.data ? <Loading what="databases" /> : null}
      {list.data && !list.data.length ? <Empty>No databases configured (OPLIA_DATABASES).</Empty> : null}
      {list.data && list.data.length ? (
        <TableWrap label="Databases">
          <thead><tr><th>Name</th><th>Engine</th><th>Cloud</th><th>Role</th><th>Health</th><th>Server role</th><th>Read-only</th><th>Lag</th><th>Checked</th><th /></tr></thead>
          <tbody>
            {list.data.map((d) => {
              const c = d.last_check;
              return (
                <tr key={d.name}>
                  <td className="mono">{d.name}{d.dr_of ? <div className="small muted">copy of {d.dr_of}</div> : null}</td>
                  <td>{ENGINE[d.engine] ?? d.engine}</td>
                  <td>{d.cloud.toUpperCase()}</td>
                  <td>{d.role}</td>
                  <td>{!c ? <span className="muted">never checked</span> : c.ok ? <Badge value="CONNECTED" /> : <><Badge value="UNREACHABLE" /><div className="small danger wrap">{c.error}</div></>}</td>
                  <td>{c?.detail.role ?? "—"}</td>
                  <td>{c?.detail.read_only === undefined ? "—" : c.detail.read_only ? "yes" : "no"}</td>
                  <td>{c ? lagOf(d) : "—"}</td>
                  <td>{c ? <>{fmtTime(c.checked_at)}<div className="small muted">{c.latency_ms} ms · {c.triggered_by}</div></> : "—"}</td>
                  <td className="row-actions">
                    <button className="btn" disabled={busy !== null} onClick={() => void check(d.name)}>{busy === d.name ? "Checking…" : "Check now"}</button>
                    {c ? <button className="btn btn-small" onClick={() => setOpen(open === d.name ? null : d.name)} aria-expanded={open === d.name}>Details</button> : null}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </TableWrap>
      ) : null}
      {open && list.data ? (<><h2>Details: {open}</h2><JsonBlock value={list.data.find((d) => d.name === open)?.last_check?.detail} /></>) : null}
    </>
  );
}
