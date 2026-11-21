import { Link, useSearchParams } from "react-router";

import { Badge, Empty, ErrorNote, Loading, PageHeader, TableWrap } from "../components/ui";
import { fmtTime, shortId } from "../format";
import { useResource, useSession } from "../session";
import type { Candidate, Finding, Scan } from "../types";

const TABS = [
  { id: "findings", label: "Tag findings" },
  { id: "scans", label: "Scans" },
  { id: "idle", label: "Idle resources" },
] as const;

export default function FinOps() {
  const [params, setParams] = useSearchParams();
  const tab = TABS.some((t) => t.id === params.get("tab")) ? params.get("tab")! : "findings";
  return (
    <>
      <PageHeader title="FinOps" intro="Tag compliance (Owner, CostCenter, Environment) and idle resources across clouds." />
      <div className="tabs" role="tablist" aria-label="FinOps views">
        {TABS.map((t) => (
          <button key={t.id} role="tab" aria-selected={tab === t.id} className={tab === t.id ? "tab active" : "tab"}
            onClick={() => setParams({ tab: t.id })}>
            {t.label}
          </button>
        ))}
      </div>
      {tab === "findings" ? <Findings /> : tab === "scans" ? <Scans /> : <Idle />}
    </>
  );
}

function Findings() {
  const { api } = useSession();
  const [params, setParams] = useSearchParams();
  const status = params.get("status") ?? "OPEN";
  const cloud = params.get("cloud") ?? "";
  const list = useResource(
    () => api.get<Finding[]>("/finops/findings", { status_filter: status || undefined, cloud: cloud || undefined, limit: 500 }),
    [api, status, cloud],
  );
  const update = (k: string, v: string) => {
    const next = new URLSearchParams(params);
    next.set("tab", "findings");
    if (v) next.set(k, v); else next.delete(k);
    if (k === "status" && !v) next.set("status", "");
    setParams(next);
  };
  return (
    <section role="tabpanel">
      <div className="filters">
        <label htmlFor="fs">Status</label>
        <select id="fs" value={status} onChange={(e) => update("status", e.target.value)}>
          <option value="OPEN">Open</option><option value="RESOLVED">Resolved</option><option value="">All</option>
        </select>
        <label htmlFor="fc">Cloud</label>
        <select id="fc" value={cloud} onChange={(e) => update("cloud", e.target.value)}>
          <option value="">All</option><option value="aws">AWS</option><option value="azure">Azure</option>
          <option value="gcp">GCP</option><option value="ibm">IBM Cloud</option>
        </select>
      </div>
      <ErrorNote error={list.error} />
      {list.loading && !list.data ? <Loading what="findings" /> : null}
      {list.data && !list.data.length ? <Empty>No findings for this filter.</Empty> : null}
      {list.data && list.data.length ? (
        <TableWrap label="Tag findings">
          <thead><tr><th>Cloud</th><th>Resource</th><th>Type</th><th>Missing</th><th>Wrong case / invalid</th><th>Owner hint</th><th>Status</th><th>Last seen</th></tr></thead>
          <tbody>
            {list.data.map((f) => (
              <tr key={f.id}>
                <td>{f.cloud}</td>
                <td className="mono wrap" title={f.resource_id}>{f.name || f.resource_id}</td>
                <td className="mono">{f.resource_type}</td>
                <td>{f.missing.join(", ") || "—"}</td>
                <td className="mono small wrap">{[f.wrong_case, f.invalid].map((x) => (x && JSON.stringify(x) !== "{}" && JSON.stringify(x) !== "[]" ? JSON.stringify(x) : "")).filter(Boolean).join(" ") || "—"}</td>
                <td>{f.owner_hint ?? "—"}</td>
                <td><Badge value={f.status} /></td>
                <td>{fmtTime(f.last_seen_at)}</td>
              </tr>
            ))}
          </tbody>
        </TableWrap>
      ) : null}
    </section>
  );
}

function Scans() {
  const { api } = useSession();
  const list = useResource(() => api.get<Scan[]>("/finops/scans", { limit: 50 }), [api]);
  return (
    <section role="tabpanel">
      <ErrorNote error={list.error} />
      {list.loading && !list.data ? <Loading what="scans" /> : null}
      {list.data && !list.data.length ? <Empty>No scans recorded yet.</Empty> : null}
      {list.data && list.data.length ? (
        <TableWrap label="Scans">
          <thead><tr><th>Started</th><th>Finished</th><th>Scanned</th><th>Non-compliant</th><th>New</th><th>Resolved</th><th>Source errors</th></tr></thead>
          <tbody>
            {list.data.map((s) => (
              <tr key={s.id}>
                <td>{fmtTime(s.started_at)}</td><td>{fmtTime(s.finished_at)}</td><td>{s.resources_scanned}</td>
                <td>{s.noncompliant}</td><td>{s.new_findings}</td><td>{s.resolved_findings}</td>
                <td className="mono small wrap">{JSON.stringify(s.source_errors) === "{}" || JSON.stringify(s.source_errors) === "[]" ? "none" : JSON.stringify(s.source_errors)}</td>
              </tr>
            ))}
          </tbody>
        </TableWrap>
      ) : null}
    </section>
  );
}

function Idle() {
  const { api } = useSession();
  const list = useResource(() => api.get<Candidate[]>("/finops/candidates", { limit: 500 }), [api]);
  return (
    <section role="tabpanel">
      <p className="muted">After the grace period a clean-up proposal is raised; approved clean-ups run only inside maintenance windows, with a snapshot first.</p>
      <ErrorNote error={list.error} />
      {list.loading && !list.data ? <Loading what="idle resources" /> : null}
      {list.data && !list.data.length ? <Empty>No idle resources tracked.</Empty> : null}
      {list.data && list.data.length ? (
        <TableWrap label="Idle resources">
          <thead><tr><th>Cloud</th><th>Kind</th><th>Resource</th><th>Size</th><th>Idle since</th><th>Last seen idle</th><th>Proposal</th></tr></thead>
          <tbody>
            {list.data.map((c) => (
              <tr key={c.id}>
                <td>{c.cloud}</td><td>{c.kind}</td><td className="mono wrap">{c.resource_id}</td><td>{c.size ?? "—"}</td>
                <td>{fmtTime(c.first_seen_idle_at)}</td><td>{fmtTime(c.last_seen_idle_at)}</td>
                <td>{c.proposal_id ? <Link className="mono" to={`/proposals/${c.proposal_id}`}>{shortId(c.proposal_id)}</Link> : "—"}</td>
              </tr>
            ))}
          </tbody>
        </TableWrap>
      ) : null}
    </section>
  );
}
