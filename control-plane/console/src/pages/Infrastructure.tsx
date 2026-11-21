import { useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router";

import { ActionDialog, Badge, Empty, ErrorNote, Loading, PageHeader, TableWrap } from "../components/ui";
import { fmtTime } from "../format";
import { useResource, useSession } from "../session";
import type { Instance, InventoryScan, Proposal } from "../types";

const CLOUDS = [
  { value: "", label: "All" }, { value: "aws", label: "AWS" }, { value: "azure", label: "Azure" },
  { value: "gcp", label: "GCP" }, { value: "ibm", label: "IBM Cloud" },
];

export default function Infrastructure() {
  const { api } = useSession();
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const cloud = params.get("cloud") ?? "";
  const region = params.get("region") ?? "";
  const state = params.get("state") ?? "";
  const list = useResource(
    () => api.get<Instance[]>("/inventory/instances", { cloud: cloud || undefined, region: region || undefined, state: state || undefined, limit: 2000 }),
    [api, cloud, region, state],
  );
  const scans = useResource(() => api.get<InventoryScan[]>("/inventory/scans", { limit: 1 }), [api]);
  const [power, setPower] = useState<Instance | null>(null);

  const set = (k: string, v: string) => {
    const next = new URLSearchParams(params);
    if (v) next.set(k, v); else next.delete(k);
    setParams(next);
  };
  const last = scans.data?.[0];
  const regions = Array.from(new Set((list.data ?? []).map((i) => i.region).filter(Boolean))).sort();

  return (
    <>
      <PageHeader
        title="Infrastructure"
        intro="Compute instances across AWS, Azure, GCP and IBM Cloud from the last inventory scan. Start/stop is a proposal: it runs only after approval."
        actions={<button className="btn" onClick={() => { list.reload(); scans.reload(); }}>Refresh</button>}
      />
      {last ? (
        <p className="muted small">
          Last scan {fmtTime(last.finished_at ?? last.started_at)}: {last.instances_seen} instances, {last.new_instances} new, {last.gone_instances} gone.
          {last.source_errors.length ? <span className="danger"> Failed sources: {last.source_errors.map((e) => e.source).join(", ")} — their machines keep their last known state.</span> : null}
        </p>
      ) : scans.data ? <div className="note">No inventory scan has run yet (CronJob oplia-inventory-scan).</div> : null}
      <div className="filters">
        <label htmlFor="ic">Cloud</label>
        <select id="ic" value={cloud} onChange={(e) => set("cloud", e.target.value)}>
          {CLOUDS.map((c) => <option key={c.value} value={c.value}>{c.label}</option>)}
        </select>
        <label htmlFor="ir">Region</label>
        <select id="ir" value={region} onChange={(e) => set("region", e.target.value)}>
          <option value="">All</option>
          {regions.map((r) => <option key={r} value={r}>{r}</option>)}
        </select>
        <label htmlFor="is">State</label>
        <input id="is" placeholder="e.g. running" value={state} maxLength={64} onChange={(e) => set("state", e.target.value.trim())} />
      </div>
      <ErrorNote error={list.error ?? scans.error} />
      {list.loading && !list.data ? <Loading what="instances" /> : null}
      {list.data && !list.data.length ? <Empty>No instances for this filter.</Empty> : null}
      {list.data && list.data.length ? (
        <TableWrap label="Instances">
          <thead><tr><th>Name</th><th>Cloud</th><th>Region</th><th>Size</th><th>State</th><th>Tags</th><th>Last seen</th><th /></tr></thead>
          <tbody>
            {list.data.map((i) => (
              <tr key={i.id}>
                <td className="wrap" title={i.resource_id}>{i.name}<div className="small muted mono">{i.resource_type}</div></td>
                <td>{i.cloud.toUpperCase()}</td>
                <td>{i.region || "—"}</td>
                <td className="mono">{i.size ?? "—"}</td>
                <td>{i.state ? <Badge value={i.state.toUpperCase()} /> : <span className="muted">not reported</span>}</td>
                <td>{i.tag_compliant ? <span className="ok small">complete</span> : <span className="small danger">missing: {i.tag_issues.join(", ")}</span>}
                  {!i.tag_compliant ? <div><Link className="small" to={`/finops?tab=findings&cloud=${i.cloud}`}>FinOps</Link></div> : null}</td>
                <td>{fmtTime(i.last_seen_at)}</td>
                <td><button className="btn" onClick={() => setPower(i)}>Propose start/stop…</button></td>
              </tr>
            ))}
          </tbody>
        </TableWrap>
      ) : null}
      {power ? (
        <ActionDialog
          title={`Propose a power change for ${power.name}`}
          description={<>Creates a proposal for <span className="mono">{power.resource_id}</span>. Another approver must approve it, then an operator executes it (dry-run applies). {power.cloud === "azure" ? "On Azure, stop deallocates the VM (billing stops)." : null}</>}
          fields={[
            { name: "operation", label: "Operation", kind: "radio", required: true, options: [
              { value: "start", label: "Start" }, { value: "stop", label: "Stop" }] },
            { name: "reason", label: "Reason (recorded)", kind: "textarea", required: true, minLength: 5, maxLength: 2000 },
          ]}
          confirmLabel="Create proposal"
          onClose={() => setPower(null)}
          onSubmit={async (v) => {
            const p = await api.post<Proposal>(`/inventory/instances/${encodeURIComponent(power.id)}/power`,
              { operation: String(v.operation), reason: String(v.reason) });
            navigate(`/proposals/${p.id}`);
          }}
        />
      ) : null}
    </>
  );
}
