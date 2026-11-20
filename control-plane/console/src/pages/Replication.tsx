import { useState } from "react";
import { useNavigate } from "react-router";

import { ActionDialog, Badge, Empty, ErrorNote, Loading, PageHeader, TableWrap } from "../components/ui";
import { fmtTime } from "../format";
import { useResource, useSession } from "../session";
import type { Connector, ObjectPairStatus, Proposal, ReplicationStatus, TagMap } from "../types";

type Dialog =
  | { kind: "pipeline"; c: Connector; action: "pause" | "resume" | "restart" }
  | { kind: "objects"; p: ObjectPairStatus }
  | { kind: "deletions"; p: ObjectPairStatus }
  | { kind: "image" };

export default function Replication() {
  const { api } = useSession();
  const navigate = useNavigate();
  const st = useResource(() => api.get<ReplicationStatus>("/dr/replication"), [api]);
  const [dlg, setDlg] = useState<Dialog | null>(null);
  const [preview, setPreview] = useState<TagMap | null>(null);
  const [tagText, setTagText] = useState("Owner Team=SRE\nCostCenter=Finance");
  const [tagTarget, setTagTarget] = useState("gcp");
  const [tagError, setTagError] = useState<unknown>(undefined);
  const d = st.data;
  const go = (p: Proposal) => navigate(`/proposals/${p.id}`);

  return (
    <>
      <PageHeader
        title="DR replication"
        intro="Database CDC pipelines, object storage and VM images replicated across AWS, Azure and GCP. Every change is a proposal; data is re-encrypted with the target cloud's key and key material never moves."
        actions={<button className="btn" onClick={st.reload} disabled={st.loading}>{st.loading ? "Reading…" : "Refresh"}</button>}
      />
      <ErrorNote error={st.error} />
      {st.loading && !d ? <Loading what="replication status" /> : null}
      {d ? (
        <>
          <section>
            <h2>Database CDC pipelines (Kafka Connect)</h2>
            {!d.pipelines.configured ? <p className="muted">Kafka Connect is not configured.</p>
              : !d.pipelines.ok ? <div className="note note-danger" role="alert">Kafka Connect could not be read: {d.pipelines.error}</div>
              : d.pipelines.items.length === 0 ? <Empty>No connectors.</Empty> : (
                <TableWrap label="CDC connectors">
                  <thead><tr><th>Connector</th><th>State</th><th>Tasks</th><th /></tr></thead>
                  <tbody>{d.pipelines.items.map((c) => (
                    <tr key={c.name}>
                      <td><div className="mono">{c.name}</div><div className="small muted">{c.class.split(".").pop()} · {c.worker}</div></td>
                      <td><Badge value={c.state} /></td>
                      <td className="small">{c.tasks.map((t) => <div key={t.id}>#{t.id} {t.state}{t.trace ? <span className="danger"> — {(t.trace.split("\n")[0] ?? "").slice(0, 120)}</span> : null}</div>)}</td>
                      <td>
                        {c.state === "RUNNING" ? <button className="btn" onClick={() => setDlg({ kind: "pipeline", c, action: "pause" })}>Pause…</button> : null}
                        {c.state === "PAUSED" ? <button className="btn" onClick={() => setDlg({ kind: "pipeline", c, action: "resume" })}>Resume…</button> : null}
                        {c.failed_tasks > 0 || c.state === "FAILED" ? <button className="btn" onClick={() => setDlg({ kind: "pipeline", c, action: "restart" })}>Restart failed…</button> : null}
                      </td>
                    </tr>
                  ))}</tbody>
                </TableWrap>
              )}
          </section>

          <section>
            <h2>Object storage</h2>
            {d.object_pairs.length === 0 ? <p className="muted">No object replication pairs configured.</p> : (
              <TableWrap label="Object replication pairs">
                <thead><tr><th>Pair</th><th>Source → target</th><th>Target key</th><th>Replicated</th><th>Last run</th><th /></tr></thead>
                <tbody>{d.object_pairs.map((p) => (
                  <tr key={p.pair}>
                    <td className="mono">{p.pair}</td>
                    <td className="small mono">{p.source} → {p.target}</td>
                    <td className="small mono">{p.target_key ?? "target default"}</td>
                    <td>{p.replicated_objects}</td>
                    <td className="small">{p.last_run ? <><Badge value={p.last_run.status} /> {fmtTime(p.last_run.started_at)} · {p.last_run.summary.kind === "delete" ? `${p.last_run.summary.deleted?.length ?? 0} deleted` : `${p.last_run.copied} copied`}, {p.last_run.summary.failed.length} failed, {p.last_run.summary.skipped.length} skipped</> : "never"}</td>
                    <td className="row-actions">
                      <button className="btn" onClick={() => setDlg({ kind: "objects", p })}>Plan sync…</button>
                      {p.replicate_deletions ? <button className="btn" onClick={() => setDlg({ kind: "deletions", p })}>Propose deletions…</button> : null}
                    </td>
                  </tr>
                ))}</tbody>
              </TableWrap>
            )}
          </section>

          <section>
            <h2>VM images</h2>
            <p className="small muted">Paths: AWS AMI → Azure / GCP, Azure snapshot or disk → AWS / GCP. GCP as a source is not supported (no image export API). SHA-256 of the raw disk is verified on the staged copy before the image is created.</p>
            {Object.values(d.image_targets).some(Boolean) ? <button className="btn" onClick={() => setDlg({ kind: "image" })}>Replicate an image…</button> : <p className="muted">No image targets configured.</p>}
            {d.image_jobs.length ? (
              <TableWrap label="Image jobs">
                <thead><tr><th>Name</th><th>Path</th><th>Status</th><th>Step</th><th>Updated</th><th>Detail</th></tr></thead>
                <tbody>{d.image_jobs.map((j) => (
                  <tr key={j.id}>
                    <td className="mono">{j.name}</td>
                    <td className="small">{j.source_cloud} → {j.target_cloud}<div className="mono muted">{j.source_id.split("/").pop()}</div></td>
                    <td><Badge value={j.status} /></td><td className="mono small">{j.step}</td>
                    <td className="small">{fmtTime(j.updated_at)}</td>
                    <td className="small wrap">{j.error ? <span className="danger">{j.error}</span> : j.state.sha256 ? <span className="mono">sha256 {String(j.state.sha256).slice(0, 16)}…</span> : null}</td>
                  </tr>
                ))}</tbody>
              </TableWrap>
            ) : null}
          </section>

          <section>
            <h2>Tag mapping preview</h2>
            <form className="row" onSubmit={async (e) => {
              e.preventDefault();
              setTagError(undefined);
              const tags = Object.fromEntries(tagText.split("\n").filter((l) => l.includes("=")).map((l) => [l.slice(0, l.indexOf("=")).trim(), l.slice(l.indexOf("=") + 1).trim()]));
              try { setPreview(await api.post<TagMap>("/dr/replication/tags/preview", { tags, target: tagTarget })); } catch (err) { setTagError(err); }
            }}>
              <label>Tags (key=value per line)<textarea value={tagText} onChange={(e) => setTagText(e.target.value)} rows={4} /></label>
              <label>Target<select value={tagTarget} onChange={(e) => setTagTarget(e.target.value)}><option value="aws">AWS</option><option value="azure">Azure</option><option value="gcp">GCP labels</option></select></label>
              <button className="btn" type="submit">Preview</button>
            </form>
            <ErrorNote error={tagError} />
            {preview ? (
              <div aria-label="Mapped tags">
                <ul className="mono small">{Object.entries(preview.tags).map(([k, v]) => <li key={k}>{k} = {v}</li>)}</ul>
                {preview.changes.map((c) => <div key={c} className="small">changed: {c}</div>)}
                {preview.dropped.map((c) => <div key={c} className="small danger">dropped: {c}</div>)}
              </div>
            ) : null}
          </section>
        </>
      ) : null}

      {dlg?.kind === "pipeline" ? (
        <ActionDialog title={`Propose: ${dlg.action} connector ${dlg.c.name}`} confirmLabel="Create proposal"
          description="Another approver approves, then an operator executes; the connector state afterwards is recorded."
          fields={[{ name: "reason", label: "Reason (recorded)", kind: "textarea", required: true, minLength: 5, maxLength: 2000 }]}
          onClose={() => setDlg(null)}
          onSubmit={async (v) => go(await api.post<Proposal>(`/dr/replication/pipelines/${encodeURIComponent(dlg.c.name)}/${dlg.action}`, { reason: String(v.reason) }))} />
      ) : null}
      {dlg?.kind === "objects" ? (
        <ActionDialog title={`Plan an object sync for ${dlg.p.pair}`} confirmLabel="Create proposal"
          description="Lists the source now and proposes copying new or changed objects. Deletions at the source are reported here; removing them from the DR copy is a separate proposal, only for pairs that opt in."
          fields={[{ name: "reason", label: "Reason (recorded)", kind: "textarea", required: true, minLength: 5, maxLength: 2000 }]}
          onClose={() => setDlg(null)}
          onSubmit={async (v) => go(await api.post<Proposal>(`/dr/replication/objects/${encodeURIComponent(dlg.p.pair)}/plan`, { reason: String(v.reason) }))} />
      ) : null}
      {dlg?.kind === "deletions" ? (
        <ActionDialog title={`Propose deletions for ${dlg.p.pair}`} confirmLabel="Create proposal" danger
          description="Lists replicated objects that no longer exist at the source and proposes removing them from the DR copy. Refused if the batch is larger than the pair's limit. Each key is checked at the source again when executed."
          fields={[{ name: "reason", label: "Reason (recorded)", kind: "textarea", required: true, minLength: 5, maxLength: 2000 }]}
          onClose={() => setDlg(null)}
          onSubmit={async (v) => go(await api.post<Proposal>(`/dr/replication/objects/${encodeURIComponent(dlg.p.pair)}/deletions`, { reason: String(v.reason) }))} />
      ) : null}
      {dlg?.kind === "image" && d ? (
        <ActionDialog title="Propose an image replication" confirmLabel="Create proposal"
          fields={[
            { name: "source_cloud", label: "Source cloud", kind: "select", required: true, initial: "aws", options: [{ value: "aws", label: "AWS (AMI id)" }, { value: "azure", label: "Azure (snapshot/disk resource id)" }] },
            { name: "source_id", label: "Source image", kind: "text", required: true, minLength: 3, maxLength: 512 },
            { name: "target_cloud", label: "Target cloud", kind: "select", required: true, initial: "gcp", options: (["aws", "azure", "gcp"] as const).filter((c) => d.image_targets[c]).map((c) => ({ value: c, label: c.toUpperCase() })) },
            { name: "name", label: "Target image name (lowercase, hyphens)", kind: "text", required: true, minLength: 2, maxLength: 63 },
            { name: "reason", label: "Reason (recorded)", kind: "textarea", required: true, minLength: 5, maxLength: 2000 },
          ]}
          onClose={() => setDlg(null)}
          onSubmit={async (v) => go(await api.post<Proposal>("/dr/replication/images", {
            source_cloud: String(v.source_cloud), source_id: String(v.source_id), target_cloud: String(v.target_cloud),
            name: String(v.name), reason: String(v.reason) }))} />
      ) : null}
    </>
  );
}
