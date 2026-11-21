import { useState } from "react";
import { Link, useParams } from "react-router";

import { ActionDialog, Badge, ErrorNote, JsonBlock, Loading, PageHeader, TableWrap } from "../components/ui";
import { fmtTime } from "../format";
import { useResource, useSession } from "../session";
import type { AuditEvent, KillSwitch, Proposal } from "../types";

type Act = "approve" | "reject" | "execute" | null;

export default function ProposalDetail() {
  const { id = "" } = useParams();
  const { api, me } = useSession();
  const p = useResource(() => api.get<Proposal>(`/proposals/${encodeURIComponent(id)}`), [api, id]);
  const kill = useResource(() => api.get<KillSwitch>("/kill-switch"), [api]);
  const trail = useResource(
    () => (me.can.approve ? api.get<AuditEvent[]>("/audit/events", { proposal_id: id, limit: 100 }) : Promise.resolve([])),
    [api, id, me.can.approve],
  );
  const [act, setAct] = useState<Act>(null);

  if (p.loading && !p.data) return <Loading what="proposal" />;
  if (!p.data) return <><PageHeader title="Proposal" /><ErrorNote error={p.error} /><Link to="/proposals">Back to proposals</Link></>;
  const pr = p.data;
  const ownRequest = pr.requested_by === me.subject;
  const canDecide = me.can.approve && pr.status === "PENDING";
  const canExecute = me.can.operate && pr.status === "APPROVED";
  const reload = () => { p.reload(); trail.reload(); kill.reload(); };

  return (
    <>
      <PageHeader
        title={pr.action_type}
        intro={<span className="mono wrap">{pr.target}</span>}
        actions={
          <>
            {canDecide ? (
              <>
                <button className="btn btn-primary" disabled={ownRequest} onClick={() => setAct("approve")}>Approve</button>
                <button className="btn" disabled={ownRequest} onClick={() => setAct("reject")}>Reject</button>
              </>
            ) : null}
            {canExecute ? (
              <button className="btn btn-primary" disabled={kill.data?.engaged === true} onClick={() => setAct("execute")}>Execute</button>
            ) : null}
          </>
        }
      />
      <ErrorNote error={p.error} />
      {canDecide && ownRequest ? (
        <div className="note">Four-eyes rule: you requested this change, so another approver must decide it.</div>
      ) : null}
      {canExecute && kill.data?.engaged ? (
        <div className="note note-danger">The kill switch is engaged; execution is blocked until it is released.</div>
      ) : null}

      <dl className="details">
        <div><dt>Status</dt><dd><Badge value={pr.status} /></dd></div>
        <div><dt>ID</dt><dd className="mono">{pr.id}</dd></div>
        <div><dt>Requested by</dt><dd>{pr.requested_by}</dd></div>
        <div><dt>Created</dt><dd>{fmtTime(pr.created_at)}</dd></div>
        <div><dt>Expires</dt><dd>{fmtTime(pr.expires_at)}</dd></div>
        <div><dt>Decided by</dt><dd>{pr.decided_by ? `${pr.decided_by} on ${fmtTime(pr.decided_at)}` : "—"}</dd></div>
        <div><dt>Decision note</dt><dd>{pr.decision_note || "—"}</dd></div>
        <div><dt>Executed</dt><dd>{fmtTime(pr.executed_at)}</dd></div>
      </dl>
      <h2>Reason</h2>
      <p>{pr.reason}</p>
      <h2>Payload</h2>
      <JsonBlock value={pr.payload} />
      {pr.result !== null && pr.result !== undefined ? (
        <>
          <h2>Result</h2>
          <JsonBlock value={pr.result} />
        </>
      ) : null}

      {me.can.approve ? (
        <>
          <h2>Audit trail</h2>
          <ErrorNote error={trail.error} />
          {trail.data && trail.data.length ? (
            <TableWrap label="Audit trail">
              <thead><tr><th>#</th><th>Time</th><th>Actor</th><th>Event</th></tr></thead>
              <tbody>
                {trail.data.map((e) => (
                  <tr key={e.seq}><td>{e.seq}</td><td>{fmtTime(e.ts)}</td><td>{e.actor}</td><td className="mono">{e.event}</td></tr>
                ))}
              </tbody>
            </TableWrap>
          ) : null}
        </>
      ) : null}
      <p><Link to="/proposals">Back to proposals</Link></p>

      {act === "approve" || act === "reject" ? (
        <ActionDialog
          title={act === "approve" ? "Approve this proposal" : "Reject this proposal"}
          description={act === "approve" ? "An operator can then execute it (subject to dry-run and the kill switch)." : "The proposal is closed and cannot be executed."}
          fields={[{ name: "note", label: "Note (recorded in the audit log)", kind: "textarea", maxLength: 2000 }]}
          confirmLabel={act === "approve" ? "Approve" : "Reject"}
          danger={act === "reject"}
          onClose={() => setAct(null)}
          onSubmit={async (v) => {
            await api.post(`/proposals/${encodeURIComponent(pr.id)}/${act}`, { note: String(v.note ?? "") });
            reload();
          }}
        />
      ) : null}
      {act === "execute" ? (
        <ActionDialog
          title="Execute this proposal"
          description={<>Runs <span className="mono">{pr.action_type}</span> against <span className="mono">{pr.target}</span>. In dry-run mode the action is recorded but not performed.</>}
          confirmLabel="Execute"
          danger
          onClose={() => setAct(null)}
          onSubmit={async () => {
            await api.post(`/proposals/${encodeURIComponent(pr.id)}/execute`);
            reload();
          }}
        />
      ) : null}
    </>
  );
}
