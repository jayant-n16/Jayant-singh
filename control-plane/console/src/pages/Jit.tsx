import { useState, type FormEvent } from "react";
import { useSearchParams } from "react-router";

import { ActionDialog, Badge, Empty, ErrorNote, Loading, PageHeader, TableWrap } from "../components/ui";
import { fmtTime } from "../format";
import { useResource, useSession } from "../session";
import type { JitRequest, JitRole } from "../types";

type Act = { kind: "approve" | "reject" | "grant" | "revoke"; req: JitRequest } | null;

export default function Jit() {
  const { api, me } = useSession();
  const [params, setParams] = useSearchParams();
  const approval = params.get("approval") ?? "";
  const roles = useResource(() => api.get<JitRole[]>("/jit/roles"), [api]);
  const requests = useResource(
    () => api.get<JitRequest[]>("/jit/requests", { approval_status: approval || undefined, limit: 200 }),
    [api, approval],
  );
  const [act, setAct] = useState<Act>(null);
  const [showForm, setShowForm] = useState(false);

  return (
    <>
      <PageHeader
        title="Just-in-time access"
        intro="Time-bound privileged access: requested, approved by someone else, granted, and removed automatically when it expires."
        actions={
          <>
            <button className="btn btn-primary" onClick={() => setShowForm((s) => !s)} aria-expanded={showForm}>
              {showForm ? "Close request form" : "Request access"}
            </button>
            <button className="btn" onClick={requests.reload}>Refresh</button>
          </>
        }
      />
      {showForm && roles.data ? (
        <RequestForm roles={roles.data} defaultUser={me.subject} onDone={() => { setShowForm(false); requests.reload(); }} />
      ) : null}
      <ErrorNote error={roles.error} />

      <h2>Requests</h2>
      <div className="filters">
        <label htmlFor="ja">Approval</label>
        <select id="ja" value={approval} onChange={(e) => setParams(e.target.value ? { approval: e.target.value } : {})}>
          <option value="">All</option>
          {["PENDING", "APPROVED", "REJECTED", "EXPIRED"].map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
      </div>
      <ErrorNote error={requests.error} />
      {requests.loading && !requests.data ? <Loading what="requests" /> : null}
      {requests.data && !requests.data.length ? <Empty>No requests.</Empty> : null}
      {requests.data && requests.data.length ? (
        <TableWrap label="JIT requests">
          <thead>
            <tr><th>User</th><th>Role</th><th>Account</th><th>Minutes</th><th>Approval</th><th>Access</th><th>Requested by</th><th>Expires</th><th>Justification</th><th /></tr>
          </thead>
          <tbody>
            {requests.data.map((r) => {
              const own = r.requested_by === me.subject;
              return (
                <tr key={r.id}>
                  <td>{r.user_id}</td>
                  <td className="mono">{r.requested_role}</td>
                  <td className="mono">{r.target_cloud_account}</td>
                  <td>{r.expiration_minutes}</td>
                  <td><Badge value={r.approval_status} /></td>
                  <td><Badge value={r.access_status} />{r.last_error ? <div className="small danger">{r.last_error}</div> : null}</td>
                  <td>{r.requested_by}</td>
                  <td>{fmtTime(r.expires_at)}</td>
                  <td className="wrap">{r.justification}</td>
                  <td className="row-actions">
                    {me.can.approve && r.approval_status === "PENDING" ? (
                      own ? <span className="small muted">needs another approver</span> : (
                        <>
                          <button className="btn btn-primary" onClick={() => setAct({ kind: "approve", req: r })}>Approve</button>
                          <button className="btn" onClick={() => setAct({ kind: "reject", req: r })}>Reject</button>
                        </>
                      )
                    ) : null}
                    {me.can.approve && r.approval_status === "APPROVED" && (r.access_status === "NONE" || r.access_status === "GRANT_FAILED") ? (
                      <button className="btn" onClick={() => setAct({ kind: "grant", req: r })}>Retry grant</button>
                    ) : null}
                    {r.access_status === "ACTIVE" && (me.can.approve || own) ? (
                      <button className="btn btn-danger" onClick={() => setAct({ kind: "revoke", req: r })}>Revoke now</button>
                    ) : null}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </TableWrap>
      ) : null}

      <h2>Role catalog</h2>
      {roles.data && !roles.data.length ? <Empty>No roles in the catalog.</Empty> : null}
      {roles.data && roles.data.length ? (
        <TableWrap label="Role catalog">
          <thead><tr><th>Role</th><th>Description</th><th>Directory</th><th>Max minutes</th><th>Accounts</th></tr></thead>
          <tbody>
            {roles.data.map((r) => (
              <tr key={r.role}>
                <td className="mono">{r.role}</td><td>{r.description}</td><td>{r.idp}</td><td>{r.max_minutes}</td>
                <td className="mono small wrap">{r.target_cloud_accounts.join(", ")}</td>
              </tr>
            ))}
          </tbody>
        </TableWrap>
      ) : null}

      {act ? (
        <ActionDialog
          title={{ approve: "Approve and grant access", reject: "Reject request", grant: "Retry the grant", revoke: "Revoke access now" }[act.kind]}
          description={<>{act.req.user_id} → <span className="mono">{act.req.requested_role}</span> on <span className="mono">{act.req.target_cloud_account}</span> for {act.req.expiration_minutes} min</>}
          fields={act.kind === "approve" || act.kind === "reject" ? [{ name: "note", label: "Note (recorded)", kind: "textarea", maxLength: 2000 }] : []}
          confirmLabel={{ approve: "Approve", reject: "Reject", grant: "Retry grant", revoke: "Revoke" }[act.kind]}
          danger={act.kind === "revoke" || act.kind === "reject"}
          onClose={() => setAct(null)}
          onSubmit={async (v) => {
            const path = `/jit/requests/${encodeURIComponent(act.req.id)}/${act.kind}`;
            await api.post(path, act.kind === "approve" || act.kind === "reject" ? { note: String(v.note ?? "") } : undefined);
            requests.reload();
          }}
        />
      ) : null}
    </>
  );
}

function RequestForm({ roles, defaultUser, onDone }: { roles: JitRole[]; defaultUser: string; onDone: () => void }) {
  const { api } = useSession();
  const [roleName, setRoleName] = useState(roles[0]?.role ?? "");
  const role = roles.find((r) => r.role === roleName);
  const wildcard = role?.target_cloud_accounts.includes("*") ?? false;
  const [userId, setUserId] = useState(defaultUser);
  const [account, setAccount] = useState("");
  const [minutes, setMinutes] = useState("60");
  const [justification, setJustification] = useState("");
  const [error, setError] = useState<unknown>(undefined);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(undefined);
    try {
      await api.post("/jit/requests", {
        user_id: userId.trim(), requested_role: roleName, target_cloud_account: account.trim(),
        expiration_minutes: Number(minutes), justification: justification.trim(),
      });
      onDone();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  if (!roles.length) return <div className="note">The role catalog is empty; nothing can be requested.</div>;
  return (
    <form className="panel form-grid" onSubmit={submit} aria-label="Request access">
      <div className="field">
        <label htmlFor="jr-user">Directory user</label>
        <input id="jr-user" required maxLength={128} value={userId} onChange={(e) => setUserId(e.target.value)} />
        <small className="muted">The account in the directory that receives the role.</small>
      </div>
      <div className="field">
        <label htmlFor="jr-role">Role</label>
        <select id="jr-role" required value={roleName} onChange={(e) => { setRoleName(e.target.value); setAccount(""); }}>
          {roles.map((r) => <option key={r.role} value={r.role}>{r.role} — {r.description}</option>)}
        </select>
      </div>
      <div className="field">
        <label htmlFor="jr-acct">Cloud account</label>
        {wildcard ? (
          <input id="jr-acct" required maxLength={128} value={account} onChange={(e) => setAccount(e.target.value)} />
        ) : (
          <select id="jr-acct" required value={account} onChange={(e) => setAccount(e.target.value)}>
            <option value="" disabled>Choose…</option>
            {(role?.target_cloud_accounts ?? []).map((a) => <option key={a} value={a}>{a}</option>)}
          </select>
        )}
      </div>
      <div className="field">
        <label htmlFor="jr-min">Minutes (max {role?.max_minutes ?? 1440})</label>
        <input id="jr-min" type="number" required min={1} max={role?.max_minutes ?? 1440} value={minutes} onChange={(e) => setMinutes(e.target.value)} />
      </div>
      <div className="field span-2">
        <label htmlFor="jr-why">Justification (ticket, incident, reason)</label>
        <textarea id="jr-why" required minLength={10} maxLength={1000} rows={2} value={justification} onChange={(e) => setJustification(e.target.value)} />
      </div>
      <ErrorNote error={error} />
      <div className="span-2">
        <button className="btn btn-primary" type="submit" disabled={busy}>{busy ? "Submitting…" : "Submit request"}</button>
      </div>
    </form>
  );
}
