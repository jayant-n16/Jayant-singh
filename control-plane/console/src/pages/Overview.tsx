import { useState } from "react";
import { Link } from "react-router";

import { ActionDialog, Badge, ErrorNote, Loading, PageHeader } from "../components/ui";
import { fmtTime } from "../format";
import { useResource, useSession } from "../session";
import type { Breaker, KillSwitch, Proposal } from "../types";

export default function Overview() {
  const { api, me } = useSession();
  const kill = useResource(() => api.get<KillSwitch>("/kill-switch"), [api]);
  const pending = useResource(() => api.get<Proposal[]>("/proposals", { status_filter: "PENDING", limit: 500 }), [api]);
  const approved = useResource(() => api.get<Proposal[]>("/proposals", { status_filter: "APPROVED", limit: 500 }), [api]);
  const breakers = useResource(
    () => (me.features.dr ? api.get<Breaker[]>("/dr/breakers") : Promise.resolve([] as Breaker[])),
    [api, me.features.dr],
  );
  const [dialog, setDialog] = useState(false);
  const [audit, setAudit] = useState<{ intact: boolean; at: string } | null>(null);
  const [auditError, setAuditError] = useState<unknown>(undefined);
  const [checking, setChecking] = useState(false);

  async function verify() {
    setChecking(true);
    setAuditError(undefined);
    try {
      const r = await api.get<{ intact: boolean }>("/audit/verify");
      setAudit({ intact: r.intact, at: new Date().toISOString() });
    } catch (e) {
      setAuditError(e);
    } finally {
      setChecking(false);
    }
  }

  const k = kill.data;
  const openBreakers = (breakers.data ?? []).filter((b) => b.state === "OPEN");

  return (
    <>
      <PageHeader title="Overview" intro="Safety state of the control plane and work waiting for people." />
      <div className="cards">
        <section className={`card ${k?.engaged ? "card-danger" : ""}`} aria-labelledby="ks-h">
          <h2 id="ks-h">Kill switch</h2>
          {kill.loading && !k ? <Loading what="kill switch" /> : null}
          <ErrorNote error={kill.error} />
          {k ? (
            <>
              <p className="big">{k.engaged ? "ENGAGED — all executors stopped" : "Released — executors may run"}</p>
              {k.set_by ? (
                <p className="muted">
                  Set by {k.set_by} on {fmtTime(k.set_at)}: “{k.reason}”
                </p>
              ) : (
                <p className="muted">Never set.</p>
              )}
              {me.can.approve ? (
                <button className={k.engaged ? "btn" : "btn btn-danger"} onClick={() => setDialog(true)}>
                  {k.engaged ? "Release kill switch" : "Engage kill switch"}
                </button>
              ) : null}
            </>
          ) : null}
        </section>

        <section className="card" aria-labelledby="wq-h">
          <h2 id="wq-h">Waiting for people</h2>
          <ErrorNote error={pending.error ?? approved.error} />
          <dl className="stats">
            <div>
              <dt>Awaiting approval</dt>
              <dd>
                <Link to="/proposals?status=PENDING">{pending.data ? pending.data.length : "…"}</Link>
              </dd>
            </div>
            <div>
              <dt>Approved, not executed</dt>
              <dd>
                <Link to="/proposals?status=APPROVED">{approved.data ? approved.data.length : "…"}</Link>
              </dd>
            </div>
            {me.features.dr ? (
              <div>
                <dt>Open DR breakers</dt>
                <dd>
                  <Link to="/dr">{breakers.data ? openBreakers.length : "…"}</Link>
                </dd>
              </div>
            ) : null}
          </dl>
        </section>

        {me.can.approve ? (
          <section className="card" aria-labelledby="au-h">
            <h2 id="au-h">Audit log integrity</h2>
            <p className="muted">Recomputes the hash chain over every audit entry.</p>
            {audit ? (
              <p className={audit.intact ? "ok big" : "danger big"} role="status">
                {audit.intact ? "Intact" : "BROKEN — the audit log was altered"}
                <span className="muted small"> (checked {fmtTime(audit.at)})</span>
              </p>
            ) : null}
            <ErrorNote error={auditError} />
            <button className="btn" onClick={verify} disabled={checking}>
              {checking ? "Checking…" : "Verify audit chain"}
            </button>{" "}
            <Link to="/audit">Open audit log</Link>
          </section>
        ) : null}
      </div>

      {openBreakers.length ? (
        <div className="note note-danger" role="alert">
          DR breaker open for {openBreakers.map((b) => b.stream).join(", ")} — replication to the DR copy is held.{" "}
          <Link to="/dr">Review</Link> <Badge value="OPEN" />
        </div>
      ) : null}

      {dialog && k ? (
        <ActionDialog
          title={k.engaged ? "Release the kill switch" : "Engage the kill switch"}
          description={
            k.engaged
              ? "Executors may run approved actions again."
              : "Every executor stops immediately. Proposals stay queued; nothing is lost."
          }
          fields={[{ name: "reason", label: "Reason (recorded in the audit log)", kind: "textarea", required: true, minLength: 3, maxLength: 2000 }]}
          confirmLabel={k.engaged ? "Release" : "Engage"}
          danger={!k.engaged}
          onClose={() => setDialog(false)}
          onSubmit={async (v) => {
            await api.post("/kill-switch", { engaged: !k.engaged, reason: String(v.reason) });
            kill.reload();
          }}
        />
      ) : null}
    </>
  );
}
