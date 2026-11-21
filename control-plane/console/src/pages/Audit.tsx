import { useEffect, useState } from "react";
import { Link } from "react-router";

import { Empty, ErrorNote, Loading, PageHeader, TableWrap } from "../components/ui";
import { fmtTime, shortId } from "../format";
import { useSession } from "../session";
import type { AuditEvent } from "../types";

const PAGE = 100;

export default function Audit() {
  const { api, me } = useSession();
  const [rows, setRows] = useState<AuditEvent[]>([]);
  const [error, setError] = useState<unknown>(undefined);
  const [loading, setLoading] = useState(false);
  const [done, setDone] = useState(false);

  async function load(before?: number) {
    setLoading(true);
    setError(undefined);
    try {
      const page = await api.get<AuditEvent[]>("/audit/events", { limit: PAGE, before_seq: before });
      setRows((r) => (before === undefined ? page : [...r, ...page]));
      setDone(page.length < PAGE);
    } catch (e) {
      setError(e);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    if (me.can.approve) void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [api, me.can.approve]);

  if (!me.can.approve)
    return (
      <>
        <PageHeader title="Audit log" />
        <div className="note">The audit log is visible to approvers only.</div>
      </>
    );

  const oldest = rows.length ? rows[rows.length - 1]!.seq : undefined;
  return (
    <>
      <PageHeader
        title="Audit log"
        intro="Append-only and hash-chained: every entry includes the hash of the one before it."
        actions={<button className="btn" onClick={() => void load()}>Refresh</button>}
      />
      <ErrorNote error={error} />
      {loading && !rows.length ? <Loading what="audit log" /> : null}
      {!loading && !rows.length && !error ? <Empty>No audit entries yet.</Empty> : null}
      {rows.length ? (
        <TableWrap label="Audit log">
          <thead>
            <tr><th>#</th><th>Time</th><th>Actor</th><th>Event</th><th>Proposal</th><th>Detail</th><th>Hash</th></tr>
          </thead>
          <tbody>
            {rows.map((e) => (
              <tr key={e.seq}>
                <td>{e.seq}</td>
                <td>{fmtTime(e.ts)}</td>
                <td>{e.actor}</td>
                <td className="mono">{e.event}</td>
                <td>{e.proposal_id ? <Link className="mono" to={`/proposals/${e.proposal_id}`}>{shortId(e.proposal_id)}</Link> : "—"}</td>
                <td className="mono small wrap">{JSON.stringify(e.detail)}</td>
                <td className="mono small" title={e.hash}>{e.hash.slice(0, 12)}</td>
              </tr>
            ))}
          </tbody>
        </TableWrap>
      ) : null}
      {rows.length && !done ? (
        <p>
          <button className="btn" disabled={loading} onClick={() => void load(oldest)}>
            {loading ? "Loading…" : "Load older entries"}
          </button>
        </p>
      ) : null}
    </>
  );
}
