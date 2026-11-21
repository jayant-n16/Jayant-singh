import { Link, useSearchParams } from "react-router";

import { Badge, Empty, ErrorNote, Loading, PageHeader, TableWrap } from "../components/ui";
import { fmtTime, shortId } from "../format";
import { useResource, useSession } from "../session";
import { PROPOSAL_STATUSES, type Proposal } from "../types";

export default function Proposals() {
  const { api } = useSession();
  const [params, setParams] = useSearchParams();
  const status = params.get("status") ?? "";
  const list = useResource(
    () => api.get<Proposal[]>("/proposals", { status_filter: status || undefined, limit: 200 }),
    [api, status],
  );

  return (
    <>
      <PageHeader
        title="Proposals"
        intro="Every change to infrastructure, identities or data is a proposal: approve, then execute."
        actions={
          <>
            <label htmlFor="pf" className="inline-label">Status</label>
            <select id="pf" value={status} onChange={(e) => setParams(e.target.value ? { status: e.target.value } : {})}>
              <option value="">All</option>
              {PROPOSAL_STATUSES.map((s) => (
                <option key={s} value={s}>{s.replace("_", " ")}</option>
              ))}
            </select>
            <button className="btn" onClick={list.reload}>Refresh</button>
          </>
        }
      />
      <ErrorNote error={list.error} />
      {list.loading && !list.data ? <Loading what="proposals" /> : null}
      {list.data && list.data.length === 0 ? <Empty>No proposals{status ? ` with status ${status}` : ""}.</Empty> : null}
      {list.data && list.data.length > 0 ? (
        <TableWrap label="Proposals">
          <thead>
            <tr>
              <th>ID</th><th>Action</th><th>Target</th><th>Status</th><th>Requested by</th><th>Created</th><th>Expires</th>
            </tr>
          </thead>
          <tbody>
            {list.data.map((p) => (
              <tr key={p.id}>
                <td><Link to={`/proposals/${p.id}`} className="mono">{shortId(p.id)}</Link></td>
                <td className="mono">{p.action_type}</td>
                <td className="mono wrap">{p.target}</td>
                <td><Badge value={p.status} /></td>
                <td>{p.requested_by}</td>
                <td>{fmtTime(p.created_at)}</td>
                <td>{fmtTime(p.expires_at)}</td>
              </tr>
            ))}
          </tbody>
        </TableWrap>
      ) : null}
    </>
  );
}
