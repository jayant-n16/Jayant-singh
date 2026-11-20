import { useState } from "react";
import { useNavigate } from "react-router";

import { ActionDialog, Badge, Empty, ErrorNote, Loading, PageHeader, TableWrap } from "../components/ui";
import { fmtTime } from "../format";
import { useResource, useSession } from "../session";
import type { EndpointGroup, NetSection, NetworkStatus, Proposal } from "../types";

function SectionState({ s, what }: { s: NetSection<unknown>; what: string }) {
  if (!s.configured) return <p className="muted">{what} is not configured.</p>;
  if (!s.ok) return <div className="note note-danger" role="alert">{what} could not be read: {s.error}</div>;
  if (s.items.length === 0) return <Empty>No {what.toLowerCase()} entries found.</Empty>;
  return null;
}

export default function Network() {
  const { api } = useSession();
  const navigate = useNavigate();
  const st = useResource(() => api.get<NetworkStatus>("/network/status"), [api]);
  const [dial, setDial] = useState<EndpointGroup | null>(null);
  const d = st.data;

  return (
    <>
      <PageHeader
        title="Network"
        intro="Global entry (AWS Global Accelerator), private interconnects (Direct Connect via Equinix Fabric / Megaport) and service-mesh peering. Traffic-dial changes are proposals: another approver approves, an operator executes."
        actions={<button className="btn" onClick={st.reload} disabled={st.loading}>{st.loading ? "Reading…" : "Refresh"}</button>}
      />
      <ErrorNote error={st.error} />
      {st.loading && !d ? <Loading what="network status" /> : null}
      {d ? (
        <>
          <section>
            <h2>Global Accelerator endpoint groups</h2>
            <p className="small muted">Step policy: increases of at most {d.policy.max_increase} points, at least {d.policy.min_hold_minutes} min apart, only while every endpoint is healthy. Decreases (rollback) are always allowed.</p>
            <SectionState s={d.global_accelerator} what="Global Accelerator" />
            {d.global_accelerator.items.length ? (
              <TableWrap label="Endpoint groups">
                <thead><tr><th>Group</th><th>Region</th><th>Traffic dial</th><th>Health</th><th>Endpoints</th><th /></tr></thead>
                <tbody>
                  {d.global_accelerator.items.map((g) => (
                    <tr key={g.key}>
                      <td className="mono">{g.key}</td>
                      <td>{g.region ?? "—"}</td>
                      <td>{g.error ? "—" : <><meter min={0} max={100} value={g.traffic_dial} aria-label={`${g.key} traffic dial`} /> {g.traffic_dial} %</>}</td>
                      <td>{g.error ? <span className="danger small">{g.error}</span> : <Badge value={g.all_healthy ? "HEALTHY" : "UNHEALTHY"} />}</td>
                      <td className="small wrap">{g.endpoints.map((e) => <div key={e.endpoint_id}><span className="mono">{e.endpoint_id.split("/").slice(-2).join("/")}</span> w{e.weight ?? "?"} {e.health}{e.health_reason ? ` (${e.health_reason})` : ""}</div>)}</td>
                      <td>{g.error ? null : <button className="btn" onClick={() => setDial(g)}>Propose dial…</button>}</td>
                    </tr>
                  ))}
                </tbody>
              </TableWrap>
            ) : null}
          </section>

          <section>
            <h2>Direct Connect (hosted connections from Equinix / Megaport)</h2>
            <SectionState s={d.direct_connect} what="Direct Connect" />
            {d.direct_connect.items.length ? (
              <TableWrap label="Direct Connect connections">
                <thead><tr><th>Connection</th><th>Partner</th><th>State</th><th>Bandwidth</th><th>Virtual interfaces (BGP)</th></tr></thead>
                <tbody>
                  {d.direct_connect.items.map((c) => (
                    <tr key={c.id}>
                      <td><div>{c.name}</div><div className="mono small muted">{c.id} · {c.region} · {c.location}</div></td>
                      <td>{c.partner || "—"}</td>
                      <td><Badge value={c.state.toUpperCase()} /></td>
                      <td>{c.bandwidth}</td>
                      <td className="small">{c.virtual_interfaces.length ? c.virtual_interfaces.map((v) => <div key={v.id}>{v.name} ({v.type}, VLAN {v.vlan}) {v.state} · BGP {v.bgp.join("/") || "—"}</div>) : "none"}</td>
                    </tr>
                  ))}
                </tbody>
              </TableWrap>
            ) : null}
          </section>

          <section>
            <h2>Consul cluster peerings</h2>
            <SectionState s={d.consul} what="Consul" />
            {d.consul.items.length ? (
              <TableWrap label="Consul peerings">
                <thead><tr><th>Peer</th><th>State</th><th>Imported</th><th>Exported</th><th>Last heartbeat</th></tr></thead>
                <tbody>{d.consul.items.map((p) => (
                  <tr key={p.name}><td>{p.name}<div className="mono small muted">{p.peer_server_name}</div></td><td><Badge value={p.state} /></td>
                    <td>{p.imported_services}</td><td>{p.exported_services}</td><td className="small">{p.last_heartbeat ? fmtTime(p.last_heartbeat) : "—"}</td></tr>
                ))}</tbody>
              </TableWrap>
            ) : null}
          </section>

          <section>
            <h2>Linkerd multicluster links</h2>
            <SectionState s={d.linkerd} what="Linkerd" />
            {d.linkerd.items.length ? (
              <TableWrap label="Linkerd links">
                <thead><tr><th>Link</th><th>Target cluster</th><th>Gateway</th><th>Mirrored services</th><th>Not ready</th></tr></thead>
                <tbody>{d.linkerd.items.map((l) => (
                  <tr key={`${l.namespace}/${l.name}`}><td className="mono">{l.namespace}/{l.name}</td><td>{l.target_cluster}</td><td className="mono">{l.gateway}</td>
                    <td>{l.mirrored_services}</td><td className={l.not_ready.length ? "danger" : ""}>{l.not_ready.join(", ") || "none"}</td></tr>
                ))}</tbody>
              </TableWrap>
            ) : null}
          </section>

          <section>
            <h2>Executed dial changes</h2>
            {d.dial_history.length ? (
              <TableWrap label="Dial history">
                <thead><tr><th>When</th><th>Group</th><th>Change</th><th>Request</th></tr></thead>
                <tbody>{d.dial_history.map((h) => (
                  <tr key={`${h.executed_at}-${h.group}`}><td className="small">{fmtTime(h.executed_at)}</td><td className="mono">{h.group}</td><td>{h.from} % → {h.to} %</td><td className="mono small">{h.request_id ?? "—"}</td></tr>
                ))}</tbody>
              </TableWrap>
            ) : <Empty>No dial changes executed through OPLIA yet.</Empty>}
          </section>
        </>
      ) : null}
      {dial ? (
        <ActionDialog
          title={`Propose a traffic-dial change for ${dial.key}`}
          description={<>Current dial {dial.traffic_dial} %. The step is checked again at execution: if the dial changed in the meantime the proposal is refused.</>}
          fields={[
            { name: "percentage", label: "New traffic dial (%)", kind: "number", required: true, min: 0, max: 100 },
            { name: "reason", label: "Reason (recorded)", kind: "textarea", required: true, minLength: 5, maxLength: 2000 },
          ]}
          confirmLabel="Create proposal"
          onClose={() => setDial(null)}
          onSubmit={async (v) => {
            const p = await api.post<Proposal>(`/network/endpoint-groups/${encodeURIComponent(dial.key)}/traffic-dial`,
              { percentage: Number(v.percentage), reason: String(v.reason) });
            navigate(`/proposals/${p.id}`);
          }}
        />
      ) : null}
    </>
  );
}
