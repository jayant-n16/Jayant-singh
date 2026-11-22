import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import Network from "../pages/Network";
import { fakeApi, me, renderAt } from "./helpers";

const off = { configured: false, ok: true, items: [], error: null, latency_ms: 0 };
const status = {
  global_accelerator: { configured: true, ok: true, error: null, latency_ms: 40, items: [
    { key: "aws", arn: "arn:eg/aws", region: "ap-south-1", traffic_dial: 100, health_check: "HTTPS:443/healthz", all_healthy: true,
      endpoints: [{ endpoint_id: "arn:aws:elasticloadbalancing:x:loadbalancer/app/web/1", weight: 128, health: "HEALTHY", health_reason: "" }] },
    { key: "azure", arn: "arn:eg/azure", error: "EndpointGroupNotFoundException: gone", all_healthy: false, endpoints: [] },
  ] },
  direct_connect: off,
  consul: { configured: true, ok: false, items: [], error: "HTTPStatusError: 500", latency_ms: 3 },
  linkerd: { configured: true, ok: true, error: null, latency_ms: 2, items: [
    { name: "gcp-mum", namespace: "linkerd-multicluster", target_cluster: "gcp-mum", gateway: "10.0.0.5:4143", mirrored_services: 2, not_ready: ["api"] }] },
  dial_history: [],
  policy: { max_increase: 25, min_hold_minutes: 30 },
};

describe("network", () => {
  it("shows each section independently, including failures", async () => {
    const { api } = fakeApi([{ method: "GET", path: "/network/status", reply: status }]);
    renderAt(<Network />, { api, user: me() });
    expect(await screen.findByText("EndpointGroupNotFoundException: gone")).toBeInTheDocument();
    expect(screen.getByRole("alert")).toHaveTextContent("Consul could not be read: HTTPStatusError: 500");
    expect(screen.getByText("Direct Connect is not configured.")).toBeInTheDocument();
    expect(screen.getByText("api")).toBeInTheDocument();
    expect(screen.getByText(/at most 25 points, at least 30 min apart/)).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: /Propose dial/ })).toHaveLength(1);   // not for the failed group
  });

  it("proposes a dial change with the entered values", async () => {
    const { api, calls } = fakeApi([
      { method: "GET", path: "/network/status", reply: status },
      { method: "POST", path: "/network/endpoint-groups/aws/traffic-dial", reply: { id: "p-9", status: "PENDING" } },
    ]);
    renderAt(<Network />, { api, user: me({}, { approve: false, operate: true }) });
    await userEvent.click(await screen.findByRole("button", { name: /Propose dial/ }));
    const dlg = screen.getByRole("dialog");
    await userEvent.type(within(dlg).getByLabelText(/New traffic dial/), "75");
    await userEvent.type(within(dlg).getByLabelText(/Reason/), "phase 4 rollback step");
    await userEvent.click(within(dlg).getByRole("button", { name: "Create proposal" }));
    await waitFor(() => expect(calls.find((c) => c.method === "POST")?.body)
      .toEqual({ percentage: 75, reason: "phase 4 rollback step" }));
  });
});
