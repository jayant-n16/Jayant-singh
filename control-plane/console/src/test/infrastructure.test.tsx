import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import Infrastructure from "../pages/Infrastructure";
import { fakeApi, me, renderAt } from "./helpers";

const inst = (over: Record<string, unknown> = {}) => ({
  id: "i-row-1", cloud: "aws", scope: "123456789012", region: "ap-south-1", resource_type: "ec2:instance",
  resource_id: "arn:aws:ec2:ap-south-1:123456789012:instance/i-0123456789abcdef0", name: "web-1", size: "t3.medium",
  state: "running", tags: {}, tag_compliant: false, tag_issues: ["Owner"], first_seen_at: "2026-11-20T10:00:00+00:00",
  last_seen_at: "2026-11-20T10:00:00+00:00", gone_at: null, ...over,
});
const scan = { id: "s1", started_at: "2026-11-20T10:00:00+00:00", finished_at: "2026-11-20T10:01:00+00:00",
  instances_seen: 1, new_instances: 1, gone_instances: 0, source_errors: [{ source: "azure", error: "x" }] };

describe("infrastructure", () => {
  it("lists instances, shows failed sources and tag gaps, filters by cloud", async () => {
    const { api, calls } = fakeApi([
      { method: "GET", path: "/inventory/instances", reply: [inst()] },
      { method: "GET", path: "/inventory/scans", reply: [scan] },
    ]);
    renderAt(<Infrastructure />, { api, user: me({}, { approve: false, operate: true }) });
    expect(await screen.findByText("web-1")).toBeInTheDocument();
    expect(screen.getByText("t3.medium")).toBeInTheDocument();
    expect(screen.getByText(/missing: Owner/)).toBeInTheDocument();
    expect(screen.getByText(/Failed sources: azure/)).toBeInTheDocument();
    await userEvent.selectOptions(screen.getByLabelText("Cloud"), "gcp");
    await waitFor(() => expect(calls.filter((c) => c.path === "/inventory/instances").at(-1)!.query).toMatchObject({ cloud: "gcp" }));
  });

  it("creates a gated start/stop proposal with a reason", async () => {
    const { api, calls } = fakeApi([
      { method: "GET", path: "/inventory/instances", reply: [inst()] },
      { method: "GET", path: "/inventory/scans", reply: [] },
      { method: "POST", path: "/inventory/instances/i-row-1/power", reply: { id: "p-9" } },
    ]);
    renderAt(<Infrastructure />, { api, user: me({}, { approve: false, operate: true }) });
    await userEvent.click(await screen.findByRole("button", { name: /Propose start\/stop/ }));
    const dlg = screen.getByRole("dialog");
    await userEvent.click(within(dlg).getByLabelText("Stop"));
    await userEvent.type(within(dlg).getByLabelText(/Reason/), "weekend cost saving");
    await userEvent.click(within(dlg).getByRole("button", { name: "Create proposal" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST")).toBe(true));
    expect(calls.find((c) => c.method === "POST")!.body).toEqual({ operation: "stop", reason: "weekend cost saving" });
  });
});
