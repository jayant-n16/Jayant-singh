import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { ApiError } from "../api";
import Dr from "../pages/Dr";
import Jit from "../pages/Jit";
import Overview from "../pages/Overview";
import ProposalDetail from "../pages/ProposalDetail";
import { fakeApi, me, renderAt } from "./helpers";

const proposal = (over: Record<string, unknown> = {}) => ({
  id: "p-1", action_type: "drift.remediate", target: "aws:111122223333:zone-1", payload: { a: 1 }, reason: "drift",
  requested_by: "drift-detector", status: "PENDING", created_at: "2026-11-19T10:00:00+00:00",
  expires_at: "2026-11-19T11:00:00+00:00", decided_by: null, decided_at: null, decision_note: null, executed_at: null,
  result: null, ...over,
});
const released = { engaged: false, set_by: null, set_at: null, reason: null };

describe("proposal detail", () => {
  it("lets an approver approve with a note, then shows the new state", async () => {
    let current = proposal();
    const { api, calls } = fakeApi([
      { method: "GET", path: "/proposals/p-1", reply: () => current },
      { method: "GET", path: "/kill-switch", reply: released },
      { method: "GET", path: "/audit/events", reply: [] },
      { method: "POST", path: "/proposals/p-1/approve", reply: (b: unknown) => { current = proposal({ status: "APPROVED", decided_by: "alice", decision_note: (b as { note: string }).note }); return current; } },
    ]);
    renderAt(<ProposalDetail />, { api, user: me(), path: "/proposals/p-1", route: "/proposals/:id" });
    await userEvent.click(await screen.findByRole("button", { name: "Approve" }));
    const dlg = screen.getByRole("dialog");
    await userEvent.type(within(dlg).getByLabelText(/Note/), "looks right");
    await userEvent.click(within(dlg).getByRole("button", { name: "Approve" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(calls.find((c) => c.method === "POST")).toEqual({ method: "POST", path: "/proposals/p-1/approve", body: { note: "looks right" } });
    expect(await screen.findByText("APPROVED")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Execute" })).not.toBeInTheDocument(); // approver without operator role
  });

  it("enforces four-eyes in the UI: the requester cannot approve their own proposal", async () => {
    const { api } = fakeApi([
      { method: "GET", path: "/proposals/p-1", reply: proposal({ requested_by: "alice" }) },
      { method: "GET", path: "/kill-switch", reply: released },
      { method: "GET", path: "/audit/events", reply: [] },
    ]);
    renderAt(<ProposalDetail />, { api, user: me(), path: "/proposals/p-1", route: "/proposals/:id" });
    expect(await screen.findByRole("button", { name: "Approve" })).toBeDisabled();
    expect(screen.getByText(/Four-eyes rule/)).toBeInTheDocument();
  });

  it("keeps the dialog open and shows the server's refusal", async () => {
    const { api } = fakeApi([
      { method: "GET", path: "/proposals/p-1", reply: proposal({ status: "APPROVED" }) },
      { method: "GET", path: "/kill-switch", reply: released },
      { method: "POST", path: "/proposals/p-1/execute", reply: new ApiError(423, "kill switch engaged") },
    ]);
    renderAt(<ProposalDetail />, { api, user: me({ subject: "bob", roles: ["oplia-operator"] }, { approve: false, operate: true }), path: "/proposals/p-1", route: "/proposals/:id" });
    await userEvent.click(await screen.findByRole("button", { name: "Execute" }));
    await userEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Execute" }));
    expect(await within(screen.getByRole("dialog")).findByRole("alert")).toHaveTextContent("Blocked by the kill switch: kill switch engaged");
  });

  it("disables Execute while the kill switch is engaged", async () => {
    const { api } = fakeApi([
      { method: "GET", path: "/proposals/p-1", reply: proposal({ status: "APPROVED" }) },
      { method: "GET", path: "/kill-switch", reply: { engaged: true, set_by: "alice", set_at: "2026-11-19T10:00:00+00:00", reason: "incident" } },
    ]);
    renderAt(<ProposalDetail />, { api, user: me({}, { approve: false, operate: true }), path: "/proposals/p-1", route: "/proposals/:id" });
    await waitFor(() => expect(screen.getByRole("button", { name: "Execute" })).toBeDisabled());
  });
});

describe("overview", () => {
  const base = [
    { method: "GET" as const, path: "/kill-switch", reply: released },
    { method: "GET" as const, path: "/proposals", reply: [] },
  ];

  it("operators see the kill switch state but cannot change it", async () => {
    const { api } = fakeApi(base);
    renderAt(<Overview />, { api, user: me({}, { approve: false, operate: true }) });
    expect(await screen.findByText(/Released/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /kill switch/ })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Verify audit chain/ })).not.toBeInTheDocument();
  });

  it("an approver engages the kill switch with a mandatory reason", async () => {
    const { api, calls } = fakeApi([...base, { method: "POST", path: "/kill-switch", reply: { engaged: true } }]);
    renderAt(<Overview />, { api, user: me() });
    await userEvent.click(await screen.findByRole("button", { name: "Engage kill switch" }));
    const dlg = screen.getByRole("dialog");
    expect(within(dlg).getByLabelText(/Reason/)).toBeRequired();
    await userEvent.type(within(dlg).getByLabelText(/Reason/), "incident 42");
    await userEvent.click(within(dlg).getByRole("button", { name: "Engage" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST")).toBe(true));
    expect(calls.find((c) => c.method === "POST")!.body).toEqual({ engaged: true, reason: "incident 42" });
  });

  it("reports a broken audit chain loudly", async () => {
    const { api } = fakeApi([...base, { method: "GET", path: "/audit/verify", reply: { intact: false } }]);
    renderAt(<Overview />, { api, user: me() });
    await userEvent.click(await screen.findByRole("button", { name: "Verify audit chain" }));
    expect(await screen.findByText(/BROKEN/)).toBeInTheDocument();
  });
});

describe("JIT", () => {
  const req = (over: Record<string, unknown>) => ({
    id: "r-1", user_id: "carol@corp", requested_role: "aws-admin", target_cloud_account: "111122223333", expiration_minutes: 60,
    approval_status: "PENDING", access_status: "NONE", idp: "entra", group_ref: "g", justification: "INC-1 fix database",
    requested_by: "carol", proposal_id: null, created_at: "2026-11-19T10:00:00+00:00", decided_at: null, decided_by: null,
    granted_at: null, expires_at: null, revoked_at: null, revoked_by: null, revoke_attempts: 0, last_error: null, ...over,
  });
  const roles = [{ role: "aws-admin", description: "AWS admin", idp: "entra", group_ref: "g", max_minutes: 240, target_cloud_accounts: ["111122223333"] }];

  it("hides approve on the approver's own request and lets the requester revoke active access", async () => {
    const { api } = fakeApi([
      { method: "GET", path: "/jit/roles", reply: roles },
      { method: "GET", path: "/jit/requests", reply: [req({ requested_by: "alice" }), req({ id: "r-2", requested_by: "bob", access_status: "ACTIVE", approval_status: "APPROVED" })] },
    ]);
    renderAt(<Jit />, { api, user: me({ subject: "bob", roles: ["oplia-operator"] }, { approve: false, operate: true }) });
    const rows = await screen.findAllByRole("row");
    expect(screen.queryByRole("button", { name: "Approve" })).not.toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: "Revoke now" })).toHaveLength(1);
    expect(rows.length).toBeGreaterThan(2);
  });

  it("submits a request with the catalog's account", async () => {
    const { api, calls } = fakeApi([
      { method: "GET", path: "/jit/roles", reply: roles },
      { method: "GET", path: "/jit/requests", reply: [] },
      { method: "POST", path: "/jit/requests", reply: req({}) },
    ]);
    renderAt(<Jit />, { api, user: me({ subject: "bob" }, { approve: false, operate: true }) });
    await userEvent.click(await screen.findByRole("button", { name: "Request access" }));
    await userEvent.selectOptions(await screen.findByLabelText("Cloud account"), "111122223333");
    await userEvent.clear(screen.getByLabelText(/Minutes/));
    await userEvent.type(screen.getByLabelText(/Minutes/), "90");
    await userEvent.type(screen.getByLabelText(/Justification/), "INC-77 restore database");
    await userEvent.click(screen.getByRole("button", { name: "Submit request" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST")).toBe(true));
    expect(calls.find((c) => c.method === "POST")!.body).toEqual({
      user_id: "bob", requested_role: "aws-admin", target_cloud_account: "111122223333", expiration_minutes: 90,
      justification: "INC-77 restore database",
    });
  });
});

describe("DR", () => {
  it("resets an open breaker with the chosen decision", async () => {
    const { api, calls } = fakeApi([
      { method: "GET", path: "/dr/breakers", reply: [{ stream: "orders-pg", state: "OPEN", incident_id: "i-1", pending_decision: null }] },
      { method: "GET", path: "/dr/incidents", reply: [] },
      { method: "POST", path: "/dr/breakers/orders-pg/reset", reply: { state: "CLOSED" } },
    ]);
    renderAt(<Dr />, { api, user: me() });
    await userEvent.click(await screen.findByRole("button", { name: "Reset…" }));
    const dlg = screen.getByRole("dialog");
    await userEvent.click(within(dlg).getByLabelText(/Discard/));
    await userEvent.click(within(dlg).getByLabelText(/Unlock the DR targets/));
    await userEvent.type(within(dlg).getByLabelText(/Note/), "bad migration, discarded");
    await userEvent.click(within(dlg).getByRole("button", { name: "Reset breaker" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST")).toBe(true));
    expect(calls.find((c) => c.method === "POST")!.body).toEqual({ decision: "discard", unlock_targets: true, note: "bad migration, discarded" });
  });

  it("operators cannot trip or reset", async () => {
    const { api } = fakeApi([
      { method: "GET", path: "/dr/breakers", reply: [{ stream: "orders-pg", state: "CLOSED", incident_id: null, pending_decision: null }] },
      { method: "GET", path: "/dr/incidents", reply: [] },
    ]);
    renderAt(<Dr />, { api, user: me({}, { approve: false, operate: true }) });
    await screen.findByText("orders-pg");
    expect(screen.queryByRole("button", { name: "Trip" })).not.toBeInTheDocument();
  });
});
