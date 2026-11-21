import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import DrJobs, { checkText } from "../pages/DrJobs";
import { fakeApi, me, renderAt } from "./helpers";

const status = { modules: [{
  kind: "restore_drill", title: "Restore drill", action: "dr.restore_drill",
  fields: [
    { name: "cloud", label: "Sandbox cloud", kind: "select", required: true, options: [{ value: "aws", label: "AWS" }] },
    { name: "image", label: "Replicated image", kind: "text", required: true, maxLength: 512 },
    { name: "checks", label: "Health checks", kind: "text", required: true, initial: "tcp:22" },
  ],
  summary: { sandboxes: ["aws"], boot_timeout_seconds: 900 },
  jobs: [{ id: "j1", kind: "restore_drill", target: "ami-0123456789abcdef0", status: "FAILED", step: "WAIT_GONE",
    payload: {}, error: "RuntimeError: health checks did not pass: tcp 22: ConnectionRefusedError", requested_by: "ann",
    created_at: "2026-11-21T10:00:00+00:00", updated_at: "2026-11-21T10:09:00+00:00",
    state: { verdict: "FAILED", boot_seconds: 61.5, torn_down: true, checks: [{ passed: false, detail: "tcp 22: ConnectionRefusedError" }] } }],
}] };

const migration = { modules: [...status.modules, {
  kind: "cdc_lag_probe", title: "CDC lag measurement (FR-03)", action: "migration.cdc_lag_probe", fields: [], summary: {},
  jobs: [{ id: "j2", kind: "cdc_lag_probe", target: "src -> dst", status: "SUCCEEDED", step: "DONE", payload: {},
    error: null, requested_by: "bob", created_at: "2026-11-21T11:00:00+00:00", updated_at: "2026-11-21T11:01:00+00:00",
    state: { result: { p50_ms: 0.4, p99_ms: 7.3, samples: 40, verdict: "MEETS SLO" } } }] }] };

describe("Migration", () => {
  it("shows only migration modules with their measured evidence", async () => {
    const { api } = fakeApi([{ method: "GET", path: "/dr/jobs", reply: migration }]);
    renderAt(<DrJobs migration />, { api, user: me() });
    expect(await screen.findByText("src -> dst")).toBeInTheDocument();
    expect(screen.getByText(/lag p50 0.4 ms · p99 7.3 ms \(40 samples\) · MEETS SLO/)).toBeInTheDocument();
    expect(screen.queryByText("ami-0123456789abcdef0")).not.toBeInTheDocument();
  });

  it("shows schema-change checks in the backend's real shape (stored jobs may lack 'passed')", async () => {
    // exactly what migration/online_ddl.py stored before and after the fix
    const checks = [{ check: "index ix_orders_customer is valid", offending_rows: 0 },
      { check: "total__oplia_new matches total on every row", offending_rows: 0, passed: true },
      { check: "email__oplia_new is not null", offending_rows: 3, passed: false }];
    const reply = { modules: [{ kind: "schema_change", title: "Online schema change (FR-02)", action: "migration.schema_change",
      fields: [], summary: {}, jobs: [{ id: "j3", kind: "schema_change", target: "shop-src", status: "SUCCEEDED", step: "DONE",
        payload: {}, error: null, requested_by: "bob", created_at: "2026-11-21T12:30:00Z", updated_at: "2026-11-21T12:31:00Z",
        state: { rows_backfilled: 20000, checks } }] }] };
    const { api } = fakeApi([{ method: "GET", path: "/dr/jobs", reply }]);
    renderAt(<DrJobs migration />, { api, user: me() });
    const cell = await screen.findByText(/20000 rows backfilled/);
    expect(cell.textContent).toContain("✓ index ix_orders_customer is valid");
    expect(cell.textContent).toContain("✓ total__oplia_new matches total on every row");
    expect(cell.textContent).toContain("✗ email__oplia_new is not null (3 offending rows)");
    expect(cell.textContent).not.toContain("undefined");
  });

  it("a parity DIFF is a completed job: SUCCEEDED with a DIFF verdict and the schema/table differences", async () => {
    const result = { status: "DIFF", schema: [{ table: "orders", issue: "columns not on target", columns: ["total__oplia_new"] }],
      tables: { orders: { source_rows: 20000, target_rows: 20000, columns_compared: 3, columns_not_on_target: ["total__oplia_new"],
        differing_buckets: 0, rows_match: true, status: "DIFF" } } };
    const reply = { modules: [{ kind: "parity_check", title: "Parity check (FR-05)", action: "migration.parity_check",
      fields: [], summary: {}, jobs: [{ id: "j4", kind: "parity_check", target: "shop-src -> shop-target", status: "SUCCEEDED",
        step: "DONE", payload: {}, error: null, requested_by: "bob", created_at: "2026-11-21T12:30:00Z",
        updated_at: "2026-11-21T12:31:00Z", state: { result } }] }] };
    const { api } = fakeApi([{ method: "GET", path: "/dr/jobs", reply }]);
    renderAt(<DrJobs migration />, { api, user: me() });
    expect(await screen.findByText("SUCCEEDED")).toBeInTheDocument();
    expect(screen.getByText("DIFF", { selector: ".badge" })).toHaveClass("badge-danger");
    expect(screen.getByText(/parity verdict DIFF · tables differing: orders · schema: orders columns not on target \(total__oplia_new\)/))
      .toBeInTheDocument();
  });

  it("checkText handles drill checks too", () => {
    expect(checkText({ check: { kind: "tcp" }, passed: false, detail: "tcp 22: refused" })).toBe("✗ tcp 22: refused");
  });

  it("keeps migration modules off the DR page", async () => {
    const { api } = fakeApi([{ method: "GET", path: "/dr/jobs", reply: migration }]);
    renderAt(<DrJobs />, { api, user: me() });
    expect(await screen.findByText("ami-0123456789abcdef0")).toBeInTheDocument();
    expect(screen.queryByText("src -> dst")).not.toBeInTheDocument();
  });
});

describe("DR jobs", () => {
  it("shows drill results including the teardown", async () => {
    const { api } = fakeApi([{ method: "GET", path: "/dr/jobs", reply: status }]);
    renderAt(<DrJobs />, { api, user: me() });
    expect(await screen.findByText("ami-0123456789abcdef0")).toBeInTheDocument();
    expect(screen.getByText(/health checks did not pass/)).toBeInTheDocument();
    expect(screen.getByText(/verdict FAILED · booted in 61.5s · ✗ tcp 22: ConnectionRefusedError · torn down/)).toBeInTheDocument();
    expect(screen.getByText(/sandboxes: aws/)).toBeInTheDocument();
  });

  it("proposes a drill with the module's own fields", async () => {
    const { api, calls } = fakeApi([
      { method: "GET", path: "/dr/jobs", reply: status },
      { method: "POST", path: "/dr/jobs/restore_drill", reply: { id: "p-9", status: "PENDING" } },
    ]);
    renderAt(<DrJobs />, { api, user: me() });
    await userEvent.click(await screen.findByRole("button", { name: "Propose restore drill…" }));
    const dlg = screen.getByRole("dialog");
    await userEvent.selectOptions(within(dlg).getByLabelText("Sandbox cloud"), "aws");
    await userEvent.type(within(dlg).getByLabelText("Replicated image"), "ami-0123456789abcdef0");
    await userEvent.type(within(dlg).getByLabelText(/Reason/), "monthly drill");
    await userEvent.click(within(dlg).getByRole("button", { name: "Create proposal" }));
    await waitFor(() => expect(calls.find((c) => c.path === "/dr/jobs/restore_drill")?.body).toEqual({
      params: { cloud: "aws", image: "ami-0123456789abcdef0", checks: "tcp:22" }, reason: "monthly drill" }));
  });
});
