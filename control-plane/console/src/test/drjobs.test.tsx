import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import DrJobs from "../pages/DrJobs";
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
