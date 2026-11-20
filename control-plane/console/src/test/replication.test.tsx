import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import Replication from "../pages/Replication";
import { fakeApi, me, renderAt } from "./helpers";

const status = {
  pipelines: { configured: true, ok: true, error: null, items: [
    { name: "pg-orders", type: "source", class: "io.debezium.connector.postgresql.PostgresConnector", state: "RUNNING", worker: "w1:8083", failed_tasks: 1,
      tasks: [{ id: 0, state: "FAILED", trace: "org.postgresql.util.PSQLException: connection refused\n at ..." }] }] },
  object_pairs: [{ pair: "data", source: "aws:prod-data/p/", target: "azure:dr", target_key: "drscope01", replicated_objects: 12,
    last_run: { status: "PARTIAL", started_at: "2026-11-20T10:00:00+00:00", copied: 3, bytes: 10, summary: { skipped: [{ key: "a", reason: "changed" }], failed: [] } } }],
  image_jobs: [{ id: "j1", source_cloud: "aws", source_id: "ami-0123", target_cloud: "gcp", name: "web-img", status: "FAILED", step: "TRANSFER",
    error: "RuntimeError: SHA-256 of the staged copy differs", created_at: "2026-11-20T10:00:00+00:00", updated_at: "2026-11-20T10:05:00+00:00", state: {} }],
  image_targets: { aws: true, azure: false, gcp: true },
};

describe("DR replication", () => {
  it("shows pipelines, pairs and image jobs including failures", async () => {
    const { api } = fakeApi([{ method: "GET", path: "/dr/replication", reply: status }]);
    renderAt(<Replication />, { api, user: me() });
    expect(await screen.findByText("pg-orders")).toBeInTheDocument();
    expect(screen.getByText(/PSQLException: connection refused/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Restart failed…" })).toBeInTheDocument();
    expect(screen.getByText(/3 copied, 0 failed, 1 skipped/)).toBeInTheDocument();
    expect(screen.getByText(/SHA-256 of the staged copy differs/)).toBeInTheDocument();
  });

  it("proposes a connector restart and previews tag mapping", async () => {
    const { api, calls } = fakeApi([
      { method: "GET", path: "/dr/replication", reply: status },
      { method: "POST", path: "/dr/replication/pipelines/pg-orders/restart", reply: { id: "p-1", status: "PENDING" } },
      { method: "POST", path: "/dr/replication/tags/preview", reply: { tags: { owner_team: "sre" }, changes: ["key 'Owner Team' -> 'owner_team'"], dropped: [] } },
    ]);
    renderAt(<Replication />, { api, user: me() });
    await userEvent.click(await screen.findByRole("button", { name: "Preview" }));
    expect(await screen.findByText("owner_team = sre")).toBeInTheDocument();
    expect(calls.find((c) => c.path === "/dr/replication/tags/preview")?.body).toEqual({ tags: { "Owner Team": "SRE", CostCenter: "Finance" }, target: "gcp" });
    await userEvent.click(await screen.findByRole("button", { name: "Restart failed…" }));
    const dlg = screen.getByRole("dialog");
    await userEvent.type(within(dlg).getByLabelText(/Reason/), "task died after failover");
    await userEvent.click(within(dlg).getByRole("button", { name: "Create proposal" }));
    await waitFor(() => expect(calls.some((c) => c.path === "/dr/replication/pipelines/pg-orders/restart")).toBe(true));
  });

  it("offers deletion proposals only for pairs that opt in", async () => {
    expect(screen.queryByRole("button", { name: "Propose deletions…" })).toBeNull();
    const optIn = { ...status, object_pairs: [{ ...status.object_pairs[0], replicate_deletions: true,
      last_run: { status: "OK", started_at: "2026-11-20T11:00:00+00:00", copied: 0, bytes: 0, summary: { kind: "delete" as const, deleted: ["p/1", "p/2"], skipped: [], failed: [] } } }] };
    const { api, calls } = fakeApi([
      { method: "GET", path: "/dr/replication", reply: optIn },
      { method: "POST", path: "/dr/replication/objects/data/deletions", reply: { id: "p-2", status: "PENDING" } },
    ]);
    renderAt(<Replication />, { api, user: me() });
    expect(await screen.findByText(/2 deleted, 0 failed, 0 skipped/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Propose deletions…" }));
    const dlg = screen.getByRole("dialog");
    await userEvent.type(within(dlg).getByLabelText(/Reason/), "source bucket cleanup");
    await userEvent.click(within(dlg).getByRole("button", { name: "Create proposal" }));
    await waitFor(() => expect(calls.find((c) => c.path === "/dr/replication/objects/data/deletions")?.body).toEqual({ reason: "source bucket cleanup" }));
  });
});
