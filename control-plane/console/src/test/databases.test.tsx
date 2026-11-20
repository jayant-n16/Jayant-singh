import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import Databases from "../pages/Databases";
import { fakeApi, me, renderAt } from "./helpers";

const entry = (over: Record<string, unknown> = {}) => ({
  name: "orders-pg", engine: "postgres", cloud: "aws", role: "primary", database: "orders", dr_of: null, description: "",
  last_check: { checked_at: "2026-11-20T10:00:00+00:00", ok: true, latency_ms: 12.5, triggered_by: "scheduler", error: null,
    detail: { version: "PostgreSQL 16.4", role: "primary", read_only: false, replication: { streaming_replicas: [] } } },
  ...over,
});

describe("databases", () => {
  it("shows health, lag and errors, and runs a check", async () => {
    const dr = entry({ name: "dr-mysql", engine: "mysql", cloud: "azure", role: "dr", dr_of: "orders-pg",
      last_check: { checked_at: "2026-11-20T10:00:00+00:00", ok: true, latency_ms: 5, triggered_by: "bob", error: null,
        detail: { version: "8.0.40", role: "replica", read_only: true, replication: { lag_seconds: 1.25 } } } });
    const down = entry({ name: "dr-mongo", engine: "mongodb", last_check: { checked_at: "2026-11-20T10:00:00+00:00", ok: false,
      latency_ms: 10000, triggered_by: "scheduler", error: "ServerSelectionTimeoutError: no servers", detail: {} } });
    const { api, calls } = fakeApi([
      { method: "GET", path: "/databases", reply: [entry(), dr, down, entry({ name: "new-db", last_check: null })] },
      { method: "POST", path: "/databases/new-db/check", reply: { ok: true } },
    ]);
    renderAt(<Databases />, { api, user: me({}, { approve: false, operate: true }) });
    expect(await screen.findByText("orders-pg")).toBeInTheDocument();
    expect(screen.getByText("1.3 s")).toBeInTheDocument();
    expect(screen.getByText("copy of orders-pg")).toBeInTheDocument();
    expect(screen.getByText(/ServerSelectionTimeoutError/)).toBeInTheDocument();
    expect(screen.getByText("never checked")).toBeInTheDocument();
    await userEvent.click(screen.getAllByRole("button", { name: "Check now" })[3]!);
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path === "/databases/new-db/check")).toBe(true));
  });
});

describe("DR consistency", () => {
  it("shows drift with its proposal and runs a check", async () => {
    const run = { id: "r1", pair: "dr-mysql", status: "DRIFT", summary: "1 table(s) with different data: products",
      report: { source: "orders-pg", target: "dr-mysql", schema: [], lag_seconds: 2,
        tables: { products: { source_rows: 150, target_rows: 150, match: false, checksum: "differ", rechecked: true } } },
      triggered_by: "scheduler", proposal_id: "p-123456789", started_at: "2026-11-20T10:00:00+00:00", finished_at: "2026-11-20T10:00:05+00:00" };
    const { api, calls } = fakeApi([
      { method: "GET", path: "/databases", reply: [entry(), entry({ name: "dr-mysql", role: "dr", dr_of: "orders-pg" })] },
      { method: "GET", path: "/databases/consistency", reply: [run] },
      { method: "POST", path: "/databases/dr-mysql/consistency", reply: run },
    ]);
    const user = me({ features: { aiops: false, finops: false, jit: false, dr: false, databases: true, consistency: true } }, { approve: false, operate: true });
    renderAt(<Databases />, { api, user, path: "/?tab=consistency" });
    expect(await screen.findByText(/with different data: products/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "p-123456" })).toHaveAttribute("href", "/proposals/p-123456789");
    await userEvent.click(screen.getByRole("button", { name: "Report" }));
    expect(screen.getByText("differ (re-checked)")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Run check" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path === "/databases/dr-mysql/consistency")).toBe(true));
  });
});
