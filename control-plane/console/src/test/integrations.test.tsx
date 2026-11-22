import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import Integrations from "../pages/Integrations";
import { fakeApi, me, renderAt } from "./helpers";

const row = (over: Record<string, unknown>) => ({ name: "aws", category: "cloud", target: "ap-south-1", secrets: [],
  status: "ok", detail: "authenticated to AWS account 123456789012", can_test_notification: false,
  checked_at: "2026-11-20T10:00:00+00:00", latency_ms: 120, ...over });

describe("integrations", () => {
  const rows = [row({}), row({ name: "github", category: "cicd", status: "error", detail: "HttpError: 401", secrets: ["github_dispatch_token"] }),
    row({ name: "slack", category: "alerting", status: "configured", detail: "secret present", can_test_notification: true })];

  it("groups by category, shows errors and hides the test button from operators", async () => {
    const { api } = fakeApi([{ method: "GET", path: "/integrations", reply: rows }]);
    renderAt(<Integrations />, { api, user: me({}, { approve: false, operate: true }) });
    expect(await screen.findByRole("heading", { name: "Clouds" })).toBeInTheDocument();
    expect(screen.getByText("HttpError: 401")).toBeInTheDocument();
    expect(screen.getByText("github_dispatch_token")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Send test/ })).not.toBeInTheDocument();
  });

  it("an approver sends a test notification and sees the result", async () => {
    const { api, calls } = fakeApi([
      { method: "GET", path: "/integrations", reply: rows },
      { method: "POST", path: "/integrations/slack/test", reply: { ok: true, detail: "Slack test message sent", error: null } },
    ]);
    renderAt(<Integrations />, { api, user: me() });
    await userEvent.click(await screen.findByRole("button", { name: /Send test/ }));
    await userEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Send test" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST")).toBe(true));
    expect(await screen.findByText(/slack: Slack test message sent/)).toBeInTheDocument();
  });
});
