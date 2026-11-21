import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import Integrations from "../pages/Integrations";
import { buildChange } from "../pages/IntegrationSettings";
import type { IntegrationSettings, SettingsCatalog } from "../types";
import { fakeApi, me, renderAt } from "./helpers";

const status = [{ name: "slack", category: "alerting", target: "incident webhook", secrets: ["slack_webhook_url"],
  status: "not_configured", detail: "not set up on this control plane", can_test_notification: false,
  checked_at: "2026-11-21T10:00:00+00:00", latency_ms: 0 },
{ name: "github", category: "cicd", target: "", secrets: ["github_dispatch_token"], status: "not_configured",
  detail: "not set up", can_test_notification: false, checked_at: "2026-11-21T10:00:00+00:00", latency_ms: 0 }];

const slack: IntegrationSettings = {
  name: "slack", category: "alerting", note: "",
  fields: [{ key: "OPLIA_AIOPS_CHANNELS", label: "Alert channels", kind: "list", options: [], help: "",
    value: ["pagerduty", "slack"], source: "default" }],
  secrets: [{ name: "slack_webhook_url", present: false }],
};
const github: IntegrationSettings = {
  name: "github", category: "cicd", note: "",
  fields: [{ key: "OPLIA_CICD__GITHUB_REPOSITORY", label: "Repository", kind: "text", options: [], help: "",
    value: "acme/old", source: "applied" }],
  secrets: [{ name: "github_dispatch_token", present: true }],
};
const catalog = (writable: boolean): SettingsCatalog => ({
  integrations: [slack, github], secrets_writable: writable,
  vault_note: writable ? "" : "Secrets cannot be saved from the console: set OPLIA_SECRET_<NAME>.",
  restart_required: true, precedence: "applied in the console > environment variable > built-in default",
});

describe("integration settings", () => {
  it("operators get no settings buttons and never call the settings API", async () => {
    const { api, calls } = fakeApi([{ method: "GET", path: "/integrations", reply: status }]);
    renderAt(<Integrations />, { api, user: me({}, { approve: false, operate: true }) });
    expect(await screen.findByRole("heading", { name: "Alerting" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Settings/ })).not.toBeInTheDocument();
    expect(calls.some((c) => c.path === "/settings/integrations")).toBe(false);
  });

  it("an approver proposes a secret through Vault; only changed values are sent and the proposal is linked", async () => {
    const { api, calls } = fakeApi([
      { method: "GET", path: "/integrations", reply: status },
      { method: "GET", path: "/settings/integrations", reply: catalog(true) },
      { method: "POST", path: "/settings/integrations/slack",
        reply: { id: "p-1", action_type: "settings.integration", payload: { integration: "slack" }, status: "PENDING" } },
    ]);
    renderAt(<Integrations />, { api, user: me() });
    await userEvent.click(await screen.findByRole("button", { name: "Edit settings of slack" }));
    const dialog = screen.getByRole("dialog");
    const secret = within(dialog).getByLabelText("Secret slack_webhook_url");
    expect(secret).toHaveAttribute("type", "password");
    expect(secret).toHaveAttribute("autocomplete", "new-password");
    await userEvent.type(secret, "https://hooks.slack.com/services/T/B/X");
    await userEvent.type(within(dialog).getByLabelText("Reason"), "connect incident alerts to Slack");
    await userEvent.click(within(dialog).getByRole("button", { name: "Propose change" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST")).toBe(true));
    expect(calls.find((c) => c.method === "POST")!.body).toEqual({
      values: {}, reason: "connect incident alerts to Slack",
      secrets: { slack_webhook_url: "https://hooks.slack.com/services/T/B/X" } });
    expect(await screen.findByRole("link", { name: "open the proposal" })).toHaveAttribute("href", "/proposals/p-1");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("without Vault the secret fields are absent and the note explains OPLIA_SECRET_<NAME>", async () => {
    const { api } = fakeApi([
      { method: "GET", path: "/integrations", reply: status },
      { method: "GET", path: "/settings/integrations", reply: catalog(false) },
    ]);
    renderAt(<Integrations />, { api, user: me() });
    await userEvent.click(await screen.findByRole("button", { name: "Edit settings of github" }));
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).queryByLabelText(/Secret/)).not.toBeInTheDocument();
    expect(within(dialog).getByText(/OPLIA_SECRET_<NAME>/)).toBeInTheDocument();
  });

  it("buildChange sends lists, reverts a cleared applied value and refuses no-op changes", () => {
    expect(buildChange(slack, { "v:OPLIA_AIOPS_CHANNELS": "slack\n\n", reason: "only slack please" })).toEqual({
      values: { OPLIA_AIOPS_CHANNELS: ["slack"] }, secrets: {}, reason: "only slack please" });
    expect(buildChange(github, { "v:OPLIA_CICD__GITHUB_REPOSITORY": "", reason: "back to env value" }).values).toEqual({
      OPLIA_CICD__GITHUB_REPOSITORY: null });
    expect(() => buildChange(github, { "v:OPLIA_CICD__GITHUB_REPOSITORY": "acme/old", reason: "nothing changed" }))
      .toThrow("Nothing was changed.");
  });
});
