import { createHmac } from "node:crypto";

import { expect, test, type Page } from "@playwright/test";

// Needs: console at baseURL (/api proxied to the API), oplia-dev-idp, and the API started with
// OPLIA_SECRET_WEBHOOK_HMAC_SECRET=$OPLIA_E2E_WEBHOOK_SECRET on a fresh database.
const SECRET = process.env.OPLIA_E2E_WEBHOOK_SECRET ?? "local-test-secret";

async function driftEvent(page: Page, zone: string): Promise<string> {
  const body = JSON.stringify({
    zone_name: zone, cloud: "aws", account_id: "111122223333", blueprint: "control-tower-standard",
    target_cicd: "github", detail: "security group opened to 0.0.0.0/0",
  });
  const ts = String(Math.floor(Date.now() / 1000));
  const sig = "sha256=" + createHmac("sha256", SECRET).update(`${ts}.${body}`).digest("hex");
  const res = await page.request.post("/api/webhooks/drift", {
    data: body,
    headers: { "Content-Type": "application/json", "X-OPLIA-Timestamp": ts, "X-OPLIA-Delivery": `e2e-${zone}-${ts}-${Math.random()}`, "X-OPLIA-Signature": sig },
  });
  expect(res.status(), await res.text()).toBe(202);
  return ((await res.json()) as { id: string }).id;
}

async function signIn(page: Page, user: string) {
  await page.goto("/");
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.getByRole("button", { name: new RegExp(`^${user}`) }).click();
  await expect(page.getByRole("heading", { name: "Overview" }).or(page.getByRole("heading", { name: "No access" }))).toBeVisible();
}

async function signOut(page: Page) {
  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page.getByRole("button", { name: "Sign in" })).toBeVisible();
}

test.describe.configure({ mode: "serial" });

test("security headers and config are served", async ({ page }) => {
  const res = await page.goto("/");
  const csp = res!.headers()["content-security-policy"] ?? "";
  // the dev setup may run without the container (vite); then there is no CSP to check
  test.skip(!csp, "console not served by the nginx container");
  expect(csp).toContain("default-src 'self'");
  expect(csp).toContain("frame-ancestors 'none'");
  expect(res!.headers()["x-content-type-options"]).toBe("nosniff");
  expect(res!.headers()["cache-control"]).toBe("no-store");
  const cfg = await (await page.request.get("/config.json")).json();
  expect(cfg).toMatchObject({ clientId: "oplia-console", apiBase: "/api" });
});

test("approver approves, engages and releases the kill switch; operator is blocked; no-role user has no access", async ({ page }) => {
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(String(e)));
  page.on("console", (m) => m.type() === "error" && errors.push(m.text()));

  const id = await driftEvent(page, "e2e-zone-a");
  await driftEvent(page, "e2e-zone-b");

  await signIn(page, "alice");
  await expect(page.locator(".who")).toContainText("oplia-approver");
  await page.goto(`/proposals/${id}`);
  await expect(page.getByRole("heading", { name: "drift.remediate" })).toBeVisible();
  await page.getByRole("button", { name: "Approve" }).click();
  const dlg = page.getByRole("dialog");
  await dlg.getByLabel(/Note/).fill("approved by e2e");
  await dlg.getByRole("button", { name: "Approve" }).click();
  await expect(dlg).toBeHidden();
  await expect(page.locator(".badge", { hasText: "APPROVED" }).first()).toBeVisible();
  await expect(page.getByRole("cell", { name: "approved", exact: true })).toBeVisible(); // audit trail row

  await page.getByRole("link", { name: "Overview" }).click();
  await page.getByRole("button", { name: "Engage kill switch" }).click();
  await page.getByRole("dialog").getByLabel(/Reason/).fill("e2e freeze");
  await page.getByRole("dialog").getByRole("button", { name: "Engage" }).click();
  await expect(page.getByText("ENGAGED — all executors stopped")).toBeVisible();
  await page.getByRole("button", { name: "Verify audit chain" }).click();
  await expect(page.getByRole("status").filter({ hasText: /^Intact/ })).toBeVisible();
  await signOut(page);

  await signIn(page, "bob");
  await expect(page.getByRole("button", { name: /kill switch/ })).toHaveCount(0);
  await expect(page.getByRole("link", { name: "Audit log", exact: true })).toHaveCount(0);
  await page.goto(`/proposals/${id}`);
  await expect(page.getByRole("button", { name: "Execute" })).toBeDisabled();
  await expect(page.getByText(/kill switch is engaged/)).toBeVisible();
  // the API refuses the approver-only call even if the UI were bypassed
  const token = await page.evaluate(() => {
    const k = Object.keys(sessionStorage).find((x) => x.startsWith("oidc.user:"));
    return k ? (JSON.parse(sessionStorage.getItem(k)!) as { access_token: string }).access_token : "";
  });
  const forbidden = await page.request.post("/api/kill-switch", {
    data: { engaged: false, reason: "operator tries" }, headers: { Authorization: `Bearer ${token}` },
  });
  expect(forbidden.status()).toBe(403);
  await signOut(page);

  await signIn(page, "alice");
  await page.getByRole("button", { name: "Release kill switch" }).click();
  await page.getByRole("dialog").getByLabel(/Reason/).fill("e2e done");
  await page.getByRole("dialog").getByRole("button", { name: "Release" }).click();
  await expect(page.getByText("Released — executors may run")).toBeVisible();
  await signOut(page);

  await signIn(page, "dave");
  await expect(page.getByRole("heading", { name: "No access" })).toBeVisible();

  expect(errors, errors.join("\n")).toEqual([]);
});

test("deep link survives sign-in and an unknown route shows not found", async ({ page }) => {
  await page.goto("/audit");
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.getByRole("button", { name: /^carol/ }).click();
  await expect(page.getByRole("heading", { name: "Audit log" })).toBeVisible();
  await expect(page).toHaveURL(/\/audit$/);
  await page.goto("/no-such-page");
  await expect(page.getByRole("heading", { name: "Not found" })).toBeVisible();
});
