import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { createApi } from "../api";
import { ConnectionBanner, ConnectionProvider, healthy, useConnection } from "../connection";

function Reporter({ status }: { status: number }) {
  const c = useConnection();
  return <button onClick={() => c.report(status)}>report</button>;
}

function healthFetch(state: { up: boolean }) {
  return vi.fn(async () =>
    state.up
      ? new Response(JSON.stringify({ status: "ok" }), { status: 200 })
      : new Response("", { status: 502 }),
  ) as unknown as typeof fetch;
}

describe("connection tracking", () => {
  it("healthy() needs HTTP 200 with status ok", async () => {
    expect(await healthy("/api", healthFetch({ up: true }))).toBe(true);
    expect(await healthy("/api", healthFetch({ up: false }))).toBe(false);
    const html = vi.fn(async () => new Response("<html>", { status: 200 })) as unknown as typeof fetch;
    expect(await healthy("/api", html)).toBe(false); // e.g. a proxy error page
    const boom = vi.fn(async () => { throw new TypeError("Failed to fetch"); }) as unknown as typeof fetch;
    expect(await healthy("/api", boom)).toBe(false);
  });

  it("shows the banner only after the health probe fails, and clears it when the API is back", async () => {
    const state = { up: false };
    const f = healthFetch(state);
    render(
      <ConnectionProvider base="/api" intervalMs={50} fetchImpl={f}>
        <ConnectionBanner />
        <Reporter status={0} />
      </ConnectionProvider>,
    );
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "report" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Connection to the OPLIA API lost — data on screen may be out of date");
    expect(f).toHaveBeenCalledWith("/api/healthz", expect.anything());
    state.up = true;
    await waitFor(() => expect(screen.queryByRole("alert")).not.toBeInTheDocument(), { timeout: 2000 });
  });

  it("a normal 4xx answer does not trigger a probe", async () => {
    const f = healthFetch({ up: false });
    render(
      <ConnectionProvider base="/api" fetchImpl={f}>
        <ConnectionBanner />
        <Reporter status={403} />
      </ConnectionProvider>,
    );
    await userEvent.click(screen.getByRole("button", { name: "report" }));
    await act(async () => { await new Promise((r) => setTimeout(r, 20)); });
    expect(f).not.toHaveBeenCalled();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("the API client reports every status, and 0 on network failure", async () => {
    const seen: number[] = [];
    const ok = vi.fn(async () => new Response("{}", { status: 200 })) as unknown as typeof fetch;
    await createApi("/api", () => null, () => {}, ok, (s) => seen.push(s)).get("/me");
    const down = vi.fn(async () => { throw new TypeError("x"); }) as unknown as typeof fetch;
    await createApi("/api", () => null, () => {}, down, (s) => seen.push(s)).get("/me").catch(() => {});
    expect(seen).toEqual([200, 0]);
  });
});
