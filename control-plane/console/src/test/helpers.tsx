import { render } from "@testing-library/react";
import type { ReactElement } from "react";
import { MemoryRouter, Route, Routes } from "react-router";

import type { Api } from "../api";
import { SessionProvider } from "../session";
import type { Me } from "../types";

export function me(over: Partial<Me> = {}, can: Partial<Me["can"]> = {}): Me {
  return {
    subject: "alice",
    roles: ["oplia-approver"],
    can: { approve: true, operate: false, read: true, ...can },
    features: { aiops: false, finops: false, jit: false, dr: false },
    ...over,
  };
}

export type Route_ = { method: "GET" | "POST"; path: string; reply: unknown | ((body: unknown, query?: unknown) => unknown) };

/** A fake API: routes are matched on method + path; every call is recorded. */
export function fakeApi(routes: Route_[]) {
  const calls: { method: string; path: string; body?: unknown; query?: unknown }[] = [];
  const find = (method: string, path: string) => {
    const r = routes.find((x) => x.method === method && x.path === path);
    if (!r) throw new Error(`unexpected ${method} ${path}`);
    return r;
  };
  const api: Api = {
    async get<T>(path: string, query?: Record<string, unknown>) {
      calls.push({ method: "GET", path, query });
      const r = find("GET", path);
      const v = typeof r.reply === "function" ? (r.reply as (b: unknown, q?: unknown) => unknown)(undefined, query) : r.reply;
      if (v instanceof Error) throw v;
      return v as T;
    },
    async post<T>(path: string, body?: unknown) {
      calls.push({ method: "POST", path, body });
      const r = find("POST", path);
      const v = typeof r.reply === "function" ? (r.reply as (b: unknown) => unknown)(body) : r.reply;
      if (v instanceof Error) throw v;
      return v as T;
    },
  };
  return { api, calls };
}

export function renderAt(ui: ReactElement, { api, user, path = "/", route = "/" }: { api: Api; user: Me; path?: string; route?: string }) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <SessionProvider api={api} me={user}>
        <Routes>
          <Route path={route} element={ui} />
        </Routes>
      </SessionProvider>
    </MemoryRouter>,
  );
}
