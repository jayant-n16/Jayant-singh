import { ApiError, createApi, detailText } from "../api";
import { safeReturnPath } from "../auth";
import { parseConfig } from "../config";

function fetchReturning(status: number, body: unknown) {
  return vi.fn(async (_url: RequestInfo | URL, _init?: RequestInit) =>
    new Response(body === undefined ? "" : JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } }));
}

describe("api client", () => {
  it("sends the bearer token, JSON body and query, under the API base", async () => {
    const f = fetchReturning(200, { ok: true });
    const api = createApi("/api", () => "tok-1", () => {}, f as unknown as typeof fetch);
    await api.get("/proposals", { status_filter: "PENDING", limit: 5, empty: "", none: undefined });
    await api.post("/kill-switch", { engaged: true, reason: "x" });
    const [url1, init1] = f.mock.calls[0]!;
    expect(url1).toBe("/api/proposals?status_filter=PENDING&limit=5");
    expect((init1!.headers as Record<string, string>).Authorization).toBe("Bearer tok-1");
    expect(init1!.credentials).toBe("omit");
    const [url2, init2] = f.mock.calls[1]!;
    expect(url2).toBe("/api/kill-switch");
    expect(init2!.method).toBe("POST");
    expect(JSON.parse(String(init2!.body))).toEqual({ engaged: true, reason: "x" });
  });

  it("omits the Authorization header when signed out", async () => {
    const f = fetchReturning(200, {});
    await createApi("/api", () => null, () => {}, f as unknown as typeof fetch).get("/healthz");
    expect((f.mock.calls[0]![1]!.headers as Record<string, string>).Authorization).toBeUndefined();
  });

  it("raises ApiError with the server's detail and reports 401", async () => {
    const expired = vi.fn();
    const api = createApi("/api", () => "t", expired, fetchReturning(401, { detail: "invalid token: ExpiredSignatureError" }) as unknown as typeof fetch);
    await expect(api.get("/me")).rejects.toMatchObject({ status: 401, detail: "invalid token: ExpiredSignatureError" });
    expect(expired).toHaveBeenCalledOnce();
    const four = createApi("/api", () => "t", () => {}, fetchReturning(403, { detail: "approver must differ from requester" }) as unknown as typeof fetch);
    const err = await four.post("/proposals/x/approve").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).detail).toBe("approver must differ from requester");
  });

  it("reports an unreachable API as status 0", async () => {
    const f = vi.fn(async () => { throw new TypeError("Failed to fetch"); });
    await expect(createApi("/api", () => null, () => {}, f as unknown as typeof fetch).get("/me")).rejects.toMatchObject({ status: 0 });
  });

  it("formats FastAPI validation errors", () => {
    expect(detailText({ detail: [{ loc: ["body", "reason"], msg: "String should have at least 3 characters" }] }))
      .toBe("reason: String should have at least 3 characters");
    expect(detailText({ detail: "plain" })).toBe("plain");
    expect(detailText("x")).toBe("");
  });
});

describe("config", () => {
  it("accepts a valid config and trims the API base", () => {
    expect(parseConfig({ authority: "https://login.microsoftonline.com/t/v2.0", clientId: "c", scope: "openid", apiBase: "/api/" }))
      .toEqual({ authority: "https://login.microsoftonline.com/t/v2.0", clientId: "c", scope: "openid", apiBase: "/api" });
  });
  it.each([
    [{ clientId: "c", scope: "s", apiBase: "/api" }, "authority"],
    [{ authority: "javascript:alert(1)", clientId: "c", scope: "s", apiBase: "/api" }, "http(s) URL"],
    [{ authority: "https://idp", clientId: "c", scope: "s", apiBase: "https://evil.example.com" }, "same-origin"],
  ])("rejects %o", (raw, msg) => {
    expect(() => parseConfig(raw)).toThrow(msg);
  });
});

describe("return path after sign-in", () => {
  it.each([
    ["/proposals/abc", "/proposals/abc"],
    ["https://evil.example.com/", "/"],
    ["//evil.example.com", "/"],
    ["/\\evil.example.com", "/"],
    [undefined, "/"],
  ])("%s -> %s", (input, out) => {
    expect(safeReturnPath(input)).toBe(out);
  });
});
