/** Thin client for the OPLIA API. Every call carries the user's access token; the API enforces roles. */
export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly detail: string,
  ) {
    super(`HTTP ${status}: ${detail}`);
    this.name = "ApiError";
  }
}

type Query = Record<string, string | number | boolean | undefined | null>;

export interface Api {
  get<T>(path: string, query?: Query): Promise<T>;
  post<T>(path: string, body?: unknown): Promise<T>;
}

export function detailText(body: unknown): string {
  if (body && typeof body === "object" && "detail" in body) {
    const d = (body as { detail: unknown }).detail;
    if (typeof d === "string") return d;
    if (Array.isArray(d)) {
      return d
        .map((e) => {
          if (e && typeof e === "object") {
            const o = e as { msg?: unknown; loc?: unknown };
            const loc = Array.isArray(o.loc) ? o.loc.filter((x) => x !== "body").join(".") : "";
            return `${loc ? loc + ": " : ""}${String(o.msg ?? "")}`;
          }
          return String(e);
        })
        .join("; ");
    }
  }
  return "";
}

export function createApi(
  base: string,
  getToken: () => string | null,
  onUnauthorized: () => void,
  fetchImpl: typeof fetch = (...a) => fetch(...a),
): Api {
  async function call<T>(method: string, path: string, query?: Query, body?: unknown): Promise<T> {
    const qs = new URLSearchParams();
    for (const [k, v] of Object.entries(query ?? {})) if (v !== undefined && v !== null && v !== "") qs.set(k, String(v));
    const url = `${base}${path}${qs.size ? `?${qs.toString()}` : ""}`;
    const headers: Record<string, string> = { Accept: "application/json" };
    const token = getToken();
    if (token) headers.Authorization = `Bearer ${token}`;
    if (body !== undefined) headers["Content-Type"] = "application/json";
    let res: Response;
    try {
      res = await fetchImpl(url, {
        method,
        headers,
        credentials: "omit",
        ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
      });
    } catch {
      throw new ApiError(0, "the OPLIA API could not be reached");
    }
    const text = await res.text();
    let parsed: unknown = undefined;
    if (text) {
      try {
        parsed = JSON.parse(text);
      } catch {
        parsed = undefined;
      }
    }
    if (res.status === 401) onUnauthorized();
    if (!res.ok) throw new ApiError(res.status, detailText(parsed) || res.statusText || "request failed");
    return parsed as T;
  }
  return {
    get: (path, query) => call("GET", path, query),
    post: (path, body) => call("POST", path, undefined, body ?? {}),
  };
}
