/** Runtime configuration, served as /config.json (generated from environment variables in the container). */
export interface ConsoleConfig {
  authority: string;
  clientId: string;
  scope: string;
  apiBase: string;
  environmentLabel?: string;
}

export function parseConfig(raw: unknown): ConsoleConfig {
  if (typeof raw !== "object" || raw === null) throw new Error("config.json is not an object");
  const r = raw as Record<string, unknown>;
  const str = (k: string): string => {
    const v = r[k];
    if (typeof v !== "string" || v.trim() === "") throw new Error(`config.json: "${k}" is required`);
    return v.trim();
  };
  const authority = str("authority");
  if (!/^https?:\/\//.test(authority)) throw new Error('config.json: "authority" must be an http(s) URL');
  const apiBase = str("apiBase").replace(/\/+$/, "");
  if (!apiBase.startsWith("/")) throw new Error('config.json: "apiBase" must be a same-origin path such as /api');
  const label = r.environmentLabel;
  return {
    authority,
    clientId: str("clientId"),
    scope: str("scope"),
    apiBase,
    ...(typeof label === "string" && label ? { environmentLabel: label } : {}),
  };
}

export async function loadConfig(fetchImpl: typeof fetch = fetch): Promise<ConsoleConfig> {
  const res = await fetchImpl("/config.json", { cache: "no-store" });
  if (!res.ok) throw new Error(`config.json: HTTP ${res.status}`);
  return parseConfig(await res.json());
}
