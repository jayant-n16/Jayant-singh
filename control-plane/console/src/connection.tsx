import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";

/**
 * Tracks whether the OPLIA API is reachable. Any call that fails at the network level, or gets a
 * gateway-type error (500/502/503/504), triggers a probe of the unauthenticated /healthz endpoint
 * through the same proxy; only that probe decides whether the connection is up. While down, the
 * probe repeats every `intervalMs`.
 */
export interface ConnectionState {
  online: boolean;
  lostAt: Date | null;
  report: (status: number) => void;
  probe: () => Promise<void>;
}

const Ctx = createContext<ConnectionState | null>(null);
export const SUSPECT_STATUSES = new Set([0, 500, 502, 503, 504]);

export async function healthy(base: string, fetchImpl: typeof fetch = (...a) => fetch(...a)): Promise<boolean> {
  try {
    const res = await fetchImpl(`${base}/healthz`, { cache: "no-store", credentials: "omit" });
    if (!res.ok) return false;
    const body = (await res.json()) as { status?: unknown };
    return body.status === "ok";
  } catch {
    return false;
  }
}

export function ConnectionProvider({
  base, intervalMs = 15000, fetchImpl, children,
}: { base: string; intervalMs?: number; fetchImpl?: typeof fetch; children: ReactNode }) {
  const [online, setOnline] = useState(true);
  const [lostAt, setLostAt] = useState<Date | null>(null);
  const probing = useRef(false);

  const probe = useCallback(async () => {
    if (probing.current) return;
    probing.current = true;
    try {
      const ok = await healthy(base, fetchImpl);
      setOnline((was) => {
        if (!ok && was) setLostAt(new Date());
        if (ok) setLostAt(null);
        return ok;
      });
    } finally {
      probing.current = false;
    }
  }, [base, fetchImpl]);

  const report = useCallback((status: number) => {
    if (SUSPECT_STATUSES.has(status)) void probe();
  }, [probe]);

  useEffect(() => {
    if (online) return;
    const t = window.setInterval(() => void probe(), intervalMs);
    return () => window.clearInterval(t);
  }, [online, intervalMs, probe]);

  return <Ctx.Provider value={{ online, lostAt, report, probe }}>{children}</Ctx.Provider>;
}

export function useConnection(): ConnectionState {
  const c = useContext(Ctx);
  if (!c) throw new Error("useConnection outside ConnectionProvider");
  return c;
}

export function ConnectionBanner() {
  const { online, lostAt, probe } = useConnection();
  if (online) return null;
  return (
    <div className="conn-banner" role="alert">
      <strong>Connection to the OPLIA API lost — data on screen may be out of date.</strong>{" "}
      {lostAt ? <span className="small">Since {lostAt.toLocaleTimeString()}. Retrying every 15 seconds.</span> : null}{" "}
      <button className="btn btn-small" onClick={() => void probe()}>Retry now</button>
    </div>
  );
}
