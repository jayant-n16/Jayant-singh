import { User, UserManager, WebStorageStateStore } from "oidc-client-ts";
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";

import type { ConsoleConfig } from "./config";

/**
 * Sign-in with the organisation's identity provider (Entra ID, Okta, or the local dev login):
 * OAuth 2.0 authorization code flow with PKCE, no client secret in the browser. Tokens are kept
 * in sessionStorage (cleared when the tab closes); an expired session sends the user back to sign in.
 */
export interface AuthState {
  status: "loading" | "signedOut" | "signedIn" | "error";
  user: User | null;
  error: string | null;
  signIn: (returnTo?: string) => Promise<void>;
  signOut: () => Promise<void>;
  accessToken: () => string | null;
  sessionExpired: () => void;
}

const AuthContext = createContext<AuthState | null>(null);

export function makeUserManager(cfg: ConsoleConfig, origin: string = window.location.origin): UserManager {
  return new UserManager({
    authority: cfg.authority,
    client_id: cfg.clientId,
    redirect_uri: `${origin}/`,
    post_logout_redirect_uri: `${origin}/`,
    response_type: "code",
    scope: cfg.scope,
    loadUserInfo: false,
    automaticSilentRenew: false,
    monitorSession: false,
    userStore: new WebStorageStateStore({ store: window.sessionStorage }),
    stateStore: new WebStorageStateStore({ store: window.sessionStorage }),
  });
}

function isCallback(loc: Location): boolean {
  const q = new URLSearchParams(loc.search);
  return (q.has("code") || q.has("error")) && q.has("state");
}

export function safeReturnPath(v: unknown): string {
  // only same-origin paths; never an absolute or protocol-relative URL
  return typeof v === "string" && v.startsWith("/") && !v.startsWith("//") && !v.includes("\\") ? v : "/";
}

export function AuthProvider({ manager, children }: { manager: UserManager; children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [status, setStatus] = useState<AuthState["status"]>("loading");
  const [error, setError] = useState<string | null>(null);
  const started = useRef(false);

  useEffect(() => {
    if (started.current) return; // React StrictMode runs effects twice in development
    started.current = true;
    (async () => {
      try {
        if (isCallback(window.location)) {
          const q = new URLSearchParams(window.location.search);
          if (q.has("error")) throw new Error(q.get("error_description") || q.get("error") || "sign-in failed");
          const u = await manager.signinRedirectCallback();
          window.history.replaceState(null, "", safeReturnPath(u.state));
          setUser(u);
          setStatus("signedIn");
          return;
        }
        const u = await manager.getUser();
        if (u && !u.expired) {
          setUser(u);
          setStatus("signedIn");
        } else {
          if (u) await manager.removeUser();
          setStatus("signedOut");
        }
      } catch (e) {
        window.history.replaceState(null, "", "/");
        setError(e instanceof Error ? e.message : String(e));
        setStatus("error");
      }
    })();
  }, [manager]);

  const signIn = useCallback(
    async (returnTo?: string) => {
      const path = safeReturnPath(returnTo ?? window.location.pathname + window.location.search);
      await manager.signinRedirect({ state: path });
    },
    [manager],
  );

  const signOut = useCallback(async () => {
    const idToken = user?.id_token;
    await manager.removeUser();
    setUser(null);
    setStatus("signedOut");
    let endSession: string | undefined;
    try {
      endSession = await manager.metadataService.getEndSessionEndpoint();
    } catch {
      endSession = undefined;
    }
    if (endSession) await manager.signoutRedirect(idToken ? { id_token_hint: idToken } : {});
  }, [manager, user]);

  const accessToken = useCallback(() => (user && !user.expired ? user.access_token : null), [user]);

  const sessionExpired = useCallback(() => {
    void manager.removeUser();
    setUser(null);
    setError("Your session has expired. Sign in again.");
    setStatus("signedOut");
  }, [manager]);

  const value = useMemo<AuthState>(
    () => ({ status, user, error, signIn, signOut, accessToken, sessionExpired }),
    [status, user, error, signIn, signOut, accessToken, sessionExpired],
  );
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth outside AuthProvider");
  return ctx;
}
