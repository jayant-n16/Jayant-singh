import { useMemo } from "react";
import { BrowserRouter, NavLink, Route, Routes } from "react-router";

import { createApi } from "./api";
import { ConnectionBanner, ConnectionProvider, useConnection } from "./connection";
import { useAuth } from "./auth";
import { ErrorNote, Loading } from "./components/ui";
import type { ConsoleConfig } from "./config";
import Aiops from "./pages/Aiops";
import Audit from "./pages/Audit";
import Dr from "./pages/Dr";
import FinOps from "./pages/FinOps";
import Jit from "./pages/Jit";
import Overview from "./pages/Overview";
import ProposalDetail from "./pages/ProposalDetail";
import Proposals from "./pages/Proposals";
import { SessionProvider, useResource } from "./session";
import type { Me } from "./types";

export default function App({ config }: { config: ConsoleConfig }) {
  const auth = useAuth();
  if (auth.status === "loading") return <Centered><Loading what="session" /></Centered>;
  if (auth.status !== "signedIn")
    return (
      <Centered>
        <h1>OPLIA Console</h1>
        {config.environmentLabel ? <p className="env-label">{config.environmentLabel}</p> : null}
        <p className="muted">Sign in with your organisation account to manage the control plane.</p>
        {auth.error ? <div className="note note-danger" role="alert">{auth.error}</div> : null}
        <button className="btn btn-primary" onClick={() => void auth.signIn()}>Sign in</button>
      </Centered>
    );
  return (
    <BrowserRouter>
      <ConnectionProvider base={config.apiBase}>
        <SignedIn config={config} />
      </ConnectionProvider>
    </BrowserRouter>
  );
}

function SignedIn({ config }: { config: ConsoleConfig }) {
  const auth = useAuth();
  const conn = useConnection();
  const api = useMemo(
    () => createApi(config.apiBase, auth.accessToken, auth.sessionExpired, undefined, conn.report),
    [config.apiBase, auth.accessToken, auth.sessionExpired, conn.report],
  );
  const me = useResource(() => api.get<Me>("/me"), [api]);

  if (me.loading && !me.data) return <Centered><Loading what="your access" /></Centered>;
  if (!me.data)
    return (
      <Centered>
        <ErrorNote error={me.error} />
        <button className="btn" onClick={me.reload}>Retry</button>{" "}
        <button className="btn" onClick={() => void auth.signOut()}>Sign out</button>
      </Centered>
    );
  const m = me.data;
  const name = (auth.user?.profile.name as string | undefined) ?? m.subject;

  return (
    <SessionProvider api={api} me={m}>
      <a className="skip" href="#main">Skip to content</a>
      <header className="topbar">
        <div className="brand">OPLIA <span>Console</span></div>
        {config.environmentLabel ? <span className="env-label">{config.environmentLabel}</span> : null}
        <div className="who">
          <span title={m.subject}>{name}</span>
          <span className="small muted">{m.roles.join(", ") || "no role"}</span>
          <button className="btn btn-small" onClick={() => void auth.signOut()}>Sign out</button>
        </div>
      </header>
      <ConnectionBanner />
      {!m.can.read ? (
        <main id="main" className="content">
          <h1>No access</h1>
          <p>
            You are signed in as <strong>{m.subject}</strong>, but your account has no OPLIA role. Ask an administrator for the
            operator or approver role in your identity provider.
          </p>
        </main>
      ) : (
        <div className="layout">
          <nav className="sidenav" aria-label="Main">
            <NavLink to="/" end>Overview</NavLink>
            <NavLink to="/proposals">Proposals</NavLink>
            {m.can.approve ? <NavLink to="/audit">Audit log</NavLink> : null}
            {m.features.dr ? <NavLink to="/dr">DR breakers</NavLink> : null}
            {m.features.finops ? <NavLink to="/finops">FinOps</NavLink> : null}
            {m.features.jit ? <NavLink to="/jit">JIT access</NavLink> : null}
            {m.features.aiops ? <NavLink to="/aiops">AIOps</NavLink> : null}
          </nav>
          <main id="main" className={conn.online ? "content" : "content stale"} aria-busy={!conn.online}>
            <Routes>
              <Route path="/" element={<Overview />} />
              <Route path="/proposals" element={<Proposals />} />
              <Route path="/proposals/:id" element={<ProposalDetail />} />
              <Route path="/audit" element={<Audit />} />
              <Route path="/dr" element={<Feature on={m.features.dr} name="DR circuit breaker"><Dr /></Feature>} />
              <Route path="/finops" element={<Feature on={m.features.finops} name="FinOps"><FinOps /></Feature>} />
              <Route path="/jit" element={<Feature on={m.features.jit} name="JIT access"><Jit /></Feature>} />
              <Route path="/aiops" element={<Feature on={m.features.aiops} name="AIOps"><Aiops /></Feature>} />
              <Route path="*" element={<><h1>Not found</h1><p><NavLink to="/">Back to overview</NavLink></p></>} />
            </Routes>
          </main>
        </div>
      )}
    </SessionProvider>
  );
}

function Feature({ on, name, children }: { on: boolean; name: string; children: React.ReactNode }) {
  if (!on) return <><h1>{name}</h1><div className="note">{name} is not configured on this control plane.</div></>;
  return <>{children}</>;
}

function Centered({ children }: { children: React.ReactNode }) {
  return <main className="centered" id="main">{children}</main>;
}
