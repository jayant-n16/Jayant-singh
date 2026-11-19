# OPLIA Console

Web console for the OPLIA control plane: proposals (approve / reject / execute), kill switch, audit
log and chain verification, DR circuit breakers, FinOps findings, JIT access and AIOps predictions.
It calls the existing API under `/api` on the same origin; **the API enforces every permission** -
the console only hides buttons a user's roles cannot use.

* React 18 + TypeScript (strict), Vite, react-router; no UI framework.
* Sign-in: OIDC authorization code + PKCE with `oidc-client-ts` (Entra ID, Okta, or the local
  dev login). No client secret; tokens in `sessionStorage` (gone when the tab closes); an expired
  token sends the user back to sign in.
* Runtime settings come from `/config.json` (`authority`, `clientId`, `scope`, `apiBase`,
  `environmentLabel`) so one build runs in every environment.

## Run locally (with the dev login)

Needs Node.js 20+ and the control plane installed (`pip install -e ".[dev,...]"` in `control-plane/`).

```bash
# terminal 1 - local login (dev only)
export OPLIA_ENVIRONMENT=dev
oplia-dev-idp

# terminal 2 - API
export OPLIA_ENVIRONMENT=dev OPLIA_DATABASE_URL=sqlite:///./oplia-dev.db
export OPLIA_OIDC_ISSUER=http://127.0.0.1:8090/ OPLIA_OIDC_AUDIENCE=oplia-api
export OPLIA_OIDC_JWKS_URL=http://127.0.0.1:8090/jwks OPLIA_SECRET_WEBHOOK_HMAC_SECRET=local-test-secret
uvicorn oplia_ctl.main:app --port 8080

# terminal 3 - console
cd console
npx -y npm@11.21.1 ci
npm run dev                       # http://localhost:5173
```

Open http://localhost:5173 (use `localhost`, not `127.0.0.1` - it is the registered redirect),
sign in as `alice` (approver), `bob` (operator), `carol` (both) or `dave` (no role).

## Checks

```bash
npm run typecheck && npm test && npm run build
```

Dependencies are pinned exactly; install with `npm@11.21.1 ci` (npm 10.9 fails to resolve vitest
4's optional peers).
