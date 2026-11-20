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
npm run e2e        # browser tests; needs the stack running (console on :8080, API, dev login)
```

## Container image

`Dockerfile` builds the app and serves it with nginx (Red Hat UBI 9, UID 1001, read-only root
filesystem supported; writes only to `/tmp`). Settings, validated at start-up (the container
exits with a clear message on a bad value):

| Variable | Required | Meaning |
|---|---|---|
| `OPLIA_CONSOLE_AUTHORITY` | yes | issuer URL of Entra ID / Okta; must be `https://` |
| `OPLIA_CONSOLE_CLIENT_ID` | yes | the console's app registration / app integration ID |
| `OPLIA_CONSOLE_SCOPE` | no | default `openid profile`; Entra also needs the API scope |
| `OPLIA_CONSOLE_API_UPSTREAM` | yes | `http(s)://host[:port]` of the API (no path) |
| `OPLIA_CONSOLE_ENVIRONMENT_LABEL` | no | header badge, e.g. `Production` |
| `OPLIA_CONSOLE_ALLOW_HTTP_AUTHORITY` | no | `true` only for the local dev login |

Responses carry a strict Content-Security-Policy (only this origin plus the identity provider's
origin), `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer` (OAuth codes never leak in
referrers), HSTS, and `no-store` for everything except fingerprinted assets. Access logs omit
query strings. Kubernetes manifests: `deploy/control-plane/console.yaml`; identity provider set-up:
`docs/console-login.md`.

Dependencies are pinned exactly; install with `npm@11.21.1 ci` (npm 10.9 fails to resolve vitest
4's optional peers).
