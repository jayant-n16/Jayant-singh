# Console sign-in: Entra ID or Okta

The console is a **public client** (single-page app, authorization code + PKCE, no secret). It
gets an access token for the OPLIA API; the API verifies the token (issuer, audience, signature
from the JWKS) and reads the user's roles from it. Two roles exist (names configurable with
`OPLIA_APPROVER_ROLE` / `OPLIA_OPERATOR_ROLE`):

| Role | Can |
|---|---|
| `oplia-approver` | approve/reject proposals and JIT requests, kill switch, audit log, DR trip/reset |
| `oplia-operator` | read everything operational, execute approved proposals, request JIT access |

A signed-in user with neither role sees "No access". Four-eyes is enforced by the API: nobody
approves their own request.

Below, `https://oplia.example.internal/` is the console URL (Ingress host) - use yours, with the
trailing slash, everywhere a redirect URI is asked for.

## Microsoft Entra ID

1. **API app registration** (Entra admin center → App registrations → New registration), name
   `OPLIA API`, single tenant, no redirect URI.
   * *Expose an API*: Application ID URI `api://oplia-api`; add scope `access` (admins and users
     can consent).
   * *App roles*: create `oplia-approver` and `oplia-operator` (allowed member types: Users/Groups).
   * *Manifest*: set the access-token version to 2 (`"requestedAccessTokenVersion": 2` in the
     Microsoft Graph manifest format, `"accessTokenAcceptedVersion": 2` in the older format).
2. **Console app registration**, name `OPLIA Console`, single tenant.
   * *Authentication* → add platform **Single-page application**, redirect URI
     `https://oplia.example.internal/`. Leave implicit grant off.
   * *API permissions* → My APIs → `OPLIA API` → delegated `access` → grant admin consent.
3. **Assign roles**: Enterprise applications → `OPLIA API` → Users and groups → add users or
   groups with `oplia-approver` / `oplia-operator`. Set "Assignment required" to Yes.
4. **API settings** (control plane, `oplia-config`):
   ```
   OPLIA_OIDC_ISSUER=https://login.microsoftonline.com/<tenant-id>/v2.0
   OPLIA_OIDC_AUDIENCE=<client id of the OPLIA API registration>   # v2 tokens carry the app id as aud
   OPLIA_OIDC_JWKS_URL=https://login.microsoftonline.com/<tenant-id>/discovery/v2.0/keys
   OPLIA_OIDC_ROLES_CLAIM=roles
   ```
5. **Console settings** (`oplia-console-config`, see `examples/console/console.env.example`):
   ```
   OPLIA_CONSOLE_AUTHORITY=https://login.microsoftonline.com/<tenant-id>/v2.0
   OPLIA_CONSOLE_CLIENT_ID=<client id of the OPLIA Console registration>
   OPLIA_CONSOLE_SCOPE=openid profile api://oplia-api/access
   ```

## Okta

1. **Authorization server** (Security → API → Authorization Servers → Add), audience `api://oplia`.
   * *Claims* → add claim `groups`, include in **Access Token**, value type *Groups*, filter
     *Starts with* `oplia-`.
   * *Access Policies* → add a policy for the console app with a rule allowing the
     Authorization Code grant.
2. **Groups**: create `oplia-approver` and `oplia-operator`, add people.
3. **App integration** (Applications → Create App Integration → OIDC → **Single-Page Application**):
   grant type Authorization Code (PKCE is enforced for SPAs), sign-in redirect URI and sign-out
   redirect URI `https://oplia.example.internal/`; assign the two groups.
4. **Trusted Origins** (Security → API → Trusted Origins): add `https://oplia.example.internal`
   with **CORS** (the browser calls Okta's token endpoint).
5. **API settings**:
   ```
   OPLIA_OIDC_ISSUER=https://<org>.okta.com/oauth2/<auth-server-id>
   OPLIA_OIDC_AUDIENCE=api://oplia
   OPLIA_OIDC_JWKS_URL=https://<org>.okta.com/oauth2/<auth-server-id>/v1/keys
   OPLIA_OIDC_ROLES_CLAIM=groups
   ```
6. **Console settings**:
   ```
   OPLIA_CONSOLE_AUTHORITY=https://<org>.okta.com/oauth2/<auth-server-id>
   OPLIA_CONSOLE_CLIENT_ID=<client id of the app integration>
   OPLIA_CONSOLE_SCOPE=openid profile
   ```

## Check it

```bash
curl -s https://oplia.example.internal/config.json          # the values above
curl -sI https://oplia.example.internal/ | grep -i content-security-policy   # connect-src lists the IdP origin
```

Sign in as an approver: the header shows the roles; `GET /api/me` (browser dev tools, Network)
returns `"can": {"approve": true, ...}`. If you get **401** after signing in, compare the token's
`iss` and `aud` (decode it at a JWT inspector you trust, offline) with `OPLIA_OIDC_ISSUER` /
`OPLIA_OIDC_AUDIENCE` - they must match exactly, including any trailing slash.

**Validation status**: these settings follow the providers' documented OIDC behaviour; they have
not been tried against a real Entra ID tenant or Okta org from this repository. The same flow is
tested end to end in CI with the local dev login (`oplia-dev-idp`).
