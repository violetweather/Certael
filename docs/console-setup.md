# Operator console setup

This guide covers the React investigation console in `console/` and its ASP.NET
Core backend-for-frontend (BFF) in `backend/Certael.Console.Bff/`.

The console is an operator surface for evidence and case management. It must not
be exposed as an unauthenticated static site, and the browser must never call the
Core API directly.

## Choose a setup

- Use the **UI preview** to inspect the interface with local fixture data. It has
  no real authentication, Core connection, or enforcement authority.
- Use the **secured setup** to connect real operators to Core through OIDC,
  token exchange, and an mTLS-authenticated BFF.

## Prerequisites

- Node.js 22 or newer with Corepack and pnpm 11.9.0 when building from source;
  published BFF packages and images already contain the React application
- .NET 10 SDK for the BFF
- A production OIDC issuer or a dedicated development issuer
- An authorization server or security-token service that supports delegated
  token exchange for the Core audience
- A client certificate trusted for the BFF workload identity
- An HTTPS Core endpoint configured to validate that certificate and the
  certificate-bound delegated access token

From the repository root, source contributors install the console dependencies:

```bash
corepack enable
cd console
pnpm install --frozen-lockfile
```

## Fast Auth0 bootstrap

Use the shared installer engine to create a bounded external configuration and a
30-day, development-only client certificate:

```bash
certaelctl console init-auth0 ./certael-config \
  https://YOUR_TENANT.auth0.com \
  https://YOUR_TENANT.mtls.auth0.com/oauth/token \
  YOUR_CONFIDENTIAL_CLIENT_ID \
  https://certael-api.example \
  https://core.internal.example
```

The command prints the certificate's `x5t#S256` thumbprint and writes:

- `console/appsettings.Certael.json` without either client secret;
- `console/workload-development.pfx` with client-auth usage;
- `console/README.txt` with the remaining Auth0 and Core trust steps;
- a transactional installation journal for rollback and diagnosis.

Inject `Authentication__ClientSecret` and `TokenExchange__ClientSecret` from a
secret manager, set `CERTAEL_CONSOLE_CONFIG` to the generated JSON file, and
start the published BFF. Do not use the generated certificate in production.

## UI-only local preview

The fixture server returns a realistic operator, case queue, evidence bundle,
notes, activity, and bounded-action state. It is for visual and interaction QA
only.

In one terminal from `console/`:

```bash
node qa/fixture-server.mjs
```

In a second terminal on macOS or Linux:

```bash
CERTAEL_BFF_TARGET=http://127.0.0.1:7184 pnpm run dev -- --host 127.0.0.1 --port 4173
```

In PowerShell:

```powershell
$env:CERTAEL_BFF_TARGET = 'http://127.0.0.1:7184'
pnpm run dev -- --host 127.0.0.1 --port 4173
```

Open `http://localhost:4173`. Do not bind this preview to a public interface or
use it to make real decisions.

## Secured request path

Production uses one browser origin:

```text
Operator browser
  https://console.example.com/
       |-- /          -> immutable React static files
       `-- /bff/*     -> Certael.Console.Bff
                              |-- OIDC authorization code + PKCE
                              |-- delegated token exchange over mTLS
                              `-- Core API over mTLS + short-lived bearer token
```

Keep Core, PostgreSQL, Redis, NATS, and ClickHouse on private networks. Only the
same-origin console gateway should be reachable by operator browsers.

## 1. Register the OIDC application

Create a confidential web application in the operator identity provider.

Configure:

- authorization-code flow;
- PKCE;
- redirect URI `https://console.example.com/signin-oidc`;
- post-logout URI for the console origin;
- scopes `openid`, `profile`, and optionally `offline_access`;
- short operator sessions with reauthentication appropriate to action risk;
- MFA for every operator;
- group or role assignment for game-security and live-operations staff.

The authenticated identity must produce stable `sub`, `tenant_id`, and
`environment_id` claims. Authorization must issue only the scopes the operator
is entitled to use:

| Scope | Capability |
|---|---|
| `evidence:read` | inspect evidence and findings |
| `cases:read` | view case queues and details |
| `cases:write` | assign, annotate, transition, and disposition cases |
| `cases:act` | approve bounded actions |
| `privacy:export` | export player data under the privacy workflow |

The BFF requests the full console scope set during token exchange. The
authorization server must intersect that request with the operator's assigned
roles; it must never grant scopes merely because the BFF requested them.

The token provider implements Auth0's RFC 8693 on-behalf-of exchange. Configure
an Auth0 Custom API client grant for the Core audience and grant only the scopes
assigned to each operator. Auth0's [OBO token exchange guide](https://auth0.com/docs/secure/call-apis-on-users-behalf/on-behalf-of-token-exchange)
documents the required confidential client and user-delegated access grant.

## 2. Provision the BFF workload identity

Issue a dedicated client certificate for the BFF. Give it client-auth usage,
short validity, a documented owner, and a rotation procedure. Store the PFX and
its password in the deployment secret manager, not in the repository or image.

Core and the token-exchange endpoint must validate the certificate. Delegated
Core tokens must contain a `cnf.x5t#S256` binding to that same certificate and
use the configured Core audience. The BFF rejects an exchanged token without
the exact binding before it can reach Core. Auth0 documents the required tenant
features in [mTLS sender constraining](https://auth0.com/docs/secure/sender-constraining/mtls-sender-constraining).

Do not reuse a game-server certificate, developer certificate, or certificate
from another environment.

## 3. Configure the BFF

The BFF reads standard ASP.NET Core hierarchical configuration. A representative
environment is:

```text
Authentication__Authority=https://identity.example.com/realms/certael
Authentication__ClientId=certael-console
Authentication__ClientSecret=<secret-manager reference>
Authentication__Scopes__0=openid
Authentication__Scopes__1=profile
TokenExchange__Endpoint=https://identity.example.com/oauth/token
TokenExchange__ClientId=certael-console-obo
TokenExchange__ClientSecret=<secret-manager reference>
TokenExchange__Audience=certael-api
TokenExchange__Scopes=evidence:read cases:read cases:write cases:act privacy:export
Core__BaseUrl=https://certael-api.internal:8080
Core__Audience=certael-api
WorkloadIdentity__CertificatePath=/run/secrets/console-bff.pfx
WorkloadIdentity__CertificatePassword=<secret-manager reference>
```

The token endpoint defaults to `<authority>/oauth/token`; set it explicitly for
Auth0's mTLS hostname. The BFF caches each delegated token until one minute
before expiry, coalesces concurrent exchanges, and never logs token bodies or
client secrets. It fails startup when required identity, Core, or certificate
configuration is missing. Never place real secrets in JSON.

The BFF itself must listen on HTTPS or sit behind a trusted TLS-terminating
proxy. If TLS terminates at a proxy, configure forwarded-header trust narrowly
and ensure the external scheme remains HTTPS so the `__Host-certael-console`
cookie is accepted.

## 4. Build the unified console deployable

Publish the BFF from the repository root:

```bash
dotnet publish backend/Certael.Console.Bff/Certael.Console.Bff.csproj \
  -c Release -o artifacts/console-bff
```

The publish target runs the locked frontend install and production build, then
places the assets in the BFF's `wwwroot`. The BFF serves immutable hashed assets,
an uncached HTML entry, OIDC endpoints, and `/bff/api/*` from one origin. Its
multi-stage Dockerfile performs the same frontend and .NET builds.

Use `-p:BuildConsole=false` only when a packaging pipeline has already populated
`wwwroot` with a separately verified console build.

The repository's Compose development profile does not currently deploy the
console, BFF, OIDC issuer, or production TLS gateway. Do not treat the plain-HTTP
Compose API as a secured console backend.

## 5. Access the console

Browse to:

```text
https://console.example.com/
```

The React application calls `/bff/session`. An unauthenticated operator sees the
sign-in screen and follows `/bff/login?returnUrl=%2F`. After OIDC completes, the
BFF returns an HTTP-only, Secure, SameSite=Lax `__Host-certael-console` cookie.
OIDC and Core access tokens remain behind the BFF and are not exposed to React.

All state-changing requests and logout require the antiforgery token returned by
`/bff/antiforgery` in the `X-Certael-CSRF` header.

## 6. Production security checklist

- Restrict the console with a VPN or zero-trust access gateway in addition to
  OIDC; it is an internal operator tool.
- Require MFA and phishing-resistant credentials for `cases:act` operators.
- Keep `/healthz` minimally informative and restrict it to monitoring networks.
- Apply rate limits to login, token exchange, search, export, and mutations.
- Set explicit absolute operator-session and upstream-token lifetimes.
- Rotate OIDC secrets and workload certificates and test revocation.
- Allow the BFF to reach only the identity service and Core endpoints it needs.
- Allow the browser origin to reach only the gateway; never expose Core directly.
- Preserve the BFF's CSP, `frame-ancestors 'none'`, no-referrer policy, disabled
  camera/microphone/location permissions, and MIME-sniffing protection.
- Ensure Core independently authorizes every scope and enforces tenant RLS. UI
  visibility is not an authorization control.
- Send sign-in, authorization denial, case mutation, bounded action, export, and
  certificate events to protected audit storage.
- Back up and exercise recovery for the authoritative PostgreSQL case data.

## 7. Verification

Before granting operator access, verify:

1. An unauthenticated browser receives the sign-in screen.
2. A user without a console role cannot obtain console scopes.
3. A read-only operator cannot mutate or execute a bounded action.
4. Tenant and environment claims cannot be changed through query parameters.
5. A missing, expired, revoked, or wrong-environment BFF certificate fails closed.
6. A request without a valid CSRF token cannot mutate state or log out.
7. Core is unreachable from the public network and from the browser directly.
8. Bounded actions require scope, reason, confirmation, and an immutable audit
   record.
9. Keyboard-only operation, focus, zoomed text, error states, and large queues
   remain usable.

For the wider deployment boundary, continue with [Production operations](operations.md),
[Authorization](authorization.md), and [Incident response](incident-response.md).
