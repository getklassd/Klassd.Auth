# Klassd.Auth

A self-hostable authentication core for .NET — email/password, **passwordless** one-time codes
(email + SMS), **passkeys** (WebAuthn/FIDO2), social login & SSO, **account linking**, MFA,
email verification, and a per-user metadata store. An independent, clean-room design built from a
public feature model, not a port or migration of any existing project's source.

> **Status:** beta (v0.0.1-beta.4). Module logic, session security, the auth methods below, and all
> three storage adapters work end-to-end and are covered by unit, Testcontainers and Playwright
> (WebAuthn) tests. Pre-1.0 — APIs may still shift, and provider endpoints track the upstream APIs.

## Packages

| Package | Purpose |
|---|---|
| `Klassd.Auth.Abstractions` | Store interfaces + DB-agnostic record types |
| `Klassd.Auth.Core` | Auth logic: email/password, sessions, third-party, MFA, email verification, metadata, account linking |
| `Klassd.Auth.AspNetCore` | JSON/JWT HTTP delivery — one `MapKlassdAuth()` call wires the whole API |
| `Klassd.Auth.AspNetCore.Cookies` | Cookie sign-in for server-rendered / Blazor apps + external-SSO & linking seam |
| `Klassd.Auth.Passwordless` | Passwordless one-time codes over email/SMS — `AddPasswordless()` + endpoints |
| `Klassd.Auth.Passkeys` | Passkeys (WebAuthn/FIDO2) via Fido2NetLib — `AddPasskeys()` + ceremony endpoints |
| `Klassd.Auth.Sms.Twilio` | Twilio `ISmsSender` for passwordless-over-SMS — `AddTwilioSms()` |
| `Klassd.Auth.Webhooks` | Inbound HMAC-signed webhooks to disable/enable/delete/anonymize users — `AddKlassdAuthWebhooks()` |
| `Klassd.Auth.Dashboard` | Drop-in Blazor (Interactive Server) user-admin dashboard — `AddKlassdAuthDashboard()` |
| `Klassd.Auth.OpenIdConnect` | OIDC external login + **Microsoft Entra ID** (`AddEntraId`) + Google (`AddGoogle`) |
| `Klassd.Auth.OAuth` | OAuth 2.0 (non-OIDC) providers — GitHub, **Facebook, Instagram, TikTok** |
| `Klassd.Auth.Data.Sqlite` | SQLite adapter (raw `Microsoft.Data.Sqlite`, JSON-in-TEXT) |
| `Klassd.Auth.Data.Postgres` | PostgreSQL adapter (raw `Npgsql`, jsonb) |
| `Klassd.Auth.Data.MongoDb` | MongoDB adapter (`MongoDB.Driver`) |
| `Klassd.Auth.Sample` | Runnable example host |

Storage adapters use **raw drivers, no EF/ORM**, matching the Klassd house convention.

## Usage

```csharp
builder.Services
    .AddKlassdAuth(new SessionConfig { SigningKey = "<32+ byte secret>" })
    .UseSqlite("Data Source=klassd-auth.db");   // or .UsePostgres(...) / .UseMongoDb(...)

var app = builder.Build();
app.MapKlassdAuth();   // mounts the full HTTP API; schema is created automatically at startup
app.Run();
```

That's the whole host. The endpoints are shipped by the library — you don't hand-write them.

### HTTP API (default prefix `/auth`)

| Method & path | Purpose |
|---|---|
| `POST /auth/signup` | Email/password sign-up → session tokens |
| `POST /auth/signin` | Email/password sign-in → session tokens |
| `POST /auth/refresh` | Rotate refresh token, issue new access token |
| `POST /auth/logout` | Revoke a session |
| `POST /auth/email/send-verification` | Send a verification link |
| `GET  /auth/email/verify?token=` | Consume a verification token |
| `POST /auth/mfa/enroll` | Generate a TOTP secret + `otpauth://` URI |
| `POST /auth/mfa/verify` | Verify a TOTP code |
| `GET  /auth/users/{id}/metadata` | Read user metadata JSON |
| `PATCH /auth/users/{id}/metadata` | Shallow-merge user metadata (null removes a key) |
| `GET  /auth/jwks.json` | Public signing keys (populated under RS256; empty for HS256) |

### Admin user-management API (`MapKlassdAuthAdmin`)

`app.MapKlassdAuthAdmin(authorizationPolicy: "Admin")` adds (protected) admin endpoints —
`GET/POST /auth/admin/users`, `GET /auth/admin/users/{id}`, `POST .../disable`,
`POST .../reset-password`, `GET/PUT .../roles`. Responses never include password hashes.

### Passwordless (one-time codes — email & SMS)

```csharp
auth.AddPasswordless();                       // codes default to 6 digits, 10-min TTL, 5 attempts
auth.AddTwilioSms(sid, token, fromNumber);    // optional: deliver SMS codes for real (else console)

app.MapKlassdPasswordless();                  // JSON: POST /auth/passwordless/{start,verify}
```

`start` sends a code to an email **or** phone (`channel` is `"Email"`/`"Sms"`) and always returns
`202` — it never reveals whether the identifier exists. `verify` checks the code (fixed-time
compare, TTL + attempt lockout) and returns session tokens, resolving or auto-provisioning the user
by email/phone. A cookie variant (`MapKlassdPasswordlessCookie`) signs the user in instead.

### Passkeys (WebAuthn / FIDO2)

```csharp
auth.AddPasskeys(o => { o.ServerDomain = "example.com"; o.Origins = ["https://example.com"]; });

app.MapKlassdPasskeys();          // POST /passkeys/{register,login}/{options,verify}
```

Built on **Fido2NetLib**. Registration requires an authenticated user; login supports
usernameless/discoverable credentials. The ceremony challenge is held in a **stateless,
DataProtection-protected cookie** by default (multi-node-safe, no shared cache), with an in-memory
option for single-node. `register/verify` issues session tokens (or a cookie via
`MapKlassdPasskeysCookie`). Credentials persist in a `passkey_credentials` table per adapter.

### Account linking

An account is one identity with N attachable `LoginMethod`s — add or remove any kind:

```csharp
// On the cookie endpoints (the signed-in user links to THEIR account):
//   GET  /auth/link/{scheme}      → challenge a provider, attach it on callback
//   POST /auth/link/password      → a social-/passwordless-only user gains a password
//   POST /auth/unlink             → remove a method (the last one is guarded)
//   GET  /auth/me/methods         → list the caller's own login methods

// From code:
await accounts.LinkExternalAsync(userId, "facebook", info);   // never steals an identity owned elsewhere
await accounts.AddPasswordAsync(userId, password);            // false if one already exists
await accounts.UnlinkAsync(userId, methodId);                 // false if it's the last method
```

Linking is explicit and tied to the signed-in session. Optionally, an unauthenticated social
sign-in can auto-merge into an existing account — but **only** on a provider-**verified** matching
email (`AutoLinkByVerifiedEmail`, off by default; unverified-email auto-link is a takeover vector).

### Collecting an email from no-email providers

Some providers never share an email — **Instagram and TikTok** don't expose one at all, and
Facebook may be denied. Those accounts are provisioned with `PrimaryEmail == null` (it's nullable
by design); collect and verify an address after sign-in:

```
POST /auth/me/email          (authenticated) [FromForm] email   → sends a verification link
GET  /auth/me/email/confirm?token=…                             → sets it as the verified primary email
```

`start` rejects an address already owned by another user (`409`). The confirm link's token is the
proof of ownership, so on confirm the address becomes the user's **verified** `PrimaryEmail` (and a
usable passwordless identity). From code: `accounts.SetPrimaryEmailAsync(userId, email, verified)`
(guards against an email owned by someone else) and `accounts.IsEmailAvailableAsync(...)`. Apps that
require an email can gate access on `user.PrimaryEmail is null` and route to the collection page.

### Self-service password reset (forgot password)

```
POST /auth/password/forgot { "identifier": "a@b.com" }   → 202 always (no account enumeration)
POST /auth/password/reset  { "token": "…", "newPassword": "…" }   → 204 / 400
```

`forgot` emails a single-use link (`{PasswordResetUrlBase}?token=…`, ~1h TTL) to the resolved account;
`reset` consumes the token, sets the password (adding an email/password method if the account had
none), and **revokes the user's existing sessions**. Configure `PasswordResetUrlBase` on
`MapKlassdAuth(o => …)`. (Distinct from the admin reset and the `AccountLifecycleService` below.)

### Account lifecycle (disable / delete / anonymize)

`AccountLifecycleService` performs the destructive ops with their cross-store cascade — used by the
dashboard and the webhooks:

```csharp
await lifecycle.DisableAsync(userId);     // + revokes live sessions
await lifecycle.EnableAsync(userId);
await lifecycle.DeleteAsync(userId);      // hard delete: user + login methods + sessions + passkeys + metadata
await lifecycle.AnonymizeAsync(userId);   // GDPR erasure: strip PII/credentials, KEEP the id row
```

### Admin dashboard (`Klassd.Auth.Dashboard`)

A drop-in Blazor (Interactive Server) UI to maintain users — list/search, create, enable/disable,
set password, edit roles, manage linked login methods, and delete/anonymize (typed confirm).

```csharp
auth.AddKlassdAuthDashboard();   // after AddKlassdAuth(...) + a storage adapter (registers Blazor Server)
…
// Mounts the UI under a configurable path (default "/auth/dashboard") and ALWAYS requires login —
// anonymous visitors are redirected to the cookie login path. Pass a policy to also gate by role.
app.MapKlassdAuthDashboard(authorizationPolicy: "Admin");
app.MapKlassdAuthDashboard("/admin/users", "Admin");   // …or mount it anywhere
```

The mount is a **self-contained pipeline branch** — it owns its routing, authentication, antiforgery
and static assets, so the host doesn't add those for the dashboard. The host must still set
`<RequiresAspNetWebAssets>true</RequiresAspNetWebAssets>` in its csproj (else `_framework/blazor.web.js`
404s). Browse the authenticated UI at the trailing-slash URL (`…/auth/dashboard/`). See
`Klassd.Auth.Sample` for a complete host.

### Webhooks (`Klassd.Auth.Webhooks`) — automate customer-service requests

Lets an external system (e.g. a CS tool) act on accounts via an **HMAC-signed** request:

```csharp
auth.AddKlassdAuthWebhooks(o => o.SigningSecrets.Add(builder.Configuration["Auth:Webhooks:Secret"]!));
app.MapKlassdAuthWebhooks();   // POST /auth/webhooks/users
```

```
POST /auth/webhooks/users
  X-Klassd-Timestamp: <unix seconds>
  X-Klassd-Signature: sha256=<hex HMAC-SHA256 of "{timestamp}.{body}">
  { "action": "disable"|"enable"|"delete"|"anonymize", "userId"|"email": "…", "reason": "…" }
```

Verification mirrors the Klassd CMS outbound signing scheme and adds a timestamp tolerance (default
300s) to reject replays. Forged/stale/unsigned requests get `401`; unknown users `404`. Each applied
action is logged via `ILogger` for an audit trail.

### Token signing

Access tokens are HS256 by default (shared secret). For asymmetric signing:

- `.UseRsaSigning(rsa)` / `.UseRsaSigning(pemString)` — RS256 with a fixed key you supply.
- `.UseRotatingRsaSigning(o => …)` — RS256 with keys **persisted** in the storage adapter and
  **auto-rotated** (newest key signs; recently-retired keys keep validating during a grace window;
  expired keys are pruned). Configurable `SigningKeyLifetime` / `ValidationGrace`.

Either way the public key(s) are published at `/auth/jwks.json` so resource servers validate
tokens without a shared secret. Email-verification tokens are likewise persisted (hashed, with a
TTL, single-use) by the storage adapter, so they survive restarts and scale across nodes.

## Design notes

- **Sessions:** short-lived access JWT (stateless) + opaque, rotating refresh token. Reusing a
  rotated refresh token is detected and revokes the session defensively.
- **Passwords:** PBKDF2-HMAC-SHA256, per-password salt. Swap for Argon2id if preferred.
- **Storage-agnostic core:** modules depend only on `IUserStore` / `ISessionStore` /
  `IUserMetadataStore`; pick a `Data.*` adapter to bind a database.

## Using it from Klassd CMS / Klassd.Workflows

Klassd.Auth ships as NuGet packages, so an app references `Klassd.Auth.Core` (+ a `Data.*`
adapter, and `Klassd.Auth.AspNetCore` if it wants the ready-made endpoints) and gets both the
HTTP API and the injectable services. The `UserAccountService` is the union of what both apps'
existing user services expose, so it can back their current Blazor cookie sign-in:

```csharp
// Replace bespoke UserService / WorkflowsUserService with the shared one:
var user = await accounts.CreateLocalAsync(username: "alice", email: null, password);  // CMS (username)
var user = await accounts.CreateLocalAsync(username: null, email: "a@x.com", password); // Workflows (email)

if (accounts.VerifyPassword(user, password) && !user.Disabled) { /* issue the app's cookie */ }

await accounts.SetDisabledAsync(user.Id, true);                 // soft-delete (both apps)
await accounts.ProvisionExternalAsync("oidc", info, autoProvision: true);  // SSO find-or-link-or-create
```

### User model (hybrid)

`User` carries the identity/lifecycle fields both apps share — `Username` (optional, CMS),
`PrimaryEmail` (Workflows), `Disabled`, and one or more `LoginMethod`s (local password and/or
external provider). Everything app-specific lives in **typed metadata**, stored as one JSON doc
but accessed as typed sections so the two apps never collide:

```csharp
await meta.SetAsync(userId, "cms:prefs", new CmsPrefs { Theme = "dark", Locale = "da" });
var prefs = await meta.GetAsync<CmsPrefs>(userId, "cms:prefs");

// Roles use the same mechanism (CMS has them, Workflows doesn't), via RolesService:
await roles.SetRolesAsync(userId, ["Administrator"]);
var isAdmin = await roles.IsInRoleAsync(userId, "Administrator");
```

Each app maps these role strings to its own capability/permission model.

### Cookie sign-in + SSO (Blazor / server-rendered)

For the Blazor apps, add the cookie delivery and any external providers on the same builder:

```csharp
var auth = builder.Services
    .AddKlassdAuth(new SessionConfig { SigningKey = "..." })
    .UseSqlite("Data Source=klassd-auth.db");

auth.AddKlassdAuthCookies(o =>
{
    o.CookieName = "cms_auth";                 // or "klassd_wf_auth"
    o.SeedAdminUsername = "admin";
    o.SeedAdminPassword = builder.Configuration["Seed:AdminPassword"];
    o.SeedAdminRoles = ["Administrator"];
    o.BypassOnLoopback = true;                 // Workflows-style dev bypass (optional)
});

// Microsoft Entra ID (Azure AD). tenantId can be a directory id, or "organizations"/"common".
auth.AddEntraId(
    tenantId:     builder.Configuration["Auth:Entra:TenantId"]!,
    clientId:     builder.Configuration["Auth:Entra:ClientId"]!,
    clientSecret: builder.Configuration["Auth:Entra:ClientSecret"]!);

var app = builder.Build();
app.UseKlassdAuthCookies();   // wires middleware + /auth/login, /auth/logout, /auth/external/{scheme}
app.Run();
```

This gives `POST /auth/login` (username-or-email + password), `POST /auth/logout`, and
`GET /auth/external/{scheme}` → provider → callback that provisions the user via
`UserAccountService` and issues the app cookie. Entra is OIDC under the hood (stable id from the
`oid` claim, name from `preferred_username`); add other OIDC providers with `auth.AddOpenIdConnect(...)`.

Social OAuth 2.0 providers live in `Klassd.Auth.OAuth`: `auth.AddGitHub(...)`, `auth.AddFacebook(...)`,
`auth.AddInstagram(...)`, `auth.AddTikTok(...)`. Note Instagram and TikTok return **no email** (the
stable subject is the provider id), so they only ever explicit-link or provision a fresh account.

## Copyright

Original work, MIT licensed. No third-party source was read or copied; this is a clean-room
implementation against a publicly documented feature set.
