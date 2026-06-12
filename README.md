# Klassd.Auth

A self-hostable authentication core for .NET — email/password, sessions, social login,
MFA, email verification, and a per-user metadata store. An independent, clean-room design
built from a public feature model, not a port or migration of any existing project's source.

> **Status:** early scaffold (v0.0.1-beta.1). The module logic, session security, and three storage
> adapters work end-to-end; OAuth providers and production hardening are still stubbed/TODO.

## Packages

| Package | Purpose |
|---|---|
| `Klassd.Auth.Abstractions` | Store interfaces + DB-agnostic record types |
| `Klassd.Auth.Core` | Auth logic: email/password, sessions, third-party, MFA, email verification, metadata |
| `Klassd.Auth.AspNetCore` | JSON/JWT HTTP delivery — one `MapKlassdAuth()` call wires the whole API |
| `Klassd.Auth.AspNetCore.Cookies` | Cookie sign-in for server-rendered / Blazor apps + external-SSO seam |
| `Klassd.Auth.OpenIdConnect` | OIDC external login + **Microsoft Entra ID** (`AddEntraId`) + Google (`AddGoogle`) |
| `Klassd.Auth.OAuth` | OAuth 2.0 (non-OIDC) providers — GitHub (`AddGitHub`) |
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

## Copyright

Original work, MIT licensed. No third-party source was read or copied; this is a clean-room
implementation against a publicly documented feature set.
