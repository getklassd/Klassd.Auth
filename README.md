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
| `Klassd.Auth.Migration` | Import users **into** Klassd.Auth from **Auth0** & **SuperTokens** (JSON exports) — `AddAuthMigration()` |
| `Klassd.Auth.Migration.SuperTokens.Postgres` | Read a SuperTokens core DB directly over **PostgreSQL** (Npgsql) by connection string |
| `Klassd.Auth.Migration.SuperTokens.MySql` | Read a SuperTokens core DB directly over **MySQL** (MySqlConnector) by connection string |
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
| `GET  /auth/.well-known/openid-configuration` | OIDC discovery doc (issuer + `jwks_uri`) for JWT-bearer auto-discovery |

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

### Migrating in from Auth0 / SuperTokens (`Klassd.Auth.Migration`)

Import an existing user base into Klassd.Auth — passwords, social logins, roles, metadata and TOTP
included. Point a source at the export file and run it through the `MigrationRunner`:

```csharp
builder.Services
    .AddKlassdAuth(sessionConfig)
    .UseSqlite("Data Source=auth.db")
    .AddAuthMigration();   // registers MigrationRunner + legacy-aware password verification

// ...later, from a scope (one-off CLI / admin endpoint / hosted task):
var runner = sp.GetRequiredService<MigrationRunner>();

// Auth0 — bulk-export NDJSON or the user-import JSON array. Map provider ids to yours.
var auth0 = new Auth0MigrationSource("auth0-users.json",
    mapProvider: p => p == "google-oauth2" ? "google" : p);

// SuperTokens — the bulk-import document ({ "users": [...] }) or a bare array.
var superTokens = new SuperTokensMigrationSource("supertokens-users.json");

// SuperTokens — or read the core database directly (no export needed):
var superTokensDb = new SuperTokensPostgresMigrationSource(   // .SuperTokens.Postgres package
    "Host=localhost;Database=supertokens;Username=…;Password=…");
// var superTokensDb = new SuperTokensMySqlMigrationSource("Server=…;Database=supertokens;…");  // .SuperTokens.MySql
// Linked accounts (grouped by SuperTokens' primary_or_recipe_user_id) become one Klassd user
// with multiple login methods. Pass SuperTokensDbOptions to set AppId / schema / provider mapping.

var report = await runner.RunAsync(auth0, new MigrationOptions
{
    DryRun = true,                          // verify first, write nothing
    OnConflict = ConflictPolicy.Skip,       // or .Merge to attach missing login methods
});
Console.WriteLine($"{report.Created} created, {report.Skipped} skipped, " +
                  $"{report.PasswordsDropped} need a reset, {report.Failed} failed");
```

How it maps:

- **Passwords** — bcrypt and argon2 hashes carry over **verbatim** and verify at sign-in via the
  legacy-aware hasher `AddAuthMigration()` installs; a credential silently upgrades to Klassd's native
  pbkdf2 the next time it's set. Unverifiable hashes (Firebase scrypt, passlib pbkdf2, …) create a
  password-less account that the user resets — these are counted in `report.PasswordsDropped`.
- **Social / OIDC** — Auth0 `identities[]` and SuperTokens `thirdparty` login methods become linked
  third-party methods (the Auth0 `auth0` database connection is treated as email/password, not social).
- **Passwordless, roles, metadata, TOTP** — email/phone passwordless methods, roles, free-form
  metadata and the TOTP secret all carry over (toggle each via `MigrationOptions`).

Runs are **idempotent**: re-running matches existing users by email then username, and either skips or
merges them. Sources stream the export, so large dumps don't load whole.

#### Running it in production (Kubernetes)

Run the migration as a **one-shot operation, not on every pod's startup.** The sample host exposes a
`migrate-auth` verb for exactly this (it creates the schema, runs the import, prints a report, exits —
without starting the web server):

```bash
# dry run first (no --apply), then commit
dotnet run -- migrate-auth --source supertokens-pg --conn "Host=…;Database=supertokens;…"
dotnet run -- migrate-auth --source supertokens-pg --conn "Host=…;Database=supertokens;…" --apply
```

Package it as a Kubernetes **`Job`** (manifest in [`docs/migrate-job.yaml`](docs/migrate-job.yaml)). This
is what makes it safe:

- **It won't re-run when your app restarts.** Nothing in `AddAuthMigration()` runs on startup — the
  migration only happens when *you* invoke it. A `Job` runs once; your web `Deployment` never touches it.
- **Racing replicas can't double-import**, because a `Job` runs a single pod. (Note: the check-then-insert
  in the runner is *not* internally locked, so do **not** run the importer from N web replicas
  concurrently — the idempotent skip only protects sequential re-runs, not a true concurrent race. One
  Job, or rely on a unique-email index in your adapter as a backstop.)

The idempotent skip is then just a safety net: re-applying the Job is harmless.

#### Embedding it in startup (multi-replica safe)

If you can't run a separate Job and must migrate from app startup with several replicas, use the
**guarded** path. It's backed by `IMigrationStateStore` (provided by the Sqlite/Postgres/MongoDb
adapters): a durable **completion ledger** so it runs at most once ever, plus a **distributed lease**
so only one replica runs it — the lease auto-expires and is heartbeated, so a crashed holder can't
wedge it.

```csharp
builder.Services
    .AddKlassdAuth(sessionConfig)
    .UsePostgres(cs)
    .AddAuthMigration()
    .RunMigrationOnStartup(
        migrationId: "auth0-import-2026-06",                  // recorded in the ledger; runs once ever
        sourceFactory: sp => new Auth0MigrationSource("/seed/auth0-export.json"),
        configureOptions: o => o.OnConflict = ConflictPolicy.Skip);
```

Every replica starts the hosted service; exactly one wins the lease and imports, the rest observe
`AlreadyCompleted`/`LockHeldByAnother` and move on. It runs in the background (never blocks the host)
and only writes the ledger on success, so a failed run retries on the next start. To drive it yourself
instead, resolve `MigrationCoordinator` and call `RunOnceAsync(migrationId, source, …)`.

### Token signing

Access tokens are HS256 by default (shared secret). For asymmetric signing:

- `.UseRsaSigning(rsa)` / `.UseRsaSigning(pemString)` — RS256 with a fixed key you supply.
- `.UseRotatingRsaSigning(o => …)` — RS256 with keys **persisted** in the storage adapter and
  **auto-rotated** (newest key signs; recently-retired keys keep validating during a grace window;
  expired keys are pruned). Configurable `SigningKeyLifetime` / `ValidationGrace`.

Either way the public key(s) are published at `/auth/jwks.json` so resource servers validate
tokens without a shared secret. Email-verification tokens are likewise persisted (hashed, with a
TTL, single-use) by the storage adapter, so they survive restarts and scale across nodes.

An **OpenID Connect discovery document** is served at `/auth/.well-known/openid-configuration`
(issuer + absolute `jwks_uri` + signing alg), so a resource server can auto-discover keys instead of
hard-coding the JWKS URL — point JWT-bearer middleware at the auth base URL as its `Authority`:

```csharp
builder.Services.AddAuthentication().AddJwtBearer(o =>
{
    o.Authority = "https://your-host/auth";   // fetches /auth/.well-known/openid-configuration
    o.TokenValidationParameters.ValidAudience = "klassd.auth";   // SessionConfig.Audience
});
```

JWKS-based validation requires RS256 (`UseRsaSigning` / `UseRotatingRsaSigning`); the doc reports
`HS256` under the default shared secret, which has no public keys to discover. The `issuer` reflects
`SessionConfig.Issuer` (default `klassd.auth`) — set it to your auth URL if your validator requires a
URL issuer.

### Custom access-token claims

Every access token carries `sub` and `sessionHandle`, plus any `SessionData` entries (prefixed
`sd_` by default — set `SessionConfig.SessionDataClaimPrefix = ""` to drop the prefix). To add your
own claims — roles, tenant, plan, profile fields — register a **claims enricher**. It runs on every
token issue, **at sign-in and on each refresh**, so claims derived from live data stay current
instead of freezing at login:

```csharp
// Inline — resolve whatever you need from DI per issue:
auth.AddAccessTokenClaims(async (ctx, sp, ct) =>
{
    var roles = await sp.GetRequiredService<RolesService>().GetRolesAsync(ctx.UserId, ct);
    return roles.Select(r => new Claim(ClaimTypes.Role, r))
                .Append(new Claim("tenant", await LookupTenantAsync(ctx.UserId)));
});

// …or a class, for testability. Register as many as you like — all contribute:
auth.AddAccessTokenClaimsEnricher<MyClaimsEnricher>();
```

```csharp
public sealed class MyClaimsEnricher(IRolesService roles) : IAccessTokenClaimsEnricher
{
    public async Task<IEnumerable<Claim>> GetClaimsAsync(AccessTokenClaimsContext ctx, CancellationToken ct = default) =>
        (await roles.GetRolesAsync(ctx.UserId, ct)).Select(r => new Claim(ClaimTypes.Role, r));
}
```

Enricher claims are emitted unprefixed (only `SessionData` gets the `sd_` prefix).

#### Merging claims into a live session (`MergeIntoAccessTokenPayload` equivalent)

When you need a claim that's only known at a point in time — e.g. captured from a third-party provider
at sign-in — write it into the **session's stored payload**. It then rides on the access token issued
next and on **every refresh** (the provider is only contacted at login, so anything you need on
refreshed tokens must be persisted, not re-fetched). This is the equivalent of SuperTokens'
`sessionContainer.MergeIntoAccessTokenPayload`:

```csharp
// after a third-party sign-in, having created the session:
await sessions.MergeIntoAccessTokenPayloadAsync(handle, new Dictionary<string, object?>
{
    ["first_name"] = profile.GivenName,
    ["picture"]    = pictureUrl,
    ["roles"]      = profile.Roles,   // string[] → a real JSON array claim
});
// pass null as a value to remove a claim.
```

String values become string claims; arrays/objects become **real JSON claims** (so `roles` lands as a
JWT array, which the handler maps to `ClaimTypes.Role` so `User.IsInRole` / `[Authorize(Roles=…)]`
work). Names use `SessionConfig.SessionDataClaimPrefix` (set it to `""` for raw names).

The full third-party pattern (mirrors the SuperTokens Azure AD example): override
`IUserAccountService.ProvisionExternalAsync` to persist the provider's claims (available on
`ExternalUserInfo.Claims`, which the default mapping fills from all provider claims) into user
metadata, then merge them onto the session — or, for claims that should always reflect live data, read
them back in an `IAccessTokenClaimsEnricher`. Use the **merge** for values fixed at login (name,
picture); use the **enricher** for values that can change between refreshes (roles from your own store).

#### Post-external-sign-in hook (with the provider's tokens)

When you need the provider's **OAuth tokens** themselves — e.g. to call Microsoft Graph for a profile
picture during sign-in, exactly like the SuperTokens `AzureAdV2PostSignInUp` hook — register an
`IExternalSignInHook`. It runs after an SSO sign-in resolves to a local user, receives the provider's
tokens, and returns any claims to add to the app cookie:

```csharp
auth.AddExternalSignInHook(async (ctx, sp, ct) =>
{
    // ctx.Provider, ctx.User, ctx.IsFirstSignIn, ctx.Tokens.AccessToken/IdToken/RefreshToken, ctx.Principal
    var picture = await FetchGraphPhotoAsync(ctx.Tokens.AccessToken!, ct);   // call the provider
    await sp.GetRequiredService<IUserMetadataService>()
            .SetAsync(ctx.User.Id, "profile", new { picture }, ct);          // persist
    return [new Claim("picture", picture)];                                  // → onto the cookie
});

// or a class, for testability:
auth.AddExternalSignInHook<AzureProfileHook>();
```

The built-in providers enable token saving, so `ctx.Tokens` is populated (access/id/refresh + expiry,
plus the full set in `ctx.Tokens.All`). Use this hook for things that need the provider token at
login; use `MergeIntoAccessTokenPayloadAsync` / the enricher for the JWT/session path.

#### Working with the session like a SuperTokens `sessionContainer`

For the JWT/bearer flow, a `KlassdSession` is the `sessionContainer` analogue. Resolve it from the
current request (the bearer token) and merge into its payload — the equivalent of
`session.GetSessionFromRequestContext(ctx).MergeIntoAccessTokenPayload(...)`:

```csharp
app.MapPost("/me/refresh-profile", async (HttpContext http) =>
{
    var session = await http.GetKlassdSessionAsync();      // from Authorization: Bearer
    if (session is null) return Results.Unauthorized();
    await session.MergeIntoAccessTokenPayloadAsync(new { picture = await FetchPictureAsync() });
    return Results.Ok();
});
```

`KlassdSession` exposes `Handle`, `UserId`, `GetAccessTokenPayload()`, `GetClaimValue<T>(key)`,
`MergeIntoAccessTokenPayloadAsync(...)` (dictionary **or** anonymous object), and `RevokeAsync()`.
You can also resolve one by handle with `ISessionService.GetSessionAsync(handle)`.

To stamp claims onto **every** session as it's created — the `CreateNewSession` override analogue —
register a session-create hook; it's handed the live session to merge into:

```csharp
auth.AddSessionCreateHook(async (session, ctx, sp, ct) =>
{
    var roles = await sp.GetRequiredService<IRolesService>().GetRolesAsync(ctx.UserId, ct);
    await session.MergeIntoAccessTokenPayloadAsync(new { roles });
});
```

When you create the session yourself you can pass provider context to those hooks:
`await sessions.CreateAsync(userId, sessionData: null, metadata: new Dictionary<string, object?> { ["provider"] = "azuread" });`
— the hook reads it from `ctx.Metadata`.

#### JWT third-party sign-in with a post-sign-in hook (provider tokens + session)

For a bearer/JWT third-party flow (no cookie), map the third-party endpoints and register an
`IThirdPartySignInHook`. It's the closest match to the Go service's `SignInUpPOST` override calling
`AzureAdV2PostSignInUp(userId, OAuthTokens, sessionContainer, newUser)`: after the code exchange and
session creation, the hook gets the provider's **tokens**, the **new-user** flag, and the live
**session** to merge into — and the returned access token reflects the merge.

```csharp
app.MapKlassdThirdParty();          // GET /auth/thirdparty/{p}/authurl, POST /auth/thirdparty/{p}/signin
auth.AddProvider<AzureAdProvider>();   // your IThirdPartyProvider (ExchangeCodeAsync returns profile + tokens)

auth.AddThirdPartySignInHook(async (ctx, sp, ct) =>
{
    // ctx.Provider, ctx.UserId, ctx.IsNewUser, ctx.Tokens (access/id/refresh), ctx.Profile, ctx.Session
    var picture = await FetchGraphPhotoAsync(ctx.Tokens.AccessToken!, ct);
    await sp.GetRequiredService<IUserMetadataService>().SetAsync(ctx.UserId, "profile", new { picture }, ct);
    await ctx.Session.MergeIntoAccessTokenPayloadAsync(new { picture, roles = ctx.Profile.Claims.GetValueOrDefault("roles") });
});
```

The frontend gets an authorization URL from `…/authurl?redirectUri=…`, redirects the user, then POSTs
the returned `code` to `…/signin`, which responds with `{ accessToken, refreshToken, handle, createdNewUser }`.

#### Per-provider profile mapping (`GetUserInfo` override)

To control how one provider's claims map to a user — the per-provider `GetUserInfo` analogue —
register a mapper for that scheme; it wins over the global `MapExternalUser`:

```csharp
auth.MapExternalProfile("azuread", principal => new ExternalUserInfo(
    ExternalId: principal.FindFirstValue("oid")!,
    Email: principal.FindFirstValue("preferred_username"),
    EmailVerified: true)
{
    Claims = principal.Claims.ToDictionary(c => c.Type, c => c.Value),
});
```

### Overriding behavior (hooks)

Every core service is an interface with a default implementation, and you can **wrap any of them** to
inject your own logic — the same model as SuperTokens' recipe-function overrides. Call
`auth.Override<IService>(...)` with a decorator that runs your code and calls `base.X(...)` for the
original. The whole suite (HTTP endpoints, cookie sign-in, webhooks) resolves these by interface, so
an override takes effect everywhere automatically.

```csharp
builder.Services
    .AddKlassdAuth(sessionConfig)
    .UseSqlite("Data Source=auth.db")
    .Override<IEmailPasswordService>((inner, sp) => new NoDisposableEmail(inner))
    .Override<IUserAccountService>((inner, sp) => new DefaultRoleOnSignup(inner, sp));

// Derive from the matching ...Decorator base so you override only what you need:
public sealed class NoDisposableEmail(IEmailPasswordService inner) : EmailPasswordServiceDecorator(inner)
{
    public override Task<AuthResult> SignUpAsync(string email, string password, CancellationToken ct = default) =>
        email.EndsWith("@tempmail.com", StringComparison.OrdinalIgnoreCase)
            ? Task.FromResult(new AuthResult(false, Error: "DISPOSABLE_EMAIL_BLOCKED"))
            : base.SignUpAsync(email, password, ct);   // ← the original
}

// The factory hands you the IServiceProvider, so an override can pull in other services:
public sealed class DefaultRoleOnSignup(IUserAccountService inner, IServiceProvider sp)
    : UserAccountServiceDecorator(inner)
{
    public override async Task<User> CreateLocalAsync(string? u, string? e, string pw, CancellationToken ct = default)
    {
        var user = await base.CreateLocalAsync(u, e, pw, ct);
        await sp.GetRequiredService<IRolesService>().SetRolesAsync(user.Id, ["member"], ct);
        return user;
    }
}
```

Overrides **stack** — the last registered wraps the previous, so each can pre/post-process and delegate
inward. Overridable services: `IEmailPasswordService`, `ISessionService`, `IThirdPartyService`,
`IPasswordResetService`, `IEmailVerificationService`, `IUserAccountService`,
`IAccountLifecycleService`, `IRolesService`, `IUserMetadataService`, `ITotpService` — each with a
`…ServiceDecorator` base class.

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
