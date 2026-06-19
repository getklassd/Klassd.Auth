using System.Security.Claims;
using Klassd.Auth.AspNetCore;
using Klassd.Auth.AspNetCore.Cookies;
using Klassd.Auth.Core.DependencyInjection;
using Klassd.Auth.Core.Sessions;
using Klassd.Auth.Data.Sqlite;
using Klassd.Auth.OAuth;
using Klassd.Auth.OpenIdConnect;
using Klassd.Auth.Passwordless;
using Klassd.Auth.Passkeys;
using Klassd.Auth.Sms.Twilio;
using Klassd.Auth.Dashboard;
using Klassd.Auth.Webhooks;

var builder = WebApplication.CreateBuilder(args);

// 1. Configure Klassd.Auth + pick a storage adapter. Swap .UseSqlite for .UsePostgres / .UseMongoDb.
var auth = builder.Services
    .AddKlassdAuth(new SessionConfig
    {
        SigningKey = builder.Configuration["Auth:SigningKey"] ?? "dev-only-change-me-please-32bytes-min!!",
    })
    .UseSqlite(builder.Configuration["Auth:Sqlite:ConnectionString"] ?? "Data Source=klassd-auth.db")
    .UseRotatingRsaSigning();   // RS256 with persisted, auto-rotating keys; public JWKS at /auth/jwks.json

// Admin endpoints require the Administrator role.
builder.Services.AddAuthorizationBuilder()
    .AddPolicy("Admin", p => p.RequireRole("Administrator"));

// 2. Cookie sign-in for server-rendered / Blazor apps, with a seeded admin.
auth.AddKlassdAuthCookies(o =>
{
    o.SeedAdminUsername = "admin";
    o.SeedAdminPassword = "change-me-now";   // sample only — set via config/secrets in real apps
    o.SeedAdminRoles = ["Administrator"];
});

// 3. Microsoft Entra ID SSO — enabled only when configured.
var entra = builder.Configuration.GetSection("Auth:Entra");
if (entra["TenantId"] is { } tenant && entra["ClientId"] is { } clientId && entra["ClientSecret"] is { } secret)
    auth.AddEntraId(tenant, clientId, secret);

// Social providers for account linking — each enabled only when configured.
var fb = builder.Configuration.GetSection("Auth:Facebook");
if (fb["ClientId"] is { } fbId && fb["ClientSecret"] is { } fbSecret) auth.AddFacebook(fbId, fbSecret);
var ig = builder.Configuration.GetSection("Auth:Instagram");
if (ig["ClientId"] is { } igId && ig["ClientSecret"] is { } igSecret) auth.AddInstagram(igId, igSecret);
var tt = builder.Configuration.GetSection("Auth:TikTok");
if (tt["ClientKey"] is { } ttKey && tt["ClientSecret"] is { } ttSecret) auth.AddTikTok(ttKey, ttSecret);

// 4. Passwordless one-time codes (email + SMS). Codes print to the console by default;
//    wire Twilio when configured to deliver SMS for real.
auth.AddPasswordless();
var twilio = builder.Configuration.GetSection("Auth:Twilio");
if (twilio["AccountSid"] is { } sid && twilio["AuthToken"] is { } token && twilio["FromNumber"] is { } from)
    auth.AddTwilioSms(sid, token, from);

// 5. Passkeys (WebAuthn). Set ServerDomain/Origins to your real host in production.
auth.AddPasskeys(o =>
{
    o.ServerDomain = builder.Configuration["Auth:Passkeys:ServerDomain"] ?? "localhost";
    o.ServerName = "Klassd.Auth Sample";
    o.Origins = [builder.Configuration["Auth:Passkeys:Origin"] ?? "https://localhost:5001"];
});

// 6. Blazor admin dashboard (Interactive Server) at /auth/dashboard.
auth.AddKlassdAuthDashboard();

// 7. Inbound HMAC webhooks so customer-service tooling can disable/delete/anonymize users.
auth.AddKlassdAuthWebhooks(o =>
    o.SigningSecrets.Add(builder.Configuration["Auth:Webhooks:Secret"] ?? "dev-webhook-secret-change-me"));

var app = builder.Build();

app.UseStaticFiles();         // serves wwwroot/ (the passkey/passwordless browser test page)
app.MapStaticAssets();        // RCL static assets (the dashboard's stylesheet under _content/…)
app.MapKlassdAuth();          // JSON/JWT API (signup/signin/refresh/email/mfa/metadata/jwks/password)
app.UseKlassdAuthCookies();   // cookie login + external SSO challenge/callback
app.UseAntiforgery();         // required by the Blazor dashboard
app.MapKlassdAuthAdmin(authorizationPolicy: "Admin");   // admin user management
app.MapKlassdPasswordless();  // JSON passwordless API (start/verify → session tokens)
app.MapKlassdPasskeys();      // JSON passkey ceremonies (register/login → session tokens)
app.MapKlassdAuthWebhooks();  // POST /auth/webhooks/users (HMAC-signed)
app.MapKlassdAuthDashboard(authorizationPolicy: "Admin");   // Blazor user-admin UI at /auth/dashboard

// Example protected endpoint reading the cookie identity.
app.MapGet("/me", (ClaimsPrincipal user) =>
    user.Identity?.IsAuthenticated == true
        ? Results.Ok(new
        {
            id = user.FindFirstValue(ClaimTypes.NameIdentifier),
            name = user.Identity!.Name,
            roles = user.FindAll(ClaimTypes.Role).Select(c => c.Value),
        })
        : Results.Unauthorized())
   .RequireAuthorization();

app.Run();
