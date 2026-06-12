using System.Security.Claims;
using Klassd.Auth.AspNetCore;
using Klassd.Auth.AspNetCore.Cookies;
using Klassd.Auth.Core.DependencyInjection;
using Klassd.Auth.Core.Sessions;
using Klassd.Auth.Data.Sqlite;
using Klassd.Auth.OpenIdConnect;

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

var app = builder.Build();

app.MapKlassdAuth();          // JSON/JWT API (signup/signin/refresh/email/mfa/metadata/jwks)
app.UseKlassdAuthCookies();   // cookie login + external SSO challenge/callback
app.MapKlassdAuthAdmin(authorizationPolicy: "Admin");   // admin user management

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
