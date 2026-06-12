using Klassd.Auth.Core.Modules.Users;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace Klassd.Auth.AspNetCore.Cookies;

public static class CookieAuthEndpoints
{
    /// <summary>Maps login, logout, and the external-SSO challenge/callback under the configured base path.</summary>
    public static IEndpointRouteBuilder MapKlassdAuthCookieEndpoints(this IEndpointRouteBuilder app)
    {
        var options = app.ServiceProvider.GetRequiredService<KlassdAuthCookieOptions>();
        var g = app.MapGroup(options.BasePath);

        // ---- Local username/email + password login (form post) ---------------------------
        g.MapPost("/login", async (
            [FromForm] string identifier, [FromForm] string password, [FromForm] string? returnUrl,
            HttpContext http, UserAccountService accounts, RolesService roles) =>
        {
            if (!options.AllowLocalLogin) return Results.Forbid();

            var user = await accounts.FindByUsernameAsync(identifier)
                       ?? await accounts.FindByEmailAsync(identifier);
            if (user is null || user.Disabled || !accounts.VerifyPassword(user, password))
                return Results.Redirect($"{options.LoginPath}?error=invalid");

            var principal = await ClaimsPrincipalFactory.BuildAsync(user, roles);
            await http.SignInAsync(KlassdAuthSchemes.Cookie, principal);
            return Results.Redirect(SafeReturn(returnUrl));
        }).DisableAntiforgery();

        // ---- Logout -----------------------------------------------------------------------
        g.MapPost("/logout", async (HttpContext http) =>
        {
            await http.SignOutAsync(KlassdAuthSchemes.Cookie);
            return Results.Redirect("/");
        }).DisableAntiforgery();

        // ---- External SSO: challenge the provider -----------------------------------------
        g.MapGet("/external/{scheme}", (string scheme, string? returnUrl) =>
        {
            var props = new AuthenticationProperties
            {
                RedirectUri = $"{options.BasePath}/external-callback",
                Items = { ["provider"] = scheme, ["returnUrl"] = SafeReturn(returnUrl) },
            };
            return Results.Challenge(props, [scheme]);
        });

        // ---- External SSO: provision/link, then issue the app cookie ----------------------
        g.MapGet("/external-callback", async (HttpContext http, UserAccountService accounts, RolesService roles) =>
        {
            var result = await http.AuthenticateAsync(KlassdAuthSchemes.External);
            if (!result.Succeeded || result.Principal is null)
                return Results.Redirect($"{options.LoginPath}?error=external");

            var items = result.Properties?.Items;
            var provider = items is not null && items.TryGetValue("provider", out var p) ? p ?? "external" : "external";
            var returnUrl = items is not null && items.TryGetValue("returnUrl", out var ru) ? ru ?? "/" : "/";

            var info = options.MapExternalUser(result.Principal);
            var user = await accounts.ProvisionExternalAsync(provider, info, options.AutoProvisionExternalUsers);
            if (user is null || user.Disabled)
                return Results.Redirect($"{options.LoginPath}?error=not_provisioned");

            var principal = await ClaimsPrincipalFactory.BuildAsync(user, roles);
            await http.SignInAsync(KlassdAuthSchemes.Cookie, principal);
            await http.SignOutAsync(KlassdAuthSchemes.External);
            return Results.Redirect(SafeReturn(returnUrl));
        });

        return app;
    }

    // Only allow local redirects, to avoid open-redirect via returnUrl.
    private static string SafeReturn(string? returnUrl) =>
        !string.IsNullOrEmpty(returnUrl) && returnUrl.StartsWith('/') && !returnUrl.StartsWith("//") ? returnUrl : "/";
}
