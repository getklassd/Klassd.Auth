using System.Security.Claims;
using Klassd.Auth.Core.Modules.EmailVerification;
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
            var user = await accounts.ProvisionExternalAsync(
                provider, info, options.AutoProvisionExternalUsers, options.AutoLinkByVerifiedEmail);
            if (user is null || user.Disabled)
                return Results.Redirect($"{options.LoginPath}?error=not_provisioned");

            var principal = await ClaimsPrincipalFactory.BuildAsync(user, roles);
            await http.SignInAsync(KlassdAuthSchemes.Cookie, principal);
            await http.SignOutAsync(KlassdAuthSchemes.External);
            return Results.Redirect(SafeReturn(returnUrl));
        });

        // ---- Account linking (a signed-in user attaches another method) -------------------
        // Challenge the provider, returning to /link-callback (vs /external-callback for sign-in).
        g.MapGet("/link/{scheme}", (string scheme, string? returnUrl) =>
        {
            var props = new AuthenticationProperties
            {
                RedirectUri = $"{options.BasePath}/link-callback",
                Items = { ["provider"] = scheme, ["returnUrl"] = SafeReturn(returnUrl) },
            };
            return Results.Challenge(props, [scheme]);
        }).RequireAuthorization();

        // Attach the external identity to the CURRENT user (never steal one owned elsewhere).
        g.MapGet("/link-callback", async (HttpContext http, UserAccountService accounts) =>
        {
            if (http.User.FindFirstValue(ClaimTypes.NameIdentifier) is not { } userId)
                return Results.Redirect($"{options.LoginPath}?error=link");

            var result = await http.AuthenticateAsync(KlassdAuthSchemes.External);
            if (!result.Succeeded || result.Principal is null)
                return Results.Redirect(AppendQuery("/", "linked", "error"));

            var items = result.Properties?.Items;
            var provider = items is not null && items.TryGetValue("provider", out var p) ? p ?? "external" : "external";
            var returnUrl = items is not null && items.TryGetValue("returnUrl", out var ru) ? ru ?? "/" : "/";

            var link = await accounts.LinkExternalAsync(userId, provider, options.MapExternalUser(result.Principal));
            await http.SignOutAsync(KlassdAuthSchemes.External);

            var status = link.Outcome switch
            {
                LinkOutcome.Linked => "ok",
                LinkOutcome.AlreadyLinkedToThisUser => "already",
                LinkOutcome.ConflictOwnedByAnotherUser => "conflict",
                _ => "error",
            };
            return Results.Redirect(AppendQuery(SafeReturn(returnUrl), "linked", status));
        }).RequireAuthorization();

        g.MapPost("/unlink", async ([FromForm] string methodId, HttpContext http, UserAccountService accounts) =>
        {
            if (http.User.FindFirstValue(ClaimTypes.NameIdentifier) is not { } userId) return Results.Unauthorized();
            return await accounts.UnlinkAsync(userId, methodId)
                ? Results.NoContent()
                : Results.BadRequest(new { error = "CANNOT_UNLINK_LAST_METHOD" });
        }).RequireAuthorization().DisableAntiforgery();

        // Let a social-/passwordless-only user gain a password.
        g.MapPost("/link/password", async ([FromForm] string password, HttpContext http, UserAccountService accounts) =>
        {
            if (http.User.FindFirstValue(ClaimTypes.NameIdentifier) is not { } userId) return Results.Unauthorized();
            return await accounts.AddPasswordAsync(userId, password)
                ? Results.NoContent()
                : Results.BadRequest(new { error = "PASSWORD_ALREADY_SET" });
        }).RequireAuthorization().DisableAntiforgery();

        // List the caller's own login methods (ids are needed to unlink).
        g.MapGet("/me/methods", async (HttpContext http, UserAccountService accounts) =>
        {
            if (http.User.FindFirstValue(ClaimTypes.NameIdentifier) is not { } userId) return Results.Unauthorized();
            var user = await accounts.GetByIdAsync(userId);
            return user is null
                ? Results.Unauthorized()
                : Results.Ok(user.LoginMethods.Select(m => new
                {
                    id = m.Id, kind = m.Kind.ToString(), providerId = m.ProviderId,
                    email = m.Email, phone = m.Phone, emailVerified = m.EmailVerified,
                }));
        }).RequireAuthorization();

        // ---- Collect & verify a primary email (for providers that don't share one) --------
        // Start: the signed-in user submits an email; we send a verification link to prove ownership.
        g.MapPost("/me/email", async (
            [FromForm] string email,
            HttpContext http, UserAccountService accounts, EmailVerificationService verification) =>
        {
            if (http.User.FindFirstValue(ClaimTypes.NameIdentifier) is not { } userId) return Results.Unauthorized();
            if (!await accounts.IsEmailAvailableAsync(userId, email)) return Results.Conflict(new { error = "EMAIL_IN_USE" });

            // SendVerificationAsync appends "?token=…", so the base URL must carry no query string.
            var confirmUrl = $"{http.Request.Scheme}://{http.Request.Host}{options.BasePath}/me/email/confirm";
            await verification.SendVerificationAsync(userId, email, confirmUrl);
            return Results.Accepted();
        }).RequireAuthorization().DisableAntiforgery();

        // Confirm: the link's token proves ownership → set it as the (verified) primary email.
        // No auth required — the token itself carries the user + email and is the capability.
        g.MapGet("/me/email/confirm", async (
            string token, UserAccountService accounts, EmailVerificationService verification) =>
        {
            var record = await verification.ConsumeTokenAsync(token);
            if (record is null) return Results.Redirect(AppendQuery("/", "email", "error"));

            var status = await accounts.SetPrimaryEmailAsync(record.UserId, record.Email, verified: true) switch
            {
                EmailUpdateOutcome.Updated => "ok",
                EmailUpdateOutcome.EmailInUse => "inuse",
                _ => "error",
            };
            return Results.Redirect(AppendQuery("/", "email", status));
        });

        return app;
    }

    private static string AppendQuery(string url, string key, string value) =>
        $"{url}{(url.Contains('?') ? '&' : '?')}{key}={value}";

    // Only allow local redirects, to avoid open-redirect via returnUrl.
    private static string SafeReturn(string? returnUrl) =>
        !string.IsNullOrEmpty(returnUrl) && returnUrl.StartsWith('/') && !returnUrl.StartsWith("//") ? returnUrl : "/";
}
