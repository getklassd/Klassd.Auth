using System.Security.Claims;
using Fido2NetLib;
using Klassd.Auth.Abstractions;
using Klassd.Auth.AspNetCore.Cookies;
using Klassd.Auth.Core.Modules.Users;
using Klassd.Auth.Core.Sessions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace Klassd.Auth.Passkeys;

/// <summary>Optional body for the login/options request (omit for usernameless/discoverable login).</summary>
public sealed record PasskeyLoginOptionsRequest(string? Identifier);

public static class PasskeyEndpoints
{
    /// <summary>JSON passkey API: register + login ceremonies; login issues session tokens.</summary>
    public static IEndpointRouteBuilder MapKlassdPasskeys(
        this IEndpointRouteBuilder app, string basePath = "/passkeys")
        => Map(app, basePath, async (http, user) =>
        {
            var sessions = http.RequestServices.GetRequiredService<SessionService>();
            return Results.Ok(await sessions.CreateAsync(user.Id));
        });

    /// <summary>Cookie passkey flow: register + login ceremonies; login issues the app cookie.</summary>
    public static IEndpointRouteBuilder MapKlassdPasskeysCookie(
        this IEndpointRouteBuilder app, string basePath = "/passkeys")
        => Map(app, basePath, async (http, user) =>
        {
            await http.SignInUserAsync(user);
            return Results.Ok(new { signedIn = true });
        });

    private static IEndpointRouteBuilder Map(
        IEndpointRouteBuilder app, string basePath, Func<HttpContext, User, Task<IResult>> onLoginSuccess)
    {
        var g = app.MapGroup(basePath);

        // ---- Registration (requires an authenticated user) --------------------------------
        g.MapPost("/register/options", async (HttpContext http, PasskeyService passkeys, UserAccountService accounts) =>
        {
            if (CurrentUserId(http) is not { } userId) return Results.Unauthorized();
            var user = await accounts.GetByIdAsync(userId);
            if (user is null) return Results.Unauthorized();

            var label = user.Username ?? user.PrimaryEmail ?? user.Id;
            var options = await passkeys.CreateRegistrationOptionsAsync(userId, label, label);
            await StashAsync(http, options.ToJson());
            return Results.Text(options.ToJson(), "application/json");
        });

        g.MapPost("/register/verify", async (
            HttpContext http, AuthenticatorAttestationRawResponse attestation, string? nickname,
            PasskeyService passkeys) =>
        {
            if (CurrentUserId(http) is not { } userId) return Results.Unauthorized();
            if (await TakeAsync(http) is not { } json) return Results.BadRequest(new { error = "NO_CEREMONY" });

            var options = CredentialCreateOptions.FromJson(json);
            var credential = await passkeys.VerifyRegistrationAsync(userId, attestation, options, nickname);
            return Results.Ok(new { credentialId = credential.Id });
        });

        // ---- Login --------------------------------------------------------------------------
        g.MapPost("/login/options", async (
            HttpContext http, PasskeyLoginOptionsRequest? req, PasskeyService passkeys, UserAccountService accounts) =>
        {
            string? userId = null;
            if (!string.IsNullOrWhiteSpace(req?.Identifier))
            {
                var user = await accounts.FindByEmailAsync(req!.Identifier)
                           ?? await accounts.FindByUsernameAsync(req.Identifier);
                userId = user?.Id;   // unknown identifier → fall through to discoverable (no enumeration)
            }

            var options = await passkeys.CreateAssertionOptionsAsync(userId);
            await StashAsync(http, options.ToJson());
            return Results.Text(options.ToJson(), "application/json");
        });

        g.MapPost("/login/verify", async (
            HttpContext http, AuthenticatorAssertionRawResponse assertion, PasskeyService passkeys) =>
        {
            if (await TakeAsync(http) is not { } json) return Results.BadRequest(new { error = "NO_CEREMONY" });

            var options = AssertionOptions.FromJson(json);
            var user = await passkeys.VerifyAssertionAsync(assertion, options);
            return user is null
                ? Results.Json(new { error = "INVALID_ASSERTION" }, statusCode: StatusCodes.Status401Unauthorized)
                : await onLoginSuccess(http, user);
        });

        return app;
    }

    private static string? CurrentUserId(HttpContext http) =>
        http.User.Identity?.IsAuthenticated == true ? http.User.FindFirstValue(ClaimTypes.NameIdentifier) : null;

    // ---- Ceremony cookie (handle round-trip) ----------------------------------------------
    private static async Task StashAsync(HttpContext http, string optionsJson)
    {
        var opts = http.RequestServices.GetRequiredService<PasskeyOptions>();
        var store = http.RequestServices.GetRequiredService<IPasskeyChallengeStore>();
        var handle = await store.StashAsync(optionsJson, opts.ChallengeLifetime, http.RequestAborted);
        http.Response.Cookies.Append(opts.CeremonyCookieName, handle, new CookieOptions
        {
            HttpOnly = true,
            Secure = http.Request.IsHttps,
            SameSite = SameSiteMode.Strict,
            MaxAge = opts.ChallengeLifetime,
            Path = "/",
        });
    }

    private static async Task<string?> TakeAsync(HttpContext http)
    {
        var opts = http.RequestServices.GetRequiredService<PasskeyOptions>();
        var store = http.RequestServices.GetRequiredService<IPasskeyChallengeStore>();
        if (!http.Request.Cookies.TryGetValue(opts.CeremonyCookieName, out var handle) || string.IsNullOrEmpty(handle))
            return null;
        http.Response.Cookies.Delete(opts.CeremonyCookieName);   // single use
        return await store.RetrieveAsync(handle, http.RequestAborted);
    }
}
