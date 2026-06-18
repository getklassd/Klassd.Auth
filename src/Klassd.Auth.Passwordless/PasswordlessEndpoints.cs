using Klassd.Auth.Abstractions;
using Klassd.Auth.AspNetCore.Cookies;
using Klassd.Auth.Core.Modules.Users;
using Klassd.Auth.Core.Sessions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace Klassd.Auth.Passwordless;

/// <summary>Request DTOs for the passwordless endpoints.</summary>
public sealed record PasswordlessStartRequest(string Identifier, PasswordlessChannel Channel);
public sealed record PasswordlessVerifyRequest(string Identifier, PasswordlessChannel Channel, string Code);

public static class PasswordlessEndpoints
{
    /// <summary>
    /// Maps the JSON passwordless API under <paramref name="basePath"/> (default "/auth/passwordless"):
    /// <c>POST /start</c> sends a code, <c>POST /verify</c> exchanges it for session tokens.
    /// </summary>
    public static IEndpointRouteBuilder MapKlassdPasswordless(
        this IEndpointRouteBuilder app, string basePath = "/auth/passwordless")
    {
        var g = app.MapGroup(basePath);

        g.MapPost("/start", async (PasswordlessStartRequest req, PasswordlessService pwl) =>
        {
            await pwl.StartAsync(req.Identifier, req.Channel);
            return Results.Accepted();   // never reveals whether the identifier exists
        });

        g.MapPost("/verify", async (PasswordlessVerifyRequest req, PasswordlessService pwl, SessionService sessions) =>
        {
            var r = await pwl.VerifyAsync(req.Identifier, req.Channel, req.Code);
            return r.Success
                ? Results.Ok(await sessions.CreateAsync(r.UserId!))
                : Results.Json(new { error = r.Error }, statusCode: StatusCodes.Status401Unauthorized);
        });

        return app;
    }

    /// <summary>
    /// Maps the cookie passwordless flow under <paramref name="basePath"/> (default
    /// "/auth/passwordless"): <c>POST /start</c> sends a code, <c>POST /verify</c> issues the app
    /// cookie. Requires <c>AddKlassdAuthCookies()</c>. Form-posted so it works from a plain page.
    /// </summary>
    public static IEndpointRouteBuilder MapKlassdPasswordlessCookie(
        this IEndpointRouteBuilder app, string basePath = "/auth/passwordless")
    {
        var g = app.MapGroup(basePath);

        g.MapPost("/start", async (
            [Microsoft.AspNetCore.Mvc.FromForm] string identifier,
            [Microsoft.AspNetCore.Mvc.FromForm] PasswordlessChannel channel,
            PasswordlessService pwl) =>
        {
            await pwl.StartAsync(identifier, channel);
            return Results.Accepted();
        }).DisableAntiforgery();

        g.MapPost("/verify", async (
            [Microsoft.AspNetCore.Mvc.FromForm] string identifier,
            [Microsoft.AspNetCore.Mvc.FromForm] PasswordlessChannel channel,
            [Microsoft.AspNetCore.Mvc.FromForm] string code,
            [Microsoft.AspNetCore.Mvc.FromForm] string? returnUrl,
            HttpContext http, PasswordlessService pwl, UserAccountService accounts) =>
        {
            var r = await pwl.VerifyAsync(identifier, channel, code);
            if (!r.Success) return Results.Redirect($"/login?error={r.Error}");

            var user = await accounts.GetByIdAsync(r.UserId!);
            if (user is null) return Results.Redirect("/login?error=NOT_PROVISIONED");

            await http.SignInUserAsync(user);
            return Results.Redirect(SafeReturn(returnUrl));
        }).DisableAntiforgery();

        return app;
    }

    private static string SafeReturn(string? returnUrl) =>
        !string.IsNullOrEmpty(returnUrl) && returnUrl.StartsWith('/') && !returnUrl.StartsWith("//") ? returnUrl : "/";
}
