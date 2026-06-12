using System.Text.Json.Nodes;
using Klassd.Auth.Core.Modules.EmailPassword;
using Klassd.Auth.Core.Modules.EmailVerification;
using Klassd.Auth.Core.Modules.Mfa;
using Klassd.Auth.Core.Modules.UserMetadata;
using Klassd.Auth.Core.Sessions;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.IdentityModel.Tokens;

namespace Klassd.Auth.AspNetCore;

public sealed class KlassdAuthEndpointOptions
{
    /// <summary>Route prefix for all endpoints. Default "/auth".</summary>
    public string BasePath { get; set; } = "/auth";

    /// <summary>Base URL the email-verification link points at (the front-end verify page).</summary>
    public string EmailVerifyUrlBase { get; set; } = "https://app.example/verify";
}

/// <summary>
/// Wires the full Klassd.Auth HTTP API in one call, so consumers don't hand-write endpoints —
/// the core ships its own HTTP surface.
/// </summary>
public static class KlassdAuthEndpoints
{
    public static IEndpointRouteBuilder MapKlassdAuth(
        this IEndpointRouteBuilder app, Action<KlassdAuthEndpointOptions>? configure = null)
    {
        var opts = new KlassdAuthEndpointOptions();
        configure?.Invoke(opts);
        var g = app.MapGroup(opts.BasePath);

        // ---- Email / password + sessions --------------------------------------------------
        g.MapPost("/signup", async (Credentials c, EmailPasswordService ep, SessionService sessions) =>
        {
            var r = await ep.SignUpAsync(c.Email, c.Password);
            return r.Success
                ? Results.Ok(await sessions.CreateAsync(r.UserId!))
                : Results.BadRequest(new { error = r.Error });
        });

        g.MapPost("/signin", async (Credentials c, EmailPasswordService ep, SessionService sessions) =>
        {
            var r = await ep.SignInAsync(c.Email, c.Password);
            return r.Success
                ? Results.Ok(await sessions.CreateAsync(r.UserId!))
                : Results.Json(new { error = r.Error }, statusCode: StatusCodes.Status401Unauthorized);
        });

        g.MapPost("/refresh", async (RefreshRequest req, SessionService sessions) =>
        {
            try { return Results.Ok(await sessions.RefreshAsync(req.RefreshToken)); }
            catch (SecurityTokenException ex)
            {
                return Results.Json(new { error = ex.Message }, statusCode: StatusCodes.Status401Unauthorized);
            }
        });

        g.MapPost("/logout", async (LogoutRequest req, SessionService sessions) =>
        {
            await sessions.RevokeAsync(req.SessionHandle);
            return Results.NoContent();
        });

        // ---- Email verification ------------------------------------------------------------
        g.MapPost("/email/send-verification", async (SendVerification req, EmailVerificationService ev) =>
        {
            await ev.SendVerificationAsync(req.UserId, req.Email, opts.EmailVerifyUrlBase);
            return Results.Accepted();
        });

        g.MapGet("/email/verify", async (string token, EmailVerificationService ev) =>
            await ev.VerifyAsync(token)
                ? Results.Ok(new { verified = true })
                : Results.BadRequest(new { verified = false }));

        // ---- MFA (TOTP) --------------------------------------------------------------------
        g.MapPost("/mfa/enroll", (MfaEnroll req, TotpService totp) =>
            Results.Ok(totp.GenerateSecret(req.AccountLabel)));

        g.MapPost("/mfa/verify", (MfaVerify req, TotpService totp) =>
            Results.Ok(new { valid = totp.VerifyCode(req.Secret, req.Code) }));

        // ---- User metadata -----------------------------------------------------------------
        g.MapGet("/users/{userId}/metadata", async (string userId, UserMetadataService meta) =>
            Results.Text((await meta.GetAsync(userId)).ToJsonString(), "application/json"));

        g.MapPatch("/users/{userId}/metadata", async (string userId, JsonObject patch, UserMetadataService meta) =>
            Results.Text((await meta.UpdateAsync(userId, patch)).ToJsonString(), "application/json"));

        // ---- JWKS (public keys for validating access tokens; empty for HS256) -------------
        g.MapGet("/jwks.json", (ITokenSigningKey signing) => Results.Ok(new
        {
            keys = signing.PublicJwks.Select(k => new
            {
                kty = k.Kty,
                use = k.Use,
                kid = k.Kid,
                alg = k.Alg,
                n = k.N,
                e = k.E,
            }),
        }));

        return app;
    }

    // Request DTOs for the auth API.
    public sealed record Credentials(string Email, string Password);
    public sealed record RefreshRequest(string RefreshToken);
    public sealed record LogoutRequest(string SessionHandle);
    public sealed record SendVerification(string UserId, string Email);
    public sealed record MfaEnroll(string AccountLabel);
    public sealed record MfaVerify(string Secret, string Code);
}
