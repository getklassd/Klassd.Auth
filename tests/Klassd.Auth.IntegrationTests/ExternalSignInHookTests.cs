using System.Net;
using System.Security.Claims;
using Klassd.Auth.AspNetCore.Cookies;
using Klassd.Auth.Core.DependencyInjection;
using Klassd.Auth.Core.Sessions;
using Klassd.Auth.Data.Sqlite;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using TUnit.Assertions;
using TUnit.Assertions.Extensions;

namespace Klassd.Auth.IntegrationTests;

/// <summary>
/// End-to-end proof that <see cref="IExternalSignInHook"/> runs during the external-SSO callback with
/// the provider's saved tokens, and that claims it returns ride on the issued app cookie. Mirrors the
/// SuperTokens post-sign-in-up pattern (use the provider token to enrich, then put claims on the token).
/// </summary>
public class ExternalSignInHookTests
{
    private static string? _capturedAccessToken;
    private static bool _capturedIsFirstSignIn;

    [Test]
    public async Task Hook_receives_provider_tokens_and_its_claims_land_on_the_cookie()
    {
        _capturedAccessToken = null;
        await using var app = await BuildAsync();
        var client = app.GetTestClient();

        // 1. Seed the external cookie as if a provider just signed the user in (with saved tokens).
        var seed = await client.GetAsync("/seed-external");
        var externalCookie = Cookie(seed);
        await Assert.That(externalCookie).IsNotNull();

        // 2. Hit the real callback carrying that external cookie.
        using var cbReq = new HttpRequestMessage(HttpMethod.Get, "/auth/external-callback");
        cbReq.Headers.Add("Cookie", externalCookie);
        var callback = await client.SendAsync(cbReq);

        // The hook saw the provider's access token and the first-sign-in flag.
        await Assert.That(_capturedAccessToken).IsEqualTo("test-access-token");
        await Assert.That(_capturedIsFirstSignIn).IsTrue();
        await Assert.That(callback.StatusCode).IsEqualTo(HttpStatusCode.Redirect);

        // 3. Present the issued app cookie to a protected echo endpoint; the hook's claim is there.
        var appCookie = Cookie(callback);
        await Assert.That(appCookie).IsNotNull();
        using var meReq = new HttpRequestMessage(HttpMethod.Get, "/whoami-hd");
        meReq.Headers.Add("Cookie", appCookie);
        var me = await client.SendAsync(meReq);

        await Assert.That(await me.Content.ReadAsStringAsync()).IsEqualTo("acme.com");
    }

    // Take the first Set-Cookie's "name=value" pair (drop attributes) to resend on the next request.
    private static string? Cookie(HttpResponseMessage resp) =>
        resp.Headers.TryGetValues("Set-Cookie", out var v)
            ? v.Select(c => c.Split(';')[0]).FirstOrDefault()
            : null;

    private static async Task<WebApplication> BuildAsync()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Logging.ClearProviders();

        var auth = builder.Services.AddKlassdAuth(new SessionConfig
        {
            SigningKey = "test-signing-key-that-is-at-least-32-chars",
        });
        auth.AddKlassdAuthCookies(o =>
        {
            o.BasePath = "/auth";
            o.LoginPath = "/login";
            o.AutoProvisionExternalUsers = true;   // create the user on first external sign-in
        });
        auth.UseSqlite($"Data Source={Path.Combine(Path.GetTempPath(), $"klassd-hook-{Guid.NewGuid():n}.db")}");

        // The hook: capture the provider token + first-sign-in, return a claim built from a provider claim.
        auth.AddExternalSignInHook((ctx, sp, ct) =>
        {
            _capturedAccessToken = ctx.Tokens.AccessToken;
            _capturedIsFirstSignIn = ctx.IsFirstSignIn;
            var hd = ctx.Principal.FindFirst("hd")?.Value;
            IEnumerable<Claim> claims = hd is null ? [] : [new Claim("hd", hd)];
            return Task.FromResult(claims);
        });

        var app = builder.Build();
        app.UseAuthentication();
        app.UseAuthorization();
        app.MapKlassdAuthCookieEndpoints();

        // Test-only: stand in for a provider by signing into the external cookie with saved tokens.
        app.MapGet("/seed-external", async (HttpContext http) =>
        {
            var identity = new ClaimsIdentity("ext");
            identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, "ext-azure-123"));
            identity.AddClaim(new Claim(ClaimTypes.Email, "jane@acme.com"));
            identity.AddClaim(new Claim("hd", "acme.com"));        // a provider claim to carry through

            var props = new AuthenticationProperties();
            props.Items["provider"] = "azuread";
            props.Items["returnUrl"] = "/";
            props.StoreTokens(
            [
                new AuthenticationToken { Name = "access_token", Value = "test-access-token" },
                new AuthenticationToken { Name = "id_token", Value = "test-id-token" },
            ]);

            await http.SignInAsync(KlassdAuthSchemes.External, new ClaimsPrincipal(identity), props);
            return Results.Ok();
        });

        // Echoes the "hd" claim from the (default = cookie) principal.
        app.MapGet("/whoami-hd", (HttpContext http) => Results.Content(http.User.FindFirst("hd")?.Value ?? "none"));

        await app.StartAsync();
        return app;
    }
}
