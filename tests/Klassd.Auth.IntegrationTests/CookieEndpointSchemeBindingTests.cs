using System.Net;
using System.Text.Encodings.Web;
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
using Microsoft.Extensions.Options;

namespace Klassd.Auth.IntegrationTests;

/// <summary>
/// The signed-in-only cookie endpoints (account linking, <c>/me/*</c>) must authorize against the
/// cookie scheme explicitly, so they keep working when the cookie is NOT the app's default scheme —
/// e.g. mounted inside a host that has its own default auth scheme. Proven by the challenge behaviour:
/// an unauthenticated call is challenged by the COOKIE handler (redirect to its login path), not by the
/// host's default scheme (which here answers with a distinctive 418).
/// </summary>
public class CookieEndpointSchemeBindingTests
{
    private const string HostScheme = "HostDefault";

    [Test]
    public async Task Me_endpoint_challenges_the_cookie_scheme_not_the_host_default()
    {
        await using var app = await BuildAsync();
        var client = app.GetTestClient();   // TestServer does not auto-follow redirects

        var response = await client.GetAsync("/auth/me/methods");

        // Cookie handler challenge → 302 to its login path. If the endpoint had used the host default
        // scheme instead, this would be the host handler's 418.
        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Redirect);
        await Assert.That(response.Headers.Location!.OriginalString).Contains("login");
    }

    private static async Task<WebApplication> BuildAsync()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Logging.ClearProviders();

        // A host with its OWN default scheme that answers challenges with a distinctive 418.
        builder.Services.AddAuthentication(HostScheme)
            .AddScheme<AuthenticationSchemeOptions, TeapotHandler>(HostScheme, _ => { });

        var auth = builder.Services.AddKlassdAuth(new SessionConfig
        {
            SigningKey = "test-signing-key-that-is-at-least-32-chars",
        });
        auth.AddKlassdAuthCookies(o =>
        {
            o.BasePath = "/auth";
            o.LoginPath = "/login";
        });
        auth.UseSqlite($"Data Source={Path.Combine(Path.GetTempPath(), $"klassd-auth-bind-{Guid.NewGuid():n}.db")}");

        // Keep the host's scheme as the app default (mirrors the shared-host wiring), so the cookie is a
        // named, non-default scheme — exactly the case the endpoint binding must survive.
        builder.Services.PostConfigure<AuthenticationOptions>(o => o.DefaultScheme = HostScheme);

        var app = builder.Build();
        app.UseAuthentication();
        app.UseAuthorization();
        app.MapKlassdAuthCookieEndpoints();

        await app.StartAsync();
        return app;
    }

    /// <summary>A host default scheme that authenticates no one and answers challenges with 418 — a value
    /// no Klassd handler emits, so it cleanly proves whether the host default was (wrongly) consulted.</summary>
    private sealed class TeapotHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder)
        : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
    {
        protected override Task<AuthenticateResult> HandleAuthenticateAsync() =>
            Task.FromResult(AuthenticateResult.NoResult());

        protected override Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            Response.StatusCode = StatusCodes.Status418ImATeapot;
            return Task.CompletedTask;
        }
    }
}
