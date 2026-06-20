using Klassd.Auth.AspNetCore;
using Klassd.Auth.Core.DependencyInjection;
using Klassd.Auth.Core.Sessions;
using Klassd.Auth.Data.Sqlite;
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
/// Proves the SuperTokens <c>GetSessionFromRequestContext(...).MergeIntoAccessTokenPayload(...)</c>
/// ergonomic: an endpoint resolves the current session from the bearer token and merges into its
/// payload, and the change persists (visible on a later request). Mirrors the Go service's
/// <c>update_metadata</c> handler.
/// </summary>
public class SessionFromRequestTests
{
    [Test]
    public async Task Endpoint_resolves_session_from_bearer_and_merges_payload()
    {
        await using var app = await BuildAsync();
        var client = app.GetTestClient();

        // Mint a session and grab its access token.
        var made = await (await client.PostAsync("/make", null)).Content.ReadAsStringAsync();

        // Merge a claim into the live session via the bearer token (like update_metadata.go).
        using (var merge = new HttpRequestMessage(HttpMethod.Post, "/merge"))
        {
            merge.Headers.Add("Authorization", $"Bearer {made}");
            var resp = await client.SendAsync(merge);
            await Assert.That(resp.IsSuccessStatusCode).IsTrue();
        }

        // Read it back through GetKlassdSessionAsync on a fresh request.
        using var read = new HttpRequestMessage(HttpMethod.Get, "/payload");
        read.Headers.Add("Authorization", $"Bearer {made}");
        var body = await (await client.SendAsync(read)).Content.ReadAsStringAsync();
        await Assert.That(body).IsEqualTo("acme.com");
    }

    [Test]
    public async Task No_bearer_token_yields_no_session()
    {
        await using var app = await BuildAsync();
        var client = app.GetTestClient();
        var body = await (await client.GetAsync("/payload")).Content.ReadAsStringAsync();
        await Assert.That(body).IsEqualTo("none");
    }

    private static async Task<WebApplication> BuildAsync()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Logging.ClearProviders();

        var auth = builder.Services.AddKlassdAuth(new SessionConfig
        {
            SigningKey = "test-signing-key-that-is-at-least-32-chars",
            SessionDataClaimPrefix = "",
        });
        auth.UseSqlite($"Data Source={Path.Combine(Path.GetTempPath(), $"klassd-sfr-{Guid.NewGuid():n}.db")}");

        var app = builder.Build();

        app.MapPost("/make", async (ISessionService s) =>
            Results.Content((await s.CreateAsync("user-1")).AccessToken));

        // GetSessionFromRequestContext(...).MergeIntoAccessTokenPayload(...) equivalent.
        app.MapPost("/merge", async (HttpContext http) =>
        {
            var session = await http.GetKlassdSessionAsync();
            if (session is null) return Results.Unauthorized();
            await session.MergeIntoAccessTokenPayloadAsync(new { hd = "acme.com" });
            return Results.Ok();
        });

        app.MapGet("/payload", async (HttpContext http) =>
        {
            var session = await http.GetKlassdSessionAsync();
            return Results.Content(session?.GetClaimValue<string>("hd") ?? "none");
        });

        await app.StartAsync();
        return app;
    }
}
