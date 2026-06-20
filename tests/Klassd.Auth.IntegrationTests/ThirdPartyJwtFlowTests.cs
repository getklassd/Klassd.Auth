using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Json;
using System.Text.Json;
using Klassd.Auth.AspNetCore;
using Klassd.Auth.Core.DependencyInjection;
using Klassd.Auth.Core.Modules.ThirdParty;
using Klassd.Auth.Core.Sessions;
using Klassd.Auth.Data.Sqlite;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using TUnit.Assertions;
using TUnit.Assertions.Extensions;

namespace Klassd.Auth.IntegrationTests;

/// <summary>
/// The full JWT third-party flow — the closest match to the Go service's <c>SignInUpPOST</c> override
/// calling <c>AzureAdV2PostSignInUp(userId, OAuthTokens, sessionContainer, newUser)</c>: exchange code →
/// session, then a hook gets the provider tokens + the live session and merges a provider claim onto
/// the access token.
/// </summary>
public class ThirdPartyJwtFlowTests
{
    private static string? _seenAccessToken;
    private static bool _seenIsNew;

    [Test]
    public async Task Signin_exchanges_creates_session_and_hook_merges_provider_claim()
    {
        _seenAccessToken = null;
        await using var app = await BuildAsync();
        var client = app.GetTestClient();

        // Authorization URL carries the state.
        var authUrl = await client.GetFromJsonAsync<JsonElement>("/auth/thirdparty/fake/authurl?redirectUri=https://app/cb");
        await Assert.That(authUrl.GetProperty("url").GetString()).Contains("state=");

        // Exchange a code → tokens.
        var resp = await client.PostAsJsonAsync("/auth/thirdparty/fake/signin",
            new { code = "auth-code", redirectUri = "https://app/cb" });
        await Assert.That(resp.IsSuccessStatusCode).IsTrue();
        var body = await resp.Content.ReadFromJsonAsync<JsonElement>();

        // The hook saw the provider access token and the new-user flag.
        await Assert.That(_seenAccessToken).IsEqualTo("provider-access-token");
        await Assert.That(_seenIsNew).IsTrue();
        await Assert.That(body.GetProperty("createdNewUser").GetBoolean()).IsTrue();

        // The returned access token carries the provider claim the hook merged.
        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(body.GetProperty("accessToken").GetString());
        await Assert.That(jwt.Claims.First(c => c.Type == "hd").Value).IsEqualTo("acme.com");
    }

    [Test]
    public async Task Unknown_provider_is_404()
    {
        await using var app = await BuildAsync();
        var client = app.GetTestClient();
        var resp = await client.PostAsJsonAsync("/auth/thirdparty/nope/signin",
            new { code = "x", redirectUri = "y" });
        await Assert.That((int)resp.StatusCode).IsEqualTo(404);
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
        auth.UseSqlite($"Data Source={Path.Combine(Path.GetTempPath(), $"klassd-tpjwt-{Guid.NewGuid():n}.db")}");
        auth.AddProvider<FakeProvider>();

        // Post-sign-in hook: capture provider token + new-user, merge a provider claim into the session.
        auth.AddThirdPartySignInHook(async (ctx, sp, ct) =>
        {
            _seenAccessToken = ctx.Tokens.AccessToken;
            _seenIsNew = ctx.IsNewUser;
            await ctx.Session.MergeIntoAccessTokenPayloadAsync(new { hd = ctx.Profile.Claims["hd"] }, ct);
        });

        var app = builder.Build();
        app.MapKlassdThirdParty();
        await app.StartAsync();
        return app;
    }

    private sealed class FakeProvider : IThirdPartyProvider
    {
        public string Id => "fake";

        public string BuildAuthorizationUrl(string state, string redirectUri) =>
            $"https://fake.example/authorize?state={state}&redirect_uri={Uri.EscapeDataString(redirectUri)}";

        public Task<ThirdPartyExchange> ExchangeCodeAsync(string code, string redirectUri, CancellationToken ct = default) =>
            Task.FromResult(new ThirdPartyExchange(
                new ThirdPartyProfile("ext-fake-1", "jane@acme.com", EmailVerified: true)
                {
                    Claims = new Dictionary<string, string> { ["hd"] = "acme.com" },
                },
                new ThirdPartyTokens("provider-access-token", "provider-id-token", "provider-refresh-token", null,
                    new Dictionary<string, string> { ["access_token"] = "provider-access-token" })));
    }
}
