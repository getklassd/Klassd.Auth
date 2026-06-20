using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Klassd.Auth.Abstractions;
using Klassd.Auth.Core.DependencyInjection;
using Klassd.Auth.Core.Modules.Users;
using Klassd.Auth.Core.Sessions;
using Microsoft.Extensions.DependencyInjection;
using TUnit.Assertions;
using TUnit.Assertions.Extensions;
using TUnit.Core;

namespace Klassd.Auth.Tests;

/// <summary>
/// Covers the SuperTokens <c>MergeIntoAccessTokenPayload</c> equivalent: claims merged into a session
/// persist on the session, land on the access token, and survive refresh.
/// </summary>
public sealed class AccessTokenPayloadTests
{
    // No prefix, so merged payload keys appear as raw claim names (SuperTokens-style).
    private static SessionService NewService(out FakeSessionStore store)
    {
        store = new FakeSessionStore();
        var config = new SessionConfig { SigningKey = "0123456789abcdef0123456789abcdef", SessionDataClaimPrefix = "" };
        return new SessionService(store, config, new SymmetricTokenSigningKey(config));
    }

    private static JwtSecurityToken Decode(string jwt) => new JwtSecurityTokenHandler().ReadJwtToken(jwt);

    [Test]
    public async Task Merge_adds_string_and_array_claims_to_the_next_token()
    {
        var svc = NewService(out _);
        var tokens = await svc.CreateAsync("user1");

        await svc.MergeIntoAccessTokenPayloadAsync(tokens.Handle, new Dictionary<string, object?>
        {
            ["first_name"] = "Jane",
            ["roles"] = new[] { "admin", "editor" },
        });

        // The current token predates the merge; the freshly-issued one (via refresh) carries it.
        var refreshed = await svc.RefreshAsync(tokens.RefreshToken);
        var principal = svc.ValidateAccessToken(refreshed.AccessToken);

        await Assert.That(principal.FindFirst("first_name")?.Value).IsEqualTo("Jane");
        // Roles came through as a JSON array → two claims. The handler maps the "roles" claim to
        // ClaimTypes.Role (so User.IsInRole / [Authorize(Roles=…)] work out of the box).
        var roles = principal.FindAll(ClaimTypes.Role).Select(c => c.Value).ToList();
        await Assert.That(roles).Contains("admin");
        await Assert.That(roles).Contains("editor");
        await Assert.That(principal.IsInRole("admin")).IsTrue();
    }

    [Test]
    public async Task Merged_payload_is_a_real_json_array_in_the_token()
    {
        var svc = NewService(out _);
        var tokens = await svc.CreateAsync("user1");
        await svc.MergeIntoAccessTokenPayloadAsync(tokens.Handle,
            new Dictionary<string, object?> { ["roles"] = new[] { "a", "b" } });

        var refreshed = await svc.RefreshAsync(tokens.RefreshToken);
        // Raw JWT payload should contain a JSON array, not an escaped string.
        var json = Decode(refreshed.AccessToken).Payload.SerializeToJson();
        await Assert.That(json).Contains("\"roles\":[\"a\",\"b\"]");
    }

    [Test]
    public async Task Merge_survives_multiple_refreshes()
    {
        var svc = NewService(out _);
        var t0 = await svc.CreateAsync("user1");
        await svc.MergeIntoAccessTokenPayloadAsync(t0.Handle, new Dictionary<string, object?> { ["tenant"] = "acme" });

        var t1 = await svc.RefreshAsync(t0.RefreshToken);
        var t2 = await svc.RefreshAsync(t1.RefreshToken);

        await Assert.That(svc.ValidateAccessToken(t2.AccessToken).FindFirst("tenant")?.Value).IsEqualTo("acme");
    }

    [Test]
    public async Task Null_value_removes_a_payload_claim()
    {
        var svc = NewService(out _);
        var t0 = await svc.CreateAsync("user1", new Dictionary<string, string> { ["tenant"] = "acme" });
        await svc.MergeIntoAccessTokenPayloadAsync(t0.Handle, new Dictionary<string, object?> { ["tenant"] = null });

        var refreshed = await svc.RefreshAsync(t0.RefreshToken);
        await Assert.That(svc.ValidateAccessToken(refreshed.AccessToken).FindFirst("tenant")).IsNull();
    }

    [Test]
    public async Task Merge_into_unknown_session_throws()
    {
        var svc = NewService(out _);
        await Assert.That(async () =>
            await svc.MergeIntoAccessTokenPayloadAsync("nope", new Dictionary<string, object?> { ["x"] = "y" }))
            .Throws<Microsoft.IdentityModel.Tokens.SecurityTokenException>();
    }

    // ---- End-to-end: a third-party provider claim → persisted at login → on every JWT. ----
    // Mirrors the SuperTokens post-sign-in-up pattern (azureadv2.go): capture provider claims,
    // store in user metadata, then surface them on the access token (here via the merge primitive).
    [Test]
    public async Task Provider_claim_flows_onto_the_jwt_via_override_plus_merge()
    {
        var services = new ServiceCollection();
        var auth = services.AddKlassdAuth(new SessionConfig
        {
            SigningKey = "0123456789abcdef0123456789abcdef",
            SessionDataClaimPrefix = "",
        });
        services.AddScoped<IUserStore, FakeUserStore>();
        services.AddScoped<ISessionStore, FakeSessionStore>();
        services.AddScoped<IUserMetadataStore, FakeMetadataStore>();
        var sp = services.BuildServiceProvider();

        await using var scope = sp.CreateAsyncScope();
        var accounts = scope.ServiceProvider.GetRequiredService<IUserAccountService>();
        var sessions = scope.ServiceProvider.GetRequiredService<ISessionService>();

        // Provider returned an extra claim ("hd" = hosted domain) alongside the identity.
        var info = new ExternalUserInfo("ext-1", "jane", "jane@acme.com", EmailVerified: true)
        {
            Claims = new Dictionary<string, string> { ["hd"] = "acme.com" },
        };
        var user = await accounts.ProvisionExternalAsync("azuread", info, autoProvision: true);
        await Assert.That(user).IsNotNull();

        // Post-sign-in: create a session and merge the captured provider claim onto its payload.
        var tokens = await sessions.CreateAsync(user!.Id);
        await sessions.MergeIntoAccessTokenPayloadAsync(tokens.Handle,
            new Dictionary<string, object?> { ["hd"] = info.Claims["hd"] });

        var refreshed = await sessions.RefreshAsync(tokens.RefreshToken);
        await Assert.That(sessions.ValidateAccessToken(refreshed.AccessToken).FindFirst("hd")?.Value).IsEqualTo("acme.com");
    }
}
