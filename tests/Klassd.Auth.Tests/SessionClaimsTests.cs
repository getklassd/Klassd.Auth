using System.Security.Claims;
using Klassd.Auth.Core.Sessions;
using TUnit.Assertions;
using TUnit.Assertions.Extensions;
using TUnit.Core;

namespace Klassd.Auth.Tests;

public sealed class SessionClaimsTests
{
    private static SessionService NewService(
        SessionConfig? config = null, params IAccessTokenClaimsEnricher[] enrichers)
    {
        config ??= new SessionConfig { SigningKey = "0123456789abcdef0123456789abcdef" };
        return new SessionService(new FakeSessionStore(), config, new SymmetricTokenSigningKey(config), enrichers);
    }

    private sealed class StaticEnricher(params Claim[] claims) : IAccessTokenClaimsEnricher
    {
        public Task<IEnumerable<Claim>> GetClaimsAsync(AccessTokenClaimsContext ctx, CancellationToken ct = default) =>
            Task.FromResult<IEnumerable<Claim>>(claims);
    }

    [Test]
    public async Task Enricher_claims_are_embedded_on_create()
    {
        var svc = NewService(enrichers: new StaticEnricher(new Claim("tenant", "acme"), new Claim("department", "eng")));
        var tokens = await svc.CreateAsync("user1");

        var principal = svc.ValidateAccessToken(tokens.AccessToken);
        await Assert.That(principal.FindFirst("tenant")?.Value).IsEqualTo("acme");
        await Assert.That(principal.FindFirst("department")?.Value).IsEqualTo("eng");
    }

    [Test]
    public async Task Enricher_runs_again_on_refresh_so_claims_stay_fresh()
    {
        // The enricher returns whatever its current state says — proving it re-runs at refresh time
        // rather than replaying claims captured at login.
        var role = new MutableEnricher { Value = "viewer" };
        var svc = NewService(enrichers: role);

        var first = await svc.CreateAsync("user1");
        await Assert.That(svc.ValidateAccessToken(first.AccessToken).FindFirst("tier")?.Value).IsEqualTo("viewer");

        role.Value = "admin";                       // the user's role changes server-side
        var refreshed = await svc.RefreshAsync(first.RefreshToken);
        await Assert.That(svc.ValidateAccessToken(refreshed.AccessToken).FindFirst("tier")?.Value).IsEqualTo("admin");
    }

    private sealed class MutableEnricher : IAccessTokenClaimsEnricher
    {
        public required string Value { get; set; }
        public Task<IEnumerable<Claim>> GetClaimsAsync(AccessTokenClaimsContext ctx, CancellationToken ct = default) =>
            Task.FromResult<IEnumerable<Claim>>([new Claim("tier", Value)]);
    }

    [Test]
    public async Task SessionData_claims_use_the_sd_prefix_by_default()
    {
        var svc = NewService();
        var tokens = await svc.CreateAsync("user1", new Dictionary<string, string> { ["theme"] = "dark" });

        var principal = svc.ValidateAccessToken(tokens.AccessToken);
        await Assert.That(principal.FindFirst("sd_theme")?.Value).IsEqualTo("dark");
        await Assert.That(principal.FindFirst("theme")).IsNull();
    }

    [Test]
    public async Task SessionData_prefix_can_be_disabled()
    {
        var config = new SessionConfig { SigningKey = "0123456789abcdef0123456789abcdef", SessionDataClaimPrefix = "" };
        var svc = NewService(config);
        var tokens = await svc.CreateAsync("user1", new Dictionary<string, string> { ["theme"] = "dark" });

        var principal = svc.ValidateAccessToken(tokens.AccessToken);
        await Assert.That(principal.FindFirst("theme")?.Value).IsEqualTo("dark");
        await Assert.That(principal.FindFirst("sd_theme")).IsNull();
    }
}
