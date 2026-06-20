using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Klassd.Auth.Core.Sessions;
using TUnit.Assertions;
using TUnit.Assertions.Extensions;
using TUnit.Core;

namespace Klassd.Auth.Tests;

/// <summary>
/// The SuperTokens <c>sessionContainer</c> ergonomics: a session create hook handed the live session
/// (CreateNewSession analogue), and a <see cref="KlassdSession"/> resolved by handle to merge into.
/// </summary>
public sealed class SessionContainerTests
{
    private static SessionService NewService(out FakeSessionStore store, params ISessionCreateHook[] createHooks)
    {
        store = new FakeSessionStore();
        var config = new SessionConfig { SigningKey = "0123456789abcdef0123456789abcdef", SessionDataClaimPrefix = "" };
        return new SessionService(store, config, new SymmetricTokenSigningKey(config), null, createHooks);
    }

    private sealed class StampHook : ISessionCreateHook
    {
        public Task OnSessionCreatedAsync(KlassdSession session, SessionCreateContext ctx, CancellationToken ct = default) =>
            session.MergeIntoAccessTokenPayloadAsync(new Dictionary<string, object?>
            {
                ["tenant"] = "acme",
                ["roles"] = new[] { "admin" },
            }, ct);
    }

    [Test]
    public async Task Create_hook_stamps_the_first_token()
    {
        var svc = NewService(out _, new StampHook());
        var tokens = await svc.CreateAsync("user1");

        var principal = svc.ValidateAccessToken(tokens.AccessToken);   // no refresh needed — stamped at create
        await Assert.That(principal.FindFirst("tenant")?.Value).IsEqualTo("acme");
        await Assert.That(principal.IsInRole("admin")).IsTrue();
    }

    [Test]
    public async Task GetSession_returns_a_container_with_the_current_payload()
    {
        var svc = NewService(out _, new StampHook());
        var tokens = await svc.CreateAsync("user1");

        var session = await svc.GetSessionAsync(tokens.Handle);
        await Assert.That(session).IsNotNull();
        await Assert.That(session!.UserId).IsEqualTo("user1");
        await Assert.That(session.GetClaimValue<string>("tenant")).IsEqualTo("acme");
        await Assert.That(session.GetClaimValue<string[]>("roles")).IsEquivalentTo(new[] { "admin" });
    }

    [Test]
    public async Task Container_merge_persists_and_shows_on_the_next_token()
    {
        var svc = NewService(out _);
        var tokens = await svc.CreateAsync("user1");
        var session = await svc.GetSessionAsync(tokens.Handle);

        await session!.MergeIntoAccessTokenPayloadAsync(new { picture = "https://img/x.png" });   // anonymous-object overload

        await Assert.That(session.GetClaimValue<string>("picture")).IsEqualTo("https://img/x.png");
        var refreshed = await svc.RefreshAsync(tokens.RefreshToken);
        await Assert.That(svc.ValidateAccessToken(refreshed.AccessToken).FindFirst("picture")?.Value)
            .IsEqualTo("https://img/x.png");
    }

    [Test]
    public async Task Create_hook_receives_caller_metadata()
    {
        string? seenProvider = null;
        var hook = new CapturingHook(ctx => seenProvider = ctx.Metadata.TryGetValue("provider", out var v) ? v as string : null);
        var svc = NewService(out _, hook);

        await svc.CreateAsync("user1", sessionData: null,
            metadata: new Dictionary<string, object?> { ["provider"] = "azuread" });

        await Assert.That(seenProvider).IsEqualTo("azuread");
    }

    private sealed class CapturingHook(Action<SessionCreateContext> capture) : ISessionCreateHook
    {
        public Task OnSessionCreatedAsync(KlassdSession session, SessionCreateContext ctx, CancellationToken ct = default)
        {
            capture(ctx);
            return Task.CompletedTask;
        }
    }

    [Test]
    public async Task GetSession_returns_null_for_unknown_handle()
    {
        var svc = NewService(out _);
        await Assert.That(await svc.GetSessionAsync("nope")).IsNull();
    }
}
