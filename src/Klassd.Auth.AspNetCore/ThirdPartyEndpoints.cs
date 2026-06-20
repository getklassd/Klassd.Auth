using Klassd.Auth.Abstractions;
using Klassd.Auth.Core.Modules.ThirdParty;
using Klassd.Auth.Core.Sessions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace Klassd.Auth.AspNetCore;

/// <summary>
/// Context for an <see cref="IThirdPartySignInHook"/> — the JWT-flow analogue of the SuperTokens
/// post-sign-in-up hook (<c>AzureAdV2PostSignInUp</c>): the resolved user, the live session to merge
/// into, the "new user" flag, and the provider's tokens + profile.
/// </summary>
public sealed record ThirdPartySignInContext(
    string Provider,
    string UserId,
    KlassdSession Session,
    bool IsNewUser,
    ThirdPartyTokens Tokens,
    ThirdPartyProfile Profile,
    HttpContext Http);

/// <summary>
/// Runs after a third-party (JWT) sign-in resolves to a user and a session is created, with the
/// provider's tokens in hand. Call the provider's APIs, persist data, and merge into
/// <see cref="ThirdPartySignInContext.Session"/> — exactly like <c>session.MergeIntoAccessTokenPayload</c>.
/// </summary>
public interface IThirdPartySignInHook
{
    Task OnSignedInAsync(ThirdPartySignInContext context, CancellationToken ct = default);
}

/// <summary>Delegate form of <see cref="IThirdPartySignInHook"/> (gets the request's services).</summary>
public delegate Task ThirdPartySignInHookDelegate(
    ThirdPartySignInContext context, IServiceProvider services, CancellationToken ct);

public sealed record ThirdPartySignInRequest(string Code, string RedirectUri);

public static class ThirdPartyHookExtensions
{
    /// <summary>Registers a post-sign-in hook for the JWT third-party flow (handed the session + provider tokens).</summary>
    public static IAuthBuilder AddThirdPartySignInHook<THook>(this IAuthBuilder auth)
        where THook : class, IThirdPartySignInHook
    {
        auth.Services.AddScoped<IThirdPartySignInHook, THook>();
        return auth;
    }

    /// <summary>Inline form of <see cref="AddThirdPartySignInHook{THook}"/>.</summary>
    public static IAuthBuilder AddThirdPartySignInHook(this IAuthBuilder auth, ThirdPartySignInHookDelegate hook)
    {
        auth.Services.AddScoped<IThirdPartySignInHook>(sp => new DelegateThirdPartySignInHook(hook, sp));
        return auth;
    }

    private sealed class DelegateThirdPartySignInHook(ThirdPartySignInHookDelegate hook, IServiceProvider services)
        : IThirdPartySignInHook
    {
        public Task OnSignedInAsync(ThirdPartySignInContext context, CancellationToken ct = default) =>
            hook(context, services, ct);
    }
}

public static class ThirdPartyEndpoints
{
    /// <summary>
    /// Maps the JWT third-party flow: get an authorization URL, then exchange the returned code for a
    /// session. After the session is created, registered <see cref="IThirdPartySignInHook"/>s run with
    /// the provider tokens and the live session; the returned access token reflects their merges.
    /// Requires one or more <see cref="IThirdPartyProvider"/> registered via <c>auth.AddProvider&lt;T&gt;()</c>.
    /// </summary>
    public static IEndpointRouteBuilder MapKlassdThirdParty(this IEndpointRouteBuilder app, string prefix = "/auth/thirdparty")
    {
        var g = app.MapGroup(prefix);

        // Build the provider's authorization URL (frontend redirects the user here).
        g.MapGet("/{provider}/authurl", (string provider, string redirectUri, string? state, IThirdPartyService tp) =>
        {
            IThirdPartyProvider impl;
            try { impl = tp.GetProvider(provider); }
            catch (KeyNotFoundException) { return Results.NotFound(new { error = "UNKNOWN_PROVIDER" }); }

            var st = string.IsNullOrEmpty(state) ? Guid.NewGuid().ToString("N") : state;
            return Results.Ok(new { url = impl.BuildAuthorizationUrl(st, redirectUri), state = st });
        });

        // Exchange the code → profile + tokens → sign-in/up → session → hooks → tokens.
        g.MapPost("/{provider}/signin", async (
            string provider, ThirdPartySignInRequest req, HttpContext http,
            IThirdPartyService tp, ISessionService sessions, IEnumerable<IThirdPartySignInHook> hooks) =>
        {
            IThirdPartyProvider impl;
            try { impl = tp.GetProvider(provider); }
            catch (KeyNotFoundException) { return Results.NotFound(new { error = "UNKNOWN_PROVIDER" }); }

            var ct = http.RequestAborted;
            var exchange = await impl.ExchangeCodeAsync(req.Code, req.RedirectUri, ct);
            var signIn = await tp.SignInOrUpAsync(provider, exchange.Profile, ct);

            var created = await sessions.CreateAsync(
                signIn.UserId, sessionData: null,
                metadata: new Dictionary<string, object?> { ["provider"] = provider }, ct);

            var hookList = hooks as IReadOnlyList<IThirdPartySignInHook> ?? hooks.ToList();
            var tokens = created;
            if (hookList.Count > 0 && await sessions.GetSessionAsync(created.Handle, ct) is { } session)
            {
                var ctx = new ThirdPartySignInContext(
                    provider, signIn.UserId, session, signIn.CreatedNewUser, exchange.Tokens, exchange.Profile, http);
                foreach (var hook in hookList)
                    await hook.OnSignedInAsync(ctx, ct);

                // Hooks persisted their merges; re-issue so the returned access token carries them.
                tokens = await sessions.RefreshAsync(created.RefreshToken, ct);
            }

            return Results.Ok(new
            {
                accessToken = tokens.AccessToken,
                refreshToken = tokens.RefreshToken,
                handle = tokens.Handle,
                createdNewUser = signIn.CreatedNewUser,
            });
        });

        return app;
    }
}
