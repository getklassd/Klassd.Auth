using System.Security.Claims;
using Klassd.Auth.Abstractions;
using Microsoft.AspNetCore.Http;

namespace Klassd.Auth.AspNetCore.Cookies;

/// <summary>
/// The provider's OAuth/OIDC tokens captured during an external sign-in, so a hook can call the
/// provider's APIs (e.g. Microsoft Graph for a profile picture) with the user's access token.
/// Populated only for providers registered with token saving enabled (the built-in providers do this).
/// </summary>
public sealed record ExternalTokens(
    string? AccessToken,
    string? IdToken,
    string? RefreshToken,
    DateTimeOffset? ExpiresAt,
    IReadOnlyDictionary<string, string> All);

/// <summary>
/// Context for an <see cref="IExternalSignInHook"/>, raised after an external (SSO) sign-in resolves to
/// a local <see cref="User"/> but before the app cookie is issued — the analogue of SuperTokens'
/// post-sign-in-up hook (which receives the user, the provider tokens, and a "new user" flag).
/// </summary>
/// <param name="Provider">The provider scheme id (e.g. "azuread", "google").</param>
/// <param name="User">The resolved/created local user.</param>
/// <param name="IsFirstSignIn">
/// True when no login method for this external identity existed before this sign-in (first time the
/// user authenticates with this provider). Use it to gate one-time provisioning.
/// </param>
/// <param name="Tokens">The provider's tokens (see <see cref="ExternalTokens"/>).</param>
/// <param name="Principal">The raw external principal as returned by the provider (all its claims).</param>
/// <param name="Http">The current request, for resolving services or reading the request.</param>
public sealed record ExternalSignInContext(
    string Provider,
    User User,
    bool IsFirstSignIn,
    ExternalTokens Tokens,
    ClaimsPrincipal Principal,
    HttpContext Http);

/// <summary>
/// Runs after an external sign-in, with the provider's tokens in hand. Do side effects here (persist
/// profile to user metadata, fetch a picture from the provider, …) and return any extra claims to add
/// to the app cookie. Multiple hooks run in registration order; all of their claims are added.
/// </summary>
public interface IExternalSignInHook
{
    Task<IEnumerable<Claim>> OnSignedInAsync(ExternalSignInContext context, CancellationToken ct = default);
}

/// <summary>Delegate form of <see cref="IExternalSignInHook"/> (gets the provider for DI lookups).</summary>
public delegate Task<IEnumerable<Claim>> ExternalSignInHookDelegate(
    ExternalSignInContext context, IServiceProvider services, CancellationToken ct);

internal sealed class DelegateExternalSignInHook(ExternalSignInHookDelegate hook, IServiceProvider services)
    : IExternalSignInHook
{
    public Task<IEnumerable<Claim>> OnSignedInAsync(ExternalSignInContext context, CancellationToken ct = default) =>
        hook(context, services, ct);
}
