using System.Security.Claims;

namespace Klassd.Auth.Core.Sessions;

/// <summary>Context handed to an enricher when an access token is being issued.</summary>
/// <param name="UserId">The user the token is for (the <c>sub</c> claim).</param>
/// <param name="SessionHandle">The session this token belongs to.</param>
/// <param name="SessionData">The session's stored key/value bag (also emitted as prefixed claims).</param>
public sealed record AccessTokenClaimsContext(
    string UserId, string SessionHandle, IReadOnlyDictionary<string, string> SessionData);

/// <summary>
/// Adds custom claims to access tokens. Invoked on <em>every</em> issue — at sign-in and on every
/// refresh — so claims derived from live data (roles, tenant, profile fields) stay current rather
/// than freezing at login. Register one or more via <c>AddAccessTokenClaimsEnricher</c> /
/// <c>AddAccessTokenClaims</c>; all registered enrichers contribute.
/// </summary>
public interface IAccessTokenClaimsEnricher
{
    Task<IEnumerable<Claim>> GetClaimsAsync(AccessTokenClaimsContext context, CancellationToken ct = default);
}
