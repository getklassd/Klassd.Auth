using System.Security.Claims;
using Klassd.Auth.Core.Sessions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Klassd.Auth.AspNetCore;

/// <summary>
/// Resolves the current request's <see cref="KlassdSession"/> — the equivalent of SuperTokens'
/// <c>session.GetSessionFromRequestContext</c> — so any endpoint can merge into the live access-token
/// payload (mirrors the Go service's <c>update_metadata</c> handler).
/// </summary>
public static class KlassdSessionRequestExtensions
{
    /// <summary>
    /// Gets the session for the current request, from the validated principal's <c>sessionHandle</c>
    /// claim if present, otherwise from the <c>Authorization: Bearer</c> access token. Returns null if
    /// there is no valid session.
    /// </summary>
    public static async Task<KlassdSession?> GetKlassdSessionAsync(this HttpContext http, CancellationToken ct = default)
    {
        var sessions = http.RequestServices.GetRequiredService<ISessionService>();

        var handle = http.User.GetSessionHandle();
        if (handle is null && ReadBearer(http.Request) is { } token)
        {
            try { handle = sessions.ValidateAccessToken(token).GetSessionHandle(); }
            catch { return null; }   // invalid/expired token → no session
        }

        return handle is null ? null : await sessions.GetSessionAsync(handle, ct);
    }

    /// <summary>The session handle embedded in an access token's principal, if any.</summary>
    public static string? GetSessionHandle(this ClaimsPrincipal principal) =>
        principal.FindFirst("sessionHandle")?.Value;

    private static string? ReadBearer(HttpRequest request)
    {
        var header = request.Headers.Authorization.ToString();
        return header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
            ? header["Bearer ".Length..].Trim()
            : null;
    }
}
