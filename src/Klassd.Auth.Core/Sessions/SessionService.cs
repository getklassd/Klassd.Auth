using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Klassd.Auth.Abstractions;
using Microsoft.IdentityModel.Tokens;

namespace Klassd.Auth.Core.Sessions;

public sealed class SessionConfig
{
    /// <summary>Symmetric signing key for access-token JWTs (use RS256 + JWKS in production).</summary>
    public required string SigningKey { get; init; }
    public string Issuer { get; init; } = "klassd.auth";
    public string Audience { get; init; } = "klassd.auth";
    public TimeSpan AccessTokenLifetime { get; init; } = TimeSpan.FromMinutes(15);
    public TimeSpan RefreshTokenLifetime { get; init; } = TimeSpan.FromDays(30);

    /// <summary>
    /// Prefix applied to claim names derived from <c>SessionData</c> (e.g. "theme" → "sd_theme"),
    /// so they can't be confused with first-class claims. Set to "" to emit them unprefixed.
    /// Claims added by an <see cref="IAccessTokenClaimsEnricher"/> are never prefixed.
    /// </summary>
    public string SessionDataClaimPrefix { get; init; } = "sd_";
}

public sealed record SessionTokens(string AccessToken, string RefreshToken, string Handle);

/// <summary>Issues/validates access + refresh tokens. Override via <c>auth.Override&lt;ISessionService&gt;(…)</c>.</summary>
public interface ISessionService
{
    Task<SessionTokens> CreateAsync(string userId, Dictionary<string, string>? sessionData = null, CancellationToken ct = default);

    /// <summary>
    /// Creates a session, passing <paramref name="metadata"/> (e.g. provider tokens) to the registered
    /// <see cref="ISessionCreateHook"/>s, which are handed the live session to stamp the payload.
    /// </summary>
    Task<SessionTokens> CreateAsync(string userId, Dictionary<string, string>? sessionData,
        IReadOnlyDictionary<string, object?>? metadata, CancellationToken ct = default);
    Task<SessionTokens> RefreshAsync(string refreshToken, CancellationToken ct = default);
    Task RevokeAsync(string handle, CancellationToken ct = default);
    ClaimsPrincipal ValidateAccessToken(string accessToken);

    /// <summary>
    /// Merges <paramref name="payload"/> into the session's stored access-token payload — the equivalent
    /// of SuperTokens' <c>sessionContainer.MergeIntoAccessTokenPayload</c>. The values are persisted on
    /// the session, so they ride on the access token issued next and on <em>every refresh</em> (the
    /// provider is only contacted at login, so anything you need on refreshed tokens belongs here).
    /// A null value removes that key. String values become string claims; arrays/objects become real
    /// JSON claims (so a <c>roles</c> string[] lands as a JSON array). Claim names use the same
    /// <see cref="SessionConfig.SessionDataClaimPrefix"/> as session data (set it to "" for raw names).
    /// </summary>
    Task MergeIntoAccessTokenPayloadAsync(string handle, IReadOnlyDictionary<string, object?> payload, CancellationToken ct = default);

    /// <summary>
    /// Resolves a live <see cref="KlassdSession"/> container by handle (the SuperTokens
    /// <c>getSessionInformation</c>/<c>sessionContainer</c> analogue), or null if unknown/revoked.
    /// </summary>
    Task<KlassdSession?> GetSessionAsync(string handle, CancellationToken ct = default);
}

/// <summary>
/// Issues short-lived access JWTs and opaque, rotating refresh tokens. A refresh validates the
/// presented refresh token against the stored hash AND rotates it, so a stolen-and-reused
/// refresh token is detected and the session is revoked defensively.
/// </summary>
public sealed class SessionService(
    ISessionStore store,
    SessionConfig config,
    ITokenSigningKey signingKey,
    IEnumerable<IAccessTokenClaimsEnricher>? claimsEnrichers = null,
    IEnumerable<ISessionCreateHook>? createHooks = null) : ISessionService
{
    private readonly JwtSecurityTokenHandler _jwt = new();
    private readonly IReadOnlyList<IAccessTokenClaimsEnricher> _enrichers = claimsEnrichers?.ToList() ?? [];
    private readonly IReadOnlyList<ISessionCreateHook> _createHooks = createHooks?.ToList() ?? [];

    public Task<SessionTokens> CreateAsync(
        string userId, Dictionary<string, string>? sessionData = null, CancellationToken ct = default) =>
        CreateAsync(userId, sessionData, metadata: null, ct);

    /// <summary>
    /// Creates a session, optionally passing <paramref name="metadata"/> (e.g. provider tokens) to the
    /// registered <see cref="ISessionCreateHook"/>s, which are handed the live session to stamp claims.
    /// </summary>
    public async Task<SessionTokens> CreateAsync(
        string userId, Dictionary<string, string>? sessionData,
        IReadOnlyDictionary<string, object?>? metadata, CancellationToken ct = default)
    {
        var handle = NewToken();
        var refresh = NewToken();
        var entity = new SessionEntity
        {
            Handle = handle,
            UserId = userId,
            RefreshTokenHash = Sha256(refresh),
            CreatedAt = DateTimeOffset.UtcNow,
            RefreshExpiresAt = DateTimeOffset.UtcNow + config.RefreshTokenLifetime,
            SessionData = sessionData ?? [],
        };
        await store.AddAsync(entity, ct);

        // Hand each create hook the live session so it can merge into the payload (CreateNewSession
        // override analogue). Hooks persist their changes; reload so the FIRST token includes them.
        if (_createHooks.Count > 0)
        {
            var session = new KlassdSession(this, handle, userId, new Dictionary<string, string>(entity.SessionData));
            var hookCtx = new SessionCreateContext(userId, metadata ?? new Dictionary<string, object?>());
            foreach (var hook in _createHooks)
                await hook.OnSessionCreatedAsync(session, hookCtx, ct);
            entity = await store.FindAsync(handle, ct) ?? entity;
        }

        return new SessionTokens(await IssueAccessTokenAsync(entity, ct), PackRefresh(handle, refresh), handle);
    }

    public async Task<KlassdSession?> GetSessionAsync(string handle, CancellationToken ct = default)
    {
        var entity = await store.FindAsync(handle, ct);
        if (entity is null || entity.Revoked) return null;
        return new KlassdSession(this, entity.Handle, entity.UserId, new Dictionary<string, string>(entity.SessionData));
    }

    /// <summary>Validates and rotates. Throws <see cref="SecurityTokenException"/> on any anomaly.</summary>
    public async Task<SessionTokens> RefreshAsync(string refreshToken, CancellationToken ct = default)
    {
        var (handle, secret) = UnpackRefresh(refreshToken);
        var entity = await store.FindAsync(handle, ct)
            ?? throw new SecurityTokenException("Unknown session.");

        if (entity.Revoked || entity.RefreshExpiresAt < DateTimeOffset.UtcNow)
            throw new SecurityTokenException("Session expired or revoked.");

        if (!CryptographicOperations.FixedTimeEquals(
                Encoding.UTF8.GetBytes(entity.RefreshTokenHash), Encoding.UTF8.GetBytes(Sha256(secret))))
        {
            await store.RevokeAsync(handle, ct);  // token reuse / tampering — kill the session
            throw new SecurityTokenException("Refresh token mismatch — session revoked.");
        }

        var newRefresh = NewToken();
        entity.RefreshTokenHash = Sha256(newRefresh);
        entity.RefreshExpiresAt = DateTimeOffset.UtcNow + config.RefreshTokenLifetime;
        await store.UpdateAsync(entity, ct);
        return new SessionTokens(await IssueAccessTokenAsync(entity, ct), PackRefresh(handle, newRefresh), handle);
    }

    public Task RevokeAsync(string handle, CancellationToken ct = default) => store.RevokeAsync(handle, ct);

    public async Task MergeIntoAccessTokenPayloadAsync(
        string handle, IReadOnlyDictionary<string, object?> payload, CancellationToken ct = default)
    {
        var entity = await store.FindAsync(handle, ct) ?? throw new SecurityTokenException("Unknown session.");
        foreach (var (key, value) in payload)
        {
            if (value is null) entity.SessionData.Remove(key);          // null removes the claim
            else entity.SessionData[key] = value as string ?? JsonSerializer.Serialize(value);
        }
        await store.UpdateAsync(entity, ct);
    }

    public ClaimsPrincipal ValidateAccessToken(string accessToken)
    {
        var parameters = new TokenValidationParameters
        {
            ValidIssuer = config.Issuer,
            ValidAudience = config.Audience,
            IssuerSigningKeys = signingKey.ValidationKeys,
            ValidateIssuerSigningKey = true,
            ClockSkew = TimeSpan.FromSeconds(30),
        };
        return _jwt.ValidateToken(accessToken, parameters, out _);
    }

    private async Task<string> IssueAccessTokenAsync(SessionEntity s, CancellationToken ct)
    {
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, s.UserId),
            new("sessionHandle", s.Handle),
        };
        claims.AddRange(s.SessionData.Select(kv => ToPayloadClaim($"{config.SessionDataClaimPrefix}{kv.Key}", kv.Value)));

        if (_enrichers.Count > 0)
        {
            var context = new AccessTokenClaimsContext(s.UserId, s.Handle, s.SessionData);
            foreach (var enricher in _enrichers)
                claims.AddRange(await enricher.GetClaimsAsync(context, ct));
        }

        var token = new JwtSecurityToken(
            issuer: config.Issuer,
            audience: config.Audience,
            claims: claims,
            expires: DateTime.UtcNow.Add(config.AccessTokenLifetime),
            signingCredentials: signingKey.SigningCredentials);
        return _jwt.WriteToken(token);
    }

    // A stored payload value that is a JSON object/array is emitted as a real JSON claim (so a roles
    // string[] becomes a JWT array, not a quoted string); everything else is a plain string claim.
    private static Claim ToPayloadClaim(string name, string value)
    {
        var trimmed = value.AsSpan().TrimStart();
        if (trimmed.Length > 0 && trimmed[0] is '[' or '{')
            return new Claim(name, value, trimmed[0] == '[' ? JsonClaimValueTypes.JsonArray : JsonClaimValueTypes.Json);
        return new Claim(name, value);
    }

    // Refresh token is "<handle>.<secret>" so we can look up the session without decoding a JWT.
    private static string PackRefresh(string handle, string secret) => $"{handle}.{secret}";

    private static (string handle, string secret) UnpackRefresh(string token)
    {
        var i = token.IndexOf('.');
        if (i <= 0) throw new SecurityTokenException("Malformed refresh token.");
        return (token[..i], token[(i + 1)..]);
    }

    private static string NewToken() =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static string Sha256(string input) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(input)));
}

/// <summary>Forwarding base for overriding <see cref="ISessionService"/>; override selectively, call <c>base</c> for the original.</summary>
public abstract class SessionServiceDecorator(ISessionService inner) : ISessionService
{
    public virtual Task<SessionTokens> CreateAsync(string userId, Dictionary<string, string>? sessionData = null, CancellationToken ct = default) =>
        inner.CreateAsync(userId, sessionData, ct);

    public virtual Task<SessionTokens> CreateAsync(string userId, Dictionary<string, string>? sessionData,
        IReadOnlyDictionary<string, object?>? metadata, CancellationToken ct = default) =>
        inner.CreateAsync(userId, sessionData, metadata, ct);

    public virtual Task<SessionTokens> RefreshAsync(string refreshToken, CancellationToken ct = default) =>
        inner.RefreshAsync(refreshToken, ct);

    public virtual Task RevokeAsync(string handle, CancellationToken ct = default) => inner.RevokeAsync(handle, ct);

    public virtual ClaimsPrincipal ValidateAccessToken(string accessToken) => inner.ValidateAccessToken(accessToken);

    public virtual Task MergeIntoAccessTokenPayloadAsync(string handle, IReadOnlyDictionary<string, object?> payload, CancellationToken ct = default) =>
        inner.MergeIntoAccessTokenPayloadAsync(handle, payload, ct);

    public virtual Task<KlassdSession?> GetSessionAsync(string handle, CancellationToken ct = default) =>
        inner.GetSessionAsync(handle, ct);
}
