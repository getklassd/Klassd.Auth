using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
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
}

public sealed record SessionTokens(string AccessToken, string RefreshToken, string Handle);

/// <summary>
/// Issues short-lived access JWTs and opaque, rotating refresh tokens. A refresh validates the
/// presented refresh token against the stored hash AND rotates it, so a stolen-and-reused
/// refresh token is detected and the session is revoked defensively.
/// </summary>
public sealed class SessionService(ISessionStore store, SessionConfig config, ITokenSigningKey signingKey)
{
    private readonly JwtSecurityTokenHandler _jwt = new();

    public async Task<SessionTokens> CreateAsync(
        string userId, Dictionary<string, string>? sessionData = null, CancellationToken ct = default)
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
        return new SessionTokens(IssueAccessToken(entity), PackRefresh(handle, refresh), handle);
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
        return new SessionTokens(IssueAccessToken(entity), PackRefresh(handle, newRefresh), handle);
    }

    public Task RevokeAsync(string handle, CancellationToken ct = default) => store.RevokeAsync(handle, ct);

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

    private string IssueAccessToken(SessionEntity s)
    {
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, s.UserId),
            new("sessionHandle", s.Handle),
        };
        claims.AddRange(s.SessionData.Select(kv => new Claim($"sd_{kv.Key}", kv.Value)));

        var token = new JwtSecurityToken(
            issuer: config.Issuer,
            audience: config.Audience,
            claims: claims,
            expires: DateTime.UtcNow.Add(config.AccessTokenLifetime),
            signingCredentials: signingKey.SigningCredentials);
        return _jwt.WriteToken(token);
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
