namespace Klassd.Auth.Abstractions;

/// <summary>A consumed password-reset token's payload (the user it authorizes a reset for).</summary>
public sealed record PasswordResetToken(string UserId, DateTimeOffset Expires);

/// <summary>
/// Persists one-time password-reset tokens (stored hashed, with a TTL). Consuming a token returns
/// and removes it atomically. Mirrors <see cref="IEmailVerificationTokenStore"/>; a Data.* adapter
/// supplies a durable implementation and an in-memory default ships in Core.
/// </summary>
public interface IPasswordResetTokenStore
{
    Task StoreAsync(string tokenHash, string userId, DateTimeOffset expires, CancellationToken ct = default);
    Task<PasswordResetToken?> ConsumeAsync(string tokenHash, CancellationToken ct = default);
}
