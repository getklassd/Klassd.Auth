namespace Klassd.Auth.Abstractions;

/// <summary>A persisted RSA signing key (PKCS#8 PEM private key) with its creation time.</summary>
public sealed record StoredSigningKey(string KeyId, string PrivateKeyPem, DateTimeOffset CreatedAt);

/// <summary>
/// Persists the signing keys used for access-token JWTs so they survive restarts and can be
/// rotated. Multiple keys may exist at once (one active signer + recently-retired validators).
/// </summary>
public interface ISigningKeyStore
{
    Task<IReadOnlyList<StoredSigningKey>> GetAllAsync(CancellationToken ct = default);
    Task AddAsync(StoredSigningKey key, CancellationToken ct = default);
    Task RemoveAsync(string keyId, CancellationToken ct = default);
}

public sealed record EmailVerificationToken(string UserId, string Email, DateTimeOffset Expires);

/// <summary>
/// Persists one-time email-verification tokens (stored hashed, with a TTL). Consuming a token
/// returns and removes it atomically.
/// </summary>
public interface IEmailVerificationTokenStore
{
    Task StoreAsync(string tokenHash, string userId, string email, DateTimeOffset expires, CancellationToken ct = default);
    Task<EmailVerificationToken?> ConsumeAsync(string tokenHash, CancellationToken ct = default);
}
