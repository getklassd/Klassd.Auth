using System.Collections.Concurrent;
using Klassd.Auth.Abstractions;

namespace Klassd.Auth.Core.Sessions;

/// <summary>In-memory signing-key store (tests / single-node without persistence). Keys are lost on restart.</summary>
public sealed class InMemorySigningKeyStore : ISigningKeyStore
{
    private readonly ConcurrentDictionary<string, StoredSigningKey> _keys = new();

    public Task<IReadOnlyList<StoredSigningKey>> GetAllAsync(CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<StoredSigningKey>>(_keys.Values.ToList());

    public Task AddAsync(StoredSigningKey key, CancellationToken ct = default)
    {
        _keys[key.KeyId] = key;
        return Task.CompletedTask;
    }

    public Task RemoveAsync(string keyId, CancellationToken ct = default)
    {
        _keys.TryRemove(keyId, out _);
        return Task.CompletedTask;
    }
}

/// <summary>In-memory email-verification token store (default / tests). Tokens are lost on restart.</summary>
public sealed class InMemoryEmailVerificationTokenStore : IEmailVerificationTokenStore
{
    private readonly ConcurrentDictionary<string, EmailVerificationToken> _tokens = new();

    public Task StoreAsync(string tokenHash, string userId, string email, DateTimeOffset expires, CancellationToken ct = default)
    {
        _tokens[tokenHash] = new EmailVerificationToken(userId, email, expires);
        return Task.CompletedTask;
    }

    public Task<EmailVerificationToken?> ConsumeAsync(string tokenHash, CancellationToken ct = default) =>
        Task.FromResult(_tokens.TryRemove(tokenHash, out var t) ? t : null);
}
