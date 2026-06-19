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

/// <summary>In-memory password-reset token store (default / tests). Tokens are lost on restart.</summary>
public sealed class InMemoryPasswordResetTokenStore : IPasswordResetTokenStore
{
    private readonly ConcurrentDictionary<string, PasswordResetToken> _tokens = new();

    public Task StoreAsync(string tokenHash, string userId, DateTimeOffset expires, CancellationToken ct = default)
    {
        _tokens[tokenHash] = new PasswordResetToken(userId, expires);
        return Task.CompletedTask;
    }

    public Task<PasswordResetToken?> ConsumeAsync(string tokenHash, CancellationToken ct = default) =>
        Task.FromResult(_tokens.TryRemove(tokenHash, out var t) ? t : null);
}

/// <summary>In-memory passwordless-code store (default / tests). Codes are lost on restart.</summary>
public sealed class InMemoryPasswordlessCodeStore : IPasswordlessCodeStore
{
    private readonly ConcurrentDictionary<string, PasswordlessCode> _codes = new();

    public Task StoreAsync(string identifier, PasswordlessChannel channel, string codeHash, DateTimeOffset expires, CancellationToken ct = default)
    {
        _codes[identifier] = new PasswordlessCode(identifier, channel, codeHash, expires, 0);
        return Task.CompletedTask;
    }

    public Task<PasswordlessCode?> FindAsync(string identifier, CancellationToken ct = default) =>
        Task.FromResult(_codes.TryGetValue(identifier, out var c) ? c : null);

    public Task IncrementAttemptsAsync(string identifier, CancellationToken ct = default)
    {
        if (_codes.TryGetValue(identifier, out var existing))
            _codes.TryUpdate(identifier, existing with { Attempts = existing.Attempts + 1 }, existing);
        return Task.CompletedTask;
    }

    public Task DeleteAsync(string identifier, CancellationToken ct = default)
    {
        _codes.TryRemove(identifier, out _);
        return Task.CompletedTask;
    }
}

/// <summary>In-memory passkey credential store (default / tests). Credentials are lost on restart.</summary>
public sealed class InMemoryPasskeyCredentialStore : IPasskeyCredentialStore
{
    // keyed by hex(CredentialId) so byte[] equality works as a dictionary key
    private readonly ConcurrentDictionary<string, PasskeyCredential> _creds = new();

    private static string Key(byte[] credentialId) => Convert.ToHexString(credentialId);

    public Task<PasskeyCredential?> FindByCredentialIdAsync(byte[] credentialId, CancellationToken ct = default) =>
        Task.FromResult(_creds.TryGetValue(Key(credentialId), out var c) ? c : null);

    public Task<IReadOnlyList<PasskeyCredential>> GetByUserIdAsync(string userId, CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<PasskeyCredential>>(
            _creds.Values.Where(c => c.UserId == userId).ToList());

    public Task<IReadOnlyList<PasskeyCredential>> GetByUserHandleAsync(byte[] userHandle, CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<PasskeyCredential>>(
            _creds.Values.Where(c => c.UserHandle.AsSpan().SequenceEqual(userHandle)).ToList());

    public Task AddAsync(PasskeyCredential credential, CancellationToken ct = default)
    {
        _creds[Key(credential.CredentialId)] = credential;
        return Task.CompletedTask;
    }

    public Task UpdateSignCountAsync(byte[] credentialId, ulong newSignCount, DateTimeOffset usedAt, CancellationToken ct = default)
    {
        if (_creds.TryGetValue(Key(credentialId), out var c))
        {
            c.SignCount = newSignCount;
            c.LastUsedAt = usedAt;
        }
        return Task.CompletedTask;
    }

    public Task DeleteByUserIdAsync(string userId, CancellationToken ct = default)
    {
        foreach (var kv in _creds.Where(kv => kv.Value.UserId == userId).ToList())
            _creds.TryRemove(kv.Key, out _);
        return Task.CompletedTask;
    }
}
