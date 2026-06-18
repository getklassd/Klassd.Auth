namespace Klassd.Auth.Abstractions;

/// <summary>
/// A registered WebAuthn/FIDO2 credential (passkey) belonging to a <see cref="User"/>. A user may
/// own several. DB-agnostic — storage adapters map the byte[] fields to their own binary columns.
/// </summary>
public sealed class PasskeyCredential
{
    public required string Id { get; init; }            // internal id (hex guid)
    public required string UserId { get; init; }

    public required byte[] CredentialId { get; init; }  // authenticator credential id (unique, indexed)
    public required byte[] PublicKey { get; init; }     // COSE-encoded public key
    public required byte[] UserHandle { get; init; }    // per-user opaque handle (indexed; resolves usernameless logins)

    /// <summary>Signature counter, advanced on each assertion; a regression signals a cloned authenticator.</summary>
    public ulong SignCount { get; set; }

    public Guid AaGuid { get; init; }
    public string? CredType { get; init; }              // e.g. "public-key"
    public string? Nickname { get; set; }

    public DateTimeOffset CreatedAt { get; init; }
    public DateTimeOffset? LastUsedAt { get; set; }
}

/// <summary>
/// Persists passkey credentials. A Klassd.Auth.Data.* adapter implements this; an in-memory default
/// ships in Core. Credentials are looked up by their credential id (login) or by user (registration
/// exclusion / management) or by user handle (usernameless/discoverable login).
/// </summary>
public interface IPasskeyCredentialStore
{
    Task<PasskeyCredential?> FindByCredentialIdAsync(byte[] credentialId, CancellationToken ct = default);
    Task<IReadOnlyList<PasskeyCredential>> GetByUserIdAsync(string userId, CancellationToken ct = default);
    Task<IReadOnlyList<PasskeyCredential>> GetByUserHandleAsync(byte[] userHandle, CancellationToken ct = default);
    Task AddAsync(PasskeyCredential credential, CancellationToken ct = default);
    Task UpdateSignCountAsync(byte[] credentialId, ulong newSignCount, DateTimeOffset usedAt, CancellationToken ct = default);
}
