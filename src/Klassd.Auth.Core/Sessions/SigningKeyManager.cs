using System.Security.Cryptography;
using Klassd.Auth.Abstractions;
using Microsoft.IdentityModel.Tokens;

namespace Klassd.Auth.Core.Sessions;

public sealed class SigningKeyOptions
{
    /// <summary>How long a key is used to sign new tokens before a fresh one is rotated in.</summary>
    public TimeSpan SigningKeyLifetime { get; init; } = TimeSpan.FromDays(90);

    /// <summary>How long a retired key still validates tokens after its signing lifetime ends.</summary>
    public TimeSpan ValidationGrace { get; init; } = TimeSpan.FromDays(7);
}

/// <summary>
/// An <see cref="ITokenSigningKey"/> backed by a persistent <see cref="ISigningKeyStore"/> with
/// rotation: the newest in-lifetime key signs, all non-expired keys validate (and are published in
/// JWKS), and keys past their grace window are pruned. Initialize at startup before first use.
/// </summary>
public sealed class SigningKeyManager(ISigningKeyStore store, SigningKeyOptions options) : ITokenSigningKey
{
    private volatile Snapshot? _snapshot;

    private sealed record Snapshot(
        SigningCredentials Signing, IReadOnlyList<SecurityKey> Validation, IReadOnlyList<JsonWebKey> Jwks);

    private Snapshot Current => _snapshot ?? throw new InvalidOperationException(
        "Signing keys not initialized. Ensure the storage initializer ran (registered by UseRotatingRsaSigning).");

    public SigningCredentials SigningCredentials => Current.Signing;
    public IReadOnlyList<SecurityKey> ValidationKeys => Current.Validation;
    public IReadOnlyList<JsonWebKey> PublicJwks => Current.Jwks;

    /// <summary>Loads keys, prunes expired ones, ensures an active signer exists, and rebuilds the snapshot.</summary>
    public async Task InitializeAsync(CancellationToken ct = default)
    {
        var keys = (await store.GetAllAsync(ct)).ToList();
        var now = DateTimeOffset.UtcNow;

        foreach (var expired in keys
                     .Where(k => k.CreatedAt + options.SigningKeyLifetime + options.ValidationGrace < now).ToList())
        {
            await store.RemoveAsync(expired.KeyId, ct);
            keys.Remove(expired);
        }

        var active = keys
            .Where(k => k.CreatedAt + options.SigningKeyLifetime >= now)
            .OrderByDescending(k => k.CreatedAt)
            .FirstOrDefault();

        if (active is null)
        {
            active = Generate(now);
            await store.AddAsync(active, ct);
            keys.Add(active);
        }

        Rebuild(keys, active);
    }

    /// <summary>Rotates if the active key has aged out and prunes expired keys. Safe to call periodically.</summary>
    public Task MaintainAsync(CancellationToken ct = default) => InitializeAsync(ct);

    private void Rebuild(List<StoredSigningKey> keys, StoredSigningKey active)
    {
        SigningCredentials? signing = null;
        var validation = new List<SecurityKey>(keys.Count);
        var jwks = new List<JsonWebKey>(keys.Count);

        foreach (var k in keys)
        {
            var rsa = RSA.Create();
            rsa.ImportFromPem(k.PrivateKeyPem);   // RSA stays alive via the SecurityKey it backs
            var key = new RsaSecurityKey(rsa) { KeyId = k.KeyId };
            validation.Add(key);

            var publicJwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(
                new RsaSecurityKey(rsa.ExportParameters(false)) { KeyId = k.KeyId });
            publicJwk.Use = "sig";
            publicJwk.Alg = SecurityAlgorithms.RsaSha256;
            jwks.Add(publicJwk);

            if (k.KeyId == active.KeyId)
                signing = new SigningCredentials(key, SecurityAlgorithms.RsaSha256);
        }

        _snapshot = new Snapshot(signing!, validation, jwks);
    }

    private static StoredSigningKey Generate(DateTimeOffset now)
    {
        using var rsa = RSA.Create(2048);
        return new StoredSigningKey($"k-{Guid.NewGuid():N}", rsa.ExportPkcs8PrivateKeyPem(), now);
    }
}
