using Klassd.Auth.Abstractions;
using MongoDB.Driver;

namespace Klassd.Auth.Data.MongoDb;

public sealed class MongoSigningKeyStore(MongoContext ctx) : ISigningKeyStore
{
    public async Task<IReadOnlyList<StoredSigningKey>> GetAllAsync(CancellationToken ct = default)
    {
        var docs = await ctx.SigningKeys.Find(FilterDefinition<SigningKeyDoc>.Empty).ToListAsync(ct);
        return docs.ConvertAll(d => new StoredSigningKey(d.KeyId, d.PrivateKeyPem, d.CreatedAt));
    }

    public Task AddAsync(StoredSigningKey key, CancellationToken ct = default) =>
        ctx.SigningKeys.InsertOneAsync(
            new SigningKeyDoc { KeyId = key.KeyId, PrivateKeyPem = key.PrivateKeyPem, CreatedAt = key.CreatedAt },
            cancellationToken: ct);

    public Task RemoveAsync(string keyId, CancellationToken ct = default) =>
        ctx.SigningKeys.DeleteOneAsync(k => k.KeyId == keyId, ct);
}

public sealed class MongoEmailVerificationTokenStore(MongoContext ctx) : IEmailVerificationTokenStore
{
    public Task StoreAsync(string tokenHash, string userId, string email, DateTimeOffset expires, CancellationToken ct = default) =>
        ctx.EmailVerificationTokens.InsertOneAsync(
            new EmailVerificationTokenDoc { TokenHash = tokenHash, UserId = userId, Email = email, Expires = expires },
            cancellationToken: ct);

    public async Task<EmailVerificationToken?> ConsumeAsync(string tokenHash, CancellationToken ct = default)
    {
        var doc = await ctx.EmailVerificationTokens.FindOneAndDeleteAsync(t => t.TokenHash == tokenHash, cancellationToken: ct);
        return doc is null ? null : new EmailVerificationToken(doc.UserId, doc.Email, doc.Expires);
    }
}

public sealed class MongoPasswordlessCodeStore(MongoContext ctx) : IPasswordlessCodeStore
{
    public Task StoreAsync(string identifier, PasswordlessChannel channel, string codeHash, DateTimeOffset expires, CancellationToken ct = default) =>
        ctx.PasswordlessCodes.ReplaceOneAsync(
            c => c.Identifier == identifier,
            new PasswordlessCodeDoc { Identifier = identifier, Channel = channel, CodeHash = codeHash, ExpiresAt = expires, Attempts = 0 },
            new ReplaceOptions { IsUpsert = true }, ct);

    public async Task<PasswordlessCode?> FindAsync(string identifier, CancellationToken ct = default)
    {
        var doc = await ctx.PasswordlessCodes.Find(c => c.Identifier == identifier).FirstOrDefaultAsync(ct);
        return doc is null ? null : new PasswordlessCode(doc.Identifier, doc.Channel, doc.CodeHash, doc.ExpiresAt, doc.Attempts);
    }

    public Task IncrementAttemptsAsync(string identifier, CancellationToken ct = default) =>
        ctx.PasswordlessCodes.UpdateOneAsync(
            c => c.Identifier == identifier,
            Builders<PasswordlessCodeDoc>.Update.Inc(c => c.Attempts, 1),
            cancellationToken: ct);

    public Task DeleteAsync(string identifier, CancellationToken ct = default) =>
        ctx.PasswordlessCodes.DeleteOneAsync(c => c.Identifier == identifier, ct);
}

public sealed class MongoPasskeyCredentialStore(MongoContext ctx) : IPasskeyCredentialStore
{
    public async Task<PasskeyCredential?> FindByCredentialIdAsync(byte[] credentialId, CancellationToken ct = default) =>
        (await ctx.PasskeyCredentials.Find(c => c.CredentialId == credentialId).FirstOrDefaultAsync(ct))?.ToDomain();

    public async Task<IReadOnlyList<PasskeyCredential>> GetByUserIdAsync(string userId, CancellationToken ct = default) =>
        (await ctx.PasskeyCredentials.Find(c => c.UserId == userId).ToListAsync(ct)).ConvertAll(d => d.ToDomain());

    public async Task<IReadOnlyList<PasskeyCredential>> GetByUserHandleAsync(byte[] userHandle, CancellationToken ct = default) =>
        (await ctx.PasskeyCredentials.Find(c => c.UserHandle == userHandle).ToListAsync(ct)).ConvertAll(d => d.ToDomain());

    public Task AddAsync(PasskeyCredential credential, CancellationToken ct = default) =>
        ctx.PasskeyCredentials.InsertOneAsync(PasskeyCredentialDoc.From(credential), cancellationToken: ct);

    public Task UpdateSignCountAsync(byte[] credentialId, ulong newSignCount, DateTimeOffset usedAt, CancellationToken ct = default) =>
        ctx.PasskeyCredentials.UpdateOneAsync(
            c => c.CredentialId == credentialId,
            Builders<PasskeyCredentialDoc>.Update
                .Set(c => c.SignCount, (long)newSignCount)
                .Set(c => c.LastUsedAt, usedAt),
            cancellationToken: ct);
}
