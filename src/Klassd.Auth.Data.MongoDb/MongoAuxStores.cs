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
