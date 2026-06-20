using System.Security.Cryptography;
using Klassd.Auth.Abstractions;
using MongoDB.Driver;

namespace Klassd.Auth.Data.MongoDb;

/// <summary>
/// MongoDB-backed migration ledger + lease lock. A single document per migration id holds the
/// completion stamp and the lease; acquisition is an atomic upsert whose filter excludes a live lease,
/// so a contending writer hits a duplicate-key error (which we read as "held elsewhere").
/// </summary>
public sealed class MongoMigrationStateStore(MongoContext ctx) : IMigrationStateStore
{
    private IMongoCollection<MigrationStateDoc> Col => ctx.MigrationState;

    public async Task<bool> IsCompletedAsync(string migrationId, CancellationToken ct = default) =>
        await Col.Find(d => d.MigrationId == migrationId && d.CompletedAt != null).AnyAsync(ct);

    public async Task MarkCompletedAsync(string migrationId, string? detailsJson = null, CancellationToken ct = default)
    {
        var update = Builders<MigrationStateDoc>.Update
            .Set(d => d.CompletedAt, DateTimeOffset.UtcNow)
            .Set(d => d.Details, detailsJson);
        await Col.UpdateOneAsync(d => d.MigrationId == migrationId, update,
            new UpdateOptions { IsUpsert = true }, ct);
    }

    public async Task<IMigrationLockHandle?> TryAcquireLockAsync(string migrationId, TimeSpan ttl, CancellationToken ct = default)
    {
        var owner = RandomNumberGenerator.GetHexString(32);
        var nowMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var expMs = DateTimeOffset.UtcNow.Add(ttl).ToUnixTimeMilliseconds();

        var filter = Builders<MigrationStateDoc>.Filter.And(
            Builders<MigrationStateDoc>.Filter.Eq(d => d.MigrationId, migrationId),
            Builders<MigrationStateDoc>.Filter.Or(
                Builders<MigrationStateDoc>.Filter.Eq(d => d.LockOwner, null),
                Builders<MigrationStateDoc>.Filter.Lt(d => d.LockExpiresUnixMs, nowMs)));

        var update = Builders<MigrationStateDoc>.Update
            .Set(d => d.LockOwner, owner)
            .Set(d => d.LockExpiresUnixMs, expMs)
            .SetOnInsert(d => d.MigrationId, migrationId);

        try
        {
            // Upsert: matches an unlocked/expired doc to update, or inserts when none exists. If a LIVE
            // lease exists the filter misses, the upsert tries to insert a duplicate _id, and Mongo
            // throws E11000 — which means "someone else holds it".
            await Col.UpdateOneAsync(filter, update, new UpdateOptions { IsUpsert = true }, ct);
        }
        catch (MongoWriteException e) when (e.WriteError?.Category == ServerErrorCategory.DuplicateKey)
        {
            return null;
        }
        catch (MongoCommandException e) when (e.Code == 11000)
        {
            return null;
        }

        return new MigrationLockHandle(
            renew: (t, c) => RenewAsync(migrationId, owner, t, c),
            release: () => ReleaseAsync(migrationId, owner));
    }

    private async Task<bool> RenewAsync(string migrationId, string owner, TimeSpan ttl, CancellationToken ct)
    {
        var expMs = DateTimeOffset.UtcNow.Add(ttl).ToUnixTimeMilliseconds();
        var result = await Col.UpdateOneAsync(
            d => d.MigrationId == migrationId && d.LockOwner == owner,
            Builders<MigrationStateDoc>.Update.Set(d => d.LockExpiresUnixMs, expMs), cancellationToken: ct);
        return result.ModifiedCount > 0;
    }

    private async ValueTask ReleaseAsync(string migrationId, string owner) =>
        await Col.UpdateOneAsync(
            d => d.MigrationId == migrationId && d.LockOwner == owner,
            Builders<MigrationStateDoc>.Update.Set(d => d.LockOwner, null).Set(d => d.LockExpiresUnixMs, null));
}
