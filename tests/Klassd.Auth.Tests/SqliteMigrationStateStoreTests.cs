using Klassd.Auth.Data.Sqlite;
using TUnit.Assertions;
using TUnit.Assertions.Extensions;
using TUnit.Core;

namespace Klassd.Auth.Tests;

/// <summary>Exercises the real SQLite ledger + lease lock against a temp-file database.</summary>
public sealed class SqliteMigrationStateStoreTests
{
    private static async Task<(SqliteMigrationStateStore store, string path)> NewStoreAsync()
    {
        var path = Path.Combine(Path.GetTempPath(), $"klassd_lease_{Guid.NewGuid():N}.db");
        // Pooling=False so no connection lingers in the pool holding the file open at File.Delete.
        var ctx = new SqliteContext(new SqliteOptions { ConnectionString = $"Data Source={path};Pooling=False" });
        await new SqliteSchemaInitializer(ctx).InitializeAsync();
        return (new SqliteMigrationStateStore(ctx), path);
    }

    [Test]
    public async Task Lease_is_exclusive_then_re_acquirable_after_release()
    {
        var (store, path) = await NewStoreAsync();
        try
        {
            var first = await store.TryAcquireLockAsync("m1", TimeSpan.FromMinutes(5));
            await Assert.That(first).IsNotNull();

            // A second contender can't take a live lease.
            var blocked = await store.TryAcquireLockAsync("m1", TimeSpan.FromMinutes(5));
            await Assert.That(blocked).IsNull();

            await first!.DisposeAsync();   // release

            var again = await store.TryAcquireLockAsync("m1", TimeSpan.FromMinutes(5));
            await Assert.That(again).IsNotNull();
            await again!.DisposeAsync();
        }
        finally { File.Delete(path); }
    }

    [Test]
    public async Task Expired_lease_can_be_taken_over()
    {
        var (store, path) = await NewStoreAsync();
        try
        {
            // Acquire with a TTL already in the past — the holder "crashed" without releasing.
            var stale = await store.TryAcquireLockAsync("m1", TimeSpan.FromSeconds(-1));
            await Assert.That(stale).IsNotNull();

            var taken = await store.TryAcquireLockAsync("m1", TimeSpan.FromMinutes(5));
            await Assert.That(taken).IsNotNull();   // expired lease is reclaimed
            await taken!.DisposeAsync();
        }
        finally { File.Delete(path); }
    }

    [Test]
    public async Task Ledger_records_completion()
    {
        var (store, path) = await NewStoreAsync();
        try
        {
            await Assert.That(await store.IsCompletedAsync("m1")).IsFalse();
            await store.MarkCompletedAsync("m1", "{\"created\":3}");
            await Assert.That(await store.IsCompletedAsync("m1")).IsTrue();
        }
        finally { File.Delete(path); }
    }

    [Test]
    public async Task Renew_keeps_the_lease()
    {
        var (store, path) = await NewStoreAsync();
        try
        {
            var handle = await store.TryAcquireLockAsync("m1", TimeSpan.FromMinutes(5));
            await Assert.That(await handle!.RenewAsync(TimeSpan.FromMinutes(5))).IsTrue();
            await handle.DisposeAsync();
        }
        finally { File.Delete(path); }
    }
}
