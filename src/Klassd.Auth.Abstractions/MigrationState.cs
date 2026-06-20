namespace Klassd.Auth.Abstractions;

/// <summary>
/// Backs the guarded ("run once") migration path: a durable completion ledger plus a distributed
/// lease lock, both keyed by a caller-chosen migration id. A storage adapter (Klassd.Auth.Data.*)
/// implements this so the same database the app uses coordinates the migration across replicas.
/// </summary>
public interface IMigrationStateStore
{
    /// <summary>True once <see cref="MarkCompletedAsync"/> has recorded this migration as finished.</summary>
    Task<bool> IsCompletedAsync(string migrationId, CancellationToken ct = default);

    /// <summary>Durably records that the migration finished, so it never runs again.</summary>
    Task MarkCompletedAsync(string migrationId, string? detailsJson = null, CancellationToken ct = default);

    /// <summary>
    /// Tries to take an exclusive lease on the migration. Returns a handle to hold (and renew) while
    /// running, or <c>null</c> if another holder owns a live lease. The lease auto-expires after
    /// <paramref name="ttl"/> so a crashed holder doesn't block forever — callers must renew it.
    /// </summary>
    Task<IMigrationLockHandle?> TryAcquireLockAsync(string migrationId, TimeSpan ttl, CancellationToken ct = default);
}

/// <summary>A held migration lease. Renew it while working; disposing releases it.</summary>
public interface IMigrationLockHandle : IAsyncDisposable
{
    /// <summary>Extends the lease by <paramref name="ttl"/>. Returns false if the lease was lost (no longer owned).</summary>
    Task<bool> RenewAsync(TimeSpan ttl, CancellationToken ct = default);
}

/// <summary>
/// Delegate-backed <see cref="IMigrationLockHandle"/> so each adapter can return a handle without a
/// bespoke class — it just supplies the renew/release calls bound to its own connection + owner token.
/// </summary>
public sealed class MigrationLockHandle(
    Func<TimeSpan, CancellationToken, Task<bool>> renew,
    Func<ValueTask> release) : IMigrationLockHandle
{
    public Task<bool> RenewAsync(TimeSpan ttl, CancellationToken ct = default) => renew(ttl, ct);
    public ValueTask DisposeAsync() => release();
}
