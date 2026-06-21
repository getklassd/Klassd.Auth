using System.Text.Json;
using Klassd.Auth.Abstractions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Klassd.Auth.Migration;

public enum MigrationRunOutcome
{
    /// <summary>This call ran the migration and recorded it complete.</summary>
    Completed,

    /// <summary>The migration had already been recorded complete by an earlier run — nothing to do.</summary>
    AlreadyCompleted,

    /// <summary>Another replica holds the lease and is running it now — this call did nothing.</summary>
    LockHeldByAnother,
}

public sealed record GuardedMigrationResult(MigrationRunOutcome Outcome, MigrationReport? Report);

public sealed class MigrationGuardOptions
{
    /// <summary>Lease lifetime. Auto-expires so a crashed holder can't block forever. Renewed while running.</summary>
    public TimeSpan LockTtl { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>How often the lease is renewed. Must be comfortably shorter than <see cref="LockTtl"/>.</summary>
    public TimeSpan HeartbeatInterval { get; set; } = TimeSpan.FromMinutes(2);
}

/// <summary>
/// Runs a migration <em>at most once across a cluster</em>: it checks a durable completion ledger,
/// takes a distributed lease (so only one replica runs), heartbeats the lease while working, and
/// records completion on success. Use this when migration is embedded in app startup with multiple
/// replicas; for a one-shot Kubernetes Job, the plain <see cref="MigrationRunner"/> is enough.
/// </summary>
public sealed class MigrationCoordinator(
    MigrationRunner runner,
    IMigrationStateStore? state = null,
    ILogger<MigrationCoordinator>? logger = null)
{
    private readonly ILogger _log = logger ?? NullLogger<MigrationCoordinator>.Instance;

    public async Task<GuardedMigrationResult> RunOnceAsync(
        string migrationId,
        IMigrationSource source,
        MigrationOptions? options = null,
        MigrationGuardOptions? guard = null,
        CancellationToken ct = default)
    {
        if (state is null)
            throw new InvalidOperationException(
                "RunOnceAsync needs a storage adapter that provides IMigrationStateStore (UseSqlite/UsePostgres/UseMongoDb) "
                + "plus AddAuthMigration(). For a one-shot Job use MigrationRunner.RunAsync instead.");

        guard ??= new MigrationGuardOptions();

        if (await state.IsCompletedAsync(migrationId, ct))
        {
            _log.LogInformation("Migration {Id} already completed — skipping.", migrationId);
            return new GuardedMigrationResult(MigrationRunOutcome.AlreadyCompleted, null);
        }

        await using var handle = await state.TryAcquireLockAsync(migrationId, guard.LockTtl, ct);
        if (handle is null)
        {
            _log.LogInformation("Migration {Id} lease held by another instance — skipping.", migrationId);
            return new GuardedMigrationResult(MigrationRunOutcome.LockHeldByAnother, null);
        }

        // Re-check now that we hold the lease: another instance may have finished between our first
        // check and acquiring the lock.
        if (await state.IsCompletedAsync(migrationId, ct))
        {
            _log.LogInformation("Migration {Id} completed by another instance — skipping.", migrationId);
            return new GuardedMigrationResult(MigrationRunOutcome.AlreadyCompleted, null);
        }

        _log.LogInformation("Acquired lease for migration {Id}; running {Source}.", migrationId, source.Name);
        await using var heartbeat = new LeaseHeartbeat(handle, guard, _log, ct);

        var report = await runner.RunAsync(source, options, ct: ct);
        await state.MarkCompletedAsync(migrationId, Summarize(report), ct);

        _log.LogInformation("Migration {Id} recorded complete.", migrationId);
        return new GuardedMigrationResult(MigrationRunOutcome.Completed, report);
    }

    private static string Summarize(MigrationReport r) => JsonSerializer.Serialize(new
    {
        created = r.Created,
        merged = r.Merged,
        skipped = r.Skipped,
        failed = r.Failed,
        passwordsDropped = r.PasswordsDropped,
    });

    /// <summary>Background task that keeps renewing the lease until disposed.</summary>
    private sealed class LeaseHeartbeat : IAsyncDisposable
    {
        private readonly CancellationTokenSource _cts;
        private readonly Task _loop;

        public LeaseHeartbeat(IMigrationLockHandle handle, MigrationGuardOptions guard, ILogger log, CancellationToken ct)
        {
            _cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            var token = _cts.Token;
            _loop = Task.Run(async () =>
            {
                try
                {
                    while (!token.IsCancellationRequested)
                    {
                        await Task.Delay(guard.HeartbeatInterval, token);
                        if (!await handle.RenewAsync(guard.LockTtl, token))
                            log.LogWarning("Lost the migration lease during the run — another instance may take over.");
                    }
                }
                catch (OperationCanceledException) { /* normal shutdown */ }
            }, CancellationToken.None);
        }

        public async ValueTask DisposeAsync()
        {
            await _cts.CancelAsync();
            try { await _loop; } catch { /* already logged */ }
            _cts.Dispose();
        }
    }
}
