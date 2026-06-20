using System.Security.Cryptography;
using Klassd.Auth.Abstractions;
using Microsoft.Data.Sqlite;

namespace Klassd.Auth.Data.Sqlite;

/// <summary>
/// SQLite-backed migration ledger + lease lock. One row per migration id holds both the completion
/// stamp and the lease. SQLite serializes writes, so the take-if-free UPDATE is atomic.
/// </summary>
public sealed class SqliteMigrationStateStore(SqliteContext ctx) : IMigrationStateStore
{
    public async Task<bool> IsCompletedAsync(string migrationId, CancellationToken ct = default)
    {
        await using var conn = ctx.Open();
        var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT 1 FROM migration_state WHERE migration_id = $id AND completed_at IS NOT NULL";
        cmd.Parameters.AddWithValue("$id", migrationId);
        return await cmd.ExecuteScalarAsync(ct) is not null;
    }

    public async Task MarkCompletedAsync(string migrationId, string? detailsJson = null, CancellationToken ct = default)
    {
        await using var conn = ctx.Open();
        var cmd = conn.CreateCommand();
        cmd.CommandText =
            """
            INSERT INTO migration_state (migration_id, completed_at, details) VALUES ($id, $now, $details)
            ON CONFLICT(migration_id) DO UPDATE SET completed_at = $now, details = $details
            """;
        cmd.Parameters.AddWithValue("$id", migrationId);
        cmd.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToString("o"));
        cmd.Parameters.AddWithValue("$details", (object?)detailsJson ?? DBNull.Value);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task<IMigrationLockHandle?> TryAcquireLockAsync(string migrationId, TimeSpan ttl, CancellationToken ct = default)
    {
        var owner = RandomNumberGenerator.GetHexString(32);
        await using var conn = ctx.Open();

        var insert = conn.CreateCommand();
        insert.CommandText = "INSERT OR IGNORE INTO migration_state (migration_id) VALUES ($id)";
        insert.Parameters.AddWithValue("$id", migrationId);
        await insert.ExecuteNonQueryAsync(ct);

        var take = conn.CreateCommand();
        take.CommandText =
            """
            UPDATE migration_state SET lock_owner = $owner, lock_expires_at = $exp
            WHERE migration_id = $id AND (lock_owner IS NULL OR lock_expires_at < $now)
            """;
        take.Parameters.AddWithValue("$owner", owner);
        take.Parameters.AddWithValue("$exp", DateTimeOffset.UtcNow.Add(ttl).ToString("o"));
        take.Parameters.AddWithValue("$id", migrationId);
        take.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToString("o"));

        if (await take.ExecuteNonQueryAsync(ct) == 0)
            return null;   // someone else holds a live lease

        return new MigrationLockHandle(
            renew: (t, c) => RenewAsync(migrationId, owner, t, c),
            release: () => ReleaseAsync(migrationId, owner));
    }

    private async Task<bool> RenewAsync(string migrationId, string owner, TimeSpan ttl, CancellationToken ct)
    {
        await using var conn = ctx.Open();
        var cmd = conn.CreateCommand();
        cmd.CommandText = "UPDATE migration_state SET lock_expires_at = $exp WHERE migration_id = $id AND lock_owner = $owner";
        cmd.Parameters.AddWithValue("$exp", DateTimeOffset.UtcNow.Add(ttl).ToString("o"));
        cmd.Parameters.AddWithValue("$id", migrationId);
        cmd.Parameters.AddWithValue("$owner", owner);
        return await cmd.ExecuteNonQueryAsync(ct) > 0;
    }

    private async ValueTask ReleaseAsync(string migrationId, string owner)
    {
        await using var conn = ctx.Open();
        var cmd = conn.CreateCommand();
        cmd.CommandText = "UPDATE migration_state SET lock_owner = NULL, lock_expires_at = NULL WHERE migration_id = $id AND lock_owner = $owner";
        cmd.Parameters.AddWithValue("$id", migrationId);
        cmd.Parameters.AddWithValue("$owner", owner);
        await cmd.ExecuteNonQueryAsync();
    }
}
