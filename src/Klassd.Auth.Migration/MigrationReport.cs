namespace Klassd.Auth.Migration;

public enum MigrationOutcome { Created, Merged, Skipped, Failed }

/// <summary>Running tallies reported while a migration is in flight (for live progress UIs).</summary>
public sealed record MigrationProgress(
    int Processed, int Created, int Merged, int Skipped, int Failed, string? Last);

/// <summary>The result of migrating a single source user.</summary>
public sealed record MigrationItemResult(
    string? ExternalId,
    string? Email,
    MigrationOutcome Outcome,
    string? UserId,
    IReadOnlyList<string> Warnings,
    string? Error = null);

/// <summary>Aggregate result of a migration run, plus the per-user detail.</summary>
public sealed record MigrationReport(IReadOnlyList<MigrationItemResult> Items)
{
    public int Created => Items.Count(i => i.Outcome == MigrationOutcome.Created);
    public int Merged => Items.Count(i => i.Outcome == MigrationOutcome.Merged);
    public int Skipped => Items.Count(i => i.Outcome == MigrationOutcome.Skipped);
    public int Failed => Items.Count(i => i.Outcome == MigrationOutcome.Failed);
    public int Total => Items.Count;

    /// <summary>Users whose password could not be carried over and who must reset it to sign in.</summary>
    public int PasswordsDropped => Items.Count(i => i.Warnings.Any(w => w.Contains("password", StringComparison.OrdinalIgnoreCase)));
}
