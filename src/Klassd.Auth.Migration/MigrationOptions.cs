namespace Klassd.Auth.Migration;

/// <summary>What the runner does when a user with the same email/username already exists.</summary>
public enum ConflictPolicy
{
    /// <summary>Leave the existing user untouched and report it as skipped (the safe default).</summary>
    Skip,

    /// <summary>Update mutable fields and attach any login methods the existing user is missing.</summary>
    Merge,
}

public sealed class MigrationOptions
{
    /// <summary>Compute and report every action without writing anything. Verify a run before committing.</summary>
    public bool DryRun { get; set; }

    public ConflictPolicy OnConflict { get; set; } = ConflictPolicy.Skip;

    public bool ImportRoles { get; set; } = true;
    public bool ImportMetadata { get; set; } = true;
    public bool ImportTotp { get; set; } = true;

    /// <summary>
    /// Metadata key the imported TOTP secret is stored under, as <c>{ "secret": "&lt;base32&gt;" }</c>.
    /// Point this at whatever section your app reads its MFA secret from.
    /// </summary>
    public string TotpMetadataKey { get; set; } = "totp";
}
