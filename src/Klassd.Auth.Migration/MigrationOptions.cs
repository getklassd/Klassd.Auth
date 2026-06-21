using Klassd.Auth.Abstractions;

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

    /// <summary>
    /// Tenant the imported users land in (shared-schema multi-tenancy). The runner sets the ambient
    /// <see cref="ITenantContext"/> from this before writing, so both the insert AND the idempotency
    /// lookups (find-by-email/username) are scoped to it — re-running into the same tenant is safe, and
    /// the same email can be imported into different tenants as separate users. To fold several source
    /// databases into one Klassd.Auth as separate tenants, run once per source with a different value
    /// (or use <see cref="MigrationRunner.RunManyAsync"/>). Defaults to the single "public" tenant.
    /// </summary>
    public string TenantId { get; set; } = TenantContext.Default;

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
