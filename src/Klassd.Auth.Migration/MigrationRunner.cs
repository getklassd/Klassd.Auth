using System.Text.Json.Nodes;
using Klassd.Auth.Abstractions;
using Klassd.Auth.Core.Modules.UserMetadata;
using Klassd.Auth.Core.Modules.Users;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Klassd.Auth.Migration;

/// <summary>
/// Writes <see cref="MigratedUser"/>s produced by an <see cref="IMigrationSource"/> into Klassd.Auth
/// through the same stores the rest of the suite uses. Idempotent: re-running matches existing users
/// by email (then username) and, per <see cref="MigrationOptions.OnConflict"/>, skips or merges them.
/// </summary>
public sealed class MigrationRunner(
    IUserStore users,
    IUserMetadataService metadata,
    IRolesService roles,
    ITenantContext? tenant = null,
    ILogger<MigrationRunner>? logger = null)
{
    private readonly ILogger _log = logger ?? NullLogger<MigrationRunner>.Instance;

    /// <summary>
    /// Imports several sources into one Klassd.Auth, each into its own tenant — e.g. folding multiple
    /// SuperTokens databases into a single multi-tenant instance. Runs sequentially (a shared store
    /// connection), re-targeting the ambient tenant per source; returns a report per tenant.
    /// <paramref name="baseOptions"/> supplies the shared flags (DryRun/OnConflict/imports); its
    /// <see cref="MigrationOptions.TenantId"/> is overridden per entry.
    /// </summary>
    public async Task<IReadOnlyDictionary<string, MigrationReport>> RunManyAsync(
        IEnumerable<(string TenantId, IMigrationSource Source)> sources,
        MigrationOptions? baseOptions = null, CancellationToken ct = default)
    {
        var reports = new Dictionary<string, MigrationReport>();
        foreach (var (tenantId, source) in sources)
        {
            ct.ThrowIfCancellationRequested();
            reports[tenantId] = await RunAsync(source, WithTenant(baseOptions, tenantId), ct: ct);
        }
        return reports;
    }

    /// <param name="progress">
    /// Optional live progress sink, reported as users are processed (throttled) so a UI can show a job
    /// running in the background. The final tallies are on the returned <see cref="MigrationReport"/>.
    /// </param>
    public async Task<MigrationReport> RunAsync(
        IMigrationSource source, MigrationOptions? options = null,
        IProgress<MigrationProgress>? progress = null, CancellationToken ct = default)
    {
        options ??= new MigrationOptions();

        // Point the ambient tenant at the target so the stores stamp inserts AND scope idempotency
        // lookups to it. Required for multi-tenant imports; a no-op for single-tenant ("public").
        if (tenant is not null) tenant.TenantId = options.TenantId;

        var results = new List<MigrationItemResult>();
        int created = 0, merged = 0, skipped = 0, failed = 0;

        _log.LogInformation("Starting {Source} migration into tenant '{Tenant}' (dryRun={DryRun}, onConflict={Conflict}).",
            source.Name, options.TenantId, options.DryRun, options.OnConflict);

        await foreach (var mu in source.ReadAsync(ct))
        {
            ct.ThrowIfCancellationRequested();
            MigrationItemResult result;
            try
            {
                result = await MigrateOneAsync(mu, options, ct);
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "Failed to migrate user {External}/{Email}.", mu.ExternalId, mu.Email);
                result = new MigrationItemResult(mu.ExternalId, mu.Email, MigrationOutcome.Failed, null, [], ex.Message);
            }
            results.Add(result);
            switch (result.Outcome)
            {
                case MigrationOutcome.Created: created++; break;
                case MigrationOutcome.Merged: merged++; break;
                case MigrationOutcome.Skipped: skipped++; break;
                case MigrationOutcome.Failed: failed++; break;
            }

            // Throttle to keep a live UI from re-rendering on every single user.
            if (progress is not null && results.Count % 20 == 0)
                progress.Report(new MigrationProgress(results.Count, created, merged, skipped, failed, result.Email ?? result.ExternalId));
        }

        progress?.Report(new MigrationProgress(results.Count, created, merged, skipped, failed, null));
        var report = new MigrationReport(results);
        _log.LogInformation("{Source} migration done: {Created} created, {Merged} merged, {Skipped} skipped, {Failed} failed.",
            source.Name, report.Created, report.Merged, report.Skipped, report.Failed);
        return report;
    }

    private async Task<MigrationItemResult> MigrateOneAsync(MigratedUser mu, MigrationOptions opt, CancellationToken ct)
    {
        var warnings = new List<string>();
        var email = Normalize(mu.Email);

        if (string.IsNullOrWhiteSpace(email) && string.IsNullOrWhiteSpace(mu.Username) && string.IsNullOrWhiteSpace(mu.Phone))
            return new MigrationItemResult(mu.ExternalId, mu.Email, MigrationOutcome.Failed, null, warnings,
                "User has no email, username, or phone — nothing to key an account on.");

        var existing = (email is not null ? await users.FindByEmailAsync(email, ct) : null)
                       ?? (mu.Username is not null ? await users.FindByUsernameAsync(mu.Username, ct) : null);

        if (existing is not null)
        {
            if (opt.OnConflict == ConflictPolicy.Skip)
                return new MigrationItemResult(mu.ExternalId, mu.Email, MigrationOutcome.Skipped, existing.Id, warnings);

            await MergeAsync(existing, mu, opt, warnings, ct);
            return new MigrationItemResult(mu.ExternalId, mu.Email, MigrationOutcome.Merged, existing.Id, warnings);
        }

        var userId = Guid.NewGuid().ToString("N");
        var methods = BuildLoginMethods(userId, mu, email, warnings);
        var user = new User
        {
            Id = userId,
            Username = mu.Username,
            PrimaryEmail = email,
            PrimaryPhone = mu.Phone,
            Disabled = mu.Disabled,
            CreatedAt = mu.CreatedAt == default ? DateTimeOffset.UtcNow : mu.CreatedAt,
        };
        user.LoginMethods.AddRange(methods);

        if (!opt.DryRun)
        {
            await users.AddUserAsync(user, ct);
            await ApplyAuxAsync(userId, mu, opt, ct);
        }

        return new MigrationItemResult(mu.ExternalId, mu.Email, MigrationOutcome.Created, userId, warnings);
    }

    private async Task MergeAsync(User existing, MigratedUser mu, MigrationOptions opt, List<string> warnings, CancellationToken ct)
    {
        var dirty = false;
        if (mu.Disabled && !existing.Disabled) { existing.Disabled = true; dirty = true; }
        if (existing.PrimaryPhone is null && mu.Phone is not null) { existing.PrimaryPhone = mu.Phone; dirty = true; }
        if (existing.Username is null && mu.Username is not null) { existing.Username = mu.Username; dirty = true; }

        if (dirty && !opt.DryRun) await users.UpdateUserAsync(existing, ct);

        // Attach only login methods the existing user is missing — never duplicate a credential.
        foreach (var tp in mu.ThirdParty)
        {
            if (existing.LoginMethods.Any(m => m.Kind == LoginMethodKind.ThirdParty
                    && string.Equals(m.ProviderId, tp.ProviderId, StringComparison.OrdinalIgnoreCase)
                    && m.ProviderUserId == tp.ProviderUserId))
                continue;
            if (!opt.DryRun)
                await users.AddLoginMethodAsync(NewThirdParty(existing.Id, tp), ct);
        }

        var hasPassword = existing.LoginMethods.Any(m => m.Kind == LoginMethodKind.EmailPassword);
        if (!hasPassword && mu.Password is not null)
        {
            var (hash, scheme) = (mu.Password.Hash, mu.Password.Scheme);
            if (scheme == PasswordHashScheme.Unsupported)
                warnings.Add($"password hash not migratable (unsupported scheme); user must reset.");
            else if (!opt.DryRun)
                await users.AddLoginMethodAsync(NewEmailPassword(existing.Id, Normalize(mu.Email), hash), ct);
        }

        if (!opt.DryRun) await ApplyAuxAsync(existing.Id, mu, opt, ct);
    }

    private List<LoginMethod> BuildLoginMethods(string userId, MigratedUser mu, string? email, List<string> warnings)
    {
        var methods = new List<LoginMethod>();

        if (mu.Password is not null)
        {
            if (mu.Password.Scheme == PasswordHashScheme.Unsupported)
            {
                warnings.Add("password hash not migratable (unsupported scheme); created without a password — user must reset.");
                // Still create an email/password method (without a hash) so the reset flow can set one.
                methods.Add(NewEmailPassword(userId, email, passwordHash: null, mu.EmailVerified));
            }
            else
            {
                methods.Add(NewEmailPassword(userId, email, mu.Password.Hash, mu.EmailVerified));
            }
        }

        foreach (var tp in mu.ThirdParty)
            methods.Add(NewThirdParty(userId, tp));

        if (mu.PasswordlessEmail && email is not null)
            methods.Add(new LoginMethod
            {
                Id = Guid.NewGuid().ToString("N"), UserId = userId, Kind = LoginMethodKind.Passwordless,
                Email = email, EmailVerified = mu.EmailVerified, CreatedAt = DateTimeOffset.UtcNow,
            });

        if (mu.PasswordlessPhone && mu.Phone is not null)
            methods.Add(new LoginMethod
            {
                Id = Guid.NewGuid().ToString("N"), UserId = userId, Kind = LoginMethodKind.Passwordless,
                Phone = mu.Phone, CreatedAt = DateTimeOffset.UtcNow,
            });

        return methods;
    }

    private async Task ApplyAuxAsync(string userId, MigratedUser mu, MigrationOptions opt, CancellationToken ct)
    {
        if (opt.ImportMetadata && mu.Metadata.Count > 0)
        {
            var patch = new JsonObject();
            foreach (var (k, v) in mu.Metadata) patch[k] = v?.DeepClone();
            await metadata.UpdateAsync(userId, patch, ct);
        }

        if (opt.ImportRoles && mu.Roles.Count > 0)
            await roles.SetRolesAsync(userId, mu.Roles, ct);

        if (opt.ImportTotp && !string.IsNullOrWhiteSpace(mu.TotpSecretBase32))
            await metadata.SetAsync(userId, opt.TotpMetadataKey, new TotpSecretSection(mu.TotpSecretBase32!), ct);
    }

    private static LoginMethod NewEmailPassword(string userId, string? email, string? passwordHash, bool emailVerified = false) => new()
    {
        Id = Guid.NewGuid().ToString("N"), UserId = userId, Kind = LoginMethodKind.EmailPassword,
        Email = email, EmailVerified = emailVerified, PasswordHash = passwordHash, CreatedAt = DateTimeOffset.UtcNow,
    };

    private static LoginMethod NewThirdParty(string userId, MigratedThirdParty tp) => new()
    {
        Id = Guid.NewGuid().ToString("N"), UserId = userId, Kind = LoginMethodKind.ThirdParty,
        ProviderId = tp.ProviderId, ProviderUserId = tp.ProviderUserId,
        Email = tp.Email, EmailVerified = tp.EmailVerified, CreatedAt = DateTimeOffset.UtcNow,
    };

    // Copy the shared options but target a specific tenant, so RunManyAsync never mutates the caller's object.
    private static MigrationOptions WithTenant(MigrationOptions? b, string tenantId)
    {
        b ??= new MigrationOptions();
        return new MigrationOptions
        {
            TenantId = tenantId,
            DryRun = b.DryRun,
            OnConflict = b.OnConflict,
            ImportRoles = b.ImportRoles,
            ImportMetadata = b.ImportMetadata,
            ImportTotp = b.ImportTotp,
            TotpMetadataKey = b.TotpMetadataKey,
        };
    }

    private static string? Normalize(string? email) =>
        string.IsNullOrWhiteSpace(email) ? null : email.Trim().ToLowerInvariant();

    private sealed record TotpSecretSection(string Secret);
}
