using Klassd.Auth.Abstractions;
using Klassd.Auth.Core.Security;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;

namespace Klassd.Auth.Migration.DependencyInjection;

public static class MigrationBuilderExtensions
{
    /// <summary>
    /// Registers the <see cref="MigrationRunner"/> and, by default, swaps in the legacy-aware password
    /// hasher so users migrated from Auth0/SuperTokens can sign in with their existing bcrypt/argon2
    /// passwords. Call after <c>AddKlassdAuth(...)</c> and a storage adapter.
    /// </summary>
    public static IAuthBuilder AddAuthMigration(this IAuthBuilder auth, bool verifyLegacyPasswords = true)
    {
        auth.Services.AddScoped<MigrationRunner>();
        // MigrationCoordinator needs IMigrationStateStore, which only DB adapters register; pull it
        // optionally so resolving the coordinator never fails just because someone used RunAsync.
        auth.Services.AddScoped(sp => new MigrationCoordinator(
            sp.GetRequiredService<MigrationRunner>(),
            sp.GetService<IMigrationStateStore>(),
            sp.GetService<ILogger<MigrationCoordinator>>()));
        if (verifyLegacyPasswords)
            auth.UseLegacyPasswordVerification();
        return auth;
    }

    /// <summary>
    /// Runs a migration once, safely, as the app starts — guarded by a durable completion ledger and a
    /// distributed lease so that across many replicas it runs exactly once and never again. Requires a
    /// storage adapter that provides <see cref="IMigrationStateStore"/> (Sqlite/Postgres/MongoDb).
    /// Prefer a one-shot Job where you can; use this when migration must be embedded in startup.
    /// </summary>
    /// <param name="migrationId">Stable id recorded in the ledger, e.g. "auth0-import-2026-06".</param>
    /// <param name="sourceFactory">Builds the migration source from DI/config at startup.</param>
    public static IAuthBuilder RunMigrationOnStartup(
        this IAuthBuilder auth,
        string migrationId,
        Func<IServiceProvider, IMigrationSource> sourceFactory,
        Action<MigrationOptions>? configureOptions = null,
        Action<MigrationGuardOptions>? configureGuard = null)
    {
        auth.Services.AddHostedService(sp => new MigrationStartupHostedService(
            sp, migrationId, sourceFactory, configureOptions, configureGuard,
            sp.GetService<ILogger<MigrationStartupHostedService>>()));
        return auth;
    }

    /// <summary>
    /// Replaces the password hasher with one that also verifies bcrypt and argon2 hashes (the formats
    /// Auth0 and SuperTokens export). New passwords are still hashed with Klassd's pbkdf2, so a
    /// credential upgrades to the native format the next time it's set.
    /// </summary>
    public static IAuthBuilder UseLegacyPasswordVerification(this IAuthBuilder auth)
    {
        auth.Services.RemoveAll<IPasswordHasher>();
        auth.Services.AddSingleton<Pbkdf2PasswordHasher>();
        auth.Services.AddSingleton<IPasswordHasher>(sp =>
            new LegacyAwarePasswordHasher(sp.GetRequiredService<Pbkdf2PasswordHasher>()));
        return auth;
    }
}
