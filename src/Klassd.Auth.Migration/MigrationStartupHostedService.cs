using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Klassd.Auth.Migration;

/// <summary>
/// Runs a guarded migration once during startup (registered by <c>RunMigrationOnStartup</c>). It runs
/// in the background so it never blocks the host from coming up, and leans entirely on the
/// <see cref="MigrationCoordinator"/> for the ledger + distributed-lease guarantees.
/// </summary>
internal sealed class MigrationStartupHostedService(
    IServiceProvider services,
    string migrationId,
    Func<IServiceProvider, IMigrationSource> sourceFactory,
    Action<MigrationOptions>? configureOptions,
    Action<MigrationGuardOptions>? configureGuard,
    ILogger<MigrationStartupHostedService>? logger) : BackgroundService
{
    private readonly ILogger _log = logger ?? NullLogger<MigrationStartupHostedService>.Instance;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await using var scope = services.CreateAsyncScope();
            var sp = scope.ServiceProvider;

            var migrationOptions = new MigrationOptions();
            configureOptions?.Invoke(migrationOptions);
            var guard = new MigrationGuardOptions();
            configureGuard?.Invoke(guard);

            var coordinator = sp.GetRequiredService<MigrationCoordinator>();
            var source = sourceFactory(sp);

            var result = await coordinator.RunOnceAsync(migrationId, source, migrationOptions, guard, stoppingToken);
            _log.LogInformation("Startup migration {Id}: {Outcome}.", migrationId, result.Outcome);
        }
        catch (OperationCanceledException) { /* host shutting down */ }
        catch (Exception ex)
        {
            // Don't crash the host on a migration failure — log it; the next start retries (ledger
            // is only written on success).
            _log.LogError(ex, "Startup migration {Id} failed; it will be retried on the next start.", migrationId);
        }
    }
}
