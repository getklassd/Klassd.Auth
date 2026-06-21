using Klassd.Auth.Migration;
using Microsoft.Extensions.DependencyInjection;

namespace Klassd.Auth.Dashboard;

public enum ImportJobState { Running, Completed, Failed, Canceled }

/// <summary>
/// A single import running in the background. Mutated by the runner thread; read by the UI. Subscribe
/// to <see cref="Changed"/> to refresh a view, and call <see cref="Cancel"/> to stop it.
/// </summary>
public sealed class ImportJob
{
    public string Id { get; } = Guid.NewGuid().ToString("N");
    public required string SourceName { get; init; }
    public required string TenantId { get; init; }
    public required bool Apply { get; init; }
    public DateTimeOffset StartedAt { get; init; }

    public ImportJobState State { get; internal set; } = ImportJobState.Running;
    public MigrationProgress? Progress { get; internal set; }
    public MigrationReport? Report { get; internal set; }
    public string? Error { get; internal set; }

    internal readonly CancellationTokenSource Cts = new();

    /// <summary>Raised (off the UI thread) whenever progress/state changes; the page marshals to the circuit.</summary>
    public event Action? Changed;
    internal void Raise() => Changed?.Invoke();

    public void Cancel() => Cts.Cancel();
}

/// <summary>
/// Runs dashboard imports in the background so the admin isn't blocked and can watch progress live.
/// Singleton: the job outlives the Blazor circuit, so navigating away and back re-attaches to it.
/// </summary>
public sealed class ImportJobManager(IServiceScopeFactory scopes)
{
    /// <summary>The most recently started job (what the import page re-attaches to). ponytail: one at a time is plenty for an admin tool.</summary>
    public ImportJob? Latest { get; private set; }

    public ImportJob Start(IMigrationSource source, MigrationOptions options)
    {
        var job = new ImportJob
        {
            SourceName = source.Name,
            TenantId = options.TenantId,
            Apply = !options.DryRun,
            StartedAt = DateTimeOffset.UtcNow,
        };
        Latest = job;
        _ = Task.Run(() => RunAsync(job, source, options));
        return job;
    }

    private async Task RunAsync(ImportJob job, IMigrationSource source, MigrationOptions options)
    {
        try
        {
            // Own DI scope: the runner mutates the scoped ITenantContext, and it must not share (or
            // outlive) any Blazor circuit scope.
            await using var scope = scopes.CreateAsyncScope();
            var runner = scope.ServiceProvider.GetService<MigrationRunner>()
                ?? throw new InvalidOperationException(
                    "Migration isn't enabled on this host — call AddAuthMigration() after AddKlassdAuth().");

            var progress = new Progress<MigrationProgress>(p => { job.Progress = p; job.Raise(); });
            job.Report = await runner.RunAsync(source, options, progress, job.Cts.Token);
            job.State = ImportJobState.Completed;
        }
        catch (OperationCanceledException) { job.State = ImportJobState.Canceled; }
        catch (Exception ex) { job.Error = ex.Message; job.State = ImportJobState.Failed; }
        finally { job.Raise(); }
    }
}
