using Klassd.Auth.Abstractions;
using Microsoft.Extensions.Hosting;

namespace Klassd.Auth.Core.Sessions;

/// <summary>Warms the key manager at startup (runs alongside the storage schema initializers).</summary>
internal sealed class SigningKeyInitializer(SigningKeyManager manager) : IAuthStorageInitializer
{
    public Task InitializeAsync(CancellationToken ct = default) => manager.InitializeAsync(ct);
}

/// <summary>Periodically rotates the signing key and prunes expired keys.</summary>
internal sealed class SigningKeyRotationHostedService(SigningKeyManager manager) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromHours(12));
        while (await timer.WaitForNextTickAsync(ct))
        {
            try { await manager.MaintainAsync(ct); }
            catch (OperationCanceledException) { break; }
            catch { /* transient store error — retry on the next tick */ }
        }
    }
}
