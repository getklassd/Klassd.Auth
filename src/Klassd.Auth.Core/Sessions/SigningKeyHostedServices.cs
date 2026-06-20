using Klassd.Auth.Abstractions;
using Microsoft.Extensions.Hosting;

namespace Klassd.Auth.Core.Sessions;

/// <summary>
/// Warms the key manager at startup (runs alongside the storage schema initializers). No-op unless the
/// rotating manager is the active signer — so it's harmless to register unconditionally (HS256 default).
/// </summary>
internal sealed class SigningKeyInitializer(ITokenSigningKey signer) : IAuthStorageInitializer
{
    public int Order => 1000;   // after the adapter's schema initializer creates the signing_keys table

    public Task InitializeAsync(CancellationToken ct = default) =>
        signer is SigningKeyManager manager ? manager.InitializeAsync(ct) : Task.CompletedTask;
}

/// <summary>Periodically rotates the signing key and prunes expired keys. Exits immediately under HS256.</summary>
internal sealed class SigningKeyRotationHostedService(ITokenSigningKey signer) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        if (signer is not SigningKeyManager manager) return;   // not rotating → nothing to maintain

        using var timer = new PeriodicTimer(TimeSpan.FromHours(12));
        while (await timer.WaitForNextTickAsync(ct))
        {
            try { await manager.MaintainAsync(ct); }
            catch (OperationCanceledException) { break; }
            catch { /* transient store error — retry on the next tick */ }
        }
    }
}
