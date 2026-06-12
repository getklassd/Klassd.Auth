using Klassd.Auth.Abstractions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Klassd.Auth.Core.DependencyInjection;

/// <summary>
/// Runs every registered <see cref="IAuthStorageInitializer"/> once at startup, so the host
/// never has to remember to create the schema. Registered automatically by AddKlassdAuth.
/// </summary>
internal sealed class StorageInitializerHostedService(IServiceProvider services) : IHostedService
{
    public async Task StartAsync(CancellationToken ct)
    {
        await using var scope = services.CreateAsyncScope();
        foreach (var init in scope.ServiceProvider.GetServices<IAuthStorageInitializer>())
            await init.InitializeAsync(ct);
    }

    public Task StopAsync(CancellationToken ct) => Task.CompletedTask;
}
