using Klassd.Auth.Core.Modules.Users;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Klassd.Auth.AspNetCore.Cookies;

/// <summary>
/// Seeds an admin account at startup if one doesn't already exist. Runs only when a seed
/// password is configured. Idempotent: skips if the username/email is already taken.
/// </summary>
internal sealed class SeedAdminHostedService(IServiceProvider services, KlassdAuthCookieOptions options) : IHostedService
{
    public async Task StartAsync(CancellationToken ct)
    {
        if (string.IsNullOrEmpty(options.SeedAdminPassword)) return;

        await using var scope = services.CreateAsyncScope();
        var accounts = scope.ServiceProvider.GetRequiredService<UserAccountService>();
        var roles = scope.ServiceProvider.GetRequiredService<RolesService>();

        var existing =
            (options.SeedAdminUsername is { } un ? await accounts.FindByUsernameAsync(un, ct) : null) ??
            (options.SeedAdminEmail is { } em ? await accounts.FindByEmailAsync(em, ct) : null);
        if (existing is not null) return;

        var user = await accounts.CreateLocalAsync(
            options.SeedAdminUsername, options.SeedAdminEmail, options.SeedAdminPassword!, ct);
        if (options.SeedAdminRoles.Count > 0)
            await roles.SetRolesAsync(user.Id, options.SeedAdminRoles, ct);
    }

    public Task StopAsync(CancellationToken ct) => Task.CompletedTask;
}
