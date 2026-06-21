using Klassd.Auth.Abstractions;
using Klassd.Auth.Dashboard.Components;
using Klassd.Auth.Migration;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace Klassd.Auth.Dashboard;

/// <summary>Database connection fields the admin fills in on the import page.</summary>
/// <param name="Host">Server host name or IP.</param>
/// <param name="Port">Port, or null/empty to use the driver default (Postgres 5432, MySQL 3306).</param>
/// <param name="Database">Database name.</param>
/// <param name="Username">Login user.</param>
/// <param name="Password">Login password (may be empty).</param>
public sealed record DbConnectionParts(string Host, string? Port, string Database, string Username, string Password);

/// <summary>
/// A live-connection import source the dashboard offers in addition to the built-in file imports
/// (Auth0/SuperTokens exports). Registered by the host via <see cref="DashboardOptions.AddConnectionSource"/>,
/// so the dashboard package itself never references a DB driver — the host that owns the driver package
/// (e.g. <c>Klassd.Auth.Migration.SuperTokens.Postgres</c>) turns the admin-entered
/// <see cref="DbConnectionParts"/> into a driver-specific connection string and builds the source.
/// </summary>
/// <param name="Key">Stable id used as the dropdown value (e.g. "supertokens-pg").</param>
/// <param name="DisplayName">Label shown in the source dropdown.</param>
/// <param name="Build">Builds the source from the connection fields and (SuperTokens) app id.</param>
public sealed record ConnectionImportSource(
    string Key, string DisplayName, Func<DbConnectionParts, string, IMigrationSource> Build);

/// <summary>Configuration for the Klassd.Auth dashboard.</summary>
public sealed class DashboardOptions
{
    /// <summary>Path the dashboard is mounted under (no trailing slash). Default <c>/auth/dashboard</c>.</summary>
    public string BasePath { get; set; } = "/auth/dashboard";

    /// <summary>Where to send unauthenticated visitors (matches the cookie LoginPath). Default <c>/login</c>.</summary>
    public string LoginPath { get; set; } = "/login";

    /// <summary>Live-connection import sources offered on the import page (in addition to file imports).</summary>
    public List<ConnectionImportSource> ConnectionSources { get; } = [];

    /// <summary>
    /// Offers a connection-string import on the dashboard's import page — e.g. import directly from a
    /// running SuperTokens database. The host supplies <paramref name="build"/> (which references the
    /// driver package), keeping that dependency out of the dashboard itself.
    /// </summary>
    public DashboardOptions AddConnectionSource(string key, string displayName, Func<DbConnectionParts, string, IMigrationSource> build)
    {
        ConnectionSources.Add(new ConnectionImportSource(key, displayName, build));
        return this;
    }
}

public static class DashboardExtensions
{
    /// <summary>
    /// Registers the Blazor (Interactive Server) services the dashboard needs. The dashboard's data
    /// services come from <c>AddKlassdAuth()</c> + a storage adapter; call this after those.
    /// </summary>
    public static IAuthBuilder AddKlassdAuthDashboard(this IAuthBuilder auth, Action<DashboardOptions>? configure = null)
    {
        var options = new DashboardOptions();
        configure?.Invoke(options);
        auth.Services.AddSingleton(options);
        auth.Services.AddSingleton<ImportJobManager>();   // runs dashboard imports in the background
        auth.Services.AddRazorComponents().AddInteractiveServerComponents();
        return auth;
    }

    /// <summary>
    /// Mounts the dashboard's Blazor host under <paramref name="basePath"/> (default
    /// <c>/auth/dashboard</c>) as an isolated pipeline branch, and <b>requires authentication</b> —
    /// anonymous requests are redirected to the cookie login path. Pass
    /// <paramref name="authorizationPolicy"/> to additionally gate it with a policy (e.g. an admin role).
    /// </summary>
    public static WebApplication MapKlassdAuthDashboard(
        this WebApplication app, string basePath = "/auth/dashboard", string? authorizationPolicy = null)
    {
        // Share the configured base path with App.razor's <base href> (LoginPath stays from AddKlassdAuthDashboard).
        app.Services.GetRequiredService<DashboardOptions>().BasePath = basePath;

        app.Map(basePath, branch =>
        {
            branch.UsePathBase(basePath);
            branch.UseRouting();
            branch.UseAuthentication();
            branch.UseAuthorization();
            branch.UseAntiforgery();
            branch.UseEndpoints(endpoints =>
            {
                endpoints.MapStaticAssets();
                var components = endpoints.MapRazorComponents<App>().AddInteractiveServerRenderMode();
                if (authorizationPolicy is null) components.RequireAuthorization();
                else components.RequireAuthorization(authorizationPolicy);
            });
        });
        return app;
    }
}
