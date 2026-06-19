using Klassd.Auth.Abstractions;
using Klassd.Auth.Dashboard.Components;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace Klassd.Auth.Dashboard;

/// <summary>Configuration for the Klassd.Auth dashboard.</summary>
public sealed class DashboardOptions
{
    /// <summary>Path the dashboard is mounted under (no trailing slash). Default <c>/auth/dashboard</c>.</summary>
    public string BasePath { get; set; } = "/auth/dashboard";

    /// <summary>Where to send unauthenticated visitors (matches the cookie LoginPath). Default <c>/login</c>.</summary>
    public string LoginPath { get; set; } = "/login";
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
