using Klassd.Auth.Abstractions;
using Klassd.Auth.Dashboard.Components;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace Klassd.Auth.Dashboard;

public static class DashboardExtensions
{
    /// <summary>
    /// Registers the Blazor (Interactive Server) services the dashboard needs. The dashboard's data
    /// services come from <c>AddKlassdAuth()</c> + a storage adapter; call this after those.
    /// </summary>
    public static IAuthBuilder AddKlassdAuthDashboard(this IAuthBuilder auth)
    {
        auth.Services.AddRazorComponents().AddInteractiveServerComponents();
        return auth;
    }

    /// <summary>
    /// Maps the dashboard's Blazor host (root <see cref="App"/>) — the user-admin UI lives at
    /// <c>/auth/dashboard</c>. The host must also <c>UseAuthentication/UseAuthorization</c>,
    /// <c>UseAntiforgery</c> and <c>MapStaticAssets()</c>, and set
    /// <c>&lt;RequiresAspNetWebAssets&gt;true&lt;/RequiresAspNetWebAssets&gt;</c> in its csproj.
    /// Components require an authenticated user; pass <paramref name="authorizationPolicy"/> to also
    /// gate the Blazor endpoint with a policy (e.g. an admin role).
    /// </summary>
    public static IEndpointRouteBuilder MapKlassdAuthDashboard(
        this IEndpointRouteBuilder app, string? authorizationPolicy = null)
    {
        var components = app.MapRazorComponents<App>().AddInteractiveServerRenderMode();
        if (authorizationPolicy is not null) components.RequireAuthorization(authorizationPolicy);
        return app;
    }
}
