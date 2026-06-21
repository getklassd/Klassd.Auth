using Klassd.Auth.Abstractions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Klassd.Auth.AspNetCore;

/// <summary>Rehydrates the per-request <see cref="ITenantContext"/> from the signed-in principal.</summary>
public static class KlassdTenantExtensions
{
    /// <summary>
    /// Copies the <c>tnt</c> claim of the authenticated user into the scoped <see cref="ITenantContext"/>,
    /// so storage lookups during the request are scoped to the caller's tenant. Place AFTER
    /// <c>UseAuthentication()</c> (the claim must be populated first). No-op for anonymous requests and
    /// for single-tenant apps (the claim is then "public"). Reads the cookie or JWT principal alike.
    /// </summary>
    public static IApplicationBuilder UseKlassdTenant(this IApplicationBuilder app) =>
        app.Use(async (http, next) =>
        {
            var tnt = http.User.FindFirst(TenantContext.ClaimName)?.Value;
            if (!string.IsNullOrEmpty(tnt))
                http.RequestServices.GetRequiredService<ITenantContext>().TenantId = tnt;
            await next();
        });
}
