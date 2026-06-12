using System.Net;
using System.Security.Claims;
using Klassd.Auth.Abstractions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Klassd.Auth.AspNetCore.Cookies;

public static class CookieAuthExtensions
{
    /// <summary>
    /// Adds cookie-based sign-in for server-rendered / Blazor apps on top of Klassd.Auth: a primary
    /// app cookie, an external-SSO callback cookie, authorization, and (optionally) a seeded admin.
    /// </summary>
    public static IAuthBuilder AddKlassdAuthCookies(
        this IAuthBuilder auth, Action<KlassdAuthCookieOptions>? configure = null)
    {
        var options = new KlassdAuthCookieOptions();
        configure?.Invoke(options);

        var services = auth.Services;
        services.AddSingleton(options);
        services.AddSingleton(options.ExternalLogins);

        services.AddAuthentication(KlassdAuthSchemes.Cookie)
            .AddCookie(KlassdAuthSchemes.Cookie, o =>
            {
                o.Cookie.Name = options.CookieName;
                o.Cookie.HttpOnly = true;
                o.Cookie.SameSite = SameSiteMode.Lax;
                o.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
                o.LoginPath = options.LoginPath;
                o.AccessDeniedPath = options.AccessDeniedPath;
                o.ExpireTimeSpan = options.ExpireTimeSpan;
                o.SlidingExpiration = options.SlidingExpiration;
            })
            .AddCookie(KlassdAuthSchemes.External, o =>
            {
                o.Cookie.Name = "klassd_external";
                o.ExpireTimeSpan = TimeSpan.FromMinutes(10);
            });

        services.AddAuthorization();
        services.AddCascadingAuthenticationState();

        if (!string.IsNullOrEmpty(options.SeedAdminPassword))
            services.AddHostedService<SeedAdminHostedService>();

        return auth;
    }

    /// <summary>
    /// Registers an external login provider (used by Klassd.Auth.OpenIdConnect's AddOpenIdConnect /
    /// AddEntraId). Call after <see cref="AddKlassdAuthCookies"/>.
    /// </summary>
    public static IAuthBuilder AddExternalLogin(
        this IAuthBuilder auth, string scheme, string displayName, Action<AuthenticationBuilder> configure)
    {
        var registry = auth.Services
            .LastOrDefault(d => d.ServiceType == typeof(ExternalLoginRegistry))?.ImplementationInstance as ExternalLoginRegistry
            ?? throw new InvalidOperationException("Call AddKlassdAuthCookies() before AddExternalLogin().");

        registry.Add(new ExternalLoginDescriptor(scheme, displayName));
        configure(auth.Services.AddAuthentication());
        return auth;
    }

    /// <summary>Wires authentication middleware, an optional loopback bypass, and the cookie endpoints.</summary>
    public static WebApplication UseKlassdAuthCookies(this WebApplication app)
    {
        var options = app.Services.GetRequiredService<KlassdAuthCookieOptions>();

        app.UseAuthentication();

        if (options.BypassOnLoopback)
            app.Use(async (ctx, next) =>
            {
                if (ctx.Connection.RemoteIpAddress is { } ip && IPAddress.IsLoopback(ip)
                    && ctx.User.Identity?.IsAuthenticated != true)
                {
                    ctx.User = new ClaimsPrincipal(new ClaimsIdentity(
                        [new Claim(ClaimTypes.Name, "localhost"), new Claim(ClaimTypes.NameIdentifier, "loopback")],
                        "Loopback"));
                }
                await next(ctx);
            });

        app.UseAuthorization();
        app.MapKlassdAuthCookieEndpoints();
        return app;
    }
}
