using System.Security.Claims;
using Klassd.Auth.Core.Modules.Users;

namespace Klassd.Auth.AspNetCore.Cookies;

/// <summary>Describes an external login provider, for rendering its button on the login page.</summary>
public sealed record ExternalLoginDescriptor(string Scheme, string DisplayName);

/// <summary>Tracks registered external providers so the host can render their sign-in buttons.</summary>
public sealed class ExternalLoginRegistry
{
    private readonly List<ExternalLoginDescriptor> _providers = [];
    public IReadOnlyList<ExternalLoginDescriptor> Providers => _providers;
    public void Add(ExternalLoginDescriptor provider) => _providers.Add(provider);
}

public sealed class KlassdAuthCookieOptions
{
    /// <summary>Route prefix for the login/logout/external endpoints. Default "/auth".</summary>
    public string BasePath { get; set; } = "/auth";

    public string CookieName { get; set; } = "klassd_auth";
    public TimeSpan ExpireTimeSpan { get; set; } = TimeSpan.FromDays(7);
    public bool SlidingExpiration { get; set; } = true;

    /// <summary>Where the cookie handler redirects unauthenticated users.</summary>
    public string LoginPath { get; set; } = "/login";
    public string AccessDeniedPath { get; set; } = "/login";

    /// <summary>Treat loopback requests as an authenticated local admin (dev / port-forward only).</summary>
    public bool BypassOnLoopback { get; set; }

    public bool AllowLocalLogin { get; set; } = true;
    public bool AutoProvisionExternalUsers { get; set; } = true;

    // Optional admin seeded at startup (provide a password + a username and/or email).
    public string? SeedAdminUsername { get; set; }
    public string? SeedAdminEmail { get; set; }
    public string? SeedAdminPassword { get; set; }
    public IReadOnlyList<string> SeedAdminRoles { get; set; } = [];

    /// <summary>Maps an external provider's claims to a normalized user. Defaults to <see cref="DefaultExternalMapping"/>.</summary>
    public Func<ClaimsPrincipal, ExternalUserInfo> MapExternalUser { get; set; } = DefaultExternalMapping;

    internal ExternalLoginRegistry ExternalLogins { get; } = new();

    /// <summary>
    /// Default claim mapping. Stable id prefers <c>oid</c> (Microsoft Entra object id) then
    /// <c>sub</c>/NameIdentifier; email/username come from the usual OIDC claims.
    /// </summary>
    public static ExternalUserInfo DefaultExternalMapping(ClaimsPrincipal p)
    {
        string? C(params string[] types) => types.Select(p.FindFirstValue).FirstOrDefault(v => !string.IsNullOrEmpty(v));

        var externalId =
            C("oid", "http://schemas.microsoft.com/identity/claims/objectidentifier", "sub", ClaimTypes.NameIdentifier)
            ?? throw new InvalidOperationException("External login is missing a stable subject/oid claim.");
        var email = C("email", ClaimTypes.Email, "preferred_username", "upn");
        var username = C("preferred_username", "name", ClaimTypes.Name) ?? email;
        return new ExternalUserInfo(externalId, username, email);
    }
}
