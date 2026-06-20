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

    /// <summary>
    /// When an UNauthenticated external sign-in matches an existing local account by email, merge into
    /// it — but only if the provider reports the email as verified. Off by default: auto-linking by an
    /// unverified email is an account-takeover vector. (Signed-in users can always link explicitly.)
    /// </summary>
    public bool AutoLinkByVerifiedEmail { get; set; }

    // Optional admin seeded at startup (provide a password + a username and/or email).
    public string? SeedAdminUsername { get; set; }
    public string? SeedAdminEmail { get; set; }
    public string? SeedAdminPassword { get; set; }
    public IReadOnlyList<string> SeedAdminRoles { get; set; } = [];

    /// <summary>Maps an external provider's claims to a normalized user. Defaults to <see cref="DefaultExternalMapping"/>.</summary>
    public Func<ClaimsPrincipal, ExternalUserInfo> MapExternalUser { get; set; } = DefaultExternalMapping;

    /// <summary>
    /// Per-provider claim → user mappings (keyed by scheme), the equivalent of SuperTokens'
    /// per-provider <c>GetUserInfo</c> override. When a scheme has an entry it wins over
    /// <see cref="MapExternalUser"/>. Register via <c>auth.MapExternalProfile(scheme, …)</c>.
    /// </summary>
    public Dictionary<string, Func<ClaimsPrincipal, ExternalUserInfo>> ProviderProfileMappers { get; } =
        new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Resolves the mapper for a scheme: the per-provider one if registered, else the default.</summary>
    public ExternalUserInfo MapExternalUserFor(string scheme, ClaimsPrincipal principal) =>
        ProviderProfileMappers.TryGetValue(scheme, out var mapper) ? mapper(principal) : MapExternalUser(principal);

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
        // OIDC providers (Google/Entra) emit email_verified; OAuth providers set it explicitly in their
        // OnCreatingTicket. Verified only when the claim is truthy — gates AutoLinkByVerifiedEmail.
        var emailVerified = email is not null
            && C("email_verified") is { } v && (v == "true" || v == "True");

        // Carry every provider claim through (last value wins per type) so an override of
        // ProvisionExternalAsync can persist the ones it wants and re-emit them on the access token.
        var claims = new Dictionary<string, string>();
        foreach (var claim in p.Claims)
            claims[claim.Type] = claim.Value;

        return new ExternalUserInfo(externalId, username, email, emailVerified) { Claims = claims };
    }
}
