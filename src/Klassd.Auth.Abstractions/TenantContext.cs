namespace Klassd.Auth.Abstractions;

/// <summary>
/// The tenant the current operation runs in (shared-schema multi-tenancy). Registered per request
/// (scoped); set from the request at login and rehydrated from the access token's <c>tnt</c> claim on
/// authed calls (<c>app.UseKlassdTenant()</c>). Storage adapters scope identity lookups to it, so a
/// login module can never accidentally resolve a user from another tenant. Defaults to the single
/// "public" tenant, so single-tenant deployments need no configuration.
/// </summary>
public interface ITenantContext
{
    string TenantId { get; set; }
}

/// <inheritdoc cref="ITenantContext"/>
public sealed class TenantContext : ITenantContext
{
    /// <summary>The implicit single tenant used when none is specified.</summary>
    public const string Default = "public";

    /// <summary>Access-token / cookie claim that carries the tenant.</summary>
    public const string ClaimName = "tnt";

    public string TenantId { get; set; } = Default;
}
