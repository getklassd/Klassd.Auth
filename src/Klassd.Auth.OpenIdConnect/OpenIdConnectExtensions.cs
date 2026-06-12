using Klassd.Auth.Abstractions;
using Klassd.Auth.AspNetCore.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.DependencyInjection;

namespace Klassd.Auth.OpenIdConnect;

public static class OpenIdConnectExtensions
{
    /// <summary>
    /// Adds a generic OpenID Connect external login. Plugs into the cookie package's external seam:
    /// the provider signs into the temporary external scheme, then the callback provisions the user
    /// and issues the app cookie. Requires <c>AddKlassdAuthCookies()</c> first.
    /// </summary>
    public static IAuthBuilder AddOpenIdConnect(
        this IAuthBuilder auth, string displayName, Action<OpenIdConnectOptions> configure, string scheme = "oidc")
        => auth.AddExternalLogin(scheme, displayName, ab =>
            ab.AddOpenIdConnect(scheme, o =>
            {
                o.SignInScheme = KlassdAuthSchemes.External;   // engine exchanges this for the app cookie
                o.CallbackPath = $"/signin-{scheme}";
                o.ResponseType = "code";
                o.UsePkce = true;
                o.SaveTokens = true;
                o.GetClaimsFromUserInfoEndpoint = true;
                o.Scope.Add("openid");
                o.Scope.Add("profile");
                o.Scope.Add("email");
                configure(o);
            }));

    /// <summary>
    /// Adds Microsoft Entra ID (formerly Azure AD) sign-in. <paramref name="tenantId"/> may be a
    /// directory (tenant) id, or "organizations" / "common" for multi-tenant. Entra is OIDC, so this
    /// is a thin convenience over <see cref="AddOpenIdConnect"/> pointed at the Microsoft authority.
    /// </summary>
    public static IAuthBuilder AddEntraId(
        this IAuthBuilder auth,
        string tenantId,
        string clientId,
        string clientSecret,
        string displayName = "Microsoft Entra ID",
        string scheme = "entra",
        Action<OpenIdConnectOptions>? configure = null)
        => auth.AddOpenIdConnect(displayName, o =>
        {
            o.Authority = $"https://login.microsoftonline.com/{tenantId}/v2.0";
            o.ClientId = clientId;
            o.ClientSecret = clientSecret;
            // Entra v2.0 puts the user's sign-in name in preferred_username; the stable id is "oid"
            // (handled by the cookie package's default external mapping).
            o.TokenValidationParameters.NameClaimType = "preferred_username";
            // For multi-tenant ("organizations"/"common") the issuer varies per tenant.
            if (tenantId is "common" or "organizations")
                o.TokenValidationParameters.ValidateIssuer = false;
            configure?.Invoke(o);
        }, scheme);

    /// <summary>
    /// Adds Google sign-in. Google is OIDC-compliant, so this is a convenience over
    /// <see cref="AddOpenIdConnect"/> pointed at Google's authority (stable id from <c>sub</c>).
    /// </summary>
    public static IAuthBuilder AddGoogle(
        this IAuthBuilder auth,
        string clientId,
        string clientSecret,
        string displayName = "Google",
        string scheme = "google",
        Action<OpenIdConnectOptions>? configure = null)
        => auth.AddOpenIdConnect(displayName, o =>
        {
            o.Authority = "https://accounts.google.com";
            o.ClientId = clientId;
            o.ClientSecret = clientSecret;
            o.TokenValidationParameters.NameClaimType = "name";
            configure?.Invoke(o);
        }, scheme);
}
