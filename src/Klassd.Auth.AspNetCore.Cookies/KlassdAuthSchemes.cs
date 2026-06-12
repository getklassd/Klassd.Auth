using Microsoft.AspNetCore.Authentication.Cookies;

namespace Klassd.Auth.AspNetCore.Cookies;

public static class KlassdAuthSchemes
{
    /// <summary>The primary application sign-in cookie.</summary>
    public const string Cookie = CookieAuthenticationDefaults.AuthenticationScheme; // "Cookies"

    /// <summary>Short-lived cookie holding the external provider's principal during SSO callback.</summary>
    public const string External = "klassd_external";
}
