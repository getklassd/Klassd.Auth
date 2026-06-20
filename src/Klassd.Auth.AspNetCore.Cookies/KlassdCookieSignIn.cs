using Klassd.Auth.Abstractions;
using Klassd.Auth.Core.Modules.Users;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Klassd.Auth.AspNetCore.Cookies;

/// <summary>
/// Issues the primary application cookie for a verified user. Shared sign-in seam for any auth
/// method that resolves to a local user (passwordless, passkeys, …), mirroring what the
/// external-SSO callback does internally.
/// </summary>
public static class KlassdCookieSignIn
{
    public static async Task SignInUserAsync(this HttpContext http, User user, CancellationToken ct = default)
    {
        var roles = http.RequestServices.GetRequiredService<IRolesService>();
        var principal = await ClaimsPrincipalFactory.BuildAsync(user, roles, extraClaims: null, ct);
        await http.SignInAsync(KlassdAuthSchemes.Cookie, principal);
    }
}
