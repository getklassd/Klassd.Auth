using System.Security.Claims;
using Klassd.Auth.Abstractions;
using Klassd.Auth.Core.Modules.Users;

namespace Klassd.Auth.AspNetCore.Cookies;

/// <summary>Builds the cookie's <see cref="ClaimsPrincipal"/> from a user + their roles.</summary>
internal static class ClaimsPrincipalFactory
{
    public static async Task<ClaimsPrincipal> BuildAsync(User user, RolesService roles, CancellationToken ct = default)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, user.Id),
            new(ClaimTypes.Name, user.Username ?? user.PrimaryEmail ?? user.Id),
        };
        if (user.PrimaryEmail is not null)
            claims.Add(new Claim(ClaimTypes.Email, user.PrimaryEmail));
        foreach (var role in await roles.GetRolesAsync(user.Id, ct))
            claims.Add(new Claim(ClaimTypes.Role, role));

        return new ClaimsPrincipal(new ClaimsIdentity(claims, KlassdAuthSchemes.Cookie));
    }
}
