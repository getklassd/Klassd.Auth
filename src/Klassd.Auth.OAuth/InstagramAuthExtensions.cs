using System.Security.Claims;
using Klassd.Auth.Abstractions;
using Klassd.Auth.AspNetCore.Cookies;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.Extensions.DependencyInjection;

namespace Klassd.Auth.OAuth;

public static class InstagramAuthExtensions
{
    /// <summary>
    /// Adds Instagram sign-in via the "Instagram API with Instagram Login" (Basic Display is deprecated).
    /// Instagram returns NO email — the stable subject is the numeric <c>id</c> and the display name is
    /// the <c>username</c>. Requires a Meta app with the Instagram product; Meta supports only
    /// Professional (Business/Creator) accounts on this API. Adjust scopes via <paramref name="configure"/>.
    /// </summary>
    public static IAuthBuilder AddInstagram(
        this IAuthBuilder auth,
        string clientId,
        string clientSecret,
        string displayName = "Instagram",
        string scheme = "instagram",
        Action<OAuthOptions>? configure = null)
        => auth.AddExternalLogin(scheme, displayName, ab =>
            ab.AddOAuth(scheme, o =>
            {
                o.SignInScheme = KlassdAuthSchemes.External;
                o.ClientId = clientId;
                o.ClientSecret = clientSecret;
                o.CallbackPath = $"/signin-{scheme}";
                o.AuthorizationEndpoint = "https://www.instagram.com/oauth/authorize";
                o.TokenEndpoint = "https://api.instagram.com/oauth/access_token";
                o.UserInformationEndpoint = "https://graph.instagram.com/me?fields=id,username";
                o.Scope.Add("instagram_business_basic");

                o.Events.OnCreatingTicket = async ctx =>
                {
                    var user = await OAuthHelpers.GetJsonAsync(ctx, ctx.Options.UserInformationEndpoint);
                    ctx.Identity.AddClaim(user, ClaimTypes.NameIdentifier, "id");
                    ctx.Identity.AddClaim(user, "oid", "id");
                    ctx.Identity.AddClaim(user, ClaimTypes.Name, "username");
                    ctx.Identity.AddClaim(user, "preferred_username", "username");
                    // No email from Instagram → no email_verified; auto-link-by-email never applies.
                };
                configure?.Invoke(o);
            }));
}
