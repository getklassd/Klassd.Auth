using System.Security.Claims;
using Klassd.Auth.Abstractions;
using Klassd.Auth.AspNetCore.Cookies;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.Extensions.DependencyInjection;

namespace Klassd.Auth.OAuth;

public static class FacebookAuthExtensions
{
    /// <summary>
    /// Adds Facebook sign-in. Facebook is OAuth 2.0 (not OIDC), so this uses the generic OAuth handler
    /// against the Graph API: numeric id as the stable subject, plus name and (Graph-verified) email.
    /// </summary>
    public static IAuthBuilder AddFacebook(
        this IAuthBuilder auth,
        string clientId,
        string clientSecret,
        string displayName = "Facebook",
        string scheme = "facebook",
        Action<OAuthOptions>? configure = null)
        => auth.AddExternalLogin(scheme, displayName, ab =>
            ab.AddOAuth(scheme, o =>
            {
                o.SignInScheme = KlassdAuthSchemes.External;
                o.ClientId = clientId;
                o.ClientSecret = clientSecret;
                o.CallbackPath = $"/signin-{scheme}";
                o.AuthorizationEndpoint = "https://www.facebook.com/v19.0/dialog/oauth";
                o.TokenEndpoint = "https://graph.facebook.com/v19.0/oauth/access_token";
                o.UserInformationEndpoint = "https://graph.facebook.com/me?fields=id,name,email";
                o.UsePkce = true;
                o.Scope.Add("email");

                o.Events.OnCreatingTicket = async ctx =>
                {
                    var user = await OAuthHelpers.GetJsonAsync(ctx, ctx.Options.UserInformationEndpoint);
                    ctx.Identity.AddClaim(user, ClaimTypes.NameIdentifier, "id");
                    ctx.Identity.AddClaim(user, "oid", "id");          // default external mapping prefers oid
                    ctx.Identity.AddClaim(user, ClaimTypes.Name, "name");
                    ctx.Identity.AddClaim(user, ClaimTypes.Email, "email");
                    // An email returned by Graph is account-verified → safe for opt-in auto-link.
                    if (user.TryGetProperty("email", out var e) && !string.IsNullOrEmpty(e.GetString()))
                        ctx.Identity?.AddClaim(new Claim("email_verified", "true"));
                };
                configure?.Invoke(o);
            }));
}
