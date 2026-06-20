using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Text.Json;
using Klassd.Auth.Abstractions;
using Klassd.Auth.AspNetCore.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Klassd.Auth.OAuth;

public static class TikTokAuthExtensions
{
    /// <summary>
    /// Adds TikTok sign-in (Login Kit v2). TikTok deviates from standard OAuth — it names the client
    /// parameter <c>client_key</c> (not <c>client_id</c>) and nests the profile under <c>data.user</c> —
    /// so this uses a small custom handler. Returns NO email; the stable subject is <c>union_id</c>
    /// (cross-app) when present, else <c>open_id</c>.
    /// </summary>
    public static IAuthBuilder AddTikTok(
        this IAuthBuilder auth,
        string clientKey,
        string clientSecret,
        string displayName = "TikTok",
        string scheme = "tiktok",
        Action<OAuthOptions>? configure = null)
        => auth.AddExternalLogin(scheme, displayName, ab =>
            ab.AddOAuth<OAuthOptions, TikTokOAuthHandler>(scheme, o =>
            {
                o.SignInScheme = KlassdAuthSchemes.External;
                o.SaveTokens = true;   // surface provider tokens to IExternalSignInHook
                o.ClientId = clientKey;          // sent as client_key by the handler
                o.ClientSecret = clientSecret;
                o.CallbackPath = $"/signin-{scheme}";
                o.AuthorizationEndpoint = "https://www.tiktok.com/v2/auth/authorize/";
                o.TokenEndpoint = "https://open.tiktokapis.com/v2/oauth/token/";
                o.UserInformationEndpoint = "https://open.tiktokapis.com/v2/user/info/?fields=open_id,union_id,display_name";
                o.UsePkce = false;
                o.Scope.Add("user.info.basic");

                // The authorize request must carry client_key, not client_id.
                o.Events.OnRedirectToAuthorizationEndpoint = ctx =>
                {
                    ctx.Response.Redirect(TikTokProfile.RewriteAuthorizeUrl(ctx.RedirectUri));
                    return Task.CompletedTask;
                };
                configure?.Invoke(o);
            }));
}

/// <summary>Pure, testable bits of the TikTok handler (kept out of the HTTP plumbing).</summary>
internal static class TikTokProfile
{
    /// <summary>TikTok names the client parameter <c>client_key</c>; the stock handler emits <c>client_id</c>.</summary>
    public static string RewriteAuthorizeUrl(string authorizeUrl) =>
        authorizeUrl.Replace("client_id=", "client_key=");

    /// <summary>
    /// Extracts the stable subject (prefer cross-app <c>union_id</c>, else per-app <c>open_id</c>) and
    /// display name from a <c>/v2/user/info/</c> response root (<c>{ data: { user: {...} } }</c>).
    /// </summary>
    public static (string? Subject, string? DisplayName) Parse(JsonElement responseRoot)
    {
        var user = responseRoot.GetProperty("data").GetProperty("user");
        var subject =
            (user.TryGetProperty("union_id", out var uid) ? uid.GetString() : null)
            ?? (user.TryGetProperty("open_id", out var oid) ? oid.GetString() : null);
        var name = user.TryGetProperty("display_name", out var dn) ? dn.GetString() : null;
        return (string.IsNullOrEmpty(subject) ? null : subject, string.IsNullOrEmpty(name) ? null : name);
    }
}

/// <summary>Handler customizing the token exchange (client_key) and profile parsing for TikTok.</summary>
internal sealed class TikTokOAuthHandler(
    IOptionsMonitor<OAuthOptions> options, ILoggerFactory logger, UrlEncoder encoder)
    : OAuthHandler<OAuthOptions>(options, logger, encoder)
{
    protected override async Task<OAuthTokenResponse> ExchangeCodeAsync(OAuthCodeExchangeContext context)
    {
        var form = new Dictionary<string, string>
        {
            ["client_key"] = Options.ClientId,
            ["client_secret"] = Options.ClientSecret,
            ["code"] = context.Code,
            ["grant_type"] = "authorization_code",
            ["redirect_uri"] = context.RedirectUri,
        };

        using var req = new HttpRequestMessage(HttpMethod.Post, Options.TokenEndpoint);
        req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        req.Content = new FormUrlEncodedContent(form);
        using var resp = await Backchannel.SendAsync(req, Context.RequestAborted);
        var body = await resp.Content.ReadAsStringAsync(Context.RequestAborted);
        return resp.IsSuccessStatusCode
            ? OAuthTokenResponse.Success(JsonDocument.Parse(body))
            : OAuthTokenResponse.Failed(new Exception($"TikTok token exchange failed: {body}"));
    }

    protected override async Task<AuthenticationTicket> CreateTicketAsync(
        ClaimsIdentity identity, AuthenticationProperties properties, OAuthTokenResponse tokens)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, Options.UserInformationEndpoint);
        req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", tokens.AccessToken);
        using var resp = await Backchannel.SendAsync(req, Context.RequestAborted);
        resp.EnsureSuccessStatusCode();
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(Context.RequestAborted));

        var (subject, name) = TikTokProfile.Parse(doc.RootElement);
        if (subject is not null)
        {
            identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, subject));
            identity.AddClaim(new Claim("oid", subject));
        }
        if (name is not null)
            identity.AddClaim(new Claim(ClaimTypes.Name, name));

        var user = doc.RootElement.GetProperty("data").GetProperty("user");
        var ctx = new OAuthCreatingTicketContext(
            new ClaimsPrincipal(identity), properties, Context, Scheme, Options, Backchannel, tokens, user);
        await Events.CreatingTicket(ctx);
        return new AuthenticationTicket(ctx.Principal!, ctx.Properties, Scheme.Name);
    }
}
