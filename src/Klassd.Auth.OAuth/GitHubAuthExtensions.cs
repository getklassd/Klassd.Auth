using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Json;
using Klassd.Auth.Abstractions;
using Klassd.Auth.AspNetCore.Cookies;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.Extensions.DependencyInjection;

namespace Klassd.Auth.OAuth;

public static class GitHubAuthExtensions
{
    /// <summary>
    /// Adds GitHub sign-in. GitHub is OAuth 2.0 (not OIDC), so this uses the generic OAuth handler
    /// with GitHub's user endpoint, surfacing the numeric id as the stable subject and falling back
    /// to the user's primary verified email when their public email is hidden.
    /// </summary>
    public static IAuthBuilder AddGitHub(
        this IAuthBuilder auth,
        string clientId,
        string clientSecret,
        string displayName = "GitHub",
        string scheme = "github",
        Action<OAuthOptions>? configure = null)
        => auth.AddExternalLogin(scheme, displayName, ab =>
            ab.AddOAuth(scheme, o =>
            {
                o.SignInScheme = KlassdAuthSchemes.External;
                o.ClientId = clientId;
                o.ClientSecret = clientSecret;
                o.CallbackPath = $"/signin-{scheme}";
                o.AuthorizationEndpoint = "https://github.com/login/oauth/authorize";
                o.TokenEndpoint = "https://github.com/login/oauth/access_token";
                o.UserInformationEndpoint = "https://api.github.com/user";
                o.UsePkce = true;
                o.Scope.Add("read:user");
                o.Scope.Add("user:email");

                o.Events.OnCreatingTicket = async ctx =>
                {
                    var user = await GetJsonAsync(ctx, ctx.Options.UserInformationEndpoint);

                    void Add(string type, string prop)
                    {
                        if (!user.TryGetProperty(prop, out var v)) return;
                        var s = v.ValueKind == JsonValueKind.Number ? v.GetRawText() : v.GetString();
                        if (!string.IsNullOrEmpty(s)) ctx.Identity?.AddClaim(new Claim(type, s));
                    }

                    Add(ClaimTypes.NameIdentifier, "id");
                    Add("oid", "id");                 // also as oid → the default external mapping prefers it
                    Add(ClaimTypes.Name, "login");
                    Add("preferred_username", "login");
                    Add(ClaimTypes.Email, "email");

                    // Public email may be null; fetch the primary verified address.
                    if (!user.TryGetProperty("email", out var em) || em.ValueKind != JsonValueKind.String)
                    {
                        var emails = await GetJsonAsync(ctx, "https://api.github.com/user/emails");
                        if (emails.ValueKind == JsonValueKind.Array)
                        {
                            foreach (var e in emails.EnumerateArray())
                                if (e.TryGetProperty("primary", out var p) && p.GetBoolean()
                                    && e.TryGetProperty("email", out var pe) && pe.GetString() is { } addr)
                                {
                                    ctx.Identity?.AddClaim(new Claim(ClaimTypes.Email, addr));
                                    break;
                                }
                        }
                    }
                };
                configure?.Invoke(o);
            }));

    private static async Task<JsonElement> GetJsonAsync(OAuthCreatingTicketContext ctx, string url)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, url);
        req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", ctx.AccessToken);
        req.Headers.UserAgent.ParseAdd("Klassd.Auth");  // GitHub requires a User-Agent
        using var resp = await ctx.Backchannel.SendAsync(req, ctx.HttpContext.RequestAborted);
        resp.EnsureSuccessStatusCode();
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ctx.HttpContext.RequestAborted));
        return doc.RootElement.Clone();
    }
}
