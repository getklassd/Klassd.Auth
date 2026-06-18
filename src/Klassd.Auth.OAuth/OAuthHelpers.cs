using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication.OAuth;

namespace Klassd.Auth.OAuth;

internal static class OAuthHelpers
{
    /// <summary>GETs a JSON document from a provider endpoint using the issued access token.</summary>
    public static async Task<JsonElement> GetJsonAsync(OAuthCreatingTicketContext ctx, string url)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, url);
        req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", ctx.AccessToken);
        req.Headers.UserAgent.ParseAdd("Klassd.Auth");
        using var resp = await ctx.Backchannel.SendAsync(req, ctx.HttpContext.RequestAborted);
        resp.EnsureSuccessStatusCode();
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ctx.HttpContext.RequestAborted));
        return doc.RootElement.Clone();
    }

    /// <summary>Adds a claim from a JSON string/number property if present and non-empty.</summary>
    public static void AddClaim(this ClaimsIdentity? identity, JsonElement obj, string claimType, string property)
    {
        if (identity is null || !obj.TryGetProperty(property, out var v)) return;
        var s = v.ValueKind == JsonValueKind.Number ? v.GetRawText() : v.GetString();
        if (!string.IsNullOrEmpty(s)) identity.AddClaim(new Claim(claimType, s));
    }
}
