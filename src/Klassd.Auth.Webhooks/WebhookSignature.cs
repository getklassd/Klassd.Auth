using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;

namespace Klassd.Auth.Webhooks;

/// <summary>
/// HMAC-SHA256 verification for inbound webhooks, mirroring the Klassd CMS outbound signing scheme
/// (<c>X-Klassd-Signature: sha256=&lt;hex&gt;</c>) and adding an <c>X-Klassd-Timestamp</c> +
/// tolerance window to defeat replays. The signed content is <c>"{timestamp}.{body}"</c> so the two
/// are bound together (a replay with a fresh timestamp would invalidate the signature).
/// </summary>
public static class WebhookSignature
{
    public const string SignatureHeader = "X-Klassd-Signature";
    public const string TimestampHeader = "X-Klassd-Timestamp";

    /// <summary>The hex (lowercase) HMAC-SHA256 of <c>"{timestamp}.{body}"</c> under <paramref name="secret"/>.</summary>
    public static string Compute(long timestamp, string body, string secret)
    {
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
        return Convert.ToHexStringLower(hmac.ComputeHash(Encoding.UTF8.GetBytes($"{timestamp}.{body}")));
    }

    /// <summary>Verifies the signature + timestamp of a request against any configured secret.</summary>
    public static bool Verify(IHeaderDictionary headers, string body, WebhookOptions options, long nowUnix, out string error)
    {
        error = "";
        if (options.SigningSecrets.Count == 0) { error = "no signing secret configured"; return false; }
        if (headers[SignatureHeader].ToString() is not { Length: > 0 } sig) { error = "missing signature"; return false; }
        if (!long.TryParse(headers[TimestampHeader].ToString(), out var ts)) { error = "missing/invalid timestamp"; return false; }
        if (Math.Abs(nowUnix - ts) > options.ToleranceSeconds) { error = "timestamp outside tolerance"; return false; }

        if (sig.StartsWith("sha256=", StringComparison.OrdinalIgnoreCase)) sig = sig["sha256=".Length..];
        foreach (var secret in options.SigningSecrets)
        {
            var expected = Compute(ts, body, secret);
            if (CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(expected), Encoding.UTF8.GetBytes(sig)))
                return true;
        }
        error = "signature mismatch";
        return false;
    }
}
