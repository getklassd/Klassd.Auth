using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using TUnit.Assertions;
using TUnit.Assertions.Extensions;
using TUnit.Core;

namespace Klassd.Auth.UiTests;

/// <summary>
/// HTTP-level E2E (no browser) for the webhook and password-reset surfaces, against the running Sample.
/// </summary>
[NotInParallel("sample-console")]   // these read one-time codes/tokens from the shared sample stdout
public sealed class WebhookAndResetE2ETests
{
    private const string WebhookSecret = "dev-webhook-secret-change-me";   // Sample's default

    private static HttpClient Client() => new() { BaseAddress = new Uri(GlobalHooks.BaseUrl) };

    private static string Sign(long ts, string body, string secret)
    {
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
        return Convert.ToHexStringLower(hmac.ComputeHash(Encoding.UTF8.GetBytes($"{ts}.{body}")));
    }

    /// <summary>Creates a user by completing the passwordless flow; returns the email.</summary>
    private static async Task<string> CreatePasswordlessUserAsync(HttpClient http)
    {
        var email = $"e2e-{Guid.NewGuid():N}@example.com";
        await http.PostAsJsonAsync("/auth/passwordless/start", new { identifier = email, channel = "Email" });
        var code = (await GlobalHooks.WaitForConsoleLineAsync(new Regex(@"code is (\d{6})"))).Groups[1].Value;
        var verify = await http.PostAsJsonAsync("/auth/passwordless/verify", new { identifier = email, channel = "Email", code });
        await Assert.That((int)verify.StatusCode).IsEqualTo(200);
        return email;
    }

    [Test]
    public async Task Signed_webhook_disables_a_user_and_bad_signature_is_rejected()
    {
        using var http = Client();
        var email = await CreatePasswordlessUserAsync(http);

        var body = JsonSerializer.Serialize(new { action = "disable", email });
        var ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        // Bad signature → 401.
        var bad = new HttpRequestMessage(HttpMethod.Post, "/auth/webhooks/users") { Content = new StringContent(body, Encoding.UTF8, "application/json") };
        bad.Headers.Add("X-Klassd-Signature", "sha256=deadbeef");
        bad.Headers.Add("X-Klassd-Timestamp", ts.ToString());
        await Assert.That((int)(await http.SendAsync(bad)).StatusCode).IsEqualTo(401);

        // Valid signature → 200.
        var ok = new HttpRequestMessage(HttpMethod.Post, "/auth/webhooks/users") { Content = new StringContent(body, Encoding.UTF8, "application/json") };
        ok.Headers.Add("X-Klassd-Signature", "sha256=" + Sign(ts, body, WebhookSecret));
        ok.Headers.Add("X-Klassd-Timestamp", ts.ToString());
        var okResp = await http.SendAsync(ok);
        await Assert.That((int)okResp.StatusCode).IsEqualTo(200);
        await Assert.That(await okResp.Content.ReadAsStringAsync()).Contains("\"applied\":true");
        // (The disable's effect on the account is covered by the unit + integration suites.)
    }

    [Test]
    public async Task Forgot_then_reset_lets_the_user_sign_in_with_the_new_password()
    {
        using var http = Client();
        var email = await CreatePasswordlessUserAsync(http);   // no password yet

        await http.PostAsJsonAsync("/auth/password/forgot", new { identifier = email });
        var token = (await GlobalHooks.WaitForConsoleLineAsync(new Regex(@"reset-password\?token=([0-9A-Fa-f]+)"))).Groups[1].Value;

        var reset = await http.PostAsJsonAsync("/auth/password/reset", new { token, newPassword = "brand-new-password" });
        await Assert.That((int)reset.StatusCode).IsEqualTo(204);

        // The new password now works for email/password sign-in.
        var signin = await http.PostAsJsonAsync("/auth/signin", new { email, password = "brand-new-password" });
        await Assert.That((int)signin.StatusCode).IsEqualTo(200);
    }
}
