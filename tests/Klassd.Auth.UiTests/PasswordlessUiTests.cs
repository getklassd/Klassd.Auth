using System.Text.Json;
using System.Text.RegularExpressions;
using TUnit.Assertions;
using TUnit.Assertions.Extensions;
using TUnit.Core;
using TUnit.Playwright;

namespace Klassd.Auth.UiTests;

/// <summary>
/// Browser E2E for passwordless sign-in: the page asks the API to send a one-time code, we read the
/// code from the sample's console output (the dev "email" sender prints it), then verify it and
/// assert the API returns session tokens.
/// </summary>
[NotInParallel("sample-console")]   // reads one-time codes from the shared sample stdout
public class PasswordlessUiTests : PageTest
{
    [Test]
    public async Task Email_code_start_then_verify_returns_tokens()
    {
        var email = $"pwl-{Guid.NewGuid():N}@example.com";
        await Page.GotoAsync(GlobalHooks.BaseUrl + "/test.html");

        var startStatus = await Page.EvaluateAsync<int>("e => passwordlessStart(e)", email);
        await Assert.That(startStatus).IsEqualTo(202);

        var codeMatch = await GlobalHooks.WaitForConsoleLineAsync(new Regex(@"code is (\d{6})"));
        var code = codeMatch.Groups[1].Value;

        var verifyJson = await Page.EvaluateAsync<string>(
            "a => passwordlessVerify(a.email, a.code)", new { email, code });

        using var doc = JsonDocument.Parse(verifyJson);
        await Assert.That(doc.RootElement.GetProperty("status").GetInt32()).IsEqualTo(200);

        using var body = JsonDocument.Parse(doc.RootElement.GetProperty("body").GetString()!);
        await Assert.That(body.RootElement.TryGetProperty("accessToken", out _)).IsTrue();
    }

    [Test]
    public async Task Wrong_code_is_rejected()
    {
        var email = $"pwl-{Guid.NewGuid():N}@example.com";
        await Page.GotoAsync(GlobalHooks.BaseUrl + "/test.html");
        await Page.EvaluateAsync<int>("e => passwordlessStart(e)", email);

        var verifyJson = await Page.EvaluateAsync<string>(
            "a => passwordlessVerify(a.email, a.code)", new { email, code = "000000" });

        using var doc = JsonDocument.Parse(verifyJson);
        await Assert.That(doc.RootElement.GetProperty("status").GetInt32()).IsEqualTo(401);
    }
}
