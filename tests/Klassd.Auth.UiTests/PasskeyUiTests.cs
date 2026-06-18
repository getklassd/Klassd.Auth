using System.Text.Json;
using TUnit.Assertions;
using TUnit.Assertions.Extensions;
using TUnit.Core;
using TUnit.Playwright;

namespace Klassd.Auth.UiTests;

/// <summary>
/// Browser E2E for passkeys (WebAuthn). Uses Chrome DevTools Protocol to attach a virtual
/// authenticator, then drives a real <c>navigator.credentials.create</c>/<c>.get</c> ceremony
/// through the Klassd.Auth endpoints: register a passkey for the seeded admin, then authenticate
/// with it. This exercises the full attestation + assertion verification against stored keys.
/// </summary>
public class PasskeyUiTests : PageTest
{
    [Test]
    public async Task Register_then_login_with_a_passkey()
    {
        // Attach a virtual authenticator that supports discoverable credentials + user verification.
        var cdp = await Context.NewCDPSessionAsync(Page);
        await cdp.SendAsync("WebAuthn.enable");
        await cdp.SendAsync("WebAuthn.addVirtualAuthenticator", new Dictionary<string, object>
        {
            ["options"] = new Dictionary<string, object>
            {
                ["protocol"] = "ctap2",
                ["transport"] = "internal",
                ["hasResidentKey"] = true,
                ["hasUserVerification"] = true,
                ["isUserVerified"] = true,
                ["automaticPresenceSimulation"] = true,
            },
        });

        await Page.GotoAsync(GlobalHooks.BaseUrl + "/test.html");

        // Registration requires an authenticated user — sign in as the seeded admin (cookie).
        await Page.EvaluateAsync<string>(
            "a => loginWithPassword(a.id, a.pw)", new { id = "admin", pw = "change-me-now" });

        var registerJson = await Page.EvaluateAsync<string>("() => registerPasskey()");
        using (var reg = JsonDocument.Parse(registerJson))
            await Assert.That(reg.RootElement.GetProperty("status").GetInt32()).IsEqualTo(200).Because(registerJson);

        // Now authenticate with the just-registered passkey (usernameless / discoverable).
        var loginJson = await Page.EvaluateAsync<string>("() => loginPasskey()");
        using var login = JsonDocument.Parse(loginJson);
        await Assert.That(login.RootElement.GetProperty("status").GetInt32()).IsEqualTo(200);

        using var body = JsonDocument.Parse(login.RootElement.GetProperty("body").GetString()!);
        await Assert.That(body.RootElement.TryGetProperty("accessToken", out _)).IsTrue();
    }
}
