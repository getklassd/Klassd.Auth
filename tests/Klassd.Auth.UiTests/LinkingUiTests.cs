using System.Text.Json;
using TUnit.Assertions;
using TUnit.Assertions.Extensions;
using TUnit.Core;
using TUnit.Playwright;

namespace Klassd.Auth.UiTests;

/// <summary>
/// Browser E2E for the account-linking cookie endpoints (/auth/me/methods, /auth/link/password,
/// /auth/unlink). Drives them as the seeded admin to prove the wiring + the security guards:
/// listing one's own methods, the "password already set" rejection, and the last-method unlink guard.
/// (The successful 204 unlink path is covered by UnlinkAsync unit tests; via cookie endpoints alone the
/// admin only ever has its single password method, since passkeys aren't LoginMethod rows.)
/// </summary>
public class LinkingUiTests : PageTest
{
    private static JsonElement Body(string envelope)
    {
        using var doc = JsonDocument.Parse(envelope);
        return JsonDocument.Parse(doc.RootElement.GetProperty("body").GetString()!).RootElement.Clone();
    }

    [Test]
    public async Task Me_methods_add_password_conflict_and_last_method_guard()
    {
        await Page.GotoAsync(GlobalHooks.BaseUrl + "/test.html");
        await Page.EvaluateAsync<string>("a => loginWithPassword(a.id, a.pw)", new { id = "admin", pw = "change-me-now" });

        // The caller can list its own methods: the seeded admin has exactly one (email/password).
        var methods = Body(await Page.EvaluateAsync<string>("() => meMethods()"));
        await Assert.That(methods.GetArrayLength()).IsEqualTo(1);
        await Assert.That(methods[0].GetProperty("kind").GetString()).IsEqualTo("EmailPassword");

        // Already has a password → /auth/link/password is refused.
        await Assert.That(await Page.EvaluateAsync<int>("p => addPassword(p)", "another-pass")).IsEqualTo(400);

        // Removing the sole remaining method is blocked by the last-method guard.
        var onlyId = methods[0].GetProperty("id").GetString()!;
        await Assert.That(await Page.EvaluateAsync<int>("id => unlinkMethod(id)", onlyId)).IsEqualTo(400);
    }
}
