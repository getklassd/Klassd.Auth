using System.Text.RegularExpressions;
using Microsoft.Playwright;
using TUnit.Assertions;
using TUnit.Assertions.Extensions;
using TUnit.Core;
using TUnit.Playwright;

namespace Klassd.Auth.UiTests;

/// <summary>
/// Browser E2E for the Blazor admin dashboard (mounted as a branch under /auth/dashboard): it
/// requires login, and once an admin is signed in the (Interactive Server) user list renders.
/// </summary>
public class DashboardUiTests : PageTest
{
    [Test]
    public async Task Unauthenticated_visit_redirects_to_login()
    {
        // Fresh context (no cookie): the endpoint's RequireAuthorization 302s to the cookie login path.
        var response = await Page.GotoAsync(GlobalHooks.BaseUrl + "/auth/dashboard");
        await Assert.That(Page.Url).Contains("/login");
    }

    [Test]
    public async Task Admin_can_open_the_dashboard_and_see_the_user_list()
    {
        // Sign in as the seeded admin (sets the app cookie) via the test page helper.
        await Page.GotoAsync(GlobalHooks.BaseUrl + "/test.html");
        await Page.EvaluateAsync<string>("a => loginWithPassword(a.id, a.pw)", new { id = "admin", pw = "change-me-now" });

        await Page.GotoAsync(GlobalHooks.BaseUrl + "/auth/dashboard/");

        await Expect(Page.Locator("text=User administration")).ToBeVisibleAsync();
        await Expect(Page.Locator(".kad-users")).ToContainTextAsync("admin");
    }
}
