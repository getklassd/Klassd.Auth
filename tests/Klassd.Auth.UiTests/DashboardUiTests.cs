using System.Text;
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

        await Expect(Page.Locator(".kad-nav")).ToContainTextAsync("Users");
        await Expect(Page.Locator(".kad-users")).ToContainTextAsync("admin");
    }

    [Test]
    public async Task Admin_can_dry_run_an_import_from_an_uploaded_export()
    {
        await Page.GotoAsync(GlobalHooks.BaseUrl + "/test.html");
        await Page.EvaluateAsync<string>("a => loginWithPassword(a.id, a.pw)", new { id = "admin", pw = "change-me-now" });

        // Navigate and wait for the Blazor Server circuit (SignalR WebSocket) to connect, so the
        // InputFile change handler is wired before we upload (a pre-circuit upload is lost on the
        // prerender → interactive re-render).
        await Page.RunAndWaitForWebSocketAsync(async () =>
            await Page.GotoAsync(GlobalHooks.BaseUrl + "/auth/dashboard/import"));
        await Expect(Page.Locator("h1")).ToContainTextAsync("Import users");

        // A minimal SuperTokens export (one email/password user).
        const string export =
            """{"users":[{"loginMethods":[{"recipeId":"emailpassword","email":"ui-import@example.com","passwordHash":"$2a$10$abcdefghijklmnopqrstuvwxyzABCDE","hashingAlgorithm":"bcrypt"}]}]}""";

        await Page.Locator("select").SelectOptionAsync("supertokens");

        // Re-attach the file until the interactive circuit has processed the change (button enables).
        var fileInput = Page.Locator("input[type=file]");
        var dryRun = Page.GetByRole(AriaRole.Button, new() { Name = "Dry run" });
        for (var attempt = 0; attempt < 30; attempt++)
        {
            await fileInput.SetInputFilesAsync(new FilePayload
            {
                Name = "st-export.json",
                MimeType = "application/json",
                Buffer = Encoding.UTF8.GetBytes(export),
            });
            await Page.WaitForTimeoutAsync(400);
            if (await dryRun.IsEnabledAsync()) break;
        }

        // Dry run starts a background job; the UI updates live and lands on a completed report.
        await dryRun.ClickAsync();
        await Expect(Page.Locator("h2")).ToContainTextAsync("completed");
        await Expect(Page.Locator(".kad-report")).ToContainTextAsync("Created");
    }

    [Test]
    public async Task Choosing_a_database_source_reveals_connection_fields()
    {
        await Page.GotoAsync(GlobalHooks.BaseUrl + "/test.html");
        await Page.EvaluateAsync<string>("a => loginWithPassword(a.id, a.pw)", new { id = "admin", pw = "change-me-now" });

        await Page.RunAndWaitForWebSocketAsync(async () =>
            await Page.GotoAsync(GlobalHooks.BaseUrl + "/auth/dashboard/import"));
        await Expect(Page.Locator("h1")).ToContainTextAsync("Import users");

        // Picking the live SuperTokens (PostgreSQL) source (registered by the sample host) swaps the
        // file upload for host/database/username/password fields. Retry the select until the circuit applies it.
        var hostField = Page.GetByText("Host", new() { Exact = true });
        for (var attempt = 0; attempt < 30; attempt++)
        {
            await Page.Locator("select").SelectOptionAsync("supertokens-pg");
            await Page.WaitForTimeoutAsync(400);
            if (await hostField.IsVisibleAsync()) break;
        }

        await Expect(hostField).ToBeVisibleAsync();
        await Expect(Page.GetByText("Database", new() { Exact = true })).ToBeVisibleAsync();
        await Expect(Page.GetByText("Username", new() { Exact = true })).ToBeVisibleAsync();
        await Expect(Page.GetByText("Password", new() { Exact = true })).ToBeVisibleAsync();
        await Expect(Page.Locator("input[type=file]")).ToBeHiddenAsync();   // file mode replaced
    }
}
