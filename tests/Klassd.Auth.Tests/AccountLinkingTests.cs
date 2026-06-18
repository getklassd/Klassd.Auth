using Klassd.Auth.Abstractions;
using Klassd.Auth.Core.Modules.Users;
using Klassd.Auth.Core.Security;
using TUnit.Assertions;
using TUnit.Assertions.Extensions;
using TUnit.Core;

namespace Klassd.Auth.Tests;

/// <summary>
/// Account-linking permutations: a user is one identity with N attachable login methods. These cover
/// linking social providers, adding a password to a social-/passwordless-only account, the unlink
/// last-method guard, identity-collision handling, and the opt-in auto-link-by-verified-email policy.
/// </summary>
public sealed class AccountLinkingTests
{
    private static (UserAccountService accounts, FakeUserStore users) New()
    {
        var users = new FakeUserStore();
        return (new UserAccountService(users, new Pbkdf2PasswordHasher()), users);
    }

    private static ExternalUserInfo Ext(string id, string? email = null, bool verified = false) =>
        new(id, Username: null, Email: email, EmailVerified: verified);

    [Test]
    public async Task Link_attaches_a_provider_and_is_idempotent()
    {
        var (accounts, _) = New();
        var user = await accounts.CreateLocalAsync(null, "a@b.com", "supersecret");

        var first = await accounts.LinkExternalAsync(user.Id, "facebook", Ext("fb-1"));
        await Assert.That(first.Outcome).IsEqualTo(LinkOutcome.Linked);
        await Assert.That(first.User!.LoginMethods.Any(m => m.ProviderId == "facebook")).IsTrue();

        var again = await accounts.LinkExternalAsync(user.Id, "facebook", Ext("fb-1"));
        await Assert.That(again.Outcome).IsEqualTo(LinkOutcome.AlreadyLinkedToThisUser);
    }

    [Test]
    public async Task Linking_an_identity_owned_by_another_user_is_a_conflict()
    {
        var (accounts, _) = New();
        var alice = await accounts.CreateLocalAsync("alice", null, "supersecret");
        var bob = await accounts.CreateLocalAsync("bob", null, "supersecret");
        await accounts.LinkExternalAsync(alice.Id, "facebook", Ext("fb-shared"));

        var result = await accounts.LinkExternalAsync(bob.Id, "facebook", Ext("fb-shared"));
        await Assert.That(result.Outcome).IsEqualTo(LinkOutcome.ConflictOwnedByAnotherUser);
    }

    [Test]
    public async Task Multiple_distinct_providers_coexist()
    {
        var (accounts, _) = New();
        var user = await accounts.CreateLocalAsync("alice", null, "supersecret");
        await accounts.LinkExternalAsync(user.Id, "facebook", Ext("fb-1"));
        await accounts.LinkExternalAsync(user.Id, "tiktok", Ext("tt-1"));

        var methods = (await accounts.GetByIdAsync(user.Id))!.LoginMethods;
        await Assert.That(methods.Count(m => m.Kind == LoginMethodKind.ThirdParty)).IsEqualTo(2);
    }

    [Test]
    public async Task Social_only_user_can_add_a_password_then_sign_in()
    {
        var (accounts, _) = New();
        // Provision a fresh social-only account (no password).
        var user = (await accounts.ProvisionExternalAsync("facebook", Ext("fb-9", "c@d.com"), autoProvision: true))!;
        await Assert.That(accounts.VerifyPassword(user, "supersecret")).IsFalse();

        await Assert.That(await accounts.AddPasswordAsync(user.Id, "supersecret")).IsTrue();
        var reloaded = (await accounts.GetByIdAsync(user.Id))!;
        await Assert.That(accounts.VerifyPassword(reloaded, "supersecret")).IsTrue();

        // Adding again is refused — ResetPasswordAsync is the change verb.
        await Assert.That(await accounts.AddPasswordAsync(user.Id, "another")).IsFalse();
    }

    [Test]
    public async Task Unlink_removes_a_method_but_guards_the_last_one()
    {
        var (accounts, _) = New();
        var user = await accounts.CreateLocalAsync("alice", null, "supersecret");   // 1 method
        await accounts.LinkExternalAsync(user.Id, "facebook", Ext("fb-1"));          // 2 methods
        var fb = (await accounts.GetByIdAsync(user.Id))!.LoginMethods.First(m => m.ProviderId == "facebook");

        await Assert.That(await accounts.UnlinkAsync(user.Id, fb.Id)).IsTrue();       // back to 1
        var remaining = (await accounts.GetByIdAsync(user.Id))!.LoginMethods;
        await Assert.That(remaining.Count).IsEqualTo(1);

        await Assert.That(await accounts.UnlinkAsync(user.Id, remaining[0].Id)).IsFalse();  // last-method guard
    }

    [Test]
    public async Task Auto_link_only_fires_for_verified_email_and_opt_in()
    {
        var (accounts, _) = New();
        var local = await accounts.CreateLocalAsync(null, "shared@x.com", "supersecret");

        // Unverified email, opt-in on → must NOT merge (creates/links nothing onto the local user).
        await accounts.ProvisionExternalAsync(
            "facebook", Ext("fb-unv", "shared@x.com", verified: false), autoProvision: true, autoLinkByVerifiedEmail: true);
        await Assert.That((await accounts.GetByIdAsync(local.Id))!.LoginMethods.Any(m => m.ProviderId == "facebook")).IsFalse();

        // Verified email but policy off → still must NOT merge.
        await accounts.ProvisionExternalAsync(
            "google", Ext("g-1", "shared@x.com", verified: true), autoProvision: true, autoLinkByVerifiedEmail: false);
        await Assert.That((await accounts.GetByIdAsync(local.Id))!.LoginMethods.Any(m => m.ProviderId == "google")).IsFalse();

        // Verified email + policy on → merges into the existing account.
        var merged = await accounts.ProvisionExternalAsync(
            "github", Ext("gh-1", "shared@x.com", verified: true), autoProvision: true, autoLinkByVerifiedEmail: true);
        await Assert.That(merged!.Id).IsEqualTo(local.Id);
        await Assert.That(merged.LoginMethods.Any(m => m.ProviderId == "github")).IsTrue();
    }

    [Test]
    public async Task No_email_provider_links_explicitly_and_provisions_a_null_email_account()
    {
        var (accounts, _) = New();
        // Instagram/TikTok shape: no email at all.
        var user = (await accounts.ProvisionExternalAsync("tiktok", Ext("tt-42"), autoProvision: true))!;
        await Assert.That(user.PrimaryEmail).IsNull();

        var link = await accounts.LinkExternalAsync(user.Id, "instagram", Ext("ig-42"));
        await Assert.That(link.Outcome).IsEqualTo(LinkOutcome.Linked);
    }

    [Test]
    public async Task AddPasswordlessIdentity_sets_primary_and_enables_resolution()
    {
        var (accounts, _) = New();
        // A username-only account (e.g. an admin) with no email/phone yet.
        var user = await accounts.CreateLocalAsync("alice", null, "supersecret");
        await Assert.That(user.PrimaryEmail).IsNull();

        var ok = await accounts.AddPasswordlessIdentityAsync(user.Id, "Alice@X.com", PasswordlessChannel.Email);
        await Assert.That(ok).IsTrue();

        var reloaded = (await accounts.GetByIdAsync(user.Id))!;
        await Assert.That(reloaded.PrimaryEmail).IsEqualTo("alice@x.com");                 // normalized + set as primary
        await Assert.That(reloaded.LoginMethods.Any(m => m.Kind == LoginMethodKind.Passwordless)).IsTrue();
        // Passwordless resolves by the new primary email.
        await Assert.That((await accounts.FindByEmailAsync("alice@x.com"))!.Id).IsEqualTo(user.Id);
    }
}
