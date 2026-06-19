using Klassd.Auth.Abstractions;
using Klassd.Auth.Core.Modules.EmailVerification;
using Klassd.Auth.Core.Modules.Users;
using Klassd.Auth.Core.Security;
using Klassd.Auth.Core.Sessions;
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
    public async Task SetPrimaryEmail_collects_a_verified_email_for_a_no_email_account()
    {
        var (accounts, _) = New();
        // A TikTok/Instagram-shaped account: no email at all.
        var user = (await accounts.ProvisionExternalAsync("tiktok", Ext("tt-7"), autoProvision: true))!;
        await Assert.That(user.PrimaryEmail).IsNull();

        var outcome = await accounts.SetPrimaryEmailAsync(user.Id, "New@User.com", verified: true);
        await Assert.That(outcome).IsEqualTo(EmailUpdateOutcome.Updated);

        var reloaded = (await accounts.GetByIdAsync(user.Id))!;
        await Assert.That(reloaded.PrimaryEmail).IsEqualTo("new@user.com");                  // normalized
        var emailMethod = reloaded.LoginMethods.FirstOrDefault(m => m.Email == "new@user.com");
        await Assert.That(emailMethod).IsNotNull();
        await Assert.That(emailMethod!.EmailVerified).IsTrue();                               // recorded as verified
        // The collected email now resolves the user (e.g. for passwordless).
        await Assert.That((await accounts.FindByEmailAsync("new@user.com"))!.Id).IsEqualTo(user.Id);
    }

    [Test]
    public async Task SetPrimaryEmail_rejects_an_email_owned_by_another_user()
    {
        var (accounts, _) = New();
        await accounts.CreateLocalAsync(null, "taken@x.com", "supersecret");
        var other = (await accounts.ProvisionExternalAsync("tiktok", Ext("tt-8"), autoProvision: true))!;

        await Assert.That(await accounts.IsEmailAvailableAsync(other.Id, "taken@x.com")).IsFalse();
        await Assert.That(await accounts.SetPrimaryEmailAsync(other.Id, "taken@x.com", verified: true))
            .IsEqualTo(EmailUpdateOutcome.EmailInUse);
    }

    [Test]
    public async Task Email_collection_flow_request_then_confirm_sets_primary()
    {
        // End-to-end at the service layer: provision a no-email account, send a verification link,
        // consume the token, and set the verified primary email — the path the cookie endpoints drive.
        var users = new FakeUserStore();
        var accounts = new UserAccountService(users, new Pbkdf2PasswordHasher());
        var sender = new CapturingEmailSender();
        var verification = new EmailVerificationService(users, sender, new InMemoryEmailVerificationTokenStore());

        var user = (await accounts.ProvisionExternalAsync("instagram", Ext("ig-1"), autoProvision: true))!;

        await verification.SendVerificationAsync(user.Id, "me@example.com", "https://app/confirm");
        var token = sender.LastBody![(sender.LastBody!.IndexOf("token=", StringComparison.Ordinal) + 6)..].Trim();

        var record = await verification.ConsumeTokenAsync(token);
        await Assert.That(record).IsNotNull();
        var outcome = await accounts.SetPrimaryEmailAsync(record!.UserId, record.Email, verified: true);
        await Assert.That(outcome).IsEqualTo(EmailUpdateOutcome.Updated);
        await Assert.That((await accounts.GetByIdAsync(user.Id))!.PrimaryEmail).IsEqualTo("me@example.com");

        // Token is single-use.
        await Assert.That(await verification.ConsumeTokenAsync(token)).IsNull();
    }

    private sealed class CapturingEmailSender : Klassd.Auth.Core.Modules.EmailVerification.IEmailSender
    {
        public string? LastBody;
        public Task SendAsync(string to, string subject, string body, CancellationToken ct = default)
        { LastBody = body; return Task.CompletedTask; }
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
