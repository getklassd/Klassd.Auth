using Klassd.Auth.Core.Modules.EmailPassword;
using Klassd.Auth.Core.Modules.EmailVerification;
using Klassd.Auth.Core.Modules.UserMetadata;
using Klassd.Auth.Core.Modules.Users;
using Klassd.Auth.Core.Security;
using Klassd.Auth.Core.Sessions;
using Microsoft.IdentityModel.Tokens;
using TUnit.Assertions;
using TUnit.Assertions.Extensions;
using TUnit.Core;

namespace Klassd.Auth.Tests;

public sealed class PasswordHasherTests
{
    [Test]
    public async Task Hash_then_verify_roundtrips()
    {
        var hasher = new Pbkdf2PasswordHasher();
        var hash = hasher.Hash("supersecret");
        await Assert.That(hasher.Verify("supersecret", hash)).IsTrue();
        await Assert.That(hasher.Verify("wrong", hash)).IsFalse();
    }
}

public sealed class SessionServiceTests
{
    private static SessionService NewService(out FakeSessionStore store)
    {
        store = new FakeSessionStore();
        var config = new SessionConfig { SigningKey = "0123456789abcdef0123456789abcdef" };
        return new SessionService(store, config, new SymmetricTokenSigningKey(config));
    }

    [Test]
    public async Task Create_issues_validatable_access_token()
    {
        var svc = NewService(out _);
        var tokens = await svc.CreateAsync("user1");
        var principal = svc.ValidateAccessToken(tokens.AccessToken);
        await Assert.That(principal.Identity!.IsAuthenticated).IsTrue();
    }

    [Test]
    public async Task Refresh_rotates_the_refresh_token()
    {
        var svc = NewService(out _);
        var first = await svc.CreateAsync("user1");
        var rotated = await svc.RefreshAsync(first.RefreshToken);
        await Assert.That(rotated.RefreshToken).IsNotEqualTo(first.RefreshToken);
    }

    [Test]
    public async Task Reusing_a_rotated_refresh_token_revokes_the_session()
    {
        var svc = NewService(out _);
        var first = await svc.CreateAsync("user1");
        await svc.RefreshAsync(first.RefreshToken);   // rotate once

        var threw = false;
        try { await svc.RefreshAsync(first.RefreshToken); }   // reuse the old token
        catch (SecurityTokenException) { threw = true; }
        await Assert.That(threw).IsTrue();
    }
}

public sealed class UserMetadataTests
{
    private sealed record Prefs(string Theme, string Locale);

    [Test]
    public async Task Typed_section_roundtrips_and_removes()
    {
        var meta = new UserMetadataService(new FakeMetadataStore());
        await meta.SetAsync("u1", "prefs", new Prefs("dark", "da"));

        var read = await meta.GetAsync<Prefs>("u1", "prefs");
        await Assert.That(read!.Theme).IsEqualTo("dark");

        await meta.RemoveAsync("u1", "prefs");
        await Assert.That(await meta.GetAsync<Prefs>("u1", "prefs")).IsNull();
    }

    [Test]
    public async Task Separate_keys_do_not_collide()
    {
        var meta = new UserMetadataService(new FakeMetadataStore());
        await meta.SetAsync("u1", "cms", new Prefs("dark", "da"));
        await meta.SetAsync("u1", "wf", new Prefs("light", "en"));
        await Assert.That((await meta.GetAsync<Prefs>("u1", "cms"))!.Locale).IsEqualTo("da");
        await Assert.That((await meta.GetAsync<Prefs>("u1", "wf"))!.Locale).IsEqualTo("en");
    }
}

public sealed class RolesServiceTests
{
    [Test]
    public async Task Roles_are_case_insensitive()
    {
        var roles = new RolesService(new UserMetadataService(new FakeMetadataStore()));
        await roles.SetRolesAsync("u1", ["Administrator", "Editor"]);
        await Assert.That(await roles.IsInRoleAsync("u1", "administrator")).IsTrue();
        await Assert.That(await roles.IsInRoleAsync("u1", "Author")).IsFalse();
    }
}

public sealed class UserAccountServiceTests
{
    private static UserAccountService NewService() =>
        new(new FakeUserStore(), new Pbkdf2PasswordHasher());

    [Test]
    public async Task Create_local_then_verify_and_lookup()
    {
        var accounts = NewService();
        var user = await accounts.CreateLocalAsync("alice", null, "supersecret");

        await Assert.That(accounts.VerifyPassword(user, "supersecret")).IsTrue();
        await Assert.That(accounts.VerifyPassword(user, "nope")).IsFalse();
        await Assert.That((await accounts.FindByUsernameAsync("alice"))!.Id).IsEqualTo(user.Id);
    }

    [Test]
    public async Task Disable_persists()
    {
        var accounts = NewService();
        var user = await accounts.CreateLocalAsync(null, "a@b.com", "supersecret");
        await accounts.SetDisabledAsync(user.Id, true);
        await Assert.That((await accounts.GetByIdAsync(user.Id))!.Disabled).IsTrue();
    }

    [Test]
    public async Task Provision_external_is_idempotent_per_provider_identity()
    {
        var accounts = NewService();
        var info = new ExternalUserInfo("gh123", "bob", "bob@x.com");
        var first = await accounts.ProvisionExternalAsync("github", info, autoProvision: true);
        var second = await accounts.ProvisionExternalAsync("github", info, autoProvision: true);
        await Assert.That(first).IsNotNull();
        await Assert.That(second!.Id).IsEqualTo(first!.Id);
    }

    [Test]
    public async Task Provision_external_without_auto_provision_returns_null()
    {
        var accounts = NewService();
        var result = await accounts.ProvisionExternalAsync(
            "github", new ExternalUserInfo("new999"), autoProvision: false);
        await Assert.That(result).IsNull();
    }
}

public sealed class SigningKeyManagerTests
{
    [Test]
    public async Task Initialize_creates_a_key_and_publishes_jwks()
    {
        var mgr = new SigningKeyManager(new InMemorySigningKeyStore(), new SigningKeyOptions());
        await mgr.InitializeAsync();
        await Assert.That(mgr.PublicJwks.Count).IsEqualTo(1);
        await Assert.That(mgr.SigningCredentials).IsNotNull();
    }

    [Test]
    public async Task Maintain_rotates_in_a_new_key_keeping_the_old_for_validation()
    {
        var opts = new SigningKeyOptions { SigningKeyLifetime = TimeSpan.Zero, ValidationGrace = TimeSpan.FromDays(7) };
        var mgr = new SigningKeyManager(new InMemorySigningKeyStore(), opts);
        await mgr.InitializeAsync();          // key #1
        await mgr.MaintainAsync();            // rotates → key #2, #1 still valid
        await Assert.That(mgr.ValidationKeys.Count).IsEqualTo(2);
    }

    [Test]
    public async Task Keys_persist_across_manager_instances()
    {
        var store = new InMemorySigningKeyStore();
        var first = new SigningKeyManager(store, new SigningKeyOptions());
        await first.InitializeAsync();
        var kid = first.PublicJwks[0].Kid;

        var second = new SigningKeyManager(store, new SigningKeyOptions());
        await second.InitializeAsync();       // should reuse the persisted key, not mint a new one
        await Assert.That(second.PublicJwks.Count).IsEqualTo(1);
        await Assert.That(second.PublicJwks[0].Kid).IsEqualTo(kid);
    }
}

public sealed class EmailVerificationTests
{
    private sealed class CapturingSender : IEmailSender
    {
        public string? LastBody;
        public Task SendAsync(string to, string subject, string body, CancellationToken ct = default)
        {
            LastBody = body;
            return Task.CompletedTask;
        }
    }

    private static string ExtractToken(string body) => body[(body.IndexOf("token=", StringComparison.Ordinal) + 6)..].Trim();

    [Test]
    public async Task Verify_marks_the_login_method_and_is_single_use()
    {
        var users = new FakeUserStore();
        var accounts = new UserAccountService(users, new Pbkdf2PasswordHasher());
        var user = await accounts.CreateLocalAsync(null, "a@b.com", "supersecret");

        var sender = new CapturingSender();
        var ev = new EmailVerificationService(users, sender, new InMemoryEmailVerificationTokenStore());
        await ev.SendVerificationAsync(user.Id, "a@b.com", "https://app/verify");
        var token = ExtractToken(sender.LastBody!);

        await Assert.That(await ev.VerifyAsync(token)).IsTrue();
        var verified = (await users.FindByIdAsync(user.Id))!.LoginMethods[0].EmailVerified;
        await Assert.That(verified).IsTrue();

        await Assert.That(await ev.VerifyAsync(token)).IsFalse();   // token already consumed
    }

    [Test]
    public async Task Unknown_token_fails()
    {
        var ev = new EmailVerificationService(new FakeUserStore(), new CapturingSender(), new InMemoryEmailVerificationTokenStore());
        await Assert.That(await ev.VerifyAsync("deadbeef")).IsFalse();
    }
}

public sealed class EmailPasswordServiceTests
{
    private static EmailPasswordService NewService() =>
        new(new FakeUserStore(), new Pbkdf2PasswordHasher());

    [Test]
    public async Task Signup_signin_and_duplicate_and_wrong_password()
    {
        var ep = NewService();

        var signup = await ep.SignUpAsync("a@b.com", "supersecret");
        await Assert.That(signup.Success).IsTrue();

        var dup = await ep.SignUpAsync("a@b.com", "supersecret");
        await Assert.That(dup.Error).IsEqualTo("EMAIL_ALREADY_EXISTS");

        await Assert.That((await ep.SignInAsync("a@b.com", "supersecret")).Success).IsTrue();
        await Assert.That((await ep.SignInAsync("a@b.com", "wrong")).Error).IsEqualTo("WRONG_CREDENTIALS");
    }

    [Test]
    public async Task Weak_password_is_rejected()
    {
        var ep = NewService();
        await Assert.That((await ep.SignUpAsync("a@b.com", "short")).Error).IsEqualTo("PASSWORD_TOO_WEAK");
    }
}
