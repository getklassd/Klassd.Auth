using System.Text.RegularExpressions;
using Klassd.Auth.Abstractions;
using Klassd.Auth.Core.Modules.EmailVerification;
using Klassd.Auth.Core.Modules.Password;
using Klassd.Auth.Core.Modules.Users;
using Klassd.Auth.Core.Security;
using Klassd.Auth.Core.Sessions;
using Klassd.Auth.Webhooks;
using Microsoft.AspNetCore.Http;
using TUnit.Assertions;
using TUnit.Assertions.Extensions;
using TUnit.Core;

namespace Klassd.Auth.Tests;

public sealed class AccountLifecycleServiceTests
{
    private static (AccountLifecycleService svc, FakeUserStore users, FakeSessionStore sessions,
        FakeMetadataStore metadata, InMemoryPasskeyCredentialStore passkeys) New()
    {
        var users = new FakeUserStore();
        var sessions = new FakeSessionStore();
        var metadata = new FakeMetadataStore();
        var passkeys = new InMemoryPasskeyCredentialStore();
        return (new AccountLifecycleService(users, sessions, metadata, passkeys), users, sessions, metadata, passkeys);
    }

    private static async Task<User> SeedAsync(FakeUserStore users, FakeSessionStore sessions,
        FakeMetadataStore metadata, InMemoryPasskeyCredentialStore passkeys)
    {
        var id = Guid.NewGuid().ToString("N");
        await users.AddUserAsync(new User
        {
            Id = id, PrimaryEmail = $"{id}@x.com", CreatedAt = DateTimeOffset.UtcNow,
            LoginMethods = { new LoginMethod { Id = Guid.NewGuid().ToString("N"), UserId = id, Kind = LoginMethodKind.EmailPassword, CreatedAt = DateTimeOffset.UtcNow } },
        });
        await sessions.AddAsync(new SessionEntity { Handle = "h-" + id, UserId = id, RefreshTokenHash = "x", CreatedAt = DateTimeOffset.UtcNow, RefreshExpiresAt = DateTimeOffset.UtcNow.AddDays(1) });
        await metadata.SetAsync(id, "{\"k\":1}");
        await passkeys.AddAsync(new PasskeyCredential { Id = Guid.NewGuid().ToString("N"), UserId = id, CredentialId = [1, 2], PublicKey = [3], UserHandle = [4], AaGuid = Guid.NewGuid(), CreatedAt = DateTimeOffset.UtcNow });
        return (await users.FindByIdAsync(id))!;
    }

    [Test]
    public async Task Disable_revokes_sessions()
    {
        var (svc, users, sessions, metadata, passkeys) = New();
        var user = await SeedAsync(users, sessions, metadata, passkeys);

        await Assert.That(await svc.DisableAsync(user.Id)).IsTrue();
        await Assert.That((await users.FindByIdAsync(user.Id))!.Disabled).IsTrue();
        await Assert.That((await sessions.FindAsync("h-" + user.Id))!.Revoked).IsTrue();
    }

    [Test]
    public async Task Delete_removes_user_and_cascades_all_per_user_data()
    {
        var (svc, users, sessions, metadata, passkeys) = New();
        var user = await SeedAsync(users, sessions, metadata, passkeys);

        await Assert.That(await svc.DeleteAsync(user.Id)).IsTrue();
        await Assert.That(await users.FindByIdAsync(user.Id)).IsNull();
        await Assert.That(await sessions.FindAsync("h-" + user.Id)).IsNull();
        await Assert.That(await metadata.GetAsync(user.Id)).IsNull();
        await Assert.That((await passkeys.GetByUserIdAsync(user.Id)).Count).IsEqualTo(0);
    }

    [Test]
    public async Task Anonymize_keeps_id_but_strips_pii_and_methods()
    {
        var (svc, users, sessions, metadata, passkeys) = New();
        var user = await SeedAsync(users, sessions, metadata, passkeys);

        await Assert.That(await svc.AnonymizeAsync(user.Id)).IsTrue();
        var after = await users.FindByIdAsync(user.Id);
        await Assert.That(after).IsNotNull();                 // id row preserved
        await Assert.That(after!.PrimaryEmail).IsNull();
        await Assert.That(after.Disabled).IsTrue();
        await Assert.That(after.LoginMethods.Count).IsEqualTo(0);
        await Assert.That((await passkeys.GetByUserIdAsync(user.Id)).Count).IsEqualTo(0);
    }
}

public sealed class PasswordResetServiceTests
{
    private sealed class CapturingEmail : IEmailSender
    {
        public string? LastBody;
        public Task SendAsync(string to, string subject, string body, CancellationToken ct = default) { LastBody = body; return Task.CompletedTask; }
    }

    private static (PasswordResetService reset, UserAccountService accounts, FakeUserStore users,
        FakeSessionStore sessions, CapturingEmail email) New()
    {
        var users = new FakeUserStore();
        var sessions = new FakeSessionStore();
        var email = new CapturingEmail();
        var hasher = new Pbkdf2PasswordHasher();
        var reset = new PasswordResetService(users, hasher, email, new InMemoryPasswordResetTokenStore(), sessions, new PasswordResetOptions());
        return (reset, new UserAccountService(users, hasher), users, sessions, email);
    }

    private static string Token(string body) => Regex.Match(body, @"token=([0-9A-F]+)").Groups[1].Value;

    [Test]
    public async Task Request_then_reset_changes_password_and_revokes_sessions()
    {
        var (reset, accounts, users, sessions, email) = New();
        var user = await accounts.CreateLocalAsync(null, "a@b.com", "originalpw");
        await sessions.AddAsync(new SessionEntity { Handle = "s1", UserId = user.Id, RefreshTokenHash = "x", CreatedAt = DateTimeOffset.UtcNow, RefreshExpiresAt = DateTimeOffset.UtcNow.AddDays(1) });

        await reset.RequestAsync("a@b.com", "https://app/reset");
        var r = await reset.ResetAsync(Token(email.LastBody!), "brand-new-pw");
        await Assert.That(r.Success).IsTrue();

        var reloaded = (await accounts.GetByIdAsync(user.Id))!;
        await Assert.That(accounts.VerifyPassword(reloaded, "brand-new-pw")).IsTrue();
        await Assert.That(accounts.VerifyPassword(reloaded, "originalpw")).IsFalse();
        await Assert.That((await sessions.FindAsync("s1"))!.Revoked).IsTrue();
    }

    [Test]
    public async Task Unknown_identifier_sends_nothing_and_does_not_throw()
    {
        var (reset, _, _, _, email) = New();
        await reset.RequestAsync("nobody@x.com", "https://app/reset");
        await Assert.That(email.LastBody).IsNull();
    }

    [Test]
    public async Task Weak_password_and_bad_token_are_rejected()
    {
        var (reset, accounts, _, _, email) = New();
        await accounts.CreateLocalAsync(null, "a@b.com", "originalpw");
        await reset.RequestAsync("a@b.com", "https://app/reset");

        await Assert.That((await reset.ResetAsync(Token(email.LastBody!), "short")).Error).IsEqualTo("PASSWORD_TOO_WEAK");
        await Assert.That((await reset.ResetAsync("deadbeef", "long-enough-pw")).Error).IsEqualTo("INVALID_TOKEN");
    }
}

public sealed class WebhookSignatureTests
{
    private static readonly WebhookOptions Options = new() { SigningSecrets = { "shhh" }, ToleranceSeconds = 300 };

    private static HeaderDictionary Headers(long ts, string sig) => new()
    {
        [WebhookSignature.SignatureHeader] = "sha256=" + sig,
        [WebhookSignature.TimestampHeader] = ts.ToString(),
    };

    [Test]
    public async Task Valid_signature_within_window_verifies()
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        const string body = """{"action":"disable","userId":"u1"}""";
        var headers = Headers(now, WebhookSignature.Compute(now, body, "shhh"));
        await Assert.That(WebhookSignature.Verify(headers, body, Options, now, out _)).IsTrue();
    }

    [Test]
    public async Task Tampered_body_fails()
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var headers = Headers(now, WebhookSignature.Compute(now, "original", "shhh"));
        await Assert.That(WebhookSignature.Verify(headers, "tampered", Options, now, out _)).IsFalse();
    }

    [Test]
    public async Task Stale_timestamp_is_a_replay_and_fails()
    {
        var signed = DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 10_000;   // well outside 300s
        const string body = "{}";
        var headers = Headers(signed, WebhookSignature.Compute(signed, body, "shhh"));
        await Assert.That(WebhookSignature.Verify(headers, body, Options, DateTimeOffset.UtcNow.ToUnixTimeSeconds(), out _)).IsFalse();
    }

    [Test]
    public async Task Missing_signature_fails()
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        await Assert.That(WebhookSignature.Verify(new HeaderDictionary(), "{}", Options, now, out _)).IsFalse();
    }
}
