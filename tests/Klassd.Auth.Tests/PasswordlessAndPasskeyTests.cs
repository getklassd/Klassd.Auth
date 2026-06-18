using System.Text.RegularExpressions;
using Klassd.Auth.Abstractions;
using Klassd.Auth.Core.Modules.EmailVerification;
using Klassd.Auth.Core.Modules.Notifications;
using Klassd.Auth.Core.Sessions;
using Klassd.Auth.Passkeys;
using Klassd.Auth.Passwordless;
using TUnit.Assertions;
using TUnit.Assertions.Extensions;
using TUnit.Core;

namespace Klassd.Auth.Tests;

public sealed class PasswordlessServiceTests
{
    private sealed class CapturingEmail : IEmailSender
    {
        public string? LastBody;
        public Task SendAsync(string to, string subject, string body, CancellationToken ct = default)
        { LastBody = body; return Task.CompletedTask; }
    }

    private sealed class CapturingSms : ISmsSender
    {
        public string? LastBody;
        public string? LastTo;
        public Task SendAsync(string toPhone, string message, CancellationToken ct = default)
        { LastTo = toPhone; LastBody = message; return Task.CompletedTask; }
    }

    private static string Code(string body) => Regex.Match(body, @"\d{4,8}").Value;

    private static (PasswordlessService svc, FakeUserStore users, CapturingEmail email, CapturingSms sms)
        NewService(PasswordlessOptions? options = null)
    {
        var users = new FakeUserStore();
        var email = new CapturingEmail();
        var sms = new CapturingSms();
        var svc = new PasswordlessService(
            users, new Klassd.Auth.Core.Sessions.InMemoryPasswordlessCodeStore(),
            email, sms, options ?? new PasswordlessOptions());
        return (svc, users, email, sms);
    }

    [Test]
    public async Task Email_start_then_verify_provisions_and_succeeds()
    {
        var (svc, users, email, _) = NewService();
        await svc.StartAsync("A@B.com", PasswordlessChannel.Email);

        var result = await svc.VerifyAsync("a@b.com", PasswordlessChannel.Email, Code(email.LastBody!));
        await Assert.That(result.Success).IsTrue();

        var user = await users.FindByEmailAsync("a@b.com");
        await Assert.That(user).IsNotNull();
        await Assert.That(user!.LoginMethods[0].Kind).IsEqualTo(LoginMethodKind.Passwordless);
    }

    [Test]
    public async Task Sms_start_then_verify_provisions_by_phone()
    {
        var (svc, users, _, sms) = NewService();
        await svc.StartAsync("+15551234567", PasswordlessChannel.Sms);
        await Assert.That(sms.LastTo).IsEqualTo("+15551234567");

        var result = await svc.VerifyAsync("+15551234567", PasswordlessChannel.Sms, Code(sms.LastBody!));
        await Assert.That(result.Success).IsTrue();
        await Assert.That(await users.FindByPhoneAsync("+15551234567")).IsNotNull();
    }

    [Test]
    public async Task Wrong_code_fails_then_locks_out_after_max_attempts()
    {
        var (svc, _, email, _) = NewService(new PasswordlessOptions { MaxAttempts = 2 });
        await svc.StartAsync("a@b.com", PasswordlessChannel.Email);
        _ = email.LastBody;   // ignore the real code; we submit wrong ones

        await Assert.That((await svc.VerifyAsync("a@b.com", PasswordlessChannel.Email, "000000")).Error).IsEqualTo("INVALID_CODE");
        await Assert.That((await svc.VerifyAsync("a@b.com", PasswordlessChannel.Email, "000000")).Error).IsEqualTo("INVALID_CODE");
        // attempts (2) >= MaxAttempts (2) → locked out
        await Assert.That((await svc.VerifyAsync("a@b.com", PasswordlessChannel.Email, "000000")).Error).IsEqualTo("TOO_MANY_ATTEMPTS");
    }

    [Test]
    public async Task Expired_code_is_rejected()
    {
        var (svc, _, email, _) = NewService(new PasswordlessOptions { CodeLifetime = TimeSpan.FromSeconds(-1) });
        await svc.StartAsync("a@b.com", PasswordlessChannel.Email);
        var r = await svc.VerifyAsync("a@b.com", PasswordlessChannel.Email, Code(email.LastBody!));
        await Assert.That(r.Error).IsEqualTo("CODE_EXPIRED");
    }

    [Test]
    public async Task Verify_without_a_started_code_fails()
    {
        var (svc, _, _, _) = NewService();
        await Assert.That((await svc.VerifyAsync("nobody@x.com", PasswordlessChannel.Email, "123456")).Error)
            .IsEqualTo("INVALID_CODE");
    }

    [Test]
    public async Task No_auto_provision_returns_not_provisioned_for_unknown_identifier()
    {
        var (svc, _, email, _) = NewService(new PasswordlessOptions { AutoProvision = false });
        await svc.StartAsync("a@b.com", PasswordlessChannel.Email);
        var r = await svc.VerifyAsync("a@b.com", PasswordlessChannel.Email, Code(email.LastBody!));
        await Assert.That(r.Error).IsEqualTo("NOT_PROVISIONED");
    }
}

public sealed class PasskeyCredentialStoreTests
{
    private static PasskeyCredential NewCredential(string userId, byte[] credId, byte[] handle) => new()
    {
        Id = Guid.NewGuid().ToString("N"),
        UserId = userId,
        CredentialId = credId,
        PublicKey = [1, 2, 3],
        UserHandle = handle,
        SignCount = 0,
        AaGuid = Guid.NewGuid(),
        CredType = "PublicKey",
        CreatedAt = DateTimeOffset.UtcNow,
    };

    [Test]
    public async Task Add_find_and_update_sign_count()
    {
        var store = new InMemoryPasskeyCredentialStore();
        var handle = new byte[] { 9, 9, 9 };
        var cred = NewCredential("user1", [1, 2, 3, 4], handle);
        await store.AddAsync(cred);

        var found = await store.FindByCredentialIdAsync([1, 2, 3, 4]);
        await Assert.That(found).IsNotNull();
        await Assert.That(found!.UserId).IsEqualTo("user1");

        await Assert.That((await store.GetByUserIdAsync("user1")).Count).IsEqualTo(1);
        await Assert.That((await store.GetByUserHandleAsync(handle)).Count).IsEqualTo(1);

        await store.UpdateSignCountAsync([1, 2, 3, 4], 42, DateTimeOffset.UtcNow);
        await Assert.That((await store.FindByCredentialIdAsync([1, 2, 3, 4]))!.SignCount).IsEqualTo(42ul);
    }

    [Test]
    public async Task Unknown_credential_returns_null()
    {
        var store = new InMemoryPasskeyCredentialStore();
        await Assert.That(await store.FindByCredentialIdAsync([7, 7, 7])).IsNull();
    }
}

public sealed class PasskeyChallengeStoreTests
{
    [Test]
    public async Task Stash_then_retrieve_roundtrips_and_is_single_use()
    {
        var store = new InMemoryPasskeyChallengeStore();
        var handle = await store.StashAsync("{\"challenge\":\"abc\"}", TimeSpan.FromMinutes(5));

        await Assert.That(await store.RetrieveAsync(handle)).IsEqualTo("{\"challenge\":\"abc\"}");
        await Assert.That(await store.RetrieveAsync(handle)).IsNull();   // single use
    }

    [Test]
    public async Task Expired_entry_is_not_returned()
    {
        var store = new InMemoryPasskeyChallengeStore();
        var handle = await store.StashAsync("{}", TimeSpan.FromSeconds(-1));
        await Assert.That(await store.RetrieveAsync(handle)).IsNull();
    }

    [Test]
    public async Task Unknown_handle_returns_null()
    {
        var store = new InMemoryPasskeyChallengeStore();
        await Assert.That(await store.RetrieveAsync("nope")).IsNull();
    }
}

public sealed class DataProtectionPasskeyChallengeStoreTests
{
    private static DataProtectionPasskeyChallengeStore New() =>
        new(new Microsoft.AspNetCore.DataProtection.EphemeralDataProtectionProvider());

    [Test]
    public async Task Protected_handle_round_trips()
    {
        var store = New();
        var handle = await store.StashAsync("""{"challenge":"abc"}""", TimeSpan.FromMinutes(5));
        await Assert.That(await store.RetrieveAsync(handle)).IsEqualTo("""{"challenge":"abc"}""");
        // Stateless by design: the handle IS the payload, so it round-trips again (the endpoint, not the
        // store, enforces single-use by clearing the ceremony cookie).
        await Assert.That(await store.RetrieveAsync(handle)).IsEqualTo("""{"challenge":"abc"}""");
    }

    [Test]
    public async Task Expired_handle_returns_null()
    {
        var store = New();
        var handle = await store.StashAsync("{}", TimeSpan.FromSeconds(-1));
        await Assert.That(await store.RetrieveAsync(handle)).IsNull();
    }

    [Test]
    public async Task Tampered_or_foreign_handle_returns_null()
    {
        var store = New();
        var handle = await store.StashAsync("{}", TimeSpan.FromMinutes(5));
        await Assert.That(await store.RetrieveAsync(handle + "x")).IsNull();   // tampered
        await Assert.That(await store.RetrieveAsync("not-protected")).IsNull(); // garbage
        await Assert.That(await New().RetrieveAsync(handle)).IsNull();          // different key ring
    }
}
