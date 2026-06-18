using Klassd.Auth.Abstractions;
using Microsoft.Extensions.DependencyInjection;
using TUnit.Assertions;
using TUnit.Assertions.Extensions;

namespace Klassd.Auth.IntegrationTests;

/// <summary>
/// Storage contract scenarios for the auth stores, run against a REAL database (SQLite file /
/// Postgres / Mongo). Each scenario isolates itself with GUID identifiers, so one database can
/// serve every test in a class.
/// </summary>
internal static class AuthStoreScenarios
{
    private static string Nid() => Guid.NewGuid().ToString("N");

    // ---- Users + the new phone identity -----------------------------------------------------
    public static async Task UserAndPhoneRoundTrip(IServiceProvider sp)
    {
        await using var scope = sp.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<IUserStore>();

        var userId = Nid();
        var phone = "+1555" + Random.Shared.Next(1000000, 9999999);
        var email = $"{Nid()}@example.com";
        await users.AddUserAsync(new User
        {
            Id = userId,
            PrimaryEmail = email,
            PrimaryPhone = phone,
            CreatedAt = DateTimeOffset.UtcNow,
            LoginMethods =
            {
                new LoginMethod
                {
                    Id = Nid(), UserId = userId, Kind = LoginMethodKind.Passwordless,
                    Phone = phone, CreatedAt = DateTimeOffset.UtcNow,
                },
            },
        });

        var byPhone = await users.FindByPhoneAsync(phone);
        await Assert.That(byPhone).IsNotNull();
        await Assert.That(byPhone!.Id).IsEqualTo(userId);
        await Assert.That(byPhone.PrimaryPhone).IsEqualTo(phone);
        await Assert.That(byPhone.LoginMethods.Single().Phone).IsEqualTo(phone);

        var byEmail = await users.FindByEmailAsync(email);
        await Assert.That(byEmail!.Id).IsEqualTo(userId);

        // Phone is mutable via UpdateUserAsync.
        var newPhone = "+1555" + Random.Shared.Next(1000000, 9999999);
        byPhone.PrimaryPhone = newPhone;
        await users.UpdateUserAsync(byPhone);
        await Assert.That((await users.FindByPhoneAsync(newPhone))!.Id).IsEqualTo(userId);
    }

    // ---- Passwordless one-time codes --------------------------------------------------------
    public static async Task PasswordlessCodeLifecycle(IServiceProvider sp)
    {
        await using var scope = sp.CreateAsyncScope();
        var codes = scope.ServiceProvider.GetRequiredService<IPasswordlessCodeStore>();

        var id = $"{Nid()}@example.com";
        await codes.StoreAsync(id, PasswordlessChannel.Email, "hash-1", DateTimeOffset.UtcNow.AddMinutes(10));

        var found = await codes.FindAsync(id);
        await Assert.That(found).IsNotNull();
        await Assert.That(found!.Channel).IsEqualTo(PasswordlessChannel.Email);
        await Assert.That(found.CodeHash).IsEqualTo("hash-1");
        await Assert.That(found.Attempts).IsEqualTo(0);

        await codes.IncrementAttemptsAsync(id);
        await codes.IncrementAttemptsAsync(id);
        await Assert.That((await codes.FindAsync(id))!.Attempts).IsEqualTo(2);

        // Re-store replaces the code and resets the attempt counter.
        await codes.StoreAsync(id, PasswordlessChannel.Email, "hash-2", DateTimeOffset.UtcNow.AddMinutes(10));
        var reset = await codes.FindAsync(id);
        await Assert.That(reset!.CodeHash).IsEqualTo("hash-2");
        await Assert.That(reset.Attempts).IsEqualTo(0);

        await codes.DeleteAsync(id);
        await Assert.That(await codes.FindAsync(id)).IsNull();
    }

    // ---- Account linking: AddLoginMethod actually persists (regression for the no-op bug) ---
    public static async Task LoginMethodAddRemove(IServiceProvider sp)
    {
        await using var scope = sp.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<IUserStore>();

        var userId = Nid();
        await users.AddUserAsync(new User
        {
            Id = userId,
            PrimaryEmail = $"{Nid()}@example.com",
            CreatedAt = DateTimeOffset.UtcNow,
            LoginMethods =
            {
                new LoginMethod { Id = Nid(), UserId = userId, Kind = LoginMethodKind.Passwordless, CreatedAt = DateTimeOffset.UtcNow },
            },
        });

        // Link a second method and confirm it PERSISTS (the old UpdateLoginMethodAsync path was a no-op).
        var linkedId = Nid();
        await users.AddLoginMethodAsync(new LoginMethod
        {
            Id = linkedId, UserId = userId, Kind = LoginMethodKind.ThirdParty,
            ProviderId = "facebook", ProviderUserId = "fb-" + Nid(), CreatedAt = DateTimeOffset.UtcNow,
        });

        var afterAdd = await users.FindByIdAsync(userId);
        await Assert.That(afterAdd!.LoginMethods.Count).IsEqualTo(2);
        await Assert.That(afterAdd.LoginMethods.Any(m => m.Id == linkedId && m.ProviderId == "facebook")).IsTrue();

        var byThirdParty = await users.FindThirdPartyAsync("facebook", afterAdd.LoginMethods.First(m => m.Id == linkedId).ProviderUserId!);
        await Assert.That(byThirdParty).IsNotNull();
        await Assert.That(byThirdParty!.UserId).IsEqualTo(userId);

        await users.RemoveLoginMethodAsync(linkedId);
        var afterRemove = await users.FindByIdAsync(userId);
        await Assert.That(afterRemove!.LoginMethods.Count).IsEqualTo(1);
    }

    // ---- Passkey credentials ----------------------------------------------------------------
    public static async Task PasskeyCredentialRoundTrip(IServiceProvider sp)
    {
        await using var scope = sp.CreateAsyncScope();
        var creds = scope.ServiceProvider.GetRequiredService<IPasskeyCredentialStore>();

        var userId = Nid();
        var credId = Guid.NewGuid().ToByteArray();
        var handle = Guid.NewGuid().ToByteArray();
        await creds.AddAsync(new PasskeyCredential
        {
            Id = Nid(),
            UserId = userId,
            CredentialId = credId,
            PublicKey = [1, 2, 3, 4, 5],
            UserHandle = handle,
            SignCount = 0,
            AaGuid = Guid.NewGuid(),
            CredType = "PublicKey",
            CreatedAt = DateTimeOffset.UtcNow,
        });

        var byCred = await creds.FindByCredentialIdAsync(credId);
        await Assert.That(byCred).IsNotNull();
        await Assert.That(byCred!.UserId).IsEqualTo(userId);
        await Assert.That(byCred.PublicKey).IsEquivalentTo(new byte[] { 1, 2, 3, 4, 5 });

        await Assert.That((await creds.GetByUserIdAsync(userId)).Count).IsEqualTo(1);
        var byHandle = await creds.GetByUserHandleAsync(handle);
        await Assert.That(byHandle.Count).IsEqualTo(1);
        await Assert.That(byHandle[0].CredentialId).IsEquivalentTo(credId);

        await creds.UpdateSignCountAsync(credId, 99, DateTimeOffset.UtcNow);
        var updated = await creds.FindByCredentialIdAsync(credId);
        await Assert.That(updated!.SignCount).IsEqualTo(99ul);
        await Assert.That(updated.LastUsedAt).IsNotNull();

        await Assert.That(await creds.FindByCredentialIdAsync(Guid.NewGuid().ToByteArray())).IsNull();
    }
}
