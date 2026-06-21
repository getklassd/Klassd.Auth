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

    // ---- Multi-tenancy: identity lookups are scoped to the ambient tenant -------------------
    public static async Task TenantIsolation(IServiceProvider sp)
    {
        var email = $"{Nid()}@example.com";

        // The same email registers independently in two tenants → two distinct users.
        var idA = await AddInTenant(sp, "tenant-a", email);
        var idB = await AddInTenant(sp, "tenant-b", email);
        await Assert.That(idA).IsNotEqualTo(idB);

        // Identity lookups (email + email/password method) resolve ONLY within the ambient tenant.
        await InTenant(sp, "tenant-a", async users =>
        {
            await Assert.That((await users.FindByEmailAsync(email))!.Id).IsEqualTo(idA);
            await Assert.That((await users.FindEmailPasswordAsync(email))!.UserId).IsEqualTo(idA);
        });
        await InTenant(sp, "tenant-b", async users =>
            await Assert.That((await users.FindByEmailAsync(email))!.Id).IsEqualTo(idB));

        // A third tenant sees neither — no cross-tenant leakage.
        await InTenant(sp, "tenant-c", async users =>
        {
            await Assert.That(await users.FindByEmailAsync(email)).IsNull();
            await Assert.That(await users.FindEmailPasswordAsync(email)).IsNull();
        });

        // FindById is intentionally global (unique GUID): resolvable regardless of ambient tenant.
        await InTenant(sp, "tenant-c", async users =>
            await Assert.That((await users.FindByIdAsync(idA))!.TenantId).IsEqualTo("tenant-a"));
    }

    private static async Task<string> AddInTenant(IServiceProvider sp, string tenant, string email)
    {
        string userId = Nid();
        await InTenant(sp, tenant, users => users.AddUserAsync(new User
        {
            Id = userId, PrimaryEmail = email, CreatedAt = DateTimeOffset.UtcNow,
            LoginMethods =
            {
                new LoginMethod
                {
                    Id = Nid(), UserId = userId, Kind = LoginMethodKind.EmailPassword,
                    Email = email, PasswordHash = "x", CreatedAt = DateTimeOffset.UtcNow,
                },
            },
        }));
        return userId;
    }

    private static async Task InTenant(IServiceProvider sp, string tenant, Func<IUserStore, Task> body)
    {
        await using var scope = sp.CreateAsyncScope();
        scope.ServiceProvider.GetRequiredService<ITenantContext>().TenantId = tenant;
        await body(scope.ServiceProvider.GetRequiredService<IUserStore>());
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

    // ---- Hard delete + cascade (sessions/passkeys persist-then-gone) ------------------------
    public static async Task UserDeleteCascade(IServiceProvider sp)
    {
        await using var scope = sp.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<IUserStore>();
        var sessions = scope.ServiceProvider.GetRequiredService<ISessionStore>();
        var passkeys = scope.ServiceProvider.GetRequiredService<IPasskeyCredentialStore>();

        var userId = Nid();
        await users.AddUserAsync(new User
        {
            Id = userId, PrimaryEmail = $"{Nid()}@example.com", CreatedAt = DateTimeOffset.UtcNow,
            LoginMethods = { new LoginMethod { Id = Nid(), UserId = userId, Kind = LoginMethodKind.EmailPassword, CreatedAt = DateTimeOffset.UtcNow } },
        });
        await sessions.AddAsync(new SessionEntity { Handle = Nid(), UserId = userId, RefreshTokenHash = "h", CreatedAt = DateTimeOffset.UtcNow, RefreshExpiresAt = DateTimeOffset.UtcNow.AddDays(1) });
        var credId = Guid.NewGuid().ToByteArray();
        await passkeys.AddAsync(new PasskeyCredential { Id = Nid(), UserId = userId, CredentialId = credId, PublicKey = [1], UserHandle = [2], AaGuid = Guid.NewGuid(), CreatedAt = DateTimeOffset.UtcNow });

        await Assert.That(await users.FindByIdAsync(userId)).IsNotNull();

        await sessions.DeleteAllForUserAsync(userId);
        await passkeys.DeleteByUserIdAsync(userId);
        await users.DeleteUserAsync(userId);

        await Assert.That(await users.FindByIdAsync(userId)).IsNull();
        await Assert.That((await passkeys.GetByUserIdAsync(userId)).Count).IsEqualTo(0);
    }

    // ---- Password-reset token round-trip ----------------------------------------------------
    public static async Task PasswordResetTokenRoundTrip(IServiceProvider sp)
    {
        await using var scope = sp.CreateAsyncScope();
        var store = scope.ServiceProvider.GetRequiredService<IPasswordResetTokenStore>();

        var hash = Nid();
        await store.StoreAsync(hash, "user-1", DateTimeOffset.UtcNow.AddHours(1));
        var consumed = await store.ConsumeAsync(hash);
        await Assert.That(consumed).IsNotNull();
        await Assert.That(consumed!.UserId).IsEqualTo("user-1");
        await Assert.That(await store.ConsumeAsync(hash)).IsNull();   // single-use
    }

    // ---- Access-token payload merge (persists on the session, survives refresh) --------------
    public static async Task AccessTokenPayloadMerge(IServiceProvider sp)
    {
        await using var scope = sp.CreateAsyncScope();
        var sessions = scope.ServiceProvider.GetRequiredService<Klassd.Auth.Core.Sessions.ISessionService>();
        var prefix = scope.ServiceProvider.GetRequiredService<Klassd.Auth.Core.Sessions.SessionConfig>().SessionDataClaimPrefix;

        var tokens = await sessions.CreateAsync("user_" + Nid());
        await sessions.MergeIntoAccessTokenPayloadAsync(tokens.Handle, new Dictionary<string, object?>
        {
            ["tenant"] = "acme",
            ["roles"] = new[] { "admin", "editor" },
        });

        // Re-issue from the persisted session and confirm the payload survived the DB round-trip,
        // including the JSON array (proves the store persists session_data on update).
        var refreshed = await sessions.RefreshAsync(tokens.RefreshToken);
        var principal = sessions.ValidateAccessToken(refreshed.AccessToken);

        await Assert.That(principal.FindFirst($"{prefix}tenant")?.Value).IsEqualTo("acme");
        var roles = principal.FindAll($"{prefix}roles").Select(c => c.Value).ToList();
        await Assert.That(roles).Contains("admin");
        await Assert.That(roles).Contains("editor");
    }

    // ---- Migration ledger + lease lock ------------------------------------------------------
    public static async Task MigrationStateLifecycle(IServiceProvider sp)
    {
        await using var scope = sp.CreateAsyncScope();
        var state = scope.ServiceProvider.GetRequiredService<IMigrationStateStore>();
        var id = "mig_" + Nid();

        await Assert.That(await state.IsCompletedAsync(id)).IsFalse();

        // Exclusive lease: a second contender is refused while it's held.
        var first = await state.TryAcquireLockAsync(id, TimeSpan.FromMinutes(5));
        await Assert.That(first).IsNotNull();
        await Assert.That(await state.TryAcquireLockAsync(id, TimeSpan.FromMinutes(5))).IsNull();
        await Assert.That(await first!.RenewAsync(TimeSpan.FromMinutes(5))).IsTrue();
        await first.DisposeAsync();

        // Re-acquirable once released.
        var again = await state.TryAcquireLockAsync(id, TimeSpan.FromMinutes(5));
        await Assert.That(again).IsNotNull();
        await again!.DisposeAsync();

        // A crashed holder's expired lease is reclaimable.
        var stale = await state.TryAcquireLockAsync(id, TimeSpan.FromSeconds(-1));
        await Assert.That(stale).IsNotNull();
        var taken = await state.TryAcquireLockAsync(id, TimeSpan.FromMinutes(5));
        await Assert.That(taken).IsNotNull();
        await taken!.DisposeAsync();

        // Ledger persists completion.
        await state.MarkCompletedAsync(id, "{\"created\":1}");
        await Assert.That(await state.IsCompletedAsync(id)).IsTrue();
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
