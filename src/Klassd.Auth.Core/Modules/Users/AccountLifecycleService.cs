using Klassd.Auth.Abstractions;

namespace Klassd.Auth.Core.Modules.Users;

/// <summary>
/// Destructive / state-changing account operations, with the cross-store cascade they require —
/// the engine behind the admin dashboard and the customer-service webhooks. Kept separate from
/// <see cref="UserAccountService"/> so that service stays free of the session/metadata/passkey deps.
/// </summary>
public sealed class AccountLifecycleService(
    IUserStore users, ISessionStore sessions, IUserMetadataStore metadata, IPasskeyCredentialStore passkeys)
{
    /// <summary>Disables an account and revokes its live sessions (so existing tokens stop refreshing).</summary>
    public async Task<bool> DisableAsync(string userId, CancellationToken ct = default)
    {
        var user = await users.FindByIdAsync(userId, ct);
        if (user is null) return false;
        if (!user.Disabled)
        {
            user.Disabled = true;
            await users.UpdateUserAsync(user, ct);
        }
        await sessions.RevokeAllForUserAsync(userId, ct);
        return true;
    }

    /// <summary>Re-enables a previously disabled account.</summary>
    public async Task<bool> EnableAsync(string userId, CancellationToken ct = default)
    {
        var user = await users.FindByIdAsync(userId, ct);
        if (user is null) return false;
        if (user.Disabled)
        {
            user.Disabled = false;
            await users.UpdateUserAsync(user, ct);
        }
        return true;
    }

    /// <summary>Hard-deletes an account and every piece of per-user data (login methods, sessions, passkeys, metadata).</summary>
    public async Task<bool> DeleteAsync(string userId, CancellationToken ct = default)
    {
        if (await users.FindByIdAsync(userId, ct) is null) return false;
        await sessions.DeleteAllForUserAsync(userId, ct);
        await passkeys.DeleteByUserIdAsync(userId, ct);
        await metadata.ClearAsync(userId, ct);
        await users.DeleteUserAsync(userId, ct);   // user row + its login methods
        return true;
    }

    /// <summary>
    /// GDPR "right to erasure": strips all PII and credentials but KEEPS the <see cref="User.Id"/> row so
    /// references elsewhere (authorship, audit) stay intact. The account can no longer sign in.
    /// </summary>
    public async Task<bool> AnonymizeAsync(string userId, CancellationToken ct = default)
    {
        var user = await users.FindByIdAsync(userId, ct);
        if (user is null) return false;

        foreach (var method in user.LoginMethods.ToList())
            await users.RemoveLoginMethodAsync(method.Id, ct);
        await passkeys.DeleteByUserIdAsync(userId, ct);
        await metadata.ClearAsync(userId, ct);
        await sessions.DeleteAllForUserAsync(userId, ct);

        user.Username = null;
        user.PrimaryEmail = null;
        user.PrimaryPhone = null;
        user.Disabled = true;
        await users.UpdateUserAsync(user, ct);
        return true;
    }
}
