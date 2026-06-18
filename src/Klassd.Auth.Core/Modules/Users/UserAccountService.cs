using Klassd.Auth.Abstractions;
using Klassd.Auth.Core.Security;

namespace Klassd.Auth.Core.Modules.Users;

/// <summary>Claims-derived info from an external (SSO/OIDC) login, normalized.</summary>
public sealed record ExternalUserInfo(
    string ExternalId, string? Username = null, string? Email = null, bool EmailVerified = false);

/// <summary>Outcome of an explicit account-link attempt.</summary>
public enum LinkOutcome { Linked, AlreadyLinkedToThisUser, ConflictOwnedByAnotherUser, UserNotFound }

public sealed record LinkResult(LinkOutcome Outcome, User? User = null);

/// <summary>
/// User lifecycle + credential management — the union of what Klassd CMS's UserService and
/// Klassd.Workflows's WorkflowsUserService expose, so one service serves both. Identity can be
/// a username (CMS) or an email (Workflows); roles/preferences live in typed metadata, not here.
/// </summary>
public sealed class UserAccountService(IUserStore users, IPasswordHasher hasher)
{
    public Task<User?> GetByIdAsync(string id, CancellationToken ct = default) => users.FindByIdAsync(id, ct);
    public Task<User?> FindByUsernameAsync(string username, CancellationToken ct = default) => users.FindByUsernameAsync(username, ct);
    public Task<User?> FindByEmailAsync(string email, CancellationToken ct = default) => users.FindByEmailAsync(Norm(email), ct);
    public Task<IReadOnlyList<User>> GetAllAsync(CancellationToken ct = default) => users.GetAllAsync(ct);

    /// <summary>Creates a local (password) user. Provide a username (CMS), an email (Workflows), or both.</summary>
    public async Task<User> CreateLocalAsync(
        string? username, string? email, string password, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(username) && string.IsNullOrWhiteSpace(email))
            throw new ArgumentException("A username or email is required.");

        var userId = Guid.NewGuid().ToString("N");
        email = email is null ? null : Norm(email);
        var user = new User
        {
            Id = userId,
            Username = username,
            PrimaryEmail = email,
            CreatedAt = DateTimeOffset.UtcNow,
            LoginMethods =
            {
                new LoginMethod
                {
                    Id = Guid.NewGuid().ToString("N"),
                    UserId = userId,
                    Kind = LoginMethodKind.EmailPassword,
                    Email = email,
                    PasswordHash = hasher.Hash(password),
                    CreatedAt = DateTimeOffset.UtcNow,
                }
            }
        };
        await users.AddUserAsync(user, ct);
        return user;
    }

    /// <summary>Find-or-link-or-create from an external provider. Returns null if not found and auto-provision is off.</summary>
    public async Task<User?> ProvisionExternalAsync(
        string provider, ExternalUserInfo info, bool autoProvision,
        bool autoLinkByVerifiedEmail = false, CancellationToken ct = default)
    {
        var existing = await users.FindThirdPartyAsync(provider, info.ExternalId, ct);
        if (existing is not null) return await users.FindByIdAsync(existing.UserId, ct);

        // Opt-in auto-link to an existing local account, but ONLY on a provider-verified matching
        // email — auto-linking by an unverified email is an account-takeover vector.
        if (autoLinkByVerifiedEmail && info is { EmailVerified: true, Email: not null }
            && await users.FindByEmailAsync(Norm(info.Email), ct) is { } linked)
        {
            if (linked.Disabled) return null;
            var method = NewExternalMethod(linked.Id, provider, info);
            linked.LoginMethods.Add(method);
            await users.AddLoginMethodAsync(method, ct);
            return linked;
        }

        if (!autoProvision) return null;

        var userId = Guid.NewGuid().ToString("N");
        var user = new User
        {
            Id = userId,
            Username = info.Username,
            PrimaryEmail = info.Email is null ? null : Norm(info.Email),
            CreatedAt = DateTimeOffset.UtcNow,
            LoginMethods = { NewExternalMethod(userId, provider, info) },
        };
        await users.AddUserAsync(user, ct);
        return user;
    }

    public async Task<bool> SetDisabledAsync(string id, bool disabled, CancellationToken ct = default)
    {
        var user = await users.FindByIdAsync(id, ct);
        if (user is null) return false;
        user.Disabled = disabled;
        await users.UpdateUserAsync(user, ct);
        return true;
    }

    public async Task<bool> ResetPasswordAsync(string id, string newPassword, CancellationToken ct = default)
    {
        var user = await users.FindByIdAsync(id, ct);
        var method = user?.LoginMethods.FirstOrDefault(m => m.Kind == LoginMethodKind.EmailPassword);
        if (method is null) return false;
        method.PasswordHash = hasher.Hash(newPassword);
        await users.UpdateLoginMethodAsync(method, ct);
        return true;
    }

    public bool VerifyPassword(User user, string password)
    {
        var method = user.LoginMethods.FirstOrDefault(m => m.Kind == LoginMethodKind.EmailPassword);
        return method?.PasswordHash is not null && hasher.Verify(password, method.PasswordHash);
    }

    // ---- Account linking -------------------------------------------------------------------

    /// <summary>
    /// Attaches a third-party identity to an explicit (already authenticated) user — the supported way
    /// for, e.g., a passwordless user to also sign in with Facebook. Never moves an identity that
    /// already belongs to a different user.
    /// </summary>
    public async Task<LinkResult> LinkExternalAsync(
        string userId, string provider, ExternalUserInfo info, CancellationToken ct = default)
    {
        var owner = await users.FindThirdPartyAsync(provider, info.ExternalId, ct);
        if (owner is not null)
            return owner.UserId == userId
                ? new LinkResult(LinkOutcome.AlreadyLinkedToThisUser, await users.FindByIdAsync(userId, ct))
                : new LinkResult(LinkOutcome.ConflictOwnedByAnotherUser);

        var user = await users.FindByIdAsync(userId, ct);
        if (user is null) return new LinkResult(LinkOutcome.UserNotFound);

        await users.AddLoginMethodAsync(NewExternalMethod(userId, provider, info), ct);
        return new LinkResult(LinkOutcome.Linked, await users.FindByIdAsync(userId, ct));
    }

    /// <summary>Removes a login method, refusing to remove a user's LAST one (keeps the account reachable).</summary>
    public async Task<bool> UnlinkAsync(string userId, string methodId, CancellationToken ct = default)
    {
        var user = await users.FindByIdAsync(userId, ct);
        if (user?.LoginMethods.FirstOrDefault(m => m.Id == methodId) is null) return false;
        if (user.LoginMethods.Count <= 1) return false;
        await users.RemoveLoginMethodAsync(methodId, ct);
        return true;
    }

    /// <summary>
    /// Adds an email/password method to an account that has none (social-/passwordless-only → also
    /// password). Returns false if the user already has a password — use <see cref="ResetPasswordAsync"/>
    /// to change an existing one.
    /// </summary>
    public async Task<bool> AddPasswordAsync(string userId, string password, CancellationToken ct = default)
    {
        var user = await users.FindByIdAsync(userId, ct);
        if (user is null) return false;
        if (user.LoginMethods.Any(m => m.Kind == LoginMethodKind.EmailPassword)) return false;

        await users.AddLoginMethodAsync(new LoginMethod
        {
            Id = Guid.NewGuid().ToString("N"),
            UserId = userId,
            Kind = LoginMethodKind.EmailPassword,
            Email = user.PrimaryEmail,
            PasswordHash = hasher.Hash(password),
            CreatedAt = DateTimeOffset.UtcNow,
        }, ct);
        return true;
    }

    /// <summary>
    /// Attaches a new email/phone identity and a Passwordless method, setting it as primary if the user
    /// has none. Passwordless to an EXISTING primary email/phone already works without this (resolution
    /// is by identifier match).
    /// </summary>
    public async Task<bool> AddPasswordlessIdentityAsync(
        string userId, string identifier, PasswordlessChannel channel, CancellationToken ct = default)
    {
        var user = await users.FindByIdAsync(userId, ct);
        if (user is null) return false;

        var isEmail = channel == PasswordlessChannel.Email;
        identifier = isEmail ? Norm(identifier) : identifier.Trim();

        if (isEmail && string.IsNullOrEmpty(user.PrimaryEmail)) user.PrimaryEmail = identifier;
        else if (!isEmail && string.IsNullOrEmpty(user.PrimaryPhone)) user.PrimaryPhone = identifier;
        await users.UpdateUserAsync(user, ct);

        await users.AddLoginMethodAsync(new LoginMethod
        {
            Id = Guid.NewGuid().ToString("N"),
            UserId = userId,
            Kind = LoginMethodKind.Passwordless,
            Email = isEmail ? identifier : null,
            Phone = isEmail ? null : identifier,
            CreatedAt = DateTimeOffset.UtcNow,
        }, ct);
        return true;
    }

    private static LoginMethod NewExternalMethod(string userId, string provider, ExternalUserInfo info) => new()
    {
        Id = Guid.NewGuid().ToString("N"),
        UserId = userId,
        Kind = LoginMethodKind.ThirdParty,
        ProviderId = provider,
        ProviderUserId = info.ExternalId,
        Email = info.Email is null ? null : Norm(info.Email),
        EmailVerified = info.EmailVerified,
        CreatedAt = DateTimeOffset.UtcNow,
    };

    private static string Norm(string email) => email.Trim().ToLowerInvariant();
}
