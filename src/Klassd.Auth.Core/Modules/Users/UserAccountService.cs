using Klassd.Auth.Abstractions;
using Klassd.Auth.Core.Security;

namespace Klassd.Auth.Core.Modules.Users;

/// <summary>Claims-derived info from an external (SSO/OIDC) login, normalized.</summary>
public sealed record ExternalUserInfo(string ExternalId, string? Username = null, string? Email = null);

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
        string provider, ExternalUserInfo info, bool autoProvision, CancellationToken ct = default)
    {
        var existing = await users.FindThirdPartyAsync(provider, info.ExternalId, ct);
        if (existing is not null) return await users.FindByIdAsync(existing.UserId, ct);

        // Link to an existing local account by email, if one exists.
        if (info.Email is not null && await users.FindByEmailAsync(Norm(info.Email), ct) is { } linked)
        {
            linked.LoginMethods.Add(NewExternalMethod(linked.Id, provider, info));
            await users.UpdateLoginMethodAsync(linked.LoginMethods[^1], ct);
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

    private static LoginMethod NewExternalMethod(string userId, string provider, ExternalUserInfo info) => new()
    {
        Id = Guid.NewGuid().ToString("N"),
        UserId = userId,
        Kind = LoginMethodKind.ThirdParty,
        ProviderId = provider,
        ProviderUserId = info.ExternalId,
        Email = info.Email is null ? null : Norm(info.Email),
        EmailVerified = info.Email is not null,
        CreatedAt = DateTimeOffset.UtcNow,
    };

    private static string Norm(string email) => email.Trim().ToLowerInvariant();
}
