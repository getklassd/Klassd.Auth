using Klassd.Auth.Abstractions;
using Klassd.Auth.Core.Security;

namespace Klassd.Auth.Core.Modules.EmailPassword;

public sealed record AuthResult(bool Success, string? UserId = null, string? Error = null);

/// <summary>Sign-up / sign-in with email + password.</summary>
public sealed class EmailPasswordService(IUserStore users, IPasswordHasher hasher)
{
    public async Task<AuthResult> SignUpAsync(string email, string password, CancellationToken ct = default)
    {
        email = Normalize(email);
        if (await users.FindEmailPasswordAsync(email, ct) is not null)
            return new AuthResult(false, Error: "EMAIL_ALREADY_EXISTS");
        if (password.Length < 8)
            return new AuthResult(false, Error: "PASSWORD_TOO_WEAK");

        var userId = Guid.NewGuid().ToString("N");
        var user = new User
        {
            Id = userId,
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
        return new AuthResult(true, userId);
    }

    public async Task<AuthResult> SignInAsync(string email, string password, CancellationToken ct = default)
    {
        var method = await users.FindEmailPasswordAsync(Normalize(email), ct);
        if (method?.PasswordHash is null || !hasher.Verify(password, method.PasswordHash))
            return new AuthResult(false, Error: "WRONG_CREDENTIALS");

        var user = await users.FindByIdAsync(method.UserId, ct);
        if (user is { Disabled: true })
            return new AuthResult(false, Error: "USER_DISABLED");
        return new AuthResult(true, method.UserId);
    }

    private static string Normalize(string email) => email.Trim().ToLowerInvariant();
}
