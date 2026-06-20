using System.Security.Cryptography;
using System.Text;
using Klassd.Auth.Abstractions;
using Klassd.Auth.Core.Modules.EmailVerification;
using Klassd.Auth.Core.Security;

namespace Klassd.Auth.Core.Modules.Password;

public sealed class PasswordResetOptions
{
    /// <summary>How long a reset link is valid. Default 1 hour.</summary>
    public TimeSpan TokenLifetime { get; set; } = TimeSpan.FromHours(1);

    /// <summary>Minimum new-password length. Default 8.</summary>
    public int MinPasswordLength { get; set; } = 8;

    public string EmailSubject { get; set; } = "Reset your password";

    /// <summary>Builds the email body for a reset link. Override to brand/localize.</summary>
    public Func<string, string> MessageFactory { get; set; } =
        link => $"Reset your password here: {link}\nThis link expires shortly. Ignore this email if you didn't request it.";
}

public sealed record PasswordResetResult(bool Success, string? Error = null);

/// <summary>Self-service password reset. Override via <c>auth.Override&lt;IPasswordResetService&gt;(…)</c>.</summary>
public interface IPasswordResetService
{
    Task RequestAsync(string identifier, string resetUrlBase, CancellationToken ct = default);
    Task<PasswordResetResult> ResetAsync(string token, string newPassword, CancellationToken ct = default);
}

/// <summary>
/// Self-service "forgot password": emails a single-use reset link, then sets a new password when the
/// link's token is presented. Resetting revokes the user's existing sessions. No account enumeration —
/// <see cref="RequestAsync"/> behaves identically whether or not the identifier exists.
/// </summary>
public sealed class PasswordResetService(
    IUserStore users,
    IPasswordHasher hasher,
    IEmailSender email,
    IPasswordResetTokenStore tokens,
    ISessionStore sessions,
    PasswordResetOptions options) : IPasswordResetService
{
    /// <summary>Sends a reset link to the account for <paramref name="identifier"/> (email or username), if any.</summary>
    public async Task RequestAsync(string identifier, string resetUrlBase, CancellationToken ct = default)
    {
        var user = await users.FindByEmailAsync(Normalize(identifier), ct)
                   ?? await users.FindByUsernameAsync(identifier, ct);
        if (user is null || user.Disabled || user.PrimaryEmail is null) return;   // silent: no enumeration

        var raw = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        await tokens.StoreAsync(Hash(raw), user.Id, DateTimeOffset.UtcNow + options.TokenLifetime, ct);
        await email.SendAsync(user.PrimaryEmail, options.EmailSubject, options.MessageFactory($"{resetUrlBase}?token={raw}"), ct);
    }

    /// <summary>Consumes a reset token and sets a new password, revoking the user's existing sessions.</summary>
    public async Task<PasswordResetResult> ResetAsync(string token, string newPassword, CancellationToken ct = default)
    {
        if (newPassword.Length < options.MinPasswordLength)
            return new PasswordResetResult(false, "PASSWORD_TOO_WEAK");

        var record = await tokens.ConsumeAsync(Hash(token), ct);
        if (record is null || record.Expires < DateTimeOffset.UtcNow)
            return new PasswordResetResult(false, "INVALID_TOKEN");

        var user = await users.FindByIdAsync(record.UserId, ct);
        if (user is null || user.Disabled) return new PasswordResetResult(false, "INVALID_TOKEN");

        var method = user.LoginMethods.FirstOrDefault(m => m.Kind == LoginMethodKind.EmailPassword);
        if (method is null)
        {
            await users.AddLoginMethodAsync(new LoginMethod
            {
                Id = Guid.NewGuid().ToString("N"),
                UserId = user.Id,
                Kind = LoginMethodKind.EmailPassword,
                Email = user.PrimaryEmail,
                PasswordHash = hasher.Hash(newPassword),
                CreatedAt = DateTimeOffset.UtcNow,
            }, ct);
        }
        else
        {
            method.PasswordHash = hasher.Hash(newPassword);
            await users.UpdateLoginMethodAsync(method, ct);
        }

        await sessions.RevokeAllForUserAsync(user.Id, ct);   // force re-login everywhere
        return new PasswordResetResult(true);
    }

    private static string Normalize(string email) => email.Trim().ToLowerInvariant();

    private static string Hash(string input) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(input)));
}

/// <summary>Forwarding base for overriding <see cref="IPasswordResetService"/>; override selectively, call <c>base</c> for the original.</summary>
public abstract class PasswordResetServiceDecorator(IPasswordResetService inner) : IPasswordResetService
{
    public virtual Task RequestAsync(string identifier, string resetUrlBase, CancellationToken ct = default) =>
        inner.RequestAsync(identifier, resetUrlBase, ct);

    public virtual Task<PasswordResetResult> ResetAsync(string token, string newPassword, CancellationToken ct = default) =>
        inner.ResetAsync(token, newPassword, ct);
}
