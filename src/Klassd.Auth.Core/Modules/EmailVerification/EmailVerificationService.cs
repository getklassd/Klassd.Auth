using System.Security.Cryptography;
using System.Text;
using Klassd.Auth.Abstractions;

namespace Klassd.Auth.Core.Modules.EmailVerification;

public interface IEmailSender
{
    Task SendAsync(string toEmail, string subject, string body, CancellationToken ct = default);
}

/// <summary>Logs the link instead of sending. Replace with SMTP/SendGrid/etc.</summary>
public sealed class ConsoleEmailSender : IEmailSender
{
    public Task SendAsync(string to, string subject, string body, CancellationToken ct = default)
    {
        Console.WriteLine($"[email] to={to} subject={subject}\n{body}");
        return Task.CompletedTask;
    }
}

/// <summary>
/// Issues one-time email-verification tokens and marks the login method verified on consume.
/// Tokens are persisted hashed (via <see cref="IEmailVerificationTokenStore"/>) so only the holder
/// of the raw token can redeem it, and they survive restarts when a persistent store is used.
/// </summary>
public sealed class EmailVerificationService(
    IUserStore users, IEmailSender email, IEmailVerificationTokenStore tokens)
{
    public async Task SendVerificationAsync(string userId, string toEmail, string verifyUrlBase, CancellationToken ct = default)
    {
        var raw = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        await tokens.StoreAsync(Hash(raw), userId, toEmail, DateTimeOffset.UtcNow.AddHours(24), ct);
        await email.SendAsync(toEmail, "Verify your email", $"Verify here: {verifyUrlBase}?token={raw}", ct);
    }

    public async Task<bool> VerifyAsync(string token, CancellationToken ct = default)
    {
        var record = await tokens.ConsumeAsync(Hash(token), ct);
        if (record is null || record.Expires < DateTimeOffset.UtcNow) return false;

        var user = await users.FindByIdAsync(record.UserId, ct);
        var method = user?.LoginMethods.FirstOrDefault(m =>
            string.Equals(m.Email, record.Email, StringComparison.OrdinalIgnoreCase));
        if (method is null) return false;

        method.EmailVerified = true;
        await users.UpdateLoginMethodAsync(method, ct);
        return true;
    }

    private static string Hash(string input) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(input)));
}
