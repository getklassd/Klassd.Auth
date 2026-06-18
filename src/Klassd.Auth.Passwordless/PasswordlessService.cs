using System.Security.Cryptography;
using System.Text;
using Klassd.Auth.Abstractions;
using Klassd.Auth.Core.Modules.EmailVerification;
using Klassd.Auth.Core.Modules.Notifications;

namespace Klassd.Auth.Passwordless;

public sealed class PasswordlessOptions
{
    /// <summary>How long a code is valid. Default 10 minutes.</summary>
    public TimeSpan CodeLifetime { get; set; } = TimeSpan.FromMinutes(10);

    /// <summary>Number of decimal digits in the code. Default 6.</summary>
    public int CodeLength { get; set; } = 6;

    /// <summary>Max failed verify attempts before the code is rejected. Default 5.</summary>
    public int MaxAttempts { get; set; } = 5;

    /// <summary>Create a new user on first successful sign-in if the identifier is unknown. Default true.</summary>
    public bool AutoProvision { get; set; } = true;

    /// <summary>Builds the message body for a code. Override to localize / brand.</summary>
    public Func<string, PasswordlessChannel, string> MessageFactory { get; set; } =
        (code, _) => $"Your sign-in code is {code}. It expires shortly.";

    /// <summary>Subject line for email codes.</summary>
    public string EmailSubject { get; set; } = "Your sign-in code";
}

public sealed record PasswordlessResult(bool Success, string? UserId = null, string? Error = null);

/// <summary>
/// Passwordless sign-in via a one-time code sent over email or SMS. Codes are stored hashed, keyed
/// by the target identifier, with a TTL and an attempt counter to throttle brute force. Verifying a
/// code resolves (or, if enabled, provisions) the local user and returns their id; the caller then
/// issues a session (JSON API) or an app cookie.
/// </summary>
public sealed class PasswordlessService(
    IUserStore users,
    IPasswordlessCodeStore codes,
    IEmailSender email,
    ISmsSender sms,
    PasswordlessOptions options)
{
    /// <summary>
    /// Generates and delivers a code to <paramref name="identifier"/> (an email address or phone
    /// number, per <paramref name="channel"/>). Always reports success — it never reveals whether
    /// the identifier maps to an existing account.
    /// </summary>
    public async Task StartAsync(string identifier, PasswordlessChannel channel, CancellationToken ct = default)
    {
        identifier = Normalize(identifier, channel);
        var code = GenerateCode(options.CodeLength);
        await codes.StoreAsync(identifier, channel, Hash(code), DateTimeOffset.UtcNow + options.CodeLifetime, ct);

        var body = options.MessageFactory(code, channel);
        if (channel == PasswordlessChannel.Email)
            await email.SendAsync(identifier, options.EmailSubject, body, ct);
        else
            await sms.SendAsync(identifier, body, ct);
    }

    /// <summary>Verifies a code and returns the resolved/provisioned user id, or a failure reason.</summary>
    public async Task<PasswordlessResult> VerifyAsync(
        string identifier, PasswordlessChannel channel, string code, CancellationToken ct = default)
    {
        identifier = Normalize(identifier, channel);
        var record = await codes.FindAsync(identifier, ct);
        if (record is null || record.Channel != channel)
            return new PasswordlessResult(false, Error: "INVALID_CODE");
        if (record.Expires < DateTimeOffset.UtcNow)
        {
            await codes.DeleteAsync(identifier, ct);
            return new PasswordlessResult(false, Error: "CODE_EXPIRED");
        }
        if (record.Attempts >= options.MaxAttempts)
        {
            await codes.DeleteAsync(identifier, ct);
            return new PasswordlessResult(false, Error: "TOO_MANY_ATTEMPTS");
        }

        if (!FixedTimeEquals(record.CodeHash, Hash(code)))
        {
            await codes.IncrementAttemptsAsync(identifier, ct);
            return new PasswordlessResult(false, Error: "INVALID_CODE");
        }

        await codes.DeleteAsync(identifier, ct);

        var user = await ResolveOrProvisionAsync(identifier, channel, ct);
        if (user is null) return new PasswordlessResult(false, Error: "NOT_PROVISIONED");
        if (user.Disabled) return new PasswordlessResult(false, Error: "USER_DISABLED");
        return new PasswordlessResult(true, user.Id);
    }

    private async Task<User?> ResolveOrProvisionAsync(string identifier, PasswordlessChannel channel, CancellationToken ct)
    {
        var existing = channel == PasswordlessChannel.Email
            ? await users.FindByEmailAsync(identifier, ct)
            : await users.FindByPhoneAsync(identifier, ct);
        if (existing is not null) return existing;

        if (!options.AutoProvision) return null;

        var userId = Guid.NewGuid().ToString("N");
        var user = new User
        {
            Id = userId,
            PrimaryEmail = channel == PasswordlessChannel.Email ? identifier : null,
            PrimaryPhone = channel == PasswordlessChannel.Sms ? identifier : null,
            CreatedAt = DateTimeOffset.UtcNow,
            LoginMethods =
            {
                new LoginMethod
                {
                    Id = Guid.NewGuid().ToString("N"),
                    UserId = userId,
                    Kind = LoginMethodKind.Passwordless,
                    Email = channel == PasswordlessChannel.Email ? identifier : null,
                    EmailVerified = channel == PasswordlessChannel.Email,
                    Phone = channel == PasswordlessChannel.Sms ? identifier : null,
                    CreatedAt = DateTimeOffset.UtcNow,
                }
            }
        };
        await users.AddUserAsync(user, ct);
        return user;
    }

    private static string GenerateCode(int digits)
    {
        // Uniform across [0, 10^digits) — avoids modulo bias.
        var max = (uint)Math.Pow(10, digits);
        var value = (uint)RandomNumberGenerator.GetInt32(0, (int)max);
        return value.ToString().PadLeft(digits, '0');
    }

    private static string Normalize(string identifier, PasswordlessChannel channel) =>
        channel == PasswordlessChannel.Email
            ? identifier.Trim().ToLowerInvariant()
            : identifier.Trim();

    private static string Hash(string input) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(input)));

    private static bool FixedTimeEquals(string a, string b) =>
        CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(a), Encoding.UTF8.GetBytes(b));
}
