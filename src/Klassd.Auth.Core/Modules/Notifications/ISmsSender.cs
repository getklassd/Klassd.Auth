namespace Klassd.Auth.Core.Modules.Notifications;

/// <summary>
/// Sends a text message (e.g. a passwordless one-time code). Mirrors
/// <see cref="EmailVerification.IEmailSender"/>; a real provider ships in Klassd.Auth.Sms.Twilio.
/// </summary>
public interface ISmsSender
{
    Task SendAsync(string toPhone, string message, CancellationToken ct = default);
}

/// <summary>Logs the message instead of sending it. Replace with a real SMS provider in production.</summary>
public sealed class ConsoleSmsSender : ISmsSender
{
    public Task SendAsync(string toPhone, string message, CancellationToken ct = default)
    {
        Console.WriteLine($"[sms] to={toPhone}\n{message}");
        return Task.CompletedTask;
    }
}
