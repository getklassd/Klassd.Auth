using Klassd.Auth.Abstractions;
using Klassd.Auth.Core.Modules.Notifications;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Twilio;
using Twilio.Rest.Api.V2010.Account;
using Twilio.Types;

namespace Klassd.Auth.Sms.Twilio;

public sealed class TwilioSmsOptions
{
    public required string AccountSid { get; init; }
    public required string AuthToken { get; init; }

    /// <summary>The sending number (E.164) or a Messaging Service SID.</summary>
    public required string FromNumber { get; init; }
}

/// <summary>Sends SMS via Twilio. Replaces the default <see cref="ConsoleSmsSender"/>.</summary>
public sealed class TwilioSmsSender : ISmsSender
{
    private readonly TwilioSmsOptions _options;

    public TwilioSmsSender(TwilioSmsOptions options)
    {
        _options = options;
        TwilioClient.Init(options.AccountSid, options.AuthToken);
    }

    public async Task SendAsync(string toPhone, string message, CancellationToken ct = default) =>
        await MessageResource.CreateAsync(new CreateMessageOptions(new PhoneNumber(toPhone))
        {
            From = new PhoneNumber(_options.FromNumber),
            Body = message,
        });
}

public static class TwilioSmsBuilderExtensions
{
    /// <summary>Registers Twilio as the <c>ISmsSender</c> for passwordless-over-SMS, replacing the console default.</summary>
    public static IAuthBuilder AddTwilioSms(
        this IAuthBuilder auth, string accountSid, string authToken, string fromNumber)
    {
        auth.Services.AddSingleton(new TwilioSmsOptions
        {
            AccountSid = accountSid,
            AuthToken = authToken,
            FromNumber = fromNumber,
        });
        auth.Services.RemoveAll<ISmsSender>();
        auth.Services.AddSingleton<ISmsSender, TwilioSmsSender>();
        return auth;
    }
}
