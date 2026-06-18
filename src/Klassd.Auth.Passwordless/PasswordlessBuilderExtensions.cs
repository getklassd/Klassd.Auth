using Klassd.Auth.Abstractions;
using Microsoft.Extensions.DependencyInjection;

namespace Klassd.Auth.Passwordless;

public static class PasswordlessBuilderExtensions
{
    /// <summary>
    /// Adds passwordless (one-time code) sign-in. Codes are delivered via the registered
    /// <c>IEmailSender</c>/<c>ISmsSender</c> and persisted via the registered <c>IPasswordlessCodeStore</c>
    /// (a Data.* adapter supplies a durable one; otherwise an in-memory default is used).
    /// </summary>
    public static IAuthBuilder AddPasswordless(
        this IAuthBuilder auth, Action<PasswordlessOptions>? configure = null)
    {
        var options = new PasswordlessOptions();
        configure?.Invoke(options);
        auth.Services.AddSingleton(options);
        auth.Services.AddScoped<PasswordlessService>();
        return auth;
    }
}
