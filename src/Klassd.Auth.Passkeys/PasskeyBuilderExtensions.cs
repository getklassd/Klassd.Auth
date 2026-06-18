using Klassd.Auth.Abstractions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Klassd.Auth.Passkeys;

public sealed class PasskeyOptions
{
    /// <summary>Relying Party ID — the registrable domain (e.g. "example.com" or "localhost"). Required.</summary>
    public string ServerDomain { get; set; } = "localhost";

    /// <summary>Human-readable relying party name shown by some authenticators.</summary>
    public string ServerName { get; set; } = "Klassd";

    /// <summary>Allowed origins (full scheme+host[+port]) the ceremony may come from. Required.</summary>
    public HashSet<string> Origins { get; set; } = [];

    /// <summary>How long a ceremony's challenge stays valid between options and verify. Default 5 minutes.</summary>
    public TimeSpan ChallengeLifetime { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>Name of the short-lived cookie holding the ceremony handle.</summary>
    public string CeremonyCookieName { get; set; } = "klassd_pk_ceremony";

    /// <summary>
    /// Use the in-memory ceremony store instead of the stateless DataProtection default. Only safe
    /// on a single node; the default works across nodes with a shared DataProtection key ring.
    /// </summary>
    public bool UseInMemoryChallengeStore { get; set; }
}

public static class PasskeyBuilderExtensions
{
    /// <summary>
    /// Adds passkey (WebAuthn/FIDO2) sign-in. Configures Fido2NetLib, the ceremony-challenge store,
    /// and the orchestration service. Map the endpoints with <c>MapKlassdPasskeys()</c> (JSON) or
    /// <c>MapKlassdPasskeysCookie()</c> (cookie sign-in).
    /// </summary>
    public static IAuthBuilder AddPasskeys(this IAuthBuilder auth, Action<PasskeyOptions> configure)
    {
        var options = new PasskeyOptions();
        configure(options);
        auth.Services.AddSingleton(options);

        auth.Services.AddFido2(f =>
        {
            f.ServerDomain = options.ServerDomain;
            f.ServerName = options.ServerName;
            f.Origins = options.Origins;
        });

        if (options.UseInMemoryChallengeStore)
            auth.Services.TryAddSingleton<IPasskeyChallengeStore, InMemoryPasskeyChallengeStore>();
        else
            auth.Services.TryAddSingleton<IPasskeyChallengeStore, DataProtectionPasskeyChallengeStore>();

        auth.Services.AddScoped<PasskeyService>();
        return auth;
    }
}
