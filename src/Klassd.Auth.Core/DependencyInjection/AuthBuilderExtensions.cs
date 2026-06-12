using Klassd.Auth.Abstractions;
using Klassd.Auth.Core.Modules.EmailPassword;
using Klassd.Auth.Core.Modules.EmailVerification;
using Klassd.Auth.Core.Modules.Mfa;
using Klassd.Auth.Core.Modules.ThirdParty;
using Klassd.Auth.Core.Modules.UserMetadata;
using Klassd.Auth.Core.Modules.Users;
using Klassd.Auth.Core.Security;
using Klassd.Auth.Core.Sessions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using System.Security.Cryptography;

namespace Klassd.Auth.Core.DependencyInjection;

internal sealed class AuthBuilder(IServiceCollection services) : IAuthBuilder
{
    public IServiceCollection Services { get; } = services;
}

public static class AuthBuilderExtensions
{
    /// <summary>
    /// Registers Klassd.Auth core services and every module. Pair with a storage adapter
    /// (e.g. <c>.UseSqlite(...)</c>) which supplies IUserStore/ISessionStore/IUserMetadataStore.
    /// </summary>
    public static IAuthBuilder AddKlassdAuth(this IServiceCollection services, SessionConfig sessionConfig)
    {
        services.AddSingleton(sessionConfig);
        services.AddSingleton<ITokenSigningKey, SymmetricTokenSigningKey>();  // HS256 default; see UseRsaSigning
        services.AddSingleton<IPasswordHasher, Pbkdf2PasswordHasher>();
        services.AddSingleton<TotpService>();
        services.TryAddSingleton<IEmailSender, ConsoleEmailSender>();
        // In-memory default; a Data.* adapter overrides this with a persistent store.
        services.TryAddSingleton<IEmailVerificationTokenStore, InMemoryEmailVerificationTokenStore>();

        services.AddScoped<SessionService>();
        services.AddScoped<EmailPasswordService>();
        services.AddScoped<EmailVerificationService>();
        services.AddScoped<UserMetadataService>();
        services.AddScoped<ThirdPartyService>();
        services.AddScoped<UserAccountService>();
        services.AddScoped<RolesService>();

        // Create the storage schema/indexes at startup so the host doesn't have to.
        services.AddHostedService<StorageInitializerHostedService>();

        return new AuthBuilder(services);
    }

    /// <summary>Registers an OAuth/OIDC provider (Google, GitHub, …) for the ThirdParty module.</summary>
    public static IAuthBuilder AddProvider<TProvider>(this IAuthBuilder builder)
        where TProvider : class, IThirdPartyProvider
    {
        builder.Services.AddSingleton<IThirdPartyProvider, TProvider>();
        return builder;
    }

    /// <summary>Signs access tokens with RS256 using the given RSA key, and publishes its public JWK.</summary>
    public static IAuthBuilder UseRsaSigning(this IAuthBuilder auth, RSA rsa, string keyId = "klassd-auth")
    {
        auth.Services.RemoveAll<ITokenSigningKey>();
        auth.Services.AddSingleton<ITokenSigningKey>(new RsaTokenSigningKey(rsa, keyId));
        return auth;
    }

    /// <summary>Signs access tokens with RS256 using an RSA private key in PEM form.</summary>
    public static IAuthBuilder UseRsaSigning(this IAuthBuilder auth, string privateKeyPem, string keyId = "klassd-auth")
    {
        var rsa = RSA.Create();
        rsa.ImportFromPem(privateKeyPem);
        return auth.UseRsaSigning(rsa, keyId);
    }

    /// <summary>
    /// Signs access tokens with RS256 using keys persisted in an <see cref="ISigningKeyStore"/>
    /// (supplied by a Data.* adapter), with automatic rotation, validation overlap, and a public
    /// JWKS. Call after a storage adapter (e.g. <c>.UseSqlite(...)</c>).
    /// </summary>
    public static IAuthBuilder UseRotatingRsaSigning(this IAuthBuilder auth, Action<SigningKeyOptions>? configure = null)
    {
        var options = new SigningKeyOptions();
        configure?.Invoke(options);
        auth.Services.AddSingleton(options);
        auth.Services.AddSingleton<SigningKeyManager>();

        auth.Services.RemoveAll<ITokenSigningKey>();
        auth.Services.AddSingleton<ITokenSigningKey>(sp => sp.GetRequiredService<SigningKeyManager>());

        auth.Services.AddSingleton<IAuthStorageInitializer>(sp =>
            new SigningKeyInitializer(sp.GetRequiredService<SigningKeyManager>()));
        auth.Services.AddHostedService<SigningKeyRotationHostedService>();
        return auth;
    }
}
