using Klassd.Auth.Abstractions;
using Klassd.Auth.Core.Modules.EmailPassword;
using Klassd.Auth.Core.Modules.EmailVerification;
using Klassd.Auth.Core.Modules.Mfa;
using Klassd.Auth.Core.Modules.Notifications;
using Klassd.Auth.Core.Modules.ThirdParty;
using Klassd.Auth.Core.Modules.UserMetadata;
using Klassd.Auth.Core.Modules.Users;
using Klassd.Auth.Core.Security;
using Klassd.Auth.Core.Sessions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using System.Security.Claims;
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
        services.AddSingleton<ITotpService, TotpService>();
        services.TryAddSingleton<IEmailSender, ConsoleEmailSender>();
        services.TryAddSingleton<ISmsSender, ConsoleSmsSender>();
        // In-memory defaults; a Data.* adapter overrides these with persistent stores.
        services.TryAddSingleton<IEmailVerificationTokenStore, InMemoryEmailVerificationTokenStore>();
        services.TryAddSingleton<IPasswordResetTokenStore, InMemoryPasswordResetTokenStore>();
        services.TryAddSingleton<IPasswordlessCodeStore, InMemoryPasswordlessCodeStore>();
        services.TryAddSingleton<IPasskeyCredentialStore, InMemoryPasskeyCredentialStore>();

        services.AddScoped<ISessionService, SessionService>();
        services.AddScoped<IEmailPasswordService, EmailPasswordService>();
        services.AddScoped<IEmailVerificationService, EmailVerificationService>();
        services.TryAddSingleton<Modules.Password.PasswordResetOptions>();
        services.AddScoped<Modules.Password.IPasswordResetService, Modules.Password.PasswordResetService>();
        services.AddScoped<IUserMetadataService, UserMetadataService>();
        services.AddScoped<IThirdPartyService, ThirdPartyService>();
        services.AddScoped<IUserAccountService, UserAccountService>();
        services.AddScoped<IAccountLifecycleService, AccountLifecycleService>();
        services.AddScoped<IRolesService, RolesService>();

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

    /// <summary>
    /// Registers an <see cref="IAccessTokenClaimsEnricher"/> that adds custom claims to every access
    /// token (issued at sign-in and on each refresh). Add as many as you like — all contribute.
    /// </summary>
    public static IAuthBuilder AddAccessTokenClaimsEnricher<TEnricher>(this IAuthBuilder auth)
        where TEnricher : class, IAccessTokenClaimsEnricher
    {
        auth.Services.AddScoped<IAccessTokenClaimsEnricher, TEnricher>();
        return auth;
    }

    /// <summary>
    /// Adds custom access-token claims via an inline callback (resolved per token issue, with access to
    /// DI for looking up roles/tenant/etc.). Runs on every issue + refresh.
    /// </summary>
    public static IAuthBuilder AddAccessTokenClaims(
        this IAuthBuilder auth,
        Func<AccessTokenClaimsContext, IServiceProvider, CancellationToken, Task<IEnumerable<Claim>>> claims)
    {
        auth.Services.AddScoped<IAccessTokenClaimsEnricher>(sp => new DelegateClaimsEnricher(claims, sp));
        return auth;
    }

    private sealed class DelegateClaimsEnricher(
        Func<AccessTokenClaimsContext, IServiceProvider, CancellationToken, Task<IEnumerable<Claim>>> claims,
        IServiceProvider services) : IAccessTokenClaimsEnricher
    {
        public Task<IEnumerable<Claim>> GetClaimsAsync(AccessTokenClaimsContext context, CancellationToken ct = default) =>
            claims(context, services, ct);
    }

    /// <summary>
    /// Registers a hook that stamps the access-token payload of every newly created session — the
    /// equivalent of overriding SuperTokens' <c>CreateNewSession</c>. Stamped values are persisted on the
    /// session, so they ride every token including refreshes.
    /// </summary>
    public static IAuthBuilder AddSessionCreateHook<THook>(this IAuthBuilder auth)
        where THook : class, ISessionCreateHook
    {
        auth.Services.AddScoped<ISessionCreateHook, THook>();
        return auth;
    }

    /// <summary>Inline form of <see cref="AddSessionCreateHook{THook}"/>; the callback is handed the live session.</summary>
    public static IAuthBuilder AddSessionCreateHook(
        this IAuthBuilder auth,
        Func<KlassdSession, SessionCreateContext, IServiceProvider, CancellationToken, Task> onCreated)
    {
        auth.Services.AddScoped<ISessionCreateHook>(sp => new DelegateSessionCreateHook(onCreated, sp));
        return auth;
    }

    private sealed class DelegateSessionCreateHook(
        Func<KlassdSession, SessionCreateContext, IServiceProvider, CancellationToken, Task> onCreated,
        IServiceProvider services) : ISessionCreateHook
    {
        public Task OnSessionCreatedAsync(KlassdSession session, SessionCreateContext context, CancellationToken ct = default) =>
            onCreated(session, context, services, ct);
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
