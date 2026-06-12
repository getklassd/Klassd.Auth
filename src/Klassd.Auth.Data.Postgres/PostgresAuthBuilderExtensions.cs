using Klassd.Auth.Abstractions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Klassd.Auth.Data.Postgres;

/// <summary>Registers the PostgreSQL storage adapter on an <see cref="IAuthBuilder"/>.</summary>
public static class PostgresAuthBuilderExtensions
{
    public static IAuthBuilder UsePostgres(this IAuthBuilder auth, string connectionString)
    {
        auth.Services.AddSingleton(new PostgresOptions { ConnectionString = connectionString });
        auth.Services.AddSingleton<PostgresContext>();
        auth.Services.AddScoped<IUserStore, PostgresUserStore>();
        auth.Services.AddScoped<ISessionStore, PostgresSessionStore>();
        auth.Services.AddScoped<IUserMetadataStore, PostgresUserMetadataStore>();
        auth.Services.AddSingleton<ISigningKeyStore, PostgresSigningKeyStore>();
        auth.Services.AddSingleton<IEmailVerificationTokenStore, PostgresEmailVerificationTokenStore>();
        auth.Services.AddSingleton<IAuthStorageInitializer, PostgresSchemaInitializer>();
        return auth;
    }

    public static IAuthBuilder UsePostgres(this IAuthBuilder auth, IConfiguration section) =>
        auth.UsePostgres(section["ConnectionString"] ?? throw new InvalidOperationException("Postgres ConnectionString missing."));
}
