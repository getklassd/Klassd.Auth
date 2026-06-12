using Klassd.Auth.Abstractions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Klassd.Auth.Data.Sqlite;

/// <summary>Registers the SQLite storage adapter on an <see cref="IAuthBuilder"/>.</summary>
public static class SqliteAuthBuilderExtensions
{
    public static IAuthBuilder UseSqlite(this IAuthBuilder auth, string connectionString)
    {
        auth.Services.AddSingleton(new SqliteOptions { ConnectionString = connectionString });
        auth.Services.AddSingleton<SqliteContext>();
        auth.Services.AddScoped<IUserStore, SqliteUserStore>();
        auth.Services.AddScoped<ISessionStore, SqliteSessionStore>();
        auth.Services.AddScoped<IUserMetadataStore, SqliteUserMetadataStore>();
        auth.Services.AddSingleton<ISigningKeyStore, SqliteSigningKeyStore>();
        auth.Services.AddSingleton<IEmailVerificationTokenStore, SqliteEmailVerificationTokenStore>();
        auth.Services.AddSingleton<IAuthStorageInitializer, SqliteSchemaInitializer>();
        return auth;
    }

    /// <summary>Reads <c>ConnectionString</c> from the given configuration section.</summary>
    public static IAuthBuilder UseSqlite(this IAuthBuilder auth, IConfiguration section) =>
        auth.UseSqlite(section["ConnectionString"] ?? "Data Source=klassd-auth.db");
}
