using Klassd.Auth.Migration.SuperTokens;
using Npgsql;

namespace Klassd.Auth.Migration.SuperTokens.Postgres;

/// <summary>
/// A <see cref="SuperTokensDbMigrationSource"/> bound to a PostgreSQL SuperTokens core database.
/// Give it the same connection string SuperTokens uses (<c>postgresql_connection_uri</c>).
/// </summary>
public sealed class SuperTokensPostgresMigrationSource(string connectionString, SuperTokensDbOptions? options = null)
    : SuperTokensDbMigrationSource(() => new NpgsqlConnection(connectionString), options);
