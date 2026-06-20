using Klassd.Auth.Migration.SuperTokens;
using MySqlConnector;

namespace Klassd.Auth.Migration.SuperTokens.MySql;

/// <summary>
/// A <see cref="SuperTokensDbMigrationSource"/> bound to a MySQL SuperTokens core database.
/// Give it the same connection string SuperTokens uses (<c>mysql_connection_uri</c>); the target
/// database is taken from that string, so leave <see cref="SuperTokensDbOptions.TableSchema"/> unset.
/// </summary>
public sealed class SuperTokensMySqlMigrationSource(string connectionString, SuperTokensDbOptions? options = null)
    : SuperTokensDbMigrationSource(() => new MySqlConnection(connectionString), options);
