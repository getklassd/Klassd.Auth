using Microsoft.Data.Sqlite;

namespace Klassd.Auth.Data.Sqlite;

public sealed class SqliteOptions
{
    public required string ConnectionString { get; init; }
}

/// <summary>Opens connections to the configured SQLite database. One connection per unit of work.</summary>
public sealed class SqliteContext(SqliteOptions options)
{
    public SqliteConnection Open()
    {
        var conn = new SqliteConnection(options.ConnectionString);
        conn.Open();
        return conn;
    }
}
