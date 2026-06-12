using Npgsql;

namespace Klassd.Auth.Data.Postgres;

public sealed class PostgresOptions
{
    public required string ConnectionString { get; init; }
}

/// <summary>Opens connections to the configured PostgreSQL database.</summary>
public sealed class PostgresContext(PostgresOptions options)
{
    public async Task<NpgsqlConnection> OpenAsync(CancellationToken ct = default)
    {
        var conn = new NpgsqlConnection(options.ConnectionString);
        await conn.OpenAsync(ct);
        return conn;
    }
}
