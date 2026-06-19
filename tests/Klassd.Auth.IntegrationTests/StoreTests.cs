using Klassd.Auth.Abstractions;
using Klassd.Auth.Core.DependencyInjection;
using Klassd.Auth.Core.Sessions;
using Klassd.Auth.Data.MongoDb;
using Klassd.Auth.Data.Postgres;
using Klassd.Auth.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using TUnit.Core;

namespace Klassd.Auth.IntegrationTests;

internal static class TestProvider
{
    private const string SigningKey = "0123456789abcdef0123456789abcdef";

    public static async Task<ServiceProvider> BuildAsync(Action<IAuthBuilder> useStore)
    {
        var services = new ServiceCollection();
        useStore(services.AddKlassdAuth(new SessionConfig { SigningKey = SigningKey }));
        var provider = services.BuildServiceProvider();

        await using var scope = provider.CreateAsyncScope();
        foreach (var init in scope.ServiceProvider.GetServices<IAuthStorageInitializer>())
            await init.InitializeAsync();
        return provider;
    }
}

/// <summary>Runs the store scenarios against the real SQLite adapter (no Docker needed).</summary>
public class SqliteStoreTests
{
    private static ServiceProvider? _provider;
    private static string _dbPath = "";

    [Before(HookType.Class)]
    public static async Task StartAsync()
    {
        _dbPath = Path.Combine(Path.GetTempPath(), $"klassd-auth-it-{Guid.NewGuid():N}.db");
        _provider = await TestProvider.BuildAsync(a => a.UseSqlite($"Data Source={_dbPath}"));
    }

    [After(HookType.Class)]
    public static async Task StopAsync()
    {
        if (_provider is not null) await _provider.DisposeAsync();
        foreach (var f in new[] { _dbPath, _dbPath + "-wal", _dbPath + "-shm" })
            try { if (File.Exists(f)) File.Delete(f); } catch { /* best effort */ }
    }

    [Test] public Task Users_and_phone() => AuthStoreScenarios.UserAndPhoneRoundTrip(_provider!);
    [Test] public Task Passwordless_codes() => AuthStoreScenarios.PasswordlessCodeLifecycle(_provider!);
    [Test] public Task Passkey_credentials() => AuthStoreScenarios.PasskeyCredentialRoundTrip(_provider!);
    [Test] public Task Login_method_add_remove() => AuthStoreScenarios.LoginMethodAddRemove(_provider!);
    [Test] public Task User_delete_cascade() => AuthStoreScenarios.UserDeleteCascade(_provider!);
    [Test] public Task Password_reset_token() => AuthStoreScenarios.PasswordResetTokenRoundTrip(_provider!);
}

/// <summary>
/// Runs the store scenarios against the SHARED PostgreSQL container, isolated in its own random
/// schema (via the Npgsql <c>Search Path</c>) so it never collides with other classes. Requires Docker.
/// </summary>
[SkipWhenDockerUnavailable]
public class PostgresStoreTests
{
    private static ServiceProvider? _provider;
    private static string? _schema;

    [Before(HookType.Class)]
    public static async Task StartAsync()
    {
        if (!DockerProbe.IsAvailable()) return;
        var baseCs = SharedContainers.Postgres!.GetConnectionString();
        _schema = "s_" + Guid.NewGuid().ToString("N");

        await using (var conn = new NpgsqlConnection(baseCs))
        {
            await conn.OpenAsync();
            await using var cmd = conn.CreateCommand();
            cmd.CommandText = $"CREATE SCHEMA \"{_schema}\"";
            await cmd.ExecuteNonQueryAsync();
        }

        // Unqualified DDL/DML from the adapter lands in this schema (first on the search path).
        var cs = new NpgsqlConnectionStringBuilder(baseCs) { SearchPath = _schema }.ConnectionString;
        _provider = await TestProvider.BuildAsync(a => a.UsePostgres(cs));
    }

    [After(HookType.Class)]
    public static async Task StopAsync()
    {
        if (_provider is not null) await _provider.DisposeAsync();
        if (_schema is null || !DockerProbe.IsAvailable() || SharedContainers.Postgres is null) return;

        await using var conn = new NpgsqlConnection(SharedContainers.Postgres.GetConnectionString());
        await conn.OpenAsync();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = $"DROP SCHEMA IF EXISTS \"{_schema}\" CASCADE";
        await cmd.ExecuteNonQueryAsync();
    }

    [Test] public Task Users_and_phone() => AuthStoreScenarios.UserAndPhoneRoundTrip(_provider!);
    [Test] public Task Passwordless_codes() => AuthStoreScenarios.PasswordlessCodeLifecycle(_provider!);
    [Test] public Task Passkey_credentials() => AuthStoreScenarios.PasskeyCredentialRoundTrip(_provider!);
    [Test] public Task Login_method_add_remove() => AuthStoreScenarios.LoginMethodAddRemove(_provider!);
    [Test] public Task User_delete_cascade() => AuthStoreScenarios.UserDeleteCascade(_provider!);
    [Test] public Task Password_reset_token() => AuthStoreScenarios.PasswordResetTokenRoundTrip(_provider!);
}

/// <summary>
/// Runs the store scenarios against the SHARED MongoDB container, isolated in its own random database
/// (Mongo databases are lazy/free). Requires Docker.
/// </summary>
[SkipWhenDockerUnavailable]
public class MongoStoreTests
{
    private static ServiceProvider? _provider;

    [Before(HookType.Class)]
    public static async Task StartAsync()
    {
        if (!DockerProbe.IsAvailable()) return;
        var db = "klassd_auth_it_" + Guid.NewGuid().ToString("N");
        _provider = await TestProvider.BuildAsync(a => a.UseMongoDb(SharedContainers.Mongo!.GetConnectionString(), db));
    }

    [After(HookType.Class)]
    public static async Task StopAsync()
    {
        if (_provider is not null) await _provider.DisposeAsync();
    }

    [Test] public Task Users_and_phone() => AuthStoreScenarios.UserAndPhoneRoundTrip(_provider!);
    [Test] public Task Passwordless_codes() => AuthStoreScenarios.PasswordlessCodeLifecycle(_provider!);
    [Test] public Task Passkey_credentials() => AuthStoreScenarios.PasskeyCredentialRoundTrip(_provider!);
    [Test] public Task Login_method_add_remove() => AuthStoreScenarios.LoginMethodAddRemove(_provider!);
    [Test] public Task User_delete_cascade() => AuthStoreScenarios.UserDeleteCascade(_provider!);
    [Test] public Task Password_reset_token() => AuthStoreScenarios.PasswordResetTokenRoundTrip(_provider!);
}
