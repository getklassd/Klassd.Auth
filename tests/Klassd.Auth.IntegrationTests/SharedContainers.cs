using Testcontainers.MongoDb;
using Testcontainers.PostgreSql;
using TUnit.Core;

namespace Klassd.Auth.IntegrationTests;

/// <summary>
/// Starts ONE Postgres and ONE Mongo container for the entire test session and shares them across
/// every test class — far cheaper than a container per class. Isolation is per-class instead of
/// per-container: each Postgres class gets its own random schema, each Mongo class its own random
/// database (see <c>StoreTests</c>). No-ops when Docker is unavailable (the classes self-skip).
/// </summary>
public static class SharedContainers
{
    public static PostgreSqlContainer? Postgres { get; private set; }
    public static MongoDbContainer? Mongo { get; private set; }

    [Before(HookType.TestSession)]
    public static async Task StartAsync()
    {
        if (!DockerProbe.IsAvailable()) return;
        Postgres = new PostgreSqlBuilder("postgres:16-alpine").Build();
        Mongo = new MongoDbBuilder("mongo:7").Build();
        await Task.WhenAll(Postgres.StartAsync(), Mongo.StartAsync());
    }

    [After(HookType.TestSession)]
    public static async Task StopAsync()
    {
        if (Postgres is not null) await Postgres.DisposeAsync();
        if (Mongo is not null) await Mongo.DisposeAsync();
    }
}
