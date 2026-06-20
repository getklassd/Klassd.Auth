using Klassd.Auth.Abstractions;
using Microsoft.Extensions.Configuration;
using MongoDB.Driver;
using Microsoft.Extensions.DependencyInjection;
using MongoDB.Bson.Serialization;
using MongoDB.Bson.Serialization.Conventions;
using MongoDB.Bson.Serialization.Serializers;

namespace Klassd.Auth.Data.MongoDb;

/// <summary>Creates indexes on the Klassd.Auth collections. Idempotent.</summary>
public sealed class MongoSchemaInitializer(MongoContext ctx) : IAuthStorageInitializer
{
    public async Task InitializeAsync(CancellationToken ct = default)
    {
        await ctx.Users.Indexes.CreateManyAsync(
        [
            new(Builders<UserDoc>.IndexKeys
                .Ascending("LoginMethods.Kind").Ascending("LoginMethods.Email")),
            new(Builders<UserDoc>.IndexKeys
                .Ascending("LoginMethods.ProviderId").Ascending("LoginMethods.ProviderUserId")),
            new(Builders<UserDoc>.IndexKeys.Ascending(u => u.PrimaryPhone)),
        ], ct);

        await ctx.PasskeyCredentials.Indexes.CreateManyAsync(
        [
            new(Builders<PasskeyCredentialDoc>.IndexKeys.Ascending(c => c.CredentialId),
                new CreateIndexOptions { Unique = true }),
            new(Builders<PasskeyCredentialDoc>.IndexKeys.Ascending(c => c.UserId)),
            new(Builders<PasskeyCredentialDoc>.IndexKeys.Ascending(c => c.UserHandle)),
        ], ct);
    }
}

/// <summary>Registers the MongoDB storage adapter on an <see cref="IAuthBuilder"/>.</summary>
public static class MongoAuthBuilderExtensions
{
    private static bool _mapsRegistered;
    private static readonly object _lock = new();

    public static IAuthBuilder UseMongoDb(this IAuthBuilder auth, string connectionString, string? databaseName = null)
    {
        RegisterClassMaps();
        var options = databaseName is null
            ? new MongoOptions { ConnectionString = connectionString }
            : new MongoOptions { ConnectionString = connectionString, DatabaseName = databaseName };

        auth.Services.AddSingleton(options);
        auth.Services.AddSingleton<MongoContext>();
        auth.Services.AddScoped<IUserStore, MongoUserStore>();
        auth.Services.AddScoped<ISessionStore, MongoSessionStore>();
        auth.Services.AddScoped<IUserMetadataStore, MongoUserMetadataStore>();
        auth.Services.AddSingleton<ISigningKeyStore, MongoSigningKeyStore>();
        auth.Services.AddSingleton<IEmailVerificationTokenStore, MongoEmailVerificationTokenStore>();
        auth.Services.AddSingleton<IPasswordResetTokenStore, MongoPasswordResetTokenStore>();
        auth.Services.AddSingleton<IPasswordlessCodeStore, MongoPasswordlessCodeStore>();
        auth.Services.AddSingleton<IPasskeyCredentialStore, MongoPasskeyCredentialStore>();
        auth.Services.AddSingleton<IMigrationStateStore, MongoMigrationStateStore>();
        auth.Services.AddSingleton<IAuthStorageInitializer, MongoSchemaInitializer>();
        return auth;
    }

    public static IAuthBuilder UseMongoDb(this IAuthBuilder auth, IConfiguration section) =>
        auth.UseMongoDb(
            section["ConnectionString"] ?? throw new InvalidOperationException("Mongo ConnectionString missing."),
            section["DatabaseName"]);

    private static void RegisterClassMaps()
    {
        if (_mapsRegistered) return;
        lock (_lock)
        {
            if (_mapsRegistered) return;

            // Store DateTimeOffset as a BSON document/string round-trippable form.
            BsonSerializer.RegisterSerializer(new DateTimeOffsetSerializer(MongoDB.Bson.BsonType.String));
            // Passkey credentials carry an AAGUID; the v3 driver needs an explicit Guid representation.
            BsonSerializer.TryRegisterSerializer(new GuidSerializer(MongoDB.Bson.GuidRepresentation.Standard));

            BsonClassMap.RegisterClassMap<MigrationStateDoc>(cm =>
            {
                cm.AutoMap();
                cm.MapIdMember(x => x.MigrationId);
            });
            BsonClassMap.RegisterClassMap<UserDoc>(cm =>
            {
                cm.AutoMap();
                cm.MapIdMember(x => x.Id);
            });
            BsonClassMap.RegisterClassMap<SessionDoc>(cm =>
            {
                cm.AutoMap();
                cm.MapIdMember(x => x.Handle);
            });
            BsonClassMap.RegisterClassMap<MetadataDoc>(cm =>
            {
                cm.AutoMap();
                cm.MapIdMember(x => x.UserId);
            });
            BsonClassMap.RegisterClassMap<SigningKeyDoc>(cm =>
            {
                cm.AutoMap();
                cm.MapIdMember(x => x.KeyId);
            });
            BsonClassMap.RegisterClassMap<EmailVerificationTokenDoc>(cm =>
            {
                cm.AutoMap();
                cm.MapIdMember(x => x.TokenHash);
            });
            BsonClassMap.RegisterClassMap<PasswordResetTokenDoc>(cm =>
            {
                cm.AutoMap();
                cm.MapIdMember(x => x.TokenHash);
            });
            BsonClassMap.RegisterClassMap<PasswordlessCodeDoc>(cm =>
            {
                cm.AutoMap();
                cm.MapIdMember(x => x.Identifier);
            });
            BsonClassMap.RegisterClassMap<PasskeyCredentialDoc>(cm =>
            {
                cm.AutoMap();
                cm.MapIdMember(x => x.Id);
            });
            ConventionRegistry.Register(
                "klassd-auth-enum-string",
                new ConventionPack { new EnumRepresentationConvention(MongoDB.Bson.BsonType.String) },
                _ => true);

            _mapsRegistered = true;
        }
    }
}
