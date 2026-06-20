using Klassd.Auth.Migration;
using Klassd.Auth.Migration.SuperTokens;
using Microsoft.Data.Sqlite;
using TUnit.Assertions;
using TUnit.Assertions.Extensions;
using TUnit.Core;

namespace Klassd.Auth.Tests;

/// <summary>
/// Exercises <see cref="SuperTokensDbMigrationSource"/> against a real (SQLite) <c>DbConnection</c>
/// seeded with the SuperTokens core schema — so the actual SQL and the primary-user grouping are
/// covered without spinning up Postgres/MySQL.
/// </summary>
public sealed class SuperTokensDbSourceTests
{
    [Test]
    public async Task Reads_and_groups_linked_recipe_users_into_one_user()
    {
        // Shared-cache in-memory DB; a kept-open connection holds it alive while the source opens its own.
        var cs = $"Data Source=st_{Guid.NewGuid():N};Mode=Memory;Cache=Shared";
        await using var keepAlive = new SqliteConnection(cs);
        await keepAlive.OpenAsync();
        await SeedAsync(keepAlive);

        var source = new SuperTokensDbMigrationSource(() => new SqliteConnection(cs));
        var users = await Auth0SourceTests.ReadAll(source);

        await Assert.That(users.Count).IsEqualTo(2);

        var jane = users.Single(u => u.ExternalId == "ext-1");
        await Assert.That(jane.Email).IsEqualTo("jane@example.com");
        await Assert.That(jane.EmailVerified).IsTrue();
        await Assert.That(jane.Password!.Scheme).IsEqualTo(PasswordHashScheme.Bcrypt);
        await Assert.That(jane.ThirdParty.Count).IsEqualTo(1);              // linked recipe user folded in
        await Assert.That(jane.ThirdParty[0].ProviderId).IsEqualTo("google");
        await Assert.That(jane.Roles).Contains("admin");
        await Assert.That(jane.TotpSecretBase32).IsEqualTo("JBSWY3DPEHPK3PXP");
        await Assert.That(jane.Metadata.ContainsKey("first_name")).IsTrue();
        await Assert.That(jane.CreatedAt.ToUnixTimeMilliseconds()).IsEqualTo(1700000000000);

        var phone = users.Single(u => u.PasswordlessPhone);
        await Assert.That(phone.Phone).IsEqualTo("+15551234567");
    }

    [Test]
    public async Task Firebase_scrypt_password_is_marked_unsupported()
    {
        var cs = $"Data Source=st_{Guid.NewGuid():N};Mode=Memory;Cache=Shared";
        await using var keepAlive = new SqliteConnection(cs);
        await keepAlive.OpenAsync();
        await CreateSchemaAsync(keepAlive);
        await ExecAsync(keepAlive,
            "INSERT INTO app_id_to_user_id VALUES ('public','u1','u1');" +
            "INSERT INTO emailpassword_users VALUES ('public','u1','x@y.com','$f_scrypt$abc',1700000000000);");

        var users = await Auth0SourceTests.ReadAll(new SuperTokensDbMigrationSource(() => new SqliteConnection(cs)));
        await Assert.That(users[0].Password!.Scheme).IsEqualTo(PasswordHashScheme.Unsupported);
    }

    private static async Task SeedAsync(SqliteConnection conn)
    {
        await CreateSchemaAsync(conn);
        var bcrypt = BCrypt.Net.BCrypt.HashPassword("hunter2!!");
        await ExecAsync(conn,
            // jane: emailpassword (primary) + google thirdparty, linked under u-primary
            "INSERT INTO app_id_to_user_id VALUES ('public','u-primary','u-primary');" +
            "INSERT INTO app_id_to_user_id VALUES ('public','u-tp','u-primary');" +
            "INSERT INTO app_id_to_user_id VALUES ('public','u-phone','u-phone');" +
            $"INSERT INTO emailpassword_users VALUES ('public','u-primary','jane@example.com','{bcrypt}',1700000000000);" +
            "INSERT INTO thirdparty_users VALUES ('public','u-tp','google','g-1','jane@example.com',1700000005000);" +
            "INSERT INTO passwordless_users VALUES ('public','u-phone',NULL,'+15551234567',1700000009000);" +
            "INSERT INTO emailverification_verified_emails VALUES ('public','u-primary','jane@example.com');" +
            "INSERT INTO user_roles VALUES ('public','u-primary','admin');" +
            "INSERT INTO totp_user_devices VALUES ('public','u-primary','JBSWY3DPEHPK3PXP',1);" +
            "INSERT INTO user_metadata VALUES ('public','u-primary','{\"first_name\":\"Jane\"}');" +
            "INSERT INTO userid_mapping VALUES ('public','u-primary','ext-1');");
    }

    private static Task CreateSchemaAsync(SqliteConnection conn) => ExecAsync(conn,
        "CREATE TABLE app_id_to_user_id (app_id TEXT, user_id TEXT, primary_or_recipe_user_id TEXT);" +
        "CREATE TABLE emailverification_verified_emails (app_id TEXT, user_id TEXT, email TEXT);" +
        "CREATE TABLE emailpassword_users (app_id TEXT, user_id TEXT, email TEXT, password_hash TEXT, time_joined INTEGER);" +
        "CREATE TABLE thirdparty_users (app_id TEXT, user_id TEXT, third_party_id TEXT, third_party_user_id TEXT, email TEXT, time_joined INTEGER);" +
        "CREATE TABLE passwordless_users (app_id TEXT, user_id TEXT, email TEXT, phone_number TEXT, time_joined INTEGER);" +
        "CREATE TABLE user_roles (app_id TEXT, user_id TEXT, role TEXT);" +
        "CREATE TABLE totp_user_devices (app_id TEXT, user_id TEXT, secret_key TEXT, verified INTEGER);" +
        "CREATE TABLE user_metadata (app_id TEXT, user_id TEXT, user_metadata TEXT);" +
        "CREATE TABLE userid_mapping (app_id TEXT, supertokens_user_id TEXT, external_user_id TEXT);");

    private static async Task ExecAsync(SqliteConnection conn, string sql)
    {
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = sql;
        await cmd.ExecuteNonQueryAsync();
    }
}
