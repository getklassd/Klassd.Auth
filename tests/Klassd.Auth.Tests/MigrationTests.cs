using System.Text;
using Klassd.Auth.Abstractions;
using Klassd.Auth.Core.Modules.EmailPassword;
using Klassd.Auth.Core.Modules.UserMetadata;
using Klassd.Auth.Core.Modules.Users;
using Klassd.Auth.Core.Security;
using Klassd.Auth.Migration;
using Klassd.Auth.Migration.Auth0;
using Klassd.Auth.Migration.SuperTokens;
using TUnit.Assertions;
using TUnit.Assertions.Extensions;
using TUnit.Core;

namespace Klassd.Auth.Tests;

public sealed class LegacyPasswordHasherTests
{
    private static readonly LegacyAwarePasswordHasher Hasher = new(new Pbkdf2PasswordHasher());

    [Test]
    public async Task Verifies_native_pbkdf2()
    {
        var hash = new Pbkdf2PasswordHasher().Hash("hunter2!!");
        await Assert.That(Hasher.Verify("hunter2!!", hash)).IsTrue();
        await Assert.That(Hasher.Verify("nope", hash)).IsFalse();
    }

    [Test]
    public async Task Verifies_bcrypt_hash_from_a_foreign_system()
    {
        var hash = BCrypt.Net.BCrypt.HashPassword("hunter2!!");
        await Assert.That(PasswordHashFormat.Detect(hash)).IsEqualTo(PasswordHashScheme.Bcrypt);
        await Assert.That(Hasher.Verify("hunter2!!", hash)).IsTrue();
        await Assert.That(Hasher.Verify("nope", hash)).IsFalse();
    }

    [Test]
    public async Task Verifies_argon2_hash_from_a_foreign_system()
    {
        var hash = Isopoh.Cryptography.Argon2.Argon2.Hash("hunter2!!");
        await Assert.That(PasswordHashFormat.Detect(hash)).IsEqualTo(PasswordHashScheme.Argon2);
        await Assert.That(Hasher.Verify("hunter2!!", hash)).IsTrue();
        await Assert.That(Hasher.Verify("nope", hash)).IsFalse();
    }

    [Test]
    public async Task New_passwords_hash_to_native_pbkdf2()
    {
        await Assert.That(Hasher.Hash("hunter2!!")).StartsWith("pbkdf2$");
    }

    [Test]
    public async Task Unsupported_hash_does_not_verify()
    {
        await Assert.That(PasswordHashFormat.Detect("scrypt$xyz")).IsEqualTo(PasswordHashScheme.Unsupported);
        await Assert.That(Hasher.Verify("anything", "scrypt$xyz")).IsFalse();
    }
}

public sealed class Auth0SourceTests
{
    private static Auth0MigrationSource From(string json, Func<string, string>? map = null) =>
        new(() => new MemoryStream(Encoding.UTF8.GetBytes(json)), map);

    [Test]
    public async Task Maps_a_user_with_bcrypt_password_social_identity_metadata_and_roles()
    {
        var bcrypt = BCrypt.Net.BCrypt.HashPassword("hunter2!!");
        var json = $$"""
        [{
          "user_id": "auth0|abc",
          "email": "Jane@Example.com",
          "email_verified": true,
          "blocked": false,
          "custom_password_hash": { "algorithm": "bcrypt", "hash": { "value": "{{bcrypt}}" } },
          "identities": [
            { "provider": "auth0", "user_id": "abc" },
            { "provider": "google-oauth2", "user_id": "g-123", "email": "jane@example.com", "email_verified": true }
          ],
          "user_metadata": { "displayName": "Jane" },
          "app_metadata": { "roles": ["editor", "admin"], "plan": "pro" }
        }]
        """;

        var users = await ReadAll(From(json, p => p == "google-oauth2" ? "google" : p));
        await Assert.That(users.Count).IsEqualTo(1);
        var u = users[0];

        await Assert.That(u.Email).IsEqualTo("Jane@Example.com");
        await Assert.That(u.EmailVerified).IsTrue();
        await Assert.That(u.Password!.Scheme).IsEqualTo(PasswordHashScheme.Bcrypt);
        await Assert.That(u.ThirdParty.Count).IsEqualTo(1);             // "auth0" identity is not a social link
        await Assert.That(u.ThirdParty[0].ProviderId).IsEqualTo("google");
        await Assert.That(u.ThirdParty[0].ProviderUserId).IsEqualTo("g-123");
        await Assert.That(u.Roles).Contains("admin");
        await Assert.That(u.Metadata.ContainsKey("displayName")).IsTrue();
        await Assert.That(u.Metadata.ContainsKey("plan")).IsTrue();
    }

    [Test]
    public async Task Reads_ndjson_export()
    {
        var json = "{\"user_id\":\"a|1\",\"email\":\"a@x.com\"}\n{\"user_id\":\"a|2\",\"email\":\"b@x.com\"}\n";
        var users = await ReadAll(From(json));
        await Assert.That(users.Count).IsEqualTo(2);
        await Assert.That(users[1].Email).IsEqualTo("b@x.com");
    }

    internal static async Task<List<MigratedUser>> ReadAll(IMigrationSource s)
    {
        var list = new List<MigratedUser>();
        await foreach (var u in s.ReadAsync()) list.Add(u);
        return list;
    }
}

public sealed class SuperTokensSourceTests
{
    private static SuperTokensMigrationSource From(string json) =>
        new(() => new MemoryStream(Encoding.UTF8.GetBytes(json)));

    [Test]
    public async Task Maps_wrapped_users_with_all_recipes_roles_and_totp()
    {
        var bcrypt = BCrypt.Net.BCrypt.HashPassword("hunter2!!");
        var json = $$"""
        { "users": [{
          "externalUserId": "ext-1",
          "userRoles": [{ "role": "admin", "tenantIds": ["public"] }],
          "userMetadata": { "first_name": "Jane" },
          "totpDevices": [{ "secretKey": "JBSWY3DPEHPK3PXP", "period": 30, "skew": 1, "deviceName": "phone" }],
          "loginMethods": [
            { "recipeId": "emailpassword", "isPrimary": true, "isVerified": true, "timeJoinedInMSSinceEpoch": 1700000000000,
              "email": "jane@example.com", "passwordHash": "{{bcrypt}}", "hashingAlgorithm": "bcrypt" },
            { "recipeId": "thirdparty", "isVerified": true, "email": "jane@example.com",
              "thirdPartyId": "github", "thirdPartyUserId": "gh-9" },
            { "recipeId": "passwordless", "phoneNumber": "+15551234567" }
          ]
        }]}
        """;

        var users = await Auth0SourceTests.ReadAll(From(json));
        var u = users[0];

        await Assert.That(u.ExternalId).IsEqualTo("ext-1");
        await Assert.That(u.Email).IsEqualTo("jane@example.com");
        await Assert.That(u.EmailVerified).IsTrue();
        await Assert.That(u.Password!.Scheme).IsEqualTo(PasswordHashScheme.Bcrypt);
        await Assert.That(u.ThirdParty[0].ProviderId).IsEqualTo("github");
        await Assert.That(u.PasswordlessPhone).IsTrue();
        await Assert.That(u.Phone).IsEqualTo("+15551234567");
        await Assert.That(u.Roles).Contains("admin");
        await Assert.That(u.TotpSecretBase32).IsEqualTo("JBSWY3DPEHPK3PXP");
        await Assert.That(u.CreatedAt.ToUnixTimeMilliseconds()).IsEqualTo(1700000000000);
    }

    [Test]
    public async Task Firebase_scrypt_is_unsupported()
    {
        var json = """
        { "users": [{ "loginMethods": [
          { "recipeId": "emailpassword", "email": "x@y.com", "passwordHash": "fb$abc", "hashingAlgorithm": "firebase_scrypt" }
        ]}]}
        """;
        var u = (await Auth0SourceTests.ReadAll(From(json)))[0];
        await Assert.That(u.Password!.Scheme).IsEqualTo(PasswordHashScheme.Unsupported);
    }
}

public sealed class MigrationRunnerTests
{
    private static (MigrationRunner runner, FakeUserStore users, UserMetadataService meta) NewRunner()
    {
        var users = new FakeUserStore();
        var meta = new UserMetadataService(new FakeMetadataStore());
        var roles = new RolesService(meta);
        return (new MigrationRunner(users, meta, roles), users, meta);
    }

    private static IMigrationSource Source(params MigratedUser[] u) => new ArraySource(u);

    private sealed class ArraySource(MigratedUser[] users) : IMigrationSource
    {
        public string Name => "Test";
        public async IAsyncEnumerable<MigratedUser> ReadAsync(
            [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct = default)
        {
            foreach (var u in users) { yield return u; await Task.Yield(); }
        }
    }

    [Test]
    public async Task Creates_user_with_password_thirdparty_roles_and_metadata()
    {
        var (runner, users, meta) = NewRunner();
        var bcrypt = BCrypt.Net.BCrypt.HashPassword("hunter2!!");
        var mu = new MigratedUser
        {
            Email = "Jane@Example.com",
            EmailVerified = true,
            Password = new MigratedPassword(bcrypt, PasswordHashScheme.Bcrypt),
            Roles = { "admin" },
            TotpSecretBase32 = "JBSWY3DPEHPK3PXP",
        };
        mu.ThirdParty.Add(new MigratedThirdParty("google", "g-1", "jane@example.com", true));

        var report = await runner.RunAsync(Source(mu));
        await Assert.That(report.Created).IsEqualTo(1);

        var user = await users.FindByEmailAsync("jane@example.com");   // normalized lower-case
        await Assert.That(user).IsNotNull();
        await Assert.That(user!.LoginMethods.Count(m => m.Kind == LoginMethodKind.EmailPassword)).IsEqualTo(1);
        await Assert.That(user.LoginMethods.Count(m => m.Kind == LoginMethodKind.ThirdParty)).IsEqualTo(1);

        var savedRoles = await new RolesService(meta).GetRolesAsync(user.Id);
        await Assert.That(savedRoles).Contains("admin");
        await Assert.That(await meta.GetAsync<TotpProbe>(user.Id, "totp")).IsNotNull();
    }

    [Test]
    public async Task Migrated_bcrypt_user_can_sign_in_with_the_legacy_aware_hasher()
    {
        var (runner, users, _) = NewRunner();
        var bcrypt = BCrypt.Net.BCrypt.HashPassword("hunter2!!");
        await runner.RunAsync(Source(new MigratedUser
        {
            Email = "jane@example.com",
            Password = new MigratedPassword(bcrypt, PasswordHashScheme.Bcrypt),
        }));

        var svc = new EmailPasswordService(users, new LegacyAwarePasswordHasher(new Pbkdf2PasswordHasher()));
        await Assert.That((await svc.SignInAsync("jane@example.com", "hunter2!!")).Success).IsTrue();
        await Assert.That((await svc.SignInAsync("jane@example.com", "wrong")).Success).IsFalse();
    }

    [Test]
    public async Task Skips_existing_user_by_default()
    {
        var (runner, users, _) = NewRunner();
        var mu = new MigratedUser { Email = "dup@x.com" };
        await runner.RunAsync(Source(mu));
        var report = await runner.RunAsync(Source(new MigratedUser { Email = "dup@x.com" }));

        await Assert.That(report.Skipped).IsEqualTo(1);
        await Assert.That((await users.GetAllAsync()).Count).IsEqualTo(1);
    }

    [Test]
    public async Task Merge_attaches_missing_thirdparty_to_existing_user()
    {
        var (runner, users, _) = NewRunner();
        await runner.RunAsync(Source(new MigratedUser { Email = "m@x.com" }));

        var mu = new MigratedUser { Email = "m@x.com" };
        mu.ThirdParty.Add(new MigratedThirdParty("github", "gh-1", "m@x.com", true));
        var report = await runner.RunAsync(Source(mu), new MigrationOptions { OnConflict = ConflictPolicy.Merge });

        await Assert.That(report.Merged).IsEqualTo(1);
        var user = await users.FindByEmailAsync("m@x.com");
        await Assert.That(user!.LoginMethods.Any(m => m.Kind == LoginMethodKind.ThirdParty)).IsTrue();
    }

    [Test]
    public async Task Dry_run_writes_nothing()
    {
        var (runner, users, _) = NewRunner();
        var report = await runner.RunAsync(Source(new MigratedUser { Email = "ghost@x.com" }),
            new MigrationOptions { DryRun = true });

        await Assert.That(report.Created).IsEqualTo(1);
        await Assert.That((await users.GetAllAsync()).Count).IsEqualTo(0);
    }

    [Test]
    public async Task Unsupported_password_warns_and_creates_resettable_account()
    {
        var (runner, users, _) = NewRunner();
        var report = await runner.RunAsync(Source(new MigratedUser
        {
            Email = "scrypt@x.com",
            Password = new MigratedPassword("fb$abc", PasswordHashScheme.Unsupported),
        }));

        await Assert.That(report.Created).IsEqualTo(1);
        await Assert.That(report.PasswordsDropped).IsEqualTo(1);
        var user = await users.FindByEmailAsync("scrypt@x.com");
        var method = user!.LoginMethods.Single(m => m.Kind == LoginMethodKind.EmailPassword);
        await Assert.That(method.PasswordHash).IsNull();   // forces a password reset
    }

    private sealed record TotpProbe(string Secret);
}
