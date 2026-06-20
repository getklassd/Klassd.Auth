using System.Runtime.CompilerServices;
using System.Text.Json.Nodes;

namespace Klassd.Auth.Migration.SuperTokens;

/// <summary>
/// Reads a SuperTokens user export / bulk-import document and normalizes it for Klassd.Auth.
/// Accepts either the wrapped form (<c>{ "users": [ … ] }</c>) emitted by the bulk-import API or a
/// bare JSON array. Each user's <c>loginMethods[]</c> (emailpassword / thirdparty / passwordless)
/// map to Klassd login methods; <c>userRoles</c>, <c>userMetadata</c> and <c>totpDevices</c> carry over.
/// </summary>
/// <remarks>
/// SuperTokens <c>firebase_scrypt</c> hashes cannot be verified by Klassd and are dropped (the user
/// must reset). bcrypt and argon2 hashes carry over and verify at login.
/// </remarks>
public sealed class SuperTokensMigrationSource : IMigrationSource
{
    private readonly Func<Stream> _open;
    private readonly Func<string, string> _mapProvider;

    public SuperTokensMigrationSource(Func<Stream> open, Func<string, string>? mapProvider = null)
    {
        _open = open;
        _mapProvider = mapProvider ?? (s => s);
    }

    public SuperTokensMigrationSource(string filePath, Func<string, string>? mapProvider = null)
        : this(() => File.OpenRead(filePath), mapProvider) { }

    public string Name => "SuperTokens";

    public async IAsyncEnumerable<MigratedUser> ReadAsync([EnumeratorCancellation] CancellationToken ct = default)
    {
        await using var stream = _open();
        await foreach (var o in JsonExportReader.ReadAsync(stream, ct))
        {
            // The bulk-import shape wraps the array as { "users": [ … ] }; unwrap if needed.
            if (o.TryGetPropertyValue("users", out var n) && n is JsonArray wrapped)
            {
                foreach (var node in wrapped)
                    if (node is JsonObject u) yield return Map(u);
            }
            else
            {
                yield return Map(o);
            }
        }
    }

    private MigratedUser Map(JsonObject o)
    {
        var user = new MigratedUser { ExternalId = o.Str("externalUserId") };

        long? earliestJoined = null;
        var primaryEmail = (string?)null;
        var firstEmail = (string?)null;

        if (o.TryGetPropertyValue("loginMethods", out var lmn) && lmn is JsonArray methods)
        {
            foreach (var node in methods)
            {
                if (node is not JsonObject m) continue;
                var recipe = m.Str("recipeId")?.ToLowerInvariant();
                var isVerified = m.Bool("isVerified");
                var isPrimary = m.Bool("isPrimary");
                var email = m.Str("email");
                if (email is not null)
                {
                    firstEmail ??= email;
                    if (isPrimary) primaryEmail = email;
                }

                if (Joined(m) is { } j) earliestJoined = earliestJoined is null ? j : Math.Min(earliestJoined.Value, j);

                switch (recipe)
                {
                    case "emailpassword":
                        if (isVerified) user.EmailVerified = true;
                        user.Password ??= MapPassword(m);
                        break;

                    case "thirdparty":
                        var pid = m.Str("thirdPartyId");
                        var puid = m.Str("thirdPartyUserId");
                        if (!string.IsNullOrEmpty(pid) && !string.IsNullOrEmpty(puid))
                            user.ThirdParty.Add(new MigratedThirdParty(_mapProvider(pid), puid, email, isVerified));
                        break;

                    case "passwordless":
                        if (email is not null) { user.PasswordlessEmail = true; if (isVerified) user.EmailVerified = true; }
                        if (m.Str("phoneNumber") is { Length: > 0 } phone) { user.PasswordlessPhone = true; user.Phone = phone; }
                        break;
                }
            }
        }

        user.Email = primaryEmail ?? firstEmail;
        if (earliestJoined is { } ms) user.CreatedAt = DateTimeOffset.FromUnixTimeMilliseconds(ms);

        MapRoles(o, user);
        MapMetadata(o, user);
        MapTotp(o, user);
        return user;
    }

    private static MigratedPassword? MapPassword(JsonObject m)
    {
        var hash = m.Str("passwordHash");
        if (string.IsNullOrEmpty(hash)) return null;

        var scheme = m.Str("hashingAlgorithm")?.ToLowerInvariant() switch
        {
            "bcrypt" => PasswordHashScheme.Bcrypt,
            "argon2" => PasswordHashScheme.Argon2,
            "firebase_scrypt" => PasswordHashScheme.Unsupported,
            _ => PasswordHashFormat.Detect(hash),
        };
        return new MigratedPassword(hash, scheme);
    }

    private static long? Joined(JsonObject m) =>
        m.TryGetPropertyValue("timeJoinedInMSSinceEpoch", out var n) && n is JsonValue v && v.TryGetValue<long>(out var ms)
            ? ms : null;

    private static void MapRoles(JsonObject o, MigratedUser user)
    {
        if (!o.TryGetPropertyValue("userRoles", out var n) || n is not JsonArray arr) return;
        foreach (var node in arr)
        {
            // Either ["admin", …] or [{ "role": "admin", "tenantIds": [...] }, …].
            var role = node is JsonObject ro ? ro.Str("role") : node?.GetValue<string?>();
            if (!string.IsNullOrEmpty(role)) user.Roles.Add(role);
        }
    }

    private static void MapMetadata(JsonObject o, MigratedUser user)
    {
        if (o.TryGetPropertyValue("userMetadata", out var n) && n is JsonObject meta)
            foreach (var (k, v) in meta)
                user.Metadata[k] = v?.DeepClone();
    }

    private static void MapTotp(JsonObject o, MigratedUser user)
    {
        if (o.TryGetPropertyValue("totpDevices", out var n) && n is JsonArray devices)
            foreach (var node in devices)
                if (node is JsonObject d && d.Str("secretKey") is { Length: > 0 } secret)
                {
                    user.TotpSecretBase32 = secret;  // first verified secret wins
                    break;
                }
    }
}
