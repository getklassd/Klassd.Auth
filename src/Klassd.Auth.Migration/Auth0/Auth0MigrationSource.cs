using System.Runtime.CompilerServices;
using System.Text.Json.Nodes;

namespace Klassd.Auth.Migration.Auth0;

/// <summary>
/// Reads an Auth0 user export and normalizes it for Klassd.Auth. Handles both the bulk-export
/// NDJSON and the user-import JSON array. Passwords come from <c>custom_password_hash</c>
/// (the import template, which can carry bcrypt/argon2) or a top-level <c>password_hash</c>;
/// social connections in <c>identities[]</c> become third-party login methods.
/// </summary>
/// <remarks>
/// Auth0's standard export does not include password hashes — obtain those via Auth0's password
/// export (support) and merge them into the records, or migrate passwordless and let users reset.
/// </remarks>
public sealed class Auth0MigrationSource : IMigrationSource
{
    private readonly Func<Stream> _open;
    private readonly Func<string, string> _mapProvider;

    /// <param name="open">Opens the export stream (called once per run).</param>
    /// <param name="mapProvider">
    /// Maps an Auth0 connection/provider id (e.g. "google-oauth2") to your registered Klassd provider
    /// id (e.g. "google"). Defaults to identity.
    /// </param>
    public Auth0MigrationSource(Func<Stream> open, Func<string, string>? mapProvider = null)
    {
        _open = open;
        _mapProvider = mapProvider ?? (s => s);
    }

    public Auth0MigrationSource(string filePath, Func<string, string>? mapProvider = null)
        : this(() => File.OpenRead(filePath), mapProvider) { }

    public string Name => "Auth0";

    public async IAsyncEnumerable<MigratedUser> ReadAsync([EnumeratorCancellation] CancellationToken ct = default)
    {
        await using var stream = _open();
        await foreach (var o in JsonExportReader.ReadAsync(stream, ct))
            yield return Map(o);
    }

    private MigratedUser Map(JsonObject o)
    {
        var user = new MigratedUser
        {
            ExternalId = o.Str("user_id"),
            Email = o.Str("email"),
            EmailVerified = o.Bool("email_verified"),
            Username = o.Str("username"),
            Phone = o.Str("phone_number"),
            Disabled = o.Bool("blocked"),
            CreatedAt = o.Date("created_at"),
            Password = MapPassword(o),
        };

        MapIdentities(o, user);
        MapMetadata(o, user);
        return user;
    }

    private static MigratedPassword? MapPassword(JsonObject o)
    {
        if (o.TryGetPropertyValue("custom_password_hash", out var n) && n is JsonObject cph)
        {
            var algorithm = cph.Str("algorithm")?.ToLowerInvariant();
            var value = (cph.TryGetPropertyValue("hash", out var h) && h is JsonObject ho ? ho.Str("value") : null)
                        ?? cph.Str("value");
            if (string.IsNullOrEmpty(value)) return null;

            var scheme = algorithm switch
            {
                "bcrypt" when value.StartsWith("$2", StringComparison.Ordinal) => PasswordHashScheme.Bcrypt,
                "argon2" or "argon2id" or "argon2i" => PasswordHashScheme.Argon2,
                _ => PasswordHashFormat.Detect(value),  // fall back to prefix sniffing
            };
            return new MigratedPassword(value, scheme);
        }

        if (o.Str("password_hash") is { Length: > 0 } ph)
            return new MigratedPassword(ph, PasswordHashFormat.Detect(ph));

        return null;
    }

    private void MapIdentities(JsonObject o, MigratedUser user)
    {
        if (!o.TryGetPropertyValue("identities", out var n) || n is not JsonArray identities) return;

        foreach (var node in identities)
        {
            if (node is not JsonObject id) continue;
            var provider = id.Str("provider");
            if (string.IsNullOrEmpty(provider)) continue;

            // The "auth0" provider is the database (email/password) connection — not a social link.
            if (provider.Equals("auth0", StringComparison.OrdinalIgnoreCase)) continue;

            var providerUserId = id.Str("user_id");
            if (string.IsNullOrEmpty(providerUserId)) continue;

            user.ThirdParty.Add(new MigratedThirdParty(
                _mapProvider(provider), providerUserId,
                id.Str("email") ?? user.Email, id.Bool("email_verified", user.EmailVerified)));
        }
    }

    private static void MapMetadata(JsonObject o, MigratedUser user)
    {
        foreach (var bag in new[] { "user_metadata", "app_metadata" })
            if (o.TryGetPropertyValue(bag, out var n) && n is JsonObject meta)
                foreach (var (k, v) in meta)
                    user.Metadata[k] = v?.DeepClone();

        // Auth0 RBAC roles, when carried in app_metadata.roles.
        if (o.TryGetPropertyValue("app_metadata", out var an) && an is JsonObject app
            && app.TryGetPropertyValue("roles", out var rn) && rn is JsonArray rolesArr)
            foreach (var r in rolesArr)
                if (r?.GetValue<string?>() is { Length: > 0 } role)
                    user.Roles.Add(role);
    }
}
