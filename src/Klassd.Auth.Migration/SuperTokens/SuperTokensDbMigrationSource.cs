using System.Data.Common;
using System.Runtime.CompilerServices;
using System.Text.Json.Nodes;

namespace Klassd.Auth.Migration.SuperTokens;

/// <summary>
/// Reads users straight out of a running SuperTokens core database instead of a JSON export.
/// Works against any ADO.NET provider (the SuperTokens schema is identical on PostgreSQL and MySQL)
/// — supply a <see cref="DbConnection"/> factory, or use the <c>Klassd.Auth.Migration.SuperTokens.Postgres</c>
/// / <c>.MySql</c> packages which take a connection string.
/// </summary>
/// <remarks>
/// Recipe users are grouped by SuperTokens' <c>primary_or_recipe_user_id</c> so a linked account
/// (email/password + a social login, say) becomes one Klassd user with multiple login methods.
/// bcrypt/argon2 password hashes carry over verbatim; Firebase scrypt hashes can't be verified and
/// force a reset (see <see cref="PasswordHashScheme"/>).
/// </remarks>
public class SuperTokensDbMigrationSource(Func<DbConnection> connectionFactory, SuperTokensDbOptions? options = null)
    : IMigrationSource
{
    private readonly SuperTokensDbOptions _opt = options ?? new SuperTokensDbOptions();

    public string Name => "SuperTokens (database)";

    public async IAsyncEnumerable<MigratedUser> ReadAsync([EnumeratorCancellation] CancellationToken ct = default)
    {
        await using var conn = connectionFactory();
        await conn.OpenAsync(ct);

        var aggregates = await LoadAsync(conn, ct);
        foreach (var agg in aggregates.Values)
            yield return agg.Build();
    }

    private async Task<Dictionary<string, Agg>> LoadAsync(DbConnection conn, CancellationToken ct)
    {
        var primaryOf = new Dictionary<string, string>(StringComparer.Ordinal);   // recipe user_id -> primary id
        var aggs = new Dictionary<string, Agg>(StringComparer.Ordinal);           // primary id -> aggregate
        var verified = new HashSet<string>(StringComparer.OrdinalIgnoreCase);     // "userId\0emailLower"

        Agg For(string userId)
        {
            var pid = primaryOf.GetValueOrDefault(userId, userId);
            return aggs.TryGetValue(pid, out var a) ? a : aggs[pid] = new Agg(pid);
        }

        // 1. Linking map: every user_id -> its primary (canonical) user id.
        await Query(conn, $"SELECT user_id, primary_or_recipe_user_id FROM {T("app_id_to_user_id")} WHERE app_id = @appId", ct,
            r => primaryOf[r.GetString(0)] = r.GetString(1));

        // Ensure an aggregate exists for every primary user even if it has no recipe rows we read.
        foreach (var pid in primaryOf.Values) _ = aggs.TryGetValue(pid, out _) ? null : aggs[pid] = new Agg(pid);

        // 2. Verified emails (presence == verified), keyed by recipe user_id + email.
        await Query(conn, $"SELECT user_id, email FROM {T("emailverification_verified_emails")} WHERE app_id = @appId", ct,
            r => verified.Add(VKey(r.GetString(0), r.GetString(1))));

        // 3. Email/password recipe users.
        await Query(conn, $"SELECT user_id, email, password_hash, time_joined FROM {T("emailpassword_users")} WHERE app_id = @appId", ct,
            r =>
            {
                var (uid, email, hash) = (r.GetString(0), r.GetString(1), r.GetString(2));
                var a = For(uid);
                a.Joined(r.GetInt64(3));
                a.Password ??= new MigratedPassword(hash, PasswordHashFormat.Detect(hash));
                a.OfferEmail(uid, email, verified.Contains(VKey(uid, email)));
            });

        // 4. Third-party recipe users.
        await Query(conn, $"SELECT user_id, third_party_id, third_party_user_id, email, time_joined FROM {T("thirdparty_users")} WHERE app_id = @appId", ct,
            r =>
            {
                var (uid, providerId, providerUserId) = (r.GetString(0), r.GetString(1), r.GetString(2));
                var email = r.IsDBNull(3) ? null : r.GetString(3);
                var a = For(uid);
                a.Joined(r.GetInt64(4));
                var isVerified = email is not null && verified.Contains(VKey(uid, email));
                a.ThirdParty.Add(new MigratedThirdParty(MapProvider(providerId), providerUserId, email, isVerified));
                if (email is not null) a.OfferEmail(uid, email, isVerified);
            });

        // 5. Passwordless recipe users.
        await Query(conn, $"SELECT user_id, email, phone_number, time_joined FROM {T("passwordless_users")} WHERE app_id = @appId", ct,
            r =>
            {
                var uid = r.GetString(0);
                var email = r.IsDBNull(1) ? null : r.GetString(1);
                var phone = r.IsDBNull(2) ? null : r.GetString(2);
                var a = For(uid);
                a.Joined(r.GetInt64(3));
                if (email is not null) { a.PasswordlessEmail = true; a.OfferEmail(uid, email, verified.Contains(VKey(uid, email))); }
                if (phone is not null) { a.PasswordlessPhone = true; a.Phone = phone; }
            });

        // 6. Roles — assigned against the primary user id (deduped across tenants).
        await Query(conn, $"SELECT user_id, role FROM {T("user_roles")} WHERE app_id = @appId", ct,
            r => { var a = For(r.GetString(0)); if (!a.Roles.Contains(r.GetString(1))) a.Roles.Add(r.GetString(1)); });

        // 7. TOTP devices — prefer a verified one.
        await Query(conn, $"SELECT user_id, secret_key, verified FROM {T("totp_user_devices")} WHERE app_id = @appId", ct,
            r =>
            {
                var a = For(r.GetString(0));
                var secret = r.GetString(1);
                if (a.Totp is null || r.GetBoolean(2)) a.Totp = secret;
            });

        // 8. User metadata (JSON document).
        await Query(conn, $"SELECT user_id, user_metadata FROM {T("user_metadata")} WHERE app_id = @appId", ct,
            r =>
            {
                var a = For(r.GetString(0));
                if (!r.IsDBNull(1) && JsonNode.Parse(r.GetString(1)) is JsonObject obj)
                    foreach (var (k, v) in obj) a.Meta[k] = v?.DeepClone();
            });

        // 9. External user-id mapping — keep the customer-facing id for traceability.
        await Query(conn, $"SELECT supertokens_user_id, external_user_id FROM {T("userid_mapping")} WHERE app_id = @appId", ct,
            r => { if (aggs.TryGetValue(r.GetString(0), out var a)) a.ExternalId = r.GetString(1); });

        return aggs;
    }

    private string MapProvider(string id) => _opt.MapProvider?.Invoke(id) ?? id;

    private string T(string name)
    {
        var table = string.IsNullOrEmpty(_opt.TablePrefix) ? name : $"{_opt.TablePrefix}_{name}";
        return string.IsNullOrEmpty(_opt.TableSchema) ? table : $"{_opt.TableSchema}.{table}";
    }

    private static string VKey(string userId, string email) => $"{userId}\0{email.ToLowerInvariant()}";

    private async Task Query(DbConnection conn, string sql, CancellationToken ct, Action<DbDataReader> onRow)
    {
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = sql;
        var p = cmd.CreateParameter();
        p.ParameterName = "appId";
        p.Value = _opt.AppId;
        cmd.Parameters.Add(p);

        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct)) onRow(reader);
    }

    /// <summary>Per-primary-user accumulator built up as the recipe tables are read.</summary>
    private sealed class Agg(string primaryId)
    {
        public string? ExternalId;
        public MigratedPassword? Password;
        public string? Phone;
        public bool PasswordlessEmail, PasswordlessPhone;
        public readonly List<MigratedThirdParty> ThirdParty = [];
        public readonly List<string> Roles = [];
        public string? Totp;
        public readonly Dictionary<string, JsonNode?> Meta = [];

        private long? _minJoined;
        private string? _firstEmail, _firstEmailVerified;
        private string? _primaryEmail, _primaryEmailVerified;

        public void Joined(long ms) => _minJoined = _minJoined is { } m ? Math.Min(m, ms) : ms;

        public void OfferEmail(string recipeUserId, string email, bool emailVerified)
        {
            _firstEmail ??= email;
            if (emailVerified) _firstEmailVerified ??= email;

            // The recipe user whose id IS the primary id owns the canonical login email.
            if (string.Equals(recipeUserId, primaryId, StringComparison.Ordinal))
            {
                _primaryEmail = email;
                if (emailVerified) _primaryEmailVerified = email;
            }
        }

        public MigratedUser Build()
        {
            var email = _primaryEmail ?? _firstEmail;
            var verified = email is not null
                && string.Equals(email, _primaryEmailVerified ?? _firstEmailVerified, StringComparison.OrdinalIgnoreCase);

            var user = new MigratedUser
            {
                ExternalId = ExternalId ?? primaryId,
                Email = email,
                EmailVerified = verified,
                Phone = Phone,
                Password = Password,
                PasswordlessEmail = PasswordlessEmail,
                PasswordlessPhone = PasswordlessPhone,
                TotpSecretBase32 = Totp,
                CreatedAt = _minJoined is { } ms ? DateTimeOffset.FromUnixTimeMilliseconds(ms) : default,
            };
            user.ThirdParty.AddRange(ThirdParty);
            user.Roles.AddRange(Roles);
            foreach (var (k, v) in Meta) user.Metadata[k] = v;
            return user;
        }
    }
}
