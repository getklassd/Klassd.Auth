using System.Text.Json;
using Klassd.Auth.Abstractions;
using Npgsql;
using NpgsqlTypes;

namespace Klassd.Auth.Data.Postgres;

internal static class PgMap
{
    public const string LoginMethodColumns =
        "id, user_id, kind, email, email_verified, password_hash, provider_id, provider_user_id, created_at";

    public static LoginMethod ReadLoginMethod(NpgsqlDataReader r) => new()
    {
        Id = r.GetString(0),
        UserId = r.GetString(1),
        Kind = (LoginMethodKind)r.GetInt32(2),
        Email = r.IsDBNull(3) ? null : r.GetString(3),
        EmailVerified = r.GetBoolean(4),
        PasswordHash = r.IsDBNull(5) ? null : r.GetString(5),
        ProviderId = r.IsDBNull(6) ? null : r.GetString(6),
        ProviderUserId = r.IsDBNull(7) ? null : r.GetString(7),
        CreatedAt = r.GetFieldValue<DateTimeOffset>(8),
    };

    public static void BindLoginMethod(NpgsqlCommand cmd, LoginMethod m)
    {
        cmd.Parameters.AddWithValue("id", m.Id);
        cmd.Parameters.AddWithValue("uid", m.UserId);
        cmd.Parameters.AddWithValue("kind", (int)m.Kind);
        cmd.Parameters.AddWithValue("email", (object?)m.Email ?? DBNull.Value);
        cmd.Parameters.AddWithValue("ev", m.EmailVerified);
        cmd.Parameters.AddWithValue("ph", (object?)m.PasswordHash ?? DBNull.Value);
        cmd.Parameters.AddWithValue("pid", (object?)m.ProviderId ?? DBNull.Value);
        cmd.Parameters.AddWithValue("puid", (object?)m.ProviderUserId ?? DBNull.Value);
        cmd.Parameters.AddWithValue("ca", m.CreatedAt);
    }
}

public sealed class PostgresUserStore(PostgresContext ctx) : IUserStore
{
    private const string UserColumns = "id, username, primary_email, disabled, created_at";

    private static User ReadUser(NpgsqlDataReader r) => new()
    {
        Id = r.GetString(0),
        Username = r.IsDBNull(1) ? null : r.GetString(1),
        PrimaryEmail = r.IsDBNull(2) ? null : r.GetString(2),
        Disabled = r.GetBoolean(3),
        CreatedAt = r.GetFieldValue<DateTimeOffset>(4),
    };

    public Task<User?> FindByIdAsync(string userId, CancellationToken ct = default) =>
        FindUserAsync("id = @v", userId, ct);

    public Task<User?> FindByUsernameAsync(string username, CancellationToken ct = default) =>
        FindUserAsync("username = @v", username, ct);

    public Task<User?> FindByEmailAsync(string email, CancellationToken ct = default) =>
        FindUserAsync("primary_email = @v", email, ct);

    private async Task<User?> FindUserAsync(string where, string value, CancellationToken ct)
    {
        await using var conn = await ctx.OpenAsync(ct);
        User? user = null;
        await using (var u = conn.CreateCommand())
        {
            u.CommandText = $"SELECT {UserColumns} FROM users WHERE {where} LIMIT 1";
            u.Parameters.AddWithValue("v", value);
            await using var r = await u.ExecuteReaderAsync(ct);
            if (await r.ReadAsync(ct)) user = ReadUser(r);
        }
        if (user is null) return null;

        await LoadLoginMethods(conn, user, ct);
        return user;
    }

    private static async Task LoadLoginMethods(NpgsqlConnection conn, User user, CancellationToken ct)
    {
        await using var lm = conn.CreateCommand();
        lm.CommandText = $"SELECT {PgMap.LoginMethodColumns} FROM login_methods WHERE user_id = @id";
        lm.Parameters.AddWithValue("id", user.Id);
        await using var lr = await lm.ExecuteReaderAsync(ct);
        while (await lr.ReadAsync(ct))
            user.LoginMethods.Add(PgMap.ReadLoginMethod(lr));
    }

    public async Task<IReadOnlyList<User>> GetAllAsync(CancellationToken ct = default)
    {
        await using var conn = await ctx.OpenAsync(ct);
        var list = new List<User>();
        await using (var cmd = conn.CreateCommand())
        {
            cmd.CommandText = $"SELECT {UserColumns} FROM users ORDER BY created_at";
            await using var r = await cmd.ExecuteReaderAsync(ct);
            while (await r.ReadAsync(ct)) list.Add(ReadUser(r));
        }
        foreach (var user in list) await LoadLoginMethods(conn, user, ct);
        return list;
    }

    public Task<LoginMethod?> FindEmailPasswordAsync(string email, CancellationToken ct = default) =>
        FindMethodAsync("kind = @k AND email = @email", c =>
        {
            c.Parameters.AddWithValue("k", (int)LoginMethodKind.EmailPassword);
            c.Parameters.AddWithValue("email", email);
        }, ct);

    public Task<LoginMethod?> FindThirdPartyAsync(string providerId, string providerUserId, CancellationToken ct = default) =>
        FindMethodAsync("provider_id = @pid AND provider_user_id = @puid", c =>
        {
            c.Parameters.AddWithValue("pid", providerId);
            c.Parameters.AddWithValue("puid", providerUserId);
        }, ct);

    private async Task<LoginMethod?> FindMethodAsync(string where, Action<NpgsqlCommand> bind, CancellationToken ct)
    {
        await using var conn = await ctx.OpenAsync(ct);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = $"SELECT {PgMap.LoginMethodColumns} FROM login_methods WHERE {where} LIMIT 1";
        bind(cmd);
        await using var r = await cmd.ExecuteReaderAsync(ct);
        return await r.ReadAsync(ct) ? PgMap.ReadLoginMethod(r) : null;
    }

    public async Task AddUserAsync(User user, CancellationToken ct = default)
    {
        await using var conn = await ctx.OpenAsync(ct);
        await using var tx = await conn.BeginTransactionAsync(ct);

        await using (var u = conn.CreateCommand())
        {
            u.CommandText =
                "INSERT INTO users (id, username, primary_email, disabled, created_at) " +
                "VALUES (@id, @un, @email, @dis, @ca)";
            u.Parameters.AddWithValue("id", user.Id);
            u.Parameters.AddWithValue("un", (object?)user.Username ?? DBNull.Value);
            u.Parameters.AddWithValue("email", (object?)user.PrimaryEmail ?? DBNull.Value);
            u.Parameters.AddWithValue("dis", user.Disabled);
            u.Parameters.AddWithValue("ca", user.CreatedAt);
            await u.ExecuteNonQueryAsync(ct);
        }

        foreach (var m in user.LoginMethods)
        {
            await using var lm = conn.CreateCommand();
            lm.CommandText =
                $"INSERT INTO login_methods ({PgMap.LoginMethodColumns}) " +
                "VALUES (@id, @uid, @kind, @email, @ev, @ph, @pid, @puid, @ca)";
            PgMap.BindLoginMethod(lm, m);
            await lm.ExecuteNonQueryAsync(ct);
        }
        await tx.CommitAsync(ct);
    }

    public async Task UpdateUserAsync(User user, CancellationToken ct = default)
    {
        await using var conn = await ctx.OpenAsync(ct);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "UPDATE users SET username=@un, primary_email=@email, disabled=@dis WHERE id=@id";
        cmd.Parameters.AddWithValue("id", user.Id);
        cmd.Parameters.AddWithValue("un", (object?)user.Username ?? DBNull.Value);
        cmd.Parameters.AddWithValue("email", (object?)user.PrimaryEmail ?? DBNull.Value);
        cmd.Parameters.AddWithValue("dis", user.Disabled);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task UpdateLoginMethodAsync(LoginMethod method, CancellationToken ct = default)
    {
        await using var conn = await ctx.OpenAsync(ct);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText =
            "UPDATE login_methods SET email=@email, email_verified=@ev, password_hash=@ph, " +
            "provider_id=@pid, provider_user_id=@puid WHERE id=@id";
        PgMap.BindLoginMethod(cmd, method);
        await cmd.ExecuteNonQueryAsync(ct);
    }
}

public sealed class PostgresSessionStore(PostgresContext ctx) : ISessionStore
{
    public async Task<SessionEntity?> FindAsync(string handle, CancellationToken ct = default)
    {
        await using var conn = await ctx.OpenAsync(ct);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText =
            "SELECT handle, user_id, refresh_token_hash, created_at, refresh_expires_at, revoked, session_data::text " +
            "FROM sessions WHERE handle = @h";
        cmd.Parameters.AddWithValue("h", handle);
        await using var r = await cmd.ExecuteReaderAsync(ct);
        if (!await r.ReadAsync(ct)) return null;
        return new SessionEntity
        {
            Handle = r.GetString(0),
            UserId = r.GetString(1),
            RefreshTokenHash = r.GetString(2),
            CreatedAt = r.GetFieldValue<DateTimeOffset>(3),
            RefreshExpiresAt = r.GetFieldValue<DateTimeOffset>(4),
            Revoked = r.GetBoolean(5),
            SessionData = JsonSerializer.Deserialize<Dictionary<string, string>>(r.GetString(6)) ?? [],
        };
    }

    public async Task AddAsync(SessionEntity s, CancellationToken ct = default)
    {
        await using var conn = await ctx.OpenAsync(ct);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText =
            "INSERT INTO sessions (handle, user_id, refresh_token_hash, created_at, refresh_expires_at, revoked, session_data) " +
            "VALUES (@h, @uid, @rth, @ca, @rea, @rev, @sd)";
        Bind(cmd, s);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task UpdateAsync(SessionEntity s, CancellationToken ct = default)
    {
        await using var conn = await ctx.OpenAsync(ct);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText =
            "UPDATE sessions SET refresh_token_hash=@rth, refresh_expires_at=@rea, revoked=@rev, session_data=@sd " +
            "WHERE handle=@h";
        Bind(cmd, s);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task RevokeAsync(string handle, CancellationToken ct = default)
    {
        await using var conn = await ctx.OpenAsync(ct);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "UPDATE sessions SET revoked = true WHERE handle = @h";
        cmd.Parameters.AddWithValue("h", handle);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    private static void Bind(NpgsqlCommand cmd, SessionEntity s)
    {
        cmd.Parameters.AddWithValue("h", s.Handle);
        cmd.Parameters.AddWithValue("uid", s.UserId);
        cmd.Parameters.AddWithValue("rth", s.RefreshTokenHash);
        cmd.Parameters.AddWithValue("ca", s.CreatedAt);
        cmd.Parameters.AddWithValue("rea", s.RefreshExpiresAt);
        cmd.Parameters.AddWithValue("rev", s.Revoked);
        cmd.Parameters.Add(new NpgsqlParameter("sd", NpgsqlDbType.Jsonb)
        {
            Value = JsonSerializer.Serialize(s.SessionData)
        });
    }
}

public sealed class PostgresUserMetadataStore(PostgresContext ctx) : IUserMetadataStore
{
    public async Task<string?> GetAsync(string userId, CancellationToken ct = default)
    {
        await using var conn = await ctx.OpenAsync(ct);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT json::text FROM user_metadata WHERE user_id = @id";
        cmd.Parameters.AddWithValue("id", userId);
        return (await cmd.ExecuteScalarAsync(ct)) as string;
    }

    public async Task SetAsync(string userId, string json, CancellationToken ct = default)
    {
        await using var conn = await ctx.OpenAsync(ct);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText =
            "INSERT INTO user_metadata (user_id, json) VALUES (@id, @json) " +
            "ON CONFLICT (user_id) DO UPDATE SET json = excluded.json";
        cmd.Parameters.AddWithValue("id", userId);
        cmd.Parameters.Add(new NpgsqlParameter("json", NpgsqlDbType.Jsonb) { Value = json });
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task ClearAsync(string userId, CancellationToken ct = default)
    {
        await using var conn = await ctx.OpenAsync(ct);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM user_metadata WHERE user_id = @id";
        cmd.Parameters.AddWithValue("id", userId);
        await cmd.ExecuteNonQueryAsync(ct);
    }
}
