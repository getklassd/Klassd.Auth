using Klassd.Auth.Abstractions;

namespace Klassd.Auth.Data.Postgres;

public sealed class PostgresSigningKeyStore(PostgresContext ctx) : ISigningKeyStore
{
    public async Task<IReadOnlyList<StoredSigningKey>> GetAllAsync(CancellationToken ct = default)
    {
        await using var conn = await ctx.OpenAsync(ct);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT key_id, private_key_pem, created_at FROM signing_keys";
        var list = new List<StoredSigningKey>();
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct))
            list.Add(new StoredSigningKey(r.GetString(0), r.GetString(1), r.GetFieldValue<DateTimeOffset>(2)));
        return list;
    }

    public async Task AddAsync(StoredSigningKey key, CancellationToken ct = default)
    {
        await using var conn = await ctx.OpenAsync(ct);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "INSERT INTO signing_keys (key_id, private_key_pem, created_at) VALUES (@id, @pem, @ca)";
        cmd.Parameters.AddWithValue("id", key.KeyId);
        cmd.Parameters.AddWithValue("pem", key.PrivateKeyPem);
        cmd.Parameters.AddWithValue("ca", key.CreatedAt);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task RemoveAsync(string keyId, CancellationToken ct = default)
    {
        await using var conn = await ctx.OpenAsync(ct);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM signing_keys WHERE key_id = @id";
        cmd.Parameters.AddWithValue("id", keyId);
        await cmd.ExecuteNonQueryAsync(ct);
    }
}

public sealed class PostgresEmailVerificationTokenStore(PostgresContext ctx) : IEmailVerificationTokenStore
{
    public async Task StoreAsync(string tokenHash, string userId, string email, DateTimeOffset expires, CancellationToken ct = default)
    {
        await using var conn = await ctx.OpenAsync(ct);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText =
            "INSERT INTO email_verification_tokens (token_hash, user_id, email, expires_at) " +
            "VALUES (@h, @uid, @email, @exp)";
        cmd.Parameters.AddWithValue("h", tokenHash);
        cmd.Parameters.AddWithValue("uid", userId);
        cmd.Parameters.AddWithValue("email", email);
        cmd.Parameters.AddWithValue("exp", expires);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task<EmailVerificationToken?> ConsumeAsync(string tokenHash, CancellationToken ct = default)
    {
        await using var conn = await ctx.OpenAsync(ct);
        await using var cmd = conn.CreateCommand();
        // Delete-returning so lookup + consume is atomic in one round trip.
        cmd.CommandText =
            "DELETE FROM email_verification_tokens WHERE token_hash = @h RETURNING user_id, email, expires_at";
        cmd.Parameters.AddWithValue("h", tokenHash);
        await using var r = await cmd.ExecuteReaderAsync(ct);
        return await r.ReadAsync(ct)
            ? new EmailVerificationToken(r.GetString(0), r.GetString(1), r.GetFieldValue<DateTimeOffset>(2))
            : null;
    }
}
