using System.Globalization;
using Klassd.Auth.Abstractions;

namespace Klassd.Auth.Data.Sqlite;

public sealed class SqliteSigningKeyStore(SqliteContext ctx) : ISigningKeyStore
{
    public async Task<IReadOnlyList<StoredSigningKey>> GetAllAsync(CancellationToken ct = default)
    {
        await using var conn = ctx.Open();
        var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT key_id, private_key_pem, created_at FROM signing_keys";
        var list = new List<StoredSigningKey>();
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct))
            list.Add(new StoredSigningKey(r.GetString(0), r.GetString(1),
                DateTimeOffset.Parse(r.GetString(2), CultureInfo.InvariantCulture)));
        return list;
    }

    public async Task AddAsync(StoredSigningKey key, CancellationToken ct = default)
    {
        await using var conn = ctx.Open();
        var cmd = conn.CreateCommand();
        cmd.CommandText = "INSERT INTO signing_keys (key_id, private_key_pem, created_at) VALUES ($id, $pem, $ca)";
        cmd.Parameters.AddWithValue("$id", key.KeyId);
        cmd.Parameters.AddWithValue("$pem", key.PrivateKeyPem);
        cmd.Parameters.AddWithValue("$ca", key.CreatedAt.ToString("o", CultureInfo.InvariantCulture));
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task RemoveAsync(string keyId, CancellationToken ct = default)
    {
        await using var conn = ctx.Open();
        var cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM signing_keys WHERE key_id = $id";
        cmd.Parameters.AddWithValue("$id", keyId);
        await cmd.ExecuteNonQueryAsync(ct);
    }
}

public sealed class SqliteEmailVerificationTokenStore(SqliteContext ctx) : IEmailVerificationTokenStore
{
    public async Task StoreAsync(string tokenHash, string userId, string email, DateTimeOffset expires, CancellationToken ct = default)
    {
        await using var conn = ctx.Open();
        var cmd = conn.CreateCommand();
        cmd.CommandText =
            "INSERT INTO email_verification_tokens (token_hash, user_id, email, expires_at) " +
            "VALUES ($h, $uid, $email, $exp)";
        cmd.Parameters.AddWithValue("$h", tokenHash);
        cmd.Parameters.AddWithValue("$uid", userId);
        cmd.Parameters.AddWithValue("$email", email);
        cmd.Parameters.AddWithValue("$exp", expires.ToString("o", CultureInfo.InvariantCulture));
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task<EmailVerificationToken?> ConsumeAsync(string tokenHash, CancellationToken ct = default)
    {
        await using var conn = ctx.Open();
        await using var tx = await conn.BeginTransactionAsync(ct);

        EmailVerificationToken? token = null;
        var sel = conn.CreateCommand();
        sel.CommandText = "SELECT user_id, email, expires_at FROM email_verification_tokens WHERE token_hash = $h";
        sel.Parameters.AddWithValue("$h", tokenHash);
        await using (var r = await sel.ExecuteReaderAsync(ct))
            if (await r.ReadAsync(ct))
                token = new EmailVerificationToken(r.GetString(0), r.GetString(1),
                    DateTimeOffset.Parse(r.GetString(2), CultureInfo.InvariantCulture));
        if (token is null) return null;

        var del = conn.CreateCommand();
        del.CommandText = "DELETE FROM email_verification_tokens WHERE token_hash = $h";
        del.Parameters.AddWithValue("$h", tokenHash);
        await del.ExecuteNonQueryAsync(ct);
        await tx.CommitAsync(ct);
        return token;
    }
}

public sealed class SqlitePasswordlessCodeStore(SqliteContext ctx) : IPasswordlessCodeStore
{
    public async Task StoreAsync(string identifier, PasswordlessChannel channel, string codeHash, DateTimeOffset expires, CancellationToken ct = default)
    {
        await using var conn = ctx.Open();
        var cmd = conn.CreateCommand();
        cmd.CommandText =
            "INSERT INTO passwordless_codes (identifier, channel, code_hash, expires_at, attempts) " +
            "VALUES ($id, $ch, $h, $exp, 0) " +
            "ON CONFLICT(identifier) DO UPDATE SET channel=$ch, code_hash=$h, expires_at=$exp, attempts=0";
        cmd.Parameters.AddWithValue("$id", identifier);
        cmd.Parameters.AddWithValue("$ch", (int)channel);
        cmd.Parameters.AddWithValue("$h", codeHash);
        cmd.Parameters.AddWithValue("$exp", expires.ToString("o", CultureInfo.InvariantCulture));
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task<PasswordlessCode?> FindAsync(string identifier, CancellationToken ct = default)
    {
        await using var conn = ctx.Open();
        var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT channel, code_hash, expires_at, attempts FROM passwordless_codes WHERE identifier = $id";
        cmd.Parameters.AddWithValue("$id", identifier);
        await using var r = await cmd.ExecuteReaderAsync(ct);
        if (!await r.ReadAsync(ct)) return null;
        return new PasswordlessCode(
            identifier, (PasswordlessChannel)r.GetInt32(0), r.GetString(1),
            DateTimeOffset.Parse(r.GetString(2), CultureInfo.InvariantCulture), r.GetInt32(3));
    }

    public async Task IncrementAttemptsAsync(string identifier, CancellationToken ct = default)
    {
        await using var conn = ctx.Open();
        var cmd = conn.CreateCommand();
        cmd.CommandText = "UPDATE passwordless_codes SET attempts = attempts + 1 WHERE identifier = $id";
        cmd.Parameters.AddWithValue("$id", identifier);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task DeleteAsync(string identifier, CancellationToken ct = default)
    {
        await using var conn = ctx.Open();
        var cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM passwordless_codes WHERE identifier = $id";
        cmd.Parameters.AddWithValue("$id", identifier);
        await cmd.ExecuteNonQueryAsync(ct);
    }
}

public sealed class SqlitePasskeyCredentialStore(SqliteContext ctx) : IPasskeyCredentialStore
{
    private const string Columns =
        "id, user_id, credential_id, public_key, user_handle, sign_count, aaguid, cred_type, nickname, created_at, last_used_at";

    private static PasskeyCredential Read(Microsoft.Data.Sqlite.SqliteDataReader r) => new()
    {
        Id = r.GetString(0),
        UserId = r.GetString(1),
        CredentialId = (byte[])r[2],
        PublicKey = (byte[])r[3],
        UserHandle = (byte[])r[4],
        SignCount = (ulong)r.GetInt64(5),
        AaGuid = Guid.Parse(r.GetString(6)),
        CredType = r.IsDBNull(7) ? null : r.GetString(7),
        Nickname = r.IsDBNull(8) ? null : r.GetString(8),
        CreatedAt = DateTimeOffset.Parse(r.GetString(9), CultureInfo.InvariantCulture),
        LastUsedAt = r.IsDBNull(10) ? null : DateTimeOffset.Parse(r.GetString(10), CultureInfo.InvariantCulture),
    };

    public async Task<PasskeyCredential?> FindByCredentialIdAsync(byte[] credentialId, CancellationToken ct = default)
    {
        await using var conn = ctx.Open();
        var cmd = conn.CreateCommand();
        cmd.CommandText = $"SELECT {Columns} FROM passkey_credentials WHERE credential_id = $c";
        cmd.Parameters.AddWithValue("$c", credentialId);
        await using var r = await cmd.ExecuteReaderAsync(ct);
        return await r.ReadAsync(ct) ? Read(r) : null;
    }

    public Task<IReadOnlyList<PasskeyCredential>> GetByUserIdAsync(string userId, CancellationToken ct = default) =>
        QueryListAsync("user_id = $v", "$v", userId, ct);

    public Task<IReadOnlyList<PasskeyCredential>> GetByUserHandleAsync(byte[] userHandle, CancellationToken ct = default) =>
        QueryListAsync("user_handle = $v", "$v", userHandle, ct);

    private async Task<IReadOnlyList<PasskeyCredential>> QueryListAsync(string where, string param, object value, CancellationToken ct)
    {
        await using var conn = ctx.Open();
        var cmd = conn.CreateCommand();
        cmd.CommandText = $"SELECT {Columns} FROM passkey_credentials WHERE {where}";
        cmd.Parameters.AddWithValue(param, value);
        var list = new List<PasskeyCredential>();
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct)) list.Add(Read(r));
        return list;
    }

    public async Task AddAsync(PasskeyCredential c, CancellationToken ct = default)
    {
        await using var conn = ctx.Open();
        var cmd = conn.CreateCommand();
        cmd.CommandText =
            $"INSERT INTO passkey_credentials ({Columns}) " +
            "VALUES ($id, $uid, $cid, $pk, $uh, $sc, $ag, $ctype, $nick, $ca, $lu)";
        cmd.Parameters.AddWithValue("$id", c.Id);
        cmd.Parameters.AddWithValue("$uid", c.UserId);
        cmd.Parameters.AddWithValue("$cid", c.CredentialId);
        cmd.Parameters.AddWithValue("$pk", c.PublicKey);
        cmd.Parameters.AddWithValue("$uh", c.UserHandle);
        cmd.Parameters.AddWithValue("$sc", (long)c.SignCount);
        cmd.Parameters.AddWithValue("$ag", c.AaGuid.ToString());
        cmd.Parameters.AddWithValue("$ctype", (object?)c.CredType ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$nick", (object?)c.Nickname ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$ca", c.CreatedAt.ToString("o", CultureInfo.InvariantCulture));
        cmd.Parameters.AddWithValue("$lu", (object?)c.LastUsedAt?.ToString("o", CultureInfo.InvariantCulture) ?? DBNull.Value);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task UpdateSignCountAsync(byte[] credentialId, ulong newSignCount, DateTimeOffset usedAt, CancellationToken ct = default)
    {
        await using var conn = ctx.Open();
        var cmd = conn.CreateCommand();
        cmd.CommandText = "UPDATE passkey_credentials SET sign_count = $sc, last_used_at = $lu WHERE credential_id = $c";
        cmd.Parameters.AddWithValue("$sc", (long)newSignCount);
        cmd.Parameters.AddWithValue("$lu", usedAt.ToString("o", CultureInfo.InvariantCulture));
        cmd.Parameters.AddWithValue("$c", credentialId);
        await cmd.ExecuteNonQueryAsync(ct);
    }
}
