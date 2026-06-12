using Klassd.Auth.Abstractions;

namespace Klassd.Auth.Data.Sqlite;

/// <summary>Creates the Klassd.Auth tables if they don't exist. Idempotent.</summary>
public sealed class SqliteSchemaInitializer(SqliteContext ctx) : IAuthStorageInitializer
{
    public async Task InitializeAsync(CancellationToken ct = default)
    {
        await using var conn = ctx.Open();
        var cmd = conn.CreateCommand();
        cmd.CommandText =
            """
            CREATE TABLE IF NOT EXISTS users (
                id            TEXT PRIMARY KEY,
                username      TEXT,
                primary_email TEXT,
                disabled      INTEGER NOT NULL DEFAULT 0,
                created_at    TEXT NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS ux_users_username ON users(username) WHERE username IS NOT NULL;
            CREATE INDEX IF NOT EXISTS ix_users_email ON users(primary_email);

            CREATE TABLE IF NOT EXISTS login_methods (
                id               TEXT PRIMARY KEY,
                user_id          TEXT NOT NULL,
                kind             INTEGER NOT NULL,
                email            TEXT,
                email_verified   INTEGER NOT NULL DEFAULT 0,
                password_hash    TEXT,
                provider_id      TEXT,
                provider_user_id TEXT,
                created_at       TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_lm_user      ON login_methods(user_id);
            CREATE INDEX IF NOT EXISTS ix_lm_email     ON login_methods(kind, email);
            CREATE INDEX IF NOT EXISTS ix_lm_provider  ON login_methods(provider_id, provider_user_id);

            CREATE TABLE IF NOT EXISTS sessions (
                handle             TEXT PRIMARY KEY,
                user_id            TEXT NOT NULL,
                refresh_token_hash TEXT NOT NULL,
                created_at         TEXT NOT NULL,
                refresh_expires_at TEXT NOT NULL,
                revoked            INTEGER NOT NULL DEFAULT 0,
                session_data       TEXT NOT NULL DEFAULT '{}'
            );

            CREATE TABLE IF NOT EXISTS user_metadata (
                user_id TEXT PRIMARY KEY,
                json    TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS signing_keys (
                key_id          TEXT PRIMARY KEY,
                private_key_pem TEXT NOT NULL,
                created_at      TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS email_verification_tokens (
                token_hash TEXT PRIMARY KEY,
                user_id    TEXT NOT NULL,
                email      TEXT NOT NULL,
                expires_at TEXT NOT NULL
            );
            """;
        await cmd.ExecuteNonQueryAsync(ct);
    }
}
