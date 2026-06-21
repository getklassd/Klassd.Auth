using Klassd.Auth.Abstractions;

namespace Klassd.Auth.Data.Sqlite;

/// <summary>Creates the Klassd.Auth tables if they don't exist. Idempotent.</summary>
public sealed class SqliteSchemaInitializer(SqliteContext ctx) : IAuthStorageInitializer
{
    public async Task InitializeAsync(CancellationToken ct = default)
    {
        await using var conn = ctx.Open();

        // Best-effort column adds for pre-existing DBs (fresh DBs get these via CREATE below). Run BEFORE
        // the CREATE/index block so the tenant-scoped indexes can reference tenant_id on upgraded DBs.
        // SQLite has no ADD COLUMN IF NOT EXISTS, so swallow dupes; ALTER on a not-yet-created table (fresh
        // DB) also throws and is swallowed — the CREATE then builds the table with the columns present.
        foreach (var alter in new[]
                 {
                     "ALTER TABLE users ADD COLUMN phone TEXT",
                     "ALTER TABLE login_methods ADD COLUMN phone TEXT",
                     "ALTER TABLE users ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'public'",
                     "ALTER TABLE sessions ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'public'",
                 })
        {
            try
            {
                var a = conn.CreateCommand();
                a.CommandText = alter;
                await a.ExecuteNonQueryAsync(ct);
            }
            catch (Microsoft.Data.Sqlite.SqliteException) { /* column / table not applicable */ }
        }

        var cmd = conn.CreateCommand();
        cmd.CommandText =
            """
            CREATE TABLE IF NOT EXISTS users (
                id            TEXT PRIMARY KEY,
                username      TEXT,
                primary_email TEXT,
                disabled      INTEGER NOT NULL DEFAULT 0,
                created_at    TEXT NOT NULL,
                phone         TEXT,
                tenant_id     TEXT NOT NULL DEFAULT 'public'
            );
            -- Identity is unique PER TENANT (the same email/username can exist in different tenants).
            DROP INDEX IF EXISTS ux_users_username;   -- old global-username unique index (pre-multi-tenancy)
            CREATE UNIQUE INDEX IF NOT EXISTS ux_users_tenant_username ON users(tenant_id, username) WHERE username IS NOT NULL;
            CREATE INDEX IF NOT EXISTS ix_users_email ON users(tenant_id, primary_email);
            CREATE INDEX IF NOT EXISTS ix_users_phone ON users(tenant_id, phone);

            CREATE TABLE IF NOT EXISTS login_methods (
                id               TEXT PRIMARY KEY,
                user_id          TEXT NOT NULL,
                kind             INTEGER NOT NULL,
                email            TEXT,
                email_verified   INTEGER NOT NULL DEFAULT 0,
                password_hash    TEXT,
                provider_id      TEXT,
                provider_user_id TEXT,
                created_at       TEXT NOT NULL,
                phone            TEXT
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
                session_data       TEXT NOT NULL DEFAULT '{}',
                tenant_id          TEXT NOT NULL DEFAULT 'public'
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

            CREATE TABLE IF NOT EXISTS password_reset_tokens (
                token_hash TEXT PRIMARY KEY,
                user_id    TEXT NOT NULL,
                expires_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS passwordless_codes (
                identifier TEXT PRIMARY KEY,
                channel    INTEGER NOT NULL,
                code_hash  TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                attempts   INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS passkey_credentials (
                id            TEXT PRIMARY KEY,
                user_id       TEXT NOT NULL,
                credential_id BLOB NOT NULL,
                public_key    BLOB NOT NULL,
                user_handle   BLOB NOT NULL,
                sign_count    INTEGER NOT NULL DEFAULT 0,
                aaguid        TEXT NOT NULL,
                cred_type     TEXT,
                nickname      TEXT,
                created_at    TEXT NOT NULL,
                last_used_at  TEXT
            );
            CREATE UNIQUE INDEX IF NOT EXISTS ux_pk_credential ON passkey_credentials(credential_id);
            CREATE INDEX IF NOT EXISTS ix_pk_user   ON passkey_credentials(user_id);
            CREATE INDEX IF NOT EXISTS ix_pk_handle ON passkey_credentials(user_handle);

            CREATE TABLE IF NOT EXISTS migration_state (
                migration_id    TEXT PRIMARY KEY,
                completed_at    TEXT,
                details         TEXT,
                lock_owner      TEXT,
                lock_expires_at TEXT
            );
            """;
        await cmd.ExecuteNonQueryAsync(ct);
    }
}
