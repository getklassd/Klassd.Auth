using Klassd.Auth.Abstractions;

namespace Klassd.Auth.Data.Postgres;

/// <summary>Creates the Klassd.Auth tables if they don't exist. Idempotent.</summary>
public sealed class PostgresSchemaInitializer(PostgresContext ctx) : IAuthStorageInitializer
{
    public async Task InitializeAsync(CancellationToken ct = default)
    {
        await using var conn = await ctx.OpenAsync(ct);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText =
            """
            CREATE TABLE IF NOT EXISTS users (
                id            text PRIMARY KEY,
                username      text,
                primary_email text,
                disabled      boolean NOT NULL DEFAULT false,
                created_at    timestamptz NOT NULL,
                phone         text
            );
            ALTER TABLE users ADD COLUMN IF NOT EXISTS phone text;
            CREATE UNIQUE INDEX IF NOT EXISTS ux_users_username ON users(username) WHERE username IS NOT NULL;
            CREATE INDEX IF NOT EXISTS ix_users_email ON users(primary_email);
            CREATE INDEX IF NOT EXISTS ix_users_phone ON users(phone);

            CREATE TABLE IF NOT EXISTS login_methods (
                id               text PRIMARY KEY,
                user_id          text NOT NULL,
                kind             int  NOT NULL,
                email            text,
                email_verified   boolean NOT NULL DEFAULT false,
                password_hash    text,
                provider_id      text,
                provider_user_id text,
                created_at       timestamptz NOT NULL,
                phone            text
            );
            ALTER TABLE login_methods ADD COLUMN IF NOT EXISTS phone text;
            CREATE INDEX IF NOT EXISTS ix_lm_user     ON login_methods(user_id);
            CREATE INDEX IF NOT EXISTS ix_lm_email    ON login_methods(kind, email);
            CREATE INDEX IF NOT EXISTS ix_lm_provider ON login_methods(provider_id, provider_user_id);

            CREATE TABLE IF NOT EXISTS sessions (
                handle             text PRIMARY KEY,
                user_id            text NOT NULL,
                refresh_token_hash text NOT NULL,
                created_at         timestamptz NOT NULL,
                refresh_expires_at timestamptz NOT NULL,
                revoked            boolean NOT NULL DEFAULT false,
                session_data       jsonb NOT NULL DEFAULT '{}'::jsonb
            );

            CREATE TABLE IF NOT EXISTS user_metadata (
                user_id text PRIMARY KEY,
                json    jsonb NOT NULL
            );

            CREATE TABLE IF NOT EXISTS signing_keys (
                key_id          text PRIMARY KEY,
                private_key_pem text NOT NULL,
                created_at      timestamptz NOT NULL
            );

            CREATE TABLE IF NOT EXISTS email_verification_tokens (
                token_hash text PRIMARY KEY,
                user_id    text NOT NULL,
                email      text NOT NULL,
                expires_at timestamptz NOT NULL
            );

            CREATE TABLE IF NOT EXISTS password_reset_tokens (
                token_hash text PRIMARY KEY,
                user_id    text NOT NULL,
                expires_at timestamptz NOT NULL
            );

            CREATE TABLE IF NOT EXISTS passwordless_codes (
                identifier text PRIMARY KEY,
                channel    int  NOT NULL,
                code_hash  text NOT NULL,
                expires_at timestamptz NOT NULL,
                attempts   int  NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS passkey_credentials (
                id            text PRIMARY KEY,
                user_id       text NOT NULL,
                credential_id bytea NOT NULL,
                public_key    bytea NOT NULL,
                user_handle   bytea NOT NULL,
                sign_count    bigint NOT NULL DEFAULT 0,
                aaguid        text NOT NULL,
                cred_type     text,
                nickname      text,
                created_at    timestamptz NOT NULL,
                last_used_at  timestamptz
            );
            CREATE UNIQUE INDEX IF NOT EXISTS ux_pk_credential ON passkey_credentials(credential_id);
            CREATE INDEX IF NOT EXISTS ix_pk_user   ON passkey_credentials(user_id);
            CREATE INDEX IF NOT EXISTS ix_pk_handle ON passkey_credentials(user_handle);

            CREATE TABLE IF NOT EXISTS migration_state (
                migration_id    text PRIMARY KEY,
                completed_at    timestamptz,
                details         text,
                lock_owner      text,
                lock_expires_at timestamptz
            );
            """;
        await cmd.ExecuteNonQueryAsync(ct);
    }
}
