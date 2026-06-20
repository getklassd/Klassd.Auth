using System.Text.Json.Nodes;

namespace Klassd.Auth.Migration;

/// <summary>
/// A user normalized out of a foreign system (Auth0, SuperTokens) and ready to be written into
/// Klassd.Auth. Sources (<see cref="IMigrationSource"/>) produce these; the
/// <see cref="MigrationRunner"/> consumes them. Provider-specific shapes never leak past here.
/// </summary>
public sealed class MigratedUser
{
    /// <summary>The user's id in the source system, kept for traceability and idempotent re-runs.</summary>
    public string? ExternalId { get; init; }

    public string? Username { get; set; }
    public string? Email { get; set; }
    public bool EmailVerified { get; set; }

    /// <summary>Phone identity in E.164, when the source had passwordless-over-SMS.</summary>
    public string? Phone { get; set; }

    /// <summary>Maps to <see cref="Abstractions.User.Disabled"/> (Auth0 "blocked", etc.).</summary>
    public bool Disabled { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    /// <summary>The migrated password, with its original hash kept verbatim, or null if none.</summary>
    public MigratedPassword? Password { get; set; }

    public List<MigratedThirdParty> ThirdParty { get; init; } = [];

    /// <summary>The source had an email passwordless (magic-link/OTP) login method.</summary>
    public bool PasswordlessEmail { get; set; }

    /// <summary>The source had a phone passwordless (SMS OTP) login method.</summary>
    public bool PasswordlessPhone { get; set; }

    public List<string> Roles { get; init; } = [];

    /// <summary>Base32 TOTP secret from the source's MFA enrollment, if any.</summary>
    public string? TotpSecretBase32 { get; set; }

    /// <summary>Free-form per-user metadata, merged into the Klassd user's JSON metadata document.</summary>
    public Dictionary<string, JsonNode?> Metadata { get; init; } = [];
}

/// <summary>
/// A password as exported by the source. <see cref="Hash"/> is stored verbatim on the Klassd login
/// method — <see cref="Scheme"/> only drives reporting and the "can we verify this at login?" check.
/// </summary>
public sealed record MigratedPassword(string Hash, PasswordHashScheme Scheme);

public enum PasswordHashScheme
{
    /// <summary>Klassd's native "pbkdf2$…" format — verified by the built-in hasher.</summary>
    Pbkdf2Klassd,

    /// <summary>bcrypt ("$2a$/$2b$/$2y$…") — verified by the legacy-aware hasher.</summary>
    Bcrypt,

    /// <summary>argon2 PHC string ("$argon2id$…") — verified by the legacy-aware hasher.</summary>
    Argon2,

    /// <summary>An algorithm Klassd can't verify (e.g. firebase scrypt, passlib pbkdf2). Forces a reset.</summary>
    Unsupported,
}

/// <summary>A linked social/OIDC identity carried over from the source.</summary>
public sealed record MigratedThirdParty(string ProviderId, string ProviderUserId, string? Email, bool EmailVerified);
