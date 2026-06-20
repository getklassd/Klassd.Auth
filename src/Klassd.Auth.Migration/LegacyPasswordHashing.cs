using Klassd.Auth.Core.Security;

namespace Klassd.Auth.Migration;

/// <summary>
/// Classifies a stored password hash by its self-describing prefix. Migrated hashes are stored
/// verbatim on the login method, so the scheme is recovered from the string at verify time.
/// </summary>
public static class PasswordHashFormat
{
    public static PasswordHashScheme Detect(string? hash) => hash switch
    {
        null or "" => PasswordHashScheme.Unsupported,
        _ when hash.StartsWith("pbkdf2$", StringComparison.Ordinal) => PasswordHashScheme.Pbkdf2Klassd,
        _ when hash.StartsWith("$2", StringComparison.Ordinal) => PasswordHashScheme.Bcrypt,        // $2a$/$2b$/$2x$/$2y$
        _ when hash.StartsWith("$argon2", StringComparison.Ordinal) => PasswordHashScheme.Argon2,
        _ => PasswordHashScheme.Unsupported,
    };

    /// <summary>True if Klassd can verify a login against this hash without the user resetting it.</summary>
    public static bool IsVerifiable(string? hash) => Detect(hash) != PasswordHashScheme.Unsupported;
}

/// <summary>
/// An <see cref="IPasswordHasher"/> that verifies Klassd's native pbkdf2 hashes <em>and</em> the
/// bcrypt / argon2 hashes carried over from Auth0 or SuperTokens — so migrated users sign in with
/// their existing passwords. New passwords are always (re)hashed with the modern pbkdf2 scheme,
/// so a credential silently upgrades the next time the user changes it.
/// </summary>
public sealed class LegacyAwarePasswordHasher(Pbkdf2PasswordHasher modern) : IPasswordHasher
{
    public string Hash(string password) => modern.Hash(password);

    public bool Verify(string password, string hash) => PasswordHashFormat.Detect(hash) switch
    {
        PasswordHashScheme.Pbkdf2Klassd => modern.Verify(password, hash),
        PasswordHashScheme.Bcrypt => BCrypt.Net.BCrypt.Verify(password, hash),
        PasswordHashScheme.Argon2 => Isopoh.Cryptography.Argon2.Argon2.Verify(hash, password),
        _ => false,
    };
}
