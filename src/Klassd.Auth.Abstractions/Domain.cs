namespace Klassd.Auth.Abstractions;

/// <summary>
/// A user account. A user can authenticate through one or more <see cref="LoginMethod"/>s
/// (email/password, a third-party provider, …) that all resolve to the same <see cref="Id"/>.
/// DB-agnostic — storage adapters map this to their own schema/documents.
/// </summary>
public sealed class User
{
    public required string Id { get; init; }

    /// <summary>Optional login identity (Klassd CMS keys on username; Workflows keys on email).</summary>
    public string? Username { get; set; }
    public string? PrimaryEmail { get; set; }

    /// <summary>Soft-delete / lockout flag. A disabled user cannot sign in but is preserved for authorship.</summary>
    public bool Disabled { get; set; }

    public DateTimeOffset CreatedAt { get; init; }

    public List<LoginMethod> LoginMethods { get; init; } = [];
}

public enum LoginMethodKind
{
    EmailPassword,
    ThirdParty,
    Passwordless
}

/// <summary>One way a <see cref="User"/> can sign in. Multiple methods may link to one user.</summary>
public sealed class LoginMethod
{
    public required string Id { get; init; }
    public required string UserId { get; init; }
    public required LoginMethodKind Kind { get; init; }

    public string? Email { get; set; }
    public bool EmailVerified { get; set; }

    // EmailPassword
    public string? PasswordHash { get; set; }

    // ThirdParty
    public string? ProviderId { get; set; }      // e.g. "google"
    public string? ProviderUserId { get; set; }  // subject from the provider

    public DateTimeOffset CreatedAt { get; init; }
}

/// <summary>
/// Server-side record backing a logged-in session. The access token is a short-lived JWT
/// (stateless); the refresh token is opaque and validated against this record so sessions
/// can be revoked and refresh tokens rotated.
/// </summary>
public sealed class SessionEntity
{
    public required string Handle { get; init; }       // stable session id, embedded in the access token
    public required string UserId { get; init; }
    public required string RefreshTokenHash { get; set; }  // hash of the current refresh token, rotated on refresh

    public DateTimeOffset CreatedAt { get; init; }
    public DateTimeOffset RefreshExpiresAt { get; set; }
    public bool Revoked { get; set; }

    public Dictionary<string, string> SessionData { get; set; } = [];
}
