using Klassd.Auth.Abstractions;
using MongoDB.Driver;

namespace Klassd.Auth.Data.MongoDb;

public sealed class MongoOptions
{
    public required string ConnectionString { get; init; }
    public string DatabaseName { get; init; } = "klassd_auth";
}

/// <summary>Holds the typed collections backing Klassd.Auth. One per document type.</summary>
public sealed class MongoContext
{
    public MongoContext(MongoOptions options)
    {
        var db = new MongoClient(options.ConnectionString).GetDatabase(options.DatabaseName);
        Users = db.GetCollection<UserDoc>("users");
        Sessions = db.GetCollection<SessionDoc>("sessions");
        Metadata = db.GetCollection<MetadataDoc>("user_metadata");
        SigningKeys = db.GetCollection<SigningKeyDoc>("signing_keys");
        EmailVerificationTokens = db.GetCollection<EmailVerificationTokenDoc>("email_verification_tokens");
        PasswordResetTokens = db.GetCollection<PasswordResetTokenDoc>("password_reset_tokens");
        PasswordlessCodes = db.GetCollection<PasswordlessCodeDoc>("passwordless_codes");
        PasskeyCredentials = db.GetCollection<PasskeyCredentialDoc>("passkey_credentials");
    }

    public IMongoCollection<UserDoc> Users { get; }
    public IMongoCollection<SessionDoc> Sessions { get; }
    public IMongoCollection<MetadataDoc> Metadata { get; }
    public IMongoCollection<SigningKeyDoc> SigningKeys { get; }
    public IMongoCollection<EmailVerificationTokenDoc> EmailVerificationTokens { get; }
    public IMongoCollection<PasswordResetTokenDoc> PasswordResetTokens { get; }
    public IMongoCollection<PasswordlessCodeDoc> PasswordlessCodes { get; }
    public IMongoCollection<PasskeyCredentialDoc> PasskeyCredentials { get; }
}

// Persistence documents. Kept separate from the Abstractions domain types so the storage
// shape can evolve independently (and so we control _id mapping).
public sealed class UserDoc
{
    public required string Id { get; set; }     // mapped to _id
    public string? Username { get; set; }
    public string? PrimaryEmail { get; set; }
    public string? PrimaryPhone { get; set; }
    public bool Disabled { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public List<LoginMethodDoc> LoginMethods { get; set; } = [];

    public User ToDomain() => new()
    {
        Id = Id,
        Username = Username,
        PrimaryEmail = PrimaryEmail,
        PrimaryPhone = PrimaryPhone,
        Disabled = Disabled,
        CreatedAt = CreatedAt,
        LoginMethods = LoginMethods.ConvertAll(m => m.ToDomain()),
    };

    public static UserDoc From(User u) => new()
    {
        Id = u.Id,
        Username = u.Username,
        PrimaryEmail = u.PrimaryEmail,
        PrimaryPhone = u.PrimaryPhone,
        Disabled = u.Disabled,
        CreatedAt = u.CreatedAt,
        LoginMethods = u.LoginMethods.ConvertAll(LoginMethodDoc.From),
    };
}

public sealed class LoginMethodDoc
{
    public required string Id { get; set; }
    public required string UserId { get; set; }
    public LoginMethodKind Kind { get; set; }
    public string? Email { get; set; }
    public bool EmailVerified { get; set; }
    public string? PasswordHash { get; set; }
    public string? ProviderId { get; set; }
    public string? ProviderUserId { get; set; }
    public string? Phone { get; set; }
    public DateTimeOffset CreatedAt { get; set; }

    public LoginMethod ToDomain() => new()
    {
        Id = Id, UserId = UserId, Kind = Kind, Email = Email, EmailVerified = EmailVerified,
        PasswordHash = PasswordHash, ProviderId = ProviderId, ProviderUserId = ProviderUserId, Phone = Phone, CreatedAt = CreatedAt,
    };

    public static LoginMethodDoc From(LoginMethod m) => new()
    {
        Id = m.Id, UserId = m.UserId, Kind = m.Kind, Email = m.Email, EmailVerified = m.EmailVerified,
        PasswordHash = m.PasswordHash, ProviderId = m.ProviderId, ProviderUserId = m.ProviderUserId, Phone = m.Phone, CreatedAt = m.CreatedAt,
    };
}

public sealed class SessionDoc
{
    public required string Handle { get; set; }   // mapped to _id
    public required string UserId { get; set; }
    public required string RefreshTokenHash { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset RefreshExpiresAt { get; set; }
    public bool Revoked { get; set; }
    public Dictionary<string, string> SessionData { get; set; } = [];

    public SessionEntity ToDomain() => new()
    {
        Handle = Handle, UserId = UserId, RefreshTokenHash = RefreshTokenHash, CreatedAt = CreatedAt,
        RefreshExpiresAt = RefreshExpiresAt, Revoked = Revoked, SessionData = SessionData,
    };

    public static SessionDoc From(SessionEntity s) => new()
    {
        Handle = s.Handle, UserId = s.UserId, RefreshTokenHash = s.RefreshTokenHash, CreatedAt = s.CreatedAt,
        RefreshExpiresAt = s.RefreshExpiresAt, Revoked = s.Revoked, SessionData = s.SessionData,
    };
}

public sealed class MetadataDoc
{
    public required string UserId { get; set; }  // mapped to _id
    public required string Json { get; set; }
}

public sealed class SigningKeyDoc
{
    public required string KeyId { get; set; }   // mapped to _id
    public required string PrivateKeyPem { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}

public sealed class EmailVerificationTokenDoc
{
    public required string TokenHash { get; set; }  // mapped to _id
    public required string UserId { get; set; }
    public required string Email { get; set; }
    public DateTimeOffset Expires { get; set; }
}

public sealed class PasswordResetTokenDoc
{
    public required string TokenHash { get; set; }  // mapped to _id
    public required string UserId { get; set; }
    public DateTimeOffset Expires { get; set; }
}

public sealed class PasswordlessCodeDoc
{
    public required string Identifier { get; set; }  // mapped to _id
    public PasswordlessChannel Channel { get; set; }
    public required string CodeHash { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public int Attempts { get; set; }
}

public sealed class PasskeyCredentialDoc
{
    public required string Id { get; set; }   // mapped to _id
    public required string UserId { get; set; }
    public required byte[] CredentialId { get; set; }
    public required byte[] PublicKey { get; set; }
    public required byte[] UserHandle { get; set; }
    public long SignCount { get; set; }
    public Guid AaGuid { get; set; }
    public string? CredType { get; set; }
    public string? Nickname { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? LastUsedAt { get; set; }

    public PasskeyCredential ToDomain() => new()
    {
        Id = Id, UserId = UserId, CredentialId = CredentialId, PublicKey = PublicKey, UserHandle = UserHandle,
        SignCount = (ulong)SignCount, AaGuid = AaGuid, CredType = CredType, Nickname = Nickname,
        CreatedAt = CreatedAt, LastUsedAt = LastUsedAt,
    };

    public static PasskeyCredentialDoc From(PasskeyCredential c) => new()
    {
        Id = c.Id, UserId = c.UserId, CredentialId = c.CredentialId, PublicKey = c.PublicKey, UserHandle = c.UserHandle,
        SignCount = (long)c.SignCount, AaGuid = c.AaGuid, CredType = c.CredType, Nickname = c.Nickname,
        CreatedAt = c.CreatedAt, LastUsedAt = c.LastUsedAt,
    };
}
