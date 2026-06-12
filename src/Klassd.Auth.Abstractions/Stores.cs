namespace Klassd.Auth.Abstractions;

/// <summary>
/// Storage abstraction. A Klassd.Auth.Data.* adapter implements these; module logic in
/// Klassd.Auth.Core depends only on the interfaces, so the database is swappable.
/// </summary>
public interface IUserStore
{
    Task<User?> FindByIdAsync(string userId, CancellationToken ct = default);
    Task<User?> FindByUsernameAsync(string username, CancellationToken ct = default);
    Task<User?> FindByEmailAsync(string email, CancellationToken ct = default);
    Task<LoginMethod?> FindEmailPasswordAsync(string email, CancellationToken ct = default);
    Task<LoginMethod?> FindThirdPartyAsync(string providerId, string providerUserId, CancellationToken ct = default);
    Task<IReadOnlyList<User>> GetAllAsync(CancellationToken ct = default);
    Task AddUserAsync(User user, CancellationToken ct = default);

    /// <summary>Persists mutable user fields (username, email, disabled). Does not touch login methods.</summary>
    Task UpdateUserAsync(User user, CancellationToken ct = default);
    Task UpdateLoginMethodAsync(LoginMethod method, CancellationToken ct = default);
}

public interface ISessionStore
{
    Task<SessionEntity?> FindAsync(string handle, CancellationToken ct = default);
    Task AddAsync(SessionEntity session, CancellationToken ct = default);
    Task UpdateAsync(SessionEntity session, CancellationToken ct = default);
    Task RevokeAsync(string handle, CancellationToken ct = default);
}

/// <summary>Free-form per-user JSON metadata store.</summary>
public interface IUserMetadataStore
{
    Task<string?> GetAsync(string userId, CancellationToken ct = default);   // raw JSON, or null
    Task SetAsync(string userId, string json, CancellationToken ct = default);
    Task ClearAsync(string userId, CancellationToken ct = default);
}

/// <summary>
/// Runs once at startup to create/migrate the adapter's schema. Each Data.* provider ships one;
/// the host invokes <see cref="InitializeAsync"/> (the sample does this on boot).
/// </summary>
public interface IAuthStorageInitializer
{
    Task InitializeAsync(CancellationToken ct = default);
}
