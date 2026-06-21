using Klassd.Auth.Abstractions;

namespace Klassd.Auth.Tests;

/// <summary>
/// In-memory stores so the Core services can be tested without a database. Honors the ambient
/// <see cref="ITenantContext"/> exactly like the real adapters: identity lookups are tenant-scoped,
/// find-by-id is global, and inserts are stamped with the current tenant. Defaults to "public" so
/// single-tenant tests are unaffected.
/// </summary>
public sealed class FakeUserStore(ITenantContext? tenant = null) : IUserStore
{
    private readonly Dictionary<string, User> _users = new();
    private readonly ITenantContext _tenant = tenant ?? new TenantContext();
    private string T => _tenant.TenantId;

    public Task<User?> FindByIdAsync(string id, CancellationToken ct = default) =>
        Task.FromResult(_users.GetValueOrDefault(id));   // id is globally unique → not tenant-scoped

    public Task<User?> FindByUsernameAsync(string username, CancellationToken ct = default) =>
        Task.FromResult<User?>(_users.Values.FirstOrDefault(u => u.TenantId == T && u.Username == username));

    public Task<User?> FindByEmailAsync(string email, CancellationToken ct = default) =>
        Task.FromResult<User?>(_users.Values.FirstOrDefault(u => u.TenantId == T && u.PrimaryEmail == email));

    public Task<User?> FindByPhoneAsync(string phone, CancellationToken ct = default) =>
        Task.FromResult<User?>(_users.Values.FirstOrDefault(u => u.TenantId == T && u.PrimaryPhone == phone));

    public Task<LoginMethod?> FindEmailPasswordAsync(string email, CancellationToken ct = default) =>
        Task.FromResult<LoginMethod?>(_users.Values.Where(u => u.TenantId == T).SelectMany(u => u.LoginMethods)
            .FirstOrDefault(m => m.Kind == LoginMethodKind.EmailPassword && m.Email == email));

    public Task<LoginMethod?> FindThirdPartyAsync(string providerId, string providerUserId, CancellationToken ct = default) =>
        Task.FromResult<LoginMethod?>(_users.Values.Where(u => u.TenantId == T).SelectMany(u => u.LoginMethods)
            .FirstOrDefault(m => m.ProviderId == providerId && m.ProviderUserId == providerUserId));

    public Task<IReadOnlyList<User>> GetAllAsync(CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<User>>(_users.Values.Where(u => u.TenantId == T).ToList());

    public Task AddUserAsync(User user, CancellationToken ct = default)
    {
        user.TenantId = T;   // store is authoritative on the owning tenant
        _users[user.Id] = user;
        return Task.CompletedTask;
    }

    public Task UpdateUserAsync(User user, CancellationToken ct = default)
    {
        _users[user.Id] = user;
        return Task.CompletedTask;
    }

    public Task UpdateLoginMethodAsync(LoginMethod method, CancellationToken ct = default)
    {
        // Update-only, matching the real adapters (a missing method is a no-op, NOT an insert).
        if (_users.TryGetValue(method.UserId, out var u))
        {
            var idx = u.LoginMethods.FindIndex(m => m.Id == method.Id);
            if (idx >= 0) u.LoginMethods[idx] = method;
        }
        return Task.CompletedTask;
    }

    public Task AddLoginMethodAsync(LoginMethod method, CancellationToken ct = default)
    {
        if (_users.TryGetValue(method.UserId, out var u)) u.LoginMethods.Add(method);
        return Task.CompletedTask;
    }

    public Task RemoveLoginMethodAsync(string methodId, CancellationToken ct = default)
    {
        foreach (var u in _users.Values) u.LoginMethods.RemoveAll(m => m.Id == methodId);
        return Task.CompletedTask;
    }

    public Task DeleteUserAsync(string userId, CancellationToken ct = default)
    {
        _users.Remove(userId);
        return Task.CompletedTask;
    }
}

public sealed class FakeSessionStore : ISessionStore
{
    private readonly Dictionary<string, SessionEntity> _sessions = new();

    public Task<SessionEntity?> FindAsync(string handle, CancellationToken ct = default) =>
        Task.FromResult(_sessions.GetValueOrDefault(handle));

    public Task AddAsync(SessionEntity session, CancellationToken ct = default)
    {
        _sessions[session.Handle] = session;
        return Task.CompletedTask;
    }

    public Task UpdateAsync(SessionEntity session, CancellationToken ct = default)
    {
        _sessions[session.Handle] = session;
        return Task.CompletedTask;
    }

    public Task RevokeAsync(string handle, CancellationToken ct = default)
    {
        if (_sessions.TryGetValue(handle, out var s)) s.Revoked = true;
        return Task.CompletedTask;
    }

    public Task RevokeAllForUserAsync(string userId, CancellationToken ct = default)
    {
        foreach (var s in _sessions.Values.Where(s => s.UserId == userId)) s.Revoked = true;
        return Task.CompletedTask;
    }

    public Task DeleteAllForUserAsync(string userId, CancellationToken ct = default)
    {
        foreach (var h in _sessions.Where(kv => kv.Value.UserId == userId).Select(kv => kv.Key).ToList())
            _sessions.Remove(h);
        return Task.CompletedTask;
    }
}

/// <summary>In-memory migration ledger + lease lock, faithful to the real adapters' semantics.</summary>
public sealed class FakeMigrationStateStore : IMigrationStateStore
{
    private readonly HashSet<string> _completed = [];
    private readonly Dictionary<string, (string Owner, DateTimeOffset Expires)> _locks = new();
    private readonly object _gate = new();

    public Task<bool> IsCompletedAsync(string migrationId, CancellationToken ct = default)
    {
        lock (_gate) return Task.FromResult(_completed.Contains(migrationId));
    }

    public Task MarkCompletedAsync(string migrationId, string? detailsJson = null, CancellationToken ct = default)
    {
        lock (_gate) _completed.Add(migrationId);
        return Task.CompletedTask;
    }

    public Task<IMigrationLockHandle?> TryAcquireLockAsync(string migrationId, TimeSpan ttl, CancellationToken ct = default)
    {
        lock (_gate)
        {
            if (_locks.TryGetValue(migrationId, out var held) && held.Expires > DateTimeOffset.UtcNow)
                return Task.FromResult<IMigrationLockHandle?>(null);   // a live lease is held

            var owner = Guid.NewGuid().ToString("N");
            _locks[migrationId] = (owner, DateTimeOffset.UtcNow.Add(ttl));
            return Task.FromResult<IMigrationLockHandle?>(new MigrationLockHandle(
                renew: (t, _) =>
                {
                    lock (_gate)
                    {
                        if (_locks.TryGetValue(migrationId, out var cur) && cur.Owner == owner)
                        {
                            _locks[migrationId] = (owner, DateTimeOffset.UtcNow.Add(t));
                            return Task.FromResult(true);
                        }
                        return Task.FromResult(false);
                    }
                },
                release: () =>
                {
                    lock (_gate)
                        if (_locks.TryGetValue(migrationId, out var cur) && cur.Owner == owner)
                            _locks.Remove(migrationId);
                    return ValueTask.CompletedTask;
                }));
        }
    }
}

public sealed class FakeMetadataStore : IUserMetadataStore
{
    private readonly Dictionary<string, string> _data = new();

    public Task<string?> GetAsync(string userId, CancellationToken ct = default) =>
        Task.FromResult(_data.GetValueOrDefault(userId));

    public Task SetAsync(string userId, string json, CancellationToken ct = default)
    {
        _data[userId] = json;
        return Task.CompletedTask;
    }

    public Task ClearAsync(string userId, CancellationToken ct = default)
    {
        _data.Remove(userId);
        return Task.CompletedTask;
    }
}
