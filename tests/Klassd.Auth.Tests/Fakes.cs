using Klassd.Auth.Abstractions;

namespace Klassd.Auth.Tests;

/// <summary>In-memory stores so the Core services can be tested without a database.</summary>
public sealed class FakeUserStore : IUserStore
{
    private readonly Dictionary<string, User> _users = new();

    public Task<User?> FindByIdAsync(string id, CancellationToken ct = default) =>
        Task.FromResult(_users.GetValueOrDefault(id));

    public Task<User?> FindByUsernameAsync(string username, CancellationToken ct = default) =>
        Task.FromResult<User?>(_users.Values.FirstOrDefault(u => u.Username == username));

    public Task<User?> FindByEmailAsync(string email, CancellationToken ct = default) =>
        Task.FromResult<User?>(_users.Values.FirstOrDefault(u => u.PrimaryEmail == email));

    public Task<LoginMethod?> FindEmailPasswordAsync(string email, CancellationToken ct = default) =>
        Task.FromResult<LoginMethod?>(_users.Values.SelectMany(u => u.LoginMethods)
            .FirstOrDefault(m => m.Kind == LoginMethodKind.EmailPassword && m.Email == email));

    public Task<LoginMethod?> FindThirdPartyAsync(string providerId, string providerUserId, CancellationToken ct = default) =>
        Task.FromResult<LoginMethod?>(_users.Values.SelectMany(u => u.LoginMethods)
            .FirstOrDefault(m => m.ProviderId == providerId && m.ProviderUserId == providerUserId));

    public Task<IReadOnlyList<User>> GetAllAsync(CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<User>>(_users.Values.ToList());

    public Task AddUserAsync(User user, CancellationToken ct = default)
    {
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
        if (_users.TryGetValue(method.UserId, out var u))
        {
            var idx = u.LoginMethods.FindIndex(m => m.Id == method.Id);
            if (idx >= 0) u.LoginMethods[idx] = method;
            else u.LoginMethods.Add(method);
        }
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
