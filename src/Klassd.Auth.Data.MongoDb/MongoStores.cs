using Klassd.Auth.Abstractions;
using MongoDB.Driver;

namespace Klassd.Auth.Data.MongoDb;

public sealed class MongoUserStore(MongoContext ctx) : IUserStore
{
    public async Task<User?> FindByIdAsync(string userId, CancellationToken ct = default) =>
        (await ctx.Users.Find(u => u.Id == userId).FirstOrDefaultAsync(ct))?.ToDomain();

    public async Task<User?> FindByUsernameAsync(string username, CancellationToken ct = default) =>
        (await ctx.Users.Find(u => u.Username == username).FirstOrDefaultAsync(ct))?.ToDomain();

    public async Task<User?> FindByEmailAsync(string email, CancellationToken ct = default) =>
        (await ctx.Users.Find(u => u.PrimaryEmail == email).FirstOrDefaultAsync(ct))?.ToDomain();

    public async Task<IReadOnlyList<User>> GetAllAsync(CancellationToken ct = default) =>
        (await ctx.Users.Find(FilterDefinition<UserDoc>.Empty).ToListAsync(ct)).ConvertAll(d => d.ToDomain());

    public Task UpdateUserAsync(User user, CancellationToken ct = default)
    {
        var update = Builders<UserDoc>.Update
            .Set(u => u.Username, user.Username)
            .Set(u => u.PrimaryEmail, user.PrimaryEmail)
            .Set(u => u.Disabled, user.Disabled);
        return ctx.Users.UpdateOneAsync(u => u.Id == user.Id, update, cancellationToken: ct);
    }

    public async Task<LoginMethod?> FindEmailPasswordAsync(string email, CancellationToken ct = default)
    {
        var doc = await ctx.Users.Find(u => u.LoginMethods.Any(m =>
            m.Kind == LoginMethodKind.EmailPassword && m.Email == email)).FirstOrDefaultAsync(ct);
        return doc?.LoginMethods.FirstOrDefault(m =>
            m.Kind == LoginMethodKind.EmailPassword && m.Email == email)?.ToDomain();
    }

    public async Task<LoginMethod?> FindThirdPartyAsync(string providerId, string providerUserId, CancellationToken ct = default)
    {
        var doc = await ctx.Users.Find(u => u.LoginMethods.Any(m =>
            m.ProviderId == providerId && m.ProviderUserId == providerUserId)).FirstOrDefaultAsync(ct);
        return doc?.LoginMethods.FirstOrDefault(m =>
            m.ProviderId == providerId && m.ProviderUserId == providerUserId)?.ToDomain();
    }

    public Task AddUserAsync(User user, CancellationToken ct = default) =>
        ctx.Users.InsertOneAsync(UserDoc.From(user), cancellationToken: ct);

    public Task UpdateLoginMethodAsync(LoginMethod method, CancellationToken ct = default)
    {
        // Replace the matching embedded login method via positional operator.
        var filter = Builders<UserDoc>.Filter.And(
            Builders<UserDoc>.Filter.Eq(u => u.Id, method.UserId),
            Builders<UserDoc>.Filter.ElemMatch(u => u.LoginMethods, m => m.Id == method.Id));
        var update = Builders<UserDoc>.Update.Set("LoginMethods.$", LoginMethodDoc.From(method));
        return ctx.Users.UpdateOneAsync(filter, update, cancellationToken: ct);
    }
}

public sealed class MongoSessionStore(MongoContext ctx) : ISessionStore
{
    public async Task<SessionEntity?> FindAsync(string handle, CancellationToken ct = default) =>
        (await ctx.Sessions.Find(s => s.Handle == handle).FirstOrDefaultAsync(ct))?.ToDomain();

    public Task AddAsync(SessionEntity session, CancellationToken ct = default) =>
        ctx.Sessions.InsertOneAsync(SessionDoc.From(session), cancellationToken: ct);

    public Task UpdateAsync(SessionEntity session, CancellationToken ct = default) =>
        ctx.Sessions.ReplaceOneAsync(s => s.Handle == session.Handle, SessionDoc.From(session), cancellationToken: ct);

    public Task RevokeAsync(string handle, CancellationToken ct = default) =>
        ctx.Sessions.UpdateOneAsync(
            s => s.Handle == handle,
            Builders<SessionDoc>.Update.Set(s => s.Revoked, true),
            cancellationToken: ct);
}

public sealed class MongoUserMetadataStore(MongoContext ctx) : IUserMetadataStore
{
    public async Task<string?> GetAsync(string userId, CancellationToken ct = default) =>
        (await ctx.Metadata.Find(m => m.UserId == userId).FirstOrDefaultAsync(ct))?.Json;

    public Task SetAsync(string userId, string json, CancellationToken ct = default) =>
        ctx.Metadata.ReplaceOneAsync(
            m => m.UserId == userId,
            new MetadataDoc { UserId = userId, Json = json },
            new ReplaceOptions { IsUpsert = true }, ct);

    public Task ClearAsync(string userId, CancellationToken ct = default) =>
        ctx.Metadata.DeleteOneAsync(m => m.UserId == userId, ct);
}
