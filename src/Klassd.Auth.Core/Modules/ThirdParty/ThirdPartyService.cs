using Klassd.Auth.Abstractions;

namespace Klassd.Auth.Core.Modules.ThirdParty;

/// <summary>Normalized profile returned by an OAuth/OIDC provider after token exchange.</summary>
public sealed record ThirdPartyProfile(string ProviderUserId, string? Email, bool EmailVerified);

/// <summary>
/// One social/OIDC provider. Concrete providers (GoogleProvider, GitHubProvider, …) build the
/// authorization URL and exchange the returned code for a normalized profile.
/// </summary>
public interface IThirdPartyProvider
{
    string Id { get; }                 // e.g. "google"
    string BuildAuthorizationUrl(string state, string redirectUri);
    Task<ThirdPartyProfile> ExchangeCodeAsync(string code, string redirectUri, CancellationToken ct = default);
}

/// <summary>
/// Resolves a third-party sign-in to a local user, creating one on first login. Account-linking
/// policy lives here so it's consistent across providers.
/// </summary>
public sealed class ThirdPartyService(IUserStore users, IEnumerable<IThirdPartyProvider> providers)
{
    private readonly Dictionary<string, IThirdPartyProvider> _providers =
        providers.ToDictionary(p => p.Id, StringComparer.OrdinalIgnoreCase);

    public IThirdPartyProvider GetProvider(string id) =>
        _providers.TryGetValue(id, out var p) ? p : throw new KeyNotFoundException($"Unknown provider '{id}'.");

    public async Task<string> SignInOrUpAsync(string providerId, ThirdPartyProfile profile, CancellationToken ct = default)
    {
        var existing = await users.FindThirdPartyAsync(providerId, profile.ProviderUserId, ct);
        if (existing is not null) return existing.UserId;

        var userId = Guid.NewGuid().ToString("N");
        var user = new User
        {
            Id = userId,
            PrimaryEmail = profile.Email,
            CreatedAt = DateTimeOffset.UtcNow,
            LoginMethods =
            {
                new LoginMethod
                {
                    Id = Guid.NewGuid().ToString("N"),
                    UserId = userId,
                    Kind = LoginMethodKind.ThirdParty,
                    ProviderId = providerId,
                    ProviderUserId = profile.ProviderUserId,
                    Email = profile.Email,
                    EmailVerified = profile.EmailVerified,
                    CreatedAt = DateTimeOffset.UtcNow,
                }
            }
        };
        await users.AddUserAsync(user, ct);
        return userId;
    }
}
