using Klassd.Auth.Abstractions;

namespace Klassd.Auth.Core.Modules.ThirdParty;

/// <summary>Normalized profile returned by an OAuth/OIDC provider after token exchange.</summary>
public sealed record ThirdPartyProfile(string ProviderUserId, string? Email, bool EmailVerified)
{
    /// <summary>The provider's other claims (e.g. name, picture, roles), keyed by name — to enrich the session.</summary>
    public IReadOnlyDictionary<string, string> Claims { get; init; } = new Dictionary<string, string>();
}

/// <summary>The provider's tokens from the code exchange, so a post-sign-in hook can call its APIs.</summary>
public sealed record ThirdPartyTokens(
    string? AccessToken,
    string? IdToken,
    string? RefreshToken,
    DateTimeOffset? ExpiresAt,
    IReadOnlyDictionary<string, string> All)
{
    public static ThirdPartyTokens Empty { get; } = new(null, null, null, null, new Dictionary<string, string>());
}

/// <summary>The result of exchanging an authorization code: the normalized profile plus the raw tokens.</summary>
public sealed record ThirdPartyExchange(ThirdPartyProfile Profile, ThirdPartyTokens Tokens);

/// <summary>Outcome of resolving a third-party sign-in to a local user.</summary>
public sealed record ThirdPartySignInResult(string UserId, bool CreatedNewUser);

/// <summary>
/// One social/OIDC provider. Concrete providers build the authorization URL and exchange the returned
/// code for a normalized profile <em>and</em> the raw provider tokens.
/// </summary>
public interface IThirdPartyProvider
{
    string Id { get; }                 // e.g. "google"
    string BuildAuthorizationUrl(string state, string redirectUri);
    Task<ThirdPartyExchange> ExchangeCodeAsync(string code, string redirectUri, CancellationToken ct = default);
}

/// <summary>Resolves a third-party sign-in to a local user. Override via <c>auth.Override&lt;IThirdPartyService&gt;(…)</c>.</summary>
public interface IThirdPartyService
{
    IThirdPartyProvider GetProvider(string id);
    Task<ThirdPartySignInResult> SignInOrUpAsync(string providerId, ThirdPartyProfile profile, CancellationToken ct = default);
}

/// <summary>
/// Resolves a third-party sign-in to a local user, creating one on first login. Account-linking
/// policy lives here so it's consistent across providers.
/// </summary>
public sealed class ThirdPartyService(IUserStore users, IEnumerable<IThirdPartyProvider> providers) : IThirdPartyService
{
    private readonly Dictionary<string, IThirdPartyProvider> _providers =
        providers.ToDictionary(p => p.Id, StringComparer.OrdinalIgnoreCase);

    public IThirdPartyProvider GetProvider(string id) =>
        _providers.TryGetValue(id, out var p) ? p : throw new KeyNotFoundException($"Unknown provider '{id}'.");

    public async Task<ThirdPartySignInResult> SignInOrUpAsync(string providerId, ThirdPartyProfile profile, CancellationToken ct = default)
    {
        var existing = await users.FindThirdPartyAsync(providerId, profile.ProviderUserId, ct);
        if (existing is not null) return new ThirdPartySignInResult(existing.UserId, CreatedNewUser: false);

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
        return new ThirdPartySignInResult(userId, CreatedNewUser: true);
    }
}

/// <summary>Forwarding base for overriding <see cref="IThirdPartyService"/>; override selectively, call <c>base</c> for the original.</summary>
public abstract class ThirdPartyServiceDecorator(IThirdPartyService inner) : IThirdPartyService
{
    public virtual IThirdPartyProvider GetProvider(string id) => inner.GetProvider(id);

    public virtual Task<ThirdPartySignInResult> SignInOrUpAsync(string providerId, ThirdPartyProfile profile, CancellationToken ct = default) =>
        inner.SignInOrUpAsync(providerId, profile, ct);
}
