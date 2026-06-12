using Klassd.Auth.Core.Modules.UserMetadata;

namespace Klassd.Auth.Core.Modules.Users;

/// <summary>
/// Per-user roles, stored as a typed section ("roles") inside the user's JSON metadata — so the
/// core stays role-model-agnostic (Klassd CMS uses roles; Klassd.Workflows doesn't). Apps map
/// these role strings to their own capability/permission model.
/// </summary>
public sealed class RolesService(UserMetadataService metadata)
{
    private const string Key = "roles";

    public async Task<IReadOnlyList<string>> GetRolesAsync(string userId, CancellationToken ct = default) =>
        await metadata.GetAsync<List<string>>(userId, Key, ct) ?? [];

    public Task SetRolesAsync(string userId, IEnumerable<string> roles, CancellationToken ct = default) =>
        metadata.SetAsync(userId, Key, roles.Distinct(StringComparer.OrdinalIgnoreCase).ToList(), ct);

    public async Task<bool> IsInRoleAsync(string userId, string role, CancellationToken ct = default) =>
        (await GetRolesAsync(userId, ct)).Contains(role, StringComparer.OrdinalIgnoreCase);
}
