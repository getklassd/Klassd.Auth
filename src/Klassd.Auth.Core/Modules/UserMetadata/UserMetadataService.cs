using System.Text.Json;
using System.Text.Json.Nodes;
using Klassd.Auth.Abstractions;

namespace Klassd.Auth.Core.Modules.UserMetadata;

/// <summary>
/// Arbitrary per-user data, stored as a single JSON document but accessed through typed,
/// key-namespaced sections — so each consumer (Klassd CMS, Klassd.Workflows, your app) can
/// keep its own strongly-typed blob under its own key without colliding. Storage stays JSON.
/// </summary>
public sealed class UserMetadataService(IUserMetadataStore store)
{
    // Web defaults => camelCase, case-insensitive: friendly for JSON interop.
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    // ---- Typed, key-namespaced access (recommended) -----------------------------------

    /// <summary>Reads the section stored under <paramref name="key"/> as <typeparamref name="T"/>, or default if absent.</summary>
    public async Task<T?> GetAsync<T>(string userId, string key, CancellationToken ct = default)
    {
        var root = await ReadAsync(userId, ct);
        var node = root[key];
        return node is null ? default : node.Deserialize<T>(Json);
    }

    /// <summary>Stores <paramref name="value"/> as the section under <paramref name="key"/> (replaces that section only).</summary>
    public async Task SetAsync<T>(string userId, string key, T value, CancellationToken ct = default)
    {
        var root = await ReadAsync(userId, ct);
        root[key] = JsonSerializer.SerializeToNode(value, Json);
        await store.SetAsync(userId, root.ToJsonString(), ct);
    }

    /// <summary>Removes the section stored under <paramref name="key"/>, if present.</summary>
    public async Task RemoveAsync(string userId, string key, CancellationToken ct = default)
    {
        var root = await ReadAsync(userId, ct);
        if (root.Remove(key))
            await store.SetAsync(userId, root.ToJsonString(), ct);
    }

    // ---- Raw JSON access (the whole document) -----------------------------------------

    public Task<JsonObject> GetAsync(string userId, CancellationToken ct = default) => ReadAsync(userId, ct);

    /// <summary>Shallow-merges <paramref name="patch"/> into the document (set a key to null to remove it).</summary>
    public async Task<JsonObject> UpdateAsync(string userId, JsonObject patch, CancellationToken ct = default)
    {
        var current = await ReadAsync(userId, ct);
        foreach (var (key, value) in patch)
        {
            if (value is null) current.Remove(key);
            else current[key] = value.DeepClone();
        }
        await store.SetAsync(userId, current.ToJsonString(), ct);
        return current;
    }

    public Task ClearAsync(string userId, CancellationToken ct = default) => store.ClearAsync(userId, ct);

    private async Task<JsonObject> ReadAsync(string userId, CancellationToken ct)
    {
        var json = await store.GetAsync(userId, ct);
        return json is null ? new JsonObject() : (JsonNode.Parse(json) as JsonObject ?? new JsonObject());
    }
}
