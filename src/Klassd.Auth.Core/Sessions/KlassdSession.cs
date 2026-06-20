using System.Text.Json;

namespace Klassd.Auth.Core.Sessions;

/// <summary>
/// A handle to a live session, modeled on SuperTokens' <c>sessionContainer</c>: read the user/handle
/// and the current access-token payload, and merge claims into it. Obtain one from the current request
/// (the bearer token) via <c>HttpContext.GetKlassdSessionAsync()</c>, from a post-sign-in hook, or from
/// <see cref="ISessionService.GetSessionAsync"/>.
/// </summary>
public sealed class KlassdSession
{
    private readonly ISessionService _sessions;
    private Dictionary<string, string> _payload;

    internal KlassdSession(ISessionService sessions, string handle, string userId, Dictionary<string, string> payload)
    {
        _sessions = sessions;
        Handle = handle;
        UserId = userId;
        _payload = payload;
    }

    public string Handle { get; }
    public string UserId { get; }

    /// <summary>The stored access-token payload (raw string values; JSON for arrays/objects).</summary>
    public IReadOnlyDictionary<string, string> GetAccessTokenPayload() => _payload;

    /// <summary>Reads one payload value deserialized as <typeparamref name="T"/> (or default if absent).</summary>
    public T? GetClaimValue<T>(string key)
    {
        if (!_payload.TryGetValue(key, out var raw)) return default;
        if (typeof(T) == typeof(string)) return (T)(object)raw;
        try { return JsonSerializer.Deserialize<T>(raw); } catch { return default; }
    }

    /// <summary>
    /// Merges values into the session's stored payload (the equivalent of
    /// <c>sessionContainer.MergeIntoAccessTokenPayload</c>). Persisted, so it rides every future token.
    /// A null value removes the key. Arrays/objects become real JSON claims.
    /// </summary>
    public async Task MergeIntoAccessTokenPayloadAsync(IReadOnlyDictionary<string, object?> payload, CancellationToken ct = default)
    {
        await _sessions.MergeIntoAccessTokenPayloadAsync(Handle, payload, ct);
        var copy = new Dictionary<string, string>(_payload);
        foreach (var (key, value) in payload)
        {
            if (value is null) copy.Remove(key);
            else copy[key] = value as string ?? JsonSerializer.Serialize(value);
        }
        _payload = copy;
    }

    /// <summary>Anonymous-object overload, so the call reads like the Go map literal:
    /// <c>MergeIntoAccessTokenPayloadAsync(new { picture, roles })</c>.</summary>
    public Task MergeIntoAccessTokenPayloadAsync(object payload, CancellationToken ct = default) =>
        MergeIntoAccessTokenPayloadAsync(ToDictionary(payload), ct);

    public Task RevokeAsync(CancellationToken ct = default) => _sessions.RevokeAsync(Handle, ct);

    internal static IReadOnlyDictionary<string, object?> ToDictionary(object payload)
    {
        if (payload is IReadOnlyDictionary<string, object?> d) return d;
        var node = JsonSerializer.SerializeToElement(payload);
        var result = new Dictionary<string, object?>();
        foreach (var prop in node.EnumerateObject())
            result[prop.Name] = FromJson(prop.Value);
        return result;
    }

    // Map JSON scalars to CLR values so the merge stores strings raw (not re-quoted); arrays/objects
    // stay as JsonElement and the merge JSON-serializes them into real JSON claims.
    private static object? FromJson(JsonElement e) => e.ValueKind switch
    {
        JsonValueKind.Null => null,
        JsonValueKind.String => e.GetString(),
        JsonValueKind.True => true,
        JsonValueKind.False => false,
        JsonValueKind.Number => e.GetRawText(),
        _ => e,
    };
}

/// <summary>Context for an <see cref="ISessionCreateHook"/>.</summary>
/// <param name="UserId">The user the session is being created for.</param>
/// <param name="Metadata">
/// Optional caller-supplied context (e.g. a provider id / provider tokens from a third-party sign-in),
/// passed to <see cref="ISessionService.CreateAsync"/> so the hook can react to how the session began.
/// </param>
public sealed record SessionCreateContext(string UserId, IReadOnlyDictionary<string, object?> Metadata);

/// <summary>
/// Runs when a new session is created, handed the live <see cref="KlassdSession"/> so it can merge into
/// the access-token payload — the equivalent of overriding SuperTokens' <c>CreateNewSession</c> (and the
/// "post-sign-in hook hands you a session" pattern). Merges persist, so they ride every token incl.
/// refreshes. Register via <c>auth.AddSessionCreateHook</c>.
/// </summary>
public interface ISessionCreateHook
{
    Task OnSessionCreatedAsync(KlassdSession session, SessionCreateContext context, CancellationToken ct = default);
}
