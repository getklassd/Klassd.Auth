using System.Collections.Concurrent;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.DataProtection;

namespace Klassd.Auth.Passkeys;

/// <summary>
/// Holds a WebAuthn ceremony's options JSON between the "options" and "verify" requests. Returns an
/// opaque handle the caller round-trips to the browser (e.g. as a short-lived cookie).
/// </summary>
public interface IPasskeyChallengeStore
{
    Task<string> StashAsync(string optionsJson, TimeSpan ttl, CancellationToken ct = default);

    /// <summary>Returns the stashed options JSON, or null if the handle is unknown/expired/tampered.</summary>
    Task<string?> RetrieveAsync(string handle, CancellationToken ct = default);
}

/// <summary>
/// Stateless default: the handle IS the DataProtection-protected <c>{expiry|json}</c> payload, so no
/// server state is kept and it works across nodes (given a shared DataProtection key ring). Single
/// use is enforced by the endpoint clearing the ceremony cookie after verify.
/// </summary>
public sealed class DataProtectionPasskeyChallengeStore : IPasskeyChallengeStore
{
    private readonly IDataProtector _protector;

    public DataProtectionPasskeyChallengeStore(IDataProtectionProvider provider) =>
        _protector = provider.CreateProtector("Klassd.Auth.Passkeys.Ceremony.v1");

    public Task<string> StashAsync(string optionsJson, TimeSpan ttl, CancellationToken ct = default)
    {
        var expires = DateTimeOffset.UtcNow.Add(ttl).ToUnixTimeSeconds();
        var payload = $"{expires}|{optionsJson}";
        return Task.FromResult(_protector.Protect(payload));
    }

    public Task<string?> RetrieveAsync(string handle, CancellationToken ct = default)
    {
        try
        {
            var payload = _protector.Unprotect(handle);
            var sep = payload.IndexOf('|');
            if (sep <= 0) return Task.FromResult<string?>(null);
            var expires = long.Parse(payload[..sep], CultureInfo.InvariantCulture);
            if (DateTimeOffset.FromUnixTimeSeconds(expires) < DateTimeOffset.UtcNow)
                return Task.FromResult<string?>(null);
            return Task.FromResult<string?>(payload[(sep + 1)..]);
        }
        catch (CryptographicException)
        {
            return Task.FromResult<string?>(null);   // tampered / wrong key ring
        }
    }
}

/// <summary>In-memory ceremony store (single node / dev). Entries are lost on restart.</summary>
public sealed class InMemoryPasskeyChallengeStore : IPasskeyChallengeStore
{
    private readonly ConcurrentDictionary<string, (string Json, DateTimeOffset Expires)> _entries = new();

    public Task<string> StashAsync(string optionsJson, TimeSpan ttl, CancellationToken ct = default)
    {
        var handle = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        _entries[handle] = (optionsJson, DateTimeOffset.UtcNow.Add(ttl));
        return Task.FromResult(handle);
    }

    public Task<string?> RetrieveAsync(string handle, CancellationToken ct = default)
    {
        if (_entries.TryRemove(handle, out var e) && e.Expires >= DateTimeOffset.UtcNow)
            return Task.FromResult<string?>(e.Json);
        return Task.FromResult<string?>(null);
    }
}
