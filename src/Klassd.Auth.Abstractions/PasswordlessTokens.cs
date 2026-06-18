using System.Text.Json.Serialization;

namespace Klassd.Auth.Abstractions;

/// <summary>Delivery channel for a passwordless one-time code.</summary>
/// <remarks>Serialized by name ("Email"/"Sms") so JSON callers needn't send the numeric value.</remarks>
[JsonConverter(typeof(JsonStringEnumConverter<PasswordlessChannel>))]
public enum PasswordlessChannel
{
    Email,
    Sms
}

/// <summary>
/// A pending passwordless one-time code, stored hashed and keyed by its target identifier
/// (email address or phone number). One active code per identifier; storing a new code replaces
/// any existing one and resets the attempt counter.
/// </summary>
public sealed record PasswordlessCode(
    string Identifier, PasswordlessChannel Channel, string CodeHash, DateTimeOffset Expires, int Attempts);

/// <summary>
/// Persists short-lived passwordless codes (hashed, with a TTL and a failed-attempt counter so the
/// service can throttle brute force). A Klassd.Auth.Data.* adapter implements this for durability;
/// an in-memory default ships in Core.
/// </summary>
public interface IPasswordlessCodeStore
{
    /// <summary>Upserts the code for <paramref name="identifier"/>, replacing any existing one and resetting attempts.</summary>
    Task StoreAsync(string identifier, PasswordlessChannel channel, string codeHash, DateTimeOffset expires, CancellationToken ct = default);
    Task<PasswordlessCode?> FindAsync(string identifier, CancellationToken ct = default);
    Task IncrementAttemptsAsync(string identifier, CancellationToken ct = default);
    Task DeleteAsync(string identifier, CancellationToken ct = default);
}
