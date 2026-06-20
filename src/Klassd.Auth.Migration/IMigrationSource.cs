namespace Klassd.Auth.Migration;

/// <summary>
/// A stream of users read out of a foreign system and normalized to <see cref="MigratedUser"/>.
/// Sources are pull-based and lazy so multi-million-row exports stream rather than load whole.
/// </summary>
public interface IMigrationSource
{
    /// <summary>The source system's name, for logging/reporting (e.g. "Auth0", "SuperTokens").</summary>
    string Name { get; }

    IAsyncEnumerable<MigratedUser> ReadAsync(CancellationToken ct = default);
}
