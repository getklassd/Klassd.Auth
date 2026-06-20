namespace Klassd.Auth.Migration.SuperTokens;

/// <summary>
/// Options for reading directly from a SuperTokens core database. Defaults match a stock
/// self-hosted install (app "public", no table prefix, default schema).
/// </summary>
public sealed class SuperTokensDbOptions
{
    /// <summary>The SuperTokens app to migrate (multitenancy). Stock installs use "public".</summary>
    public string AppId { get; set; } = "public";

    /// <summary>Schema to qualify table names with (e.g. "public" on Postgres). Null = unqualified.</summary>
    public string? TableSchema { get; set; }

    /// <summary>SuperTokens <c>table_names_prefix</c>, if one was configured. Joined as <c>prefix_table</c>.</summary>
    public string TablePrefix { get; set; } = "";

    /// <summary>Maps a SuperTokens <c>thirdPartyId</c> (e.g. "google") to your registered provider id.</summary>
    public Func<string, string>? MapProvider { get; set; }
}
