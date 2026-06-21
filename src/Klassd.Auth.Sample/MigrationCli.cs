using System.Text.Json;
using Klassd.Auth.Abstractions;
using Klassd.Auth.Migration;
using Klassd.Auth.Migration.SuperTokens;
using Klassd.Auth.Migration.SuperTokens.MySql;
using Klassd.Auth.Migration.SuperTokens.Postgres;
using Microsoft.Extensions.DependencyInjection;

/// <summary>
/// The <c>migrate-auth</c> verb. Intended to run as a one-shot Kubernetes Job / initContainer:
/// it ensures the Klassd.Auth schema exists, runs the chosen importer to completion, prints a
/// report, and exits with 0 on success (non-zero if any user failed).
/// </summary>
///
/// <example>
/// dotnet run -- migrate-auth --source auth0          --file ./auth0-export.json --apply
/// dotnet run -- migrate-auth --source supertokens    --file ./st-export.json
/// dotnet run -- migrate-auth --source supertokens-pg --conn "Host=…;Database=supertokens;Username=…;Password=…" --apply
/// dotnet run -- migrate-auth --source supertokens-mysql --conn "Server=…;Database=supertokens;User ID=…;Password=…" --apply
/// # Import into a specific tenant (shared-schema multi-tenancy):
/// dotnet run -- migrate-auth --source supertokens-pg --conn "…" --tenant acme --apply
/// # Fold MANY SuperTokens databases into one Klassd.Auth, each as its own tenant:
/// dotnet run -- migrate-auth --manifest ./tenants.json --apply
/// </example>
internal static class MigrationCli
{
    public static async Task<int> RunAsync(IServiceProvider services, string[] args)
    {
        var opts = ParseArgs(args);
        if (opts is null) return 2;   // usage already printed

        await using var scope = services.CreateAsyncScope();
        var sp = scope.ServiceProvider;

        // The Job may run before the app has ever started, so create the schema ourselves
        // (this is exactly what the StorageInitializerHostedService does on web startup).
        foreach (var init in sp.GetServices<IAuthStorageInitializer>().OrderBy(i => i.Order))
            await init.InitializeAsync();

        var o = opts.Value;
        var runner = sp.GetRequiredService<MigrationRunner>();
        var baseOptions = new MigrationOptions
        {
            DryRun = !o.Apply,
            OnConflict = o.Merge ? ConflictPolicy.Merge : ConflictPolicy.Skip,
        };

        // ---- Multi-database → multi-tenant (manifest) ----------------------------------------
        if (o.Manifest is not null)
        {
            List<(string Tenant, IMigrationSource Source)> sources;
            try
            {
                sources = LoadManifest(o.Manifest);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Cannot load manifest: {ex.Message}");
                return 2;
            }

            var reports = await runner.RunManyAsync(sources, baseOptions);
            var anyFailed = false;
            foreach (var (tenant, report) in reports)
            {
                PrintReport($"tenant '{tenant}'", report, o.Apply);
                anyFailed |= report.Failed != 0;
            }
            return anyFailed ? 1 : 0;
        }

        // ---- Single database (optionally into one tenant) ------------------------------------
        IMigrationSource source;
        try
        {
            source = BuildSource(o);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Cannot build source: {ex.Message}");
            return 2;
        }

        baseOptions.TenantId = o.Tenant ?? "public";
        var single = await runner.RunAsync(source, baseOptions);
        PrintReport($"{source.Name} → tenant '{baseOptions.TenantId}'", single, o.Apply);
        return single.Failed == 0 ? 0 : 1;
    }

    private static void PrintReport(string label, MigrationReport report, bool applied)
    {
        Console.WriteLine();
        Console.WriteLine($"{label} {(applied ? "applied" : "DRY RUN (pass --apply to write)")}:");
        Console.WriteLine($"  created : {report.Created}");
        Console.WriteLine($"  merged  : {report.Merged}");
        Console.WriteLine($"  skipped : {report.Skipped}");
        Console.WriteLine($"  failed  : {report.Failed}");
        Console.WriteLine($"  passwords needing reset: {report.PasswordsDropped}");

        foreach (var item in report.Items.Where(i => i.Outcome == MigrationOutcome.Failed))
            Console.Error.WriteLine($"  FAILED {item.Email ?? item.ExternalId}: {item.Error}");
    }

    // A manifest is a JSON array of source databases, each pinned to a tenant. See ManifestEntry.
    private static List<(string Tenant, IMigrationSource Source)> LoadManifest(string path)
    {
        var json = File.ReadAllText(path);
        var entries = JsonSerializer.Deserialize<List<ManifestEntry>>(json,
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
            ?? throw new ArgumentException("manifest is empty or not a JSON array.");

        return entries.ConvertAll(e =>
        {
            if (string.IsNullOrWhiteSpace(e.Tenant)) throw new ArgumentException("every manifest entry needs a \"tenant\".");
            var src = BuildSource(new Options { Source = e.Source, File = e.File, Conn = e.Conn, AppId = e.AppId ?? "public" });
            return (e.Tenant!, src);
        });
    }

    private static IMigrationSource BuildSource(Options o)
    {
        var stOptions = new SuperTokensDbOptions { AppId = o.AppId };
        return o.Source switch
        {
            "auth0" => new Klassd.Auth.Migration.Auth0.Auth0MigrationSource(Require(o.File, "--file")),
            "supertokens" => new SuperTokensMigrationSource(Require(o.File, "--file")),
            "supertokens-pg" => new SuperTokensPostgresMigrationSource(Require(o.Conn, "--conn"), stOptions),
            "supertokens-mysql" => new SuperTokensMySqlMigrationSource(Require(o.Conn, "--conn"), stOptions),
            _ => throw new ArgumentException($"Unknown --source '{o.Source}'."),
        };
    }

    private static string Require(string? value, string flag) =>
        string.IsNullOrWhiteSpace(value) ? throw new ArgumentException($"{flag} is required for this source.") : value;

    private static Options? ParseArgs(string[] args)
    {
        var o = new Options();
        for (var i = 1; i < args.Length; i++)   // args[0] is "migrate-auth"
        {
            switch (args[i])
            {
                case "--source": o.Source = Next(args, ref i); break;
                case "--file": o.File = Next(args, ref i); break;
                case "--conn": o.Conn = Next(args, ref i); break;
                case "--app-id": o.AppId = Next(args, ref i) ?? "public"; break;
                case "--tenant": o.Tenant = Next(args, ref i); break;
                case "--manifest": o.Manifest = Next(args, ref i); break;
                case "--apply": o.Apply = true; break;
                case "--merge": o.Merge = true; break;
                default:
                    Console.Error.WriteLine($"Unknown argument '{args[i]}'.");
                    PrintUsage();
                    return null;
            }
        }

        // Either a single --source, or a --manifest of many sources (each into its own tenant).
        if (string.IsNullOrWhiteSpace(o.Manifest) && string.IsNullOrWhiteSpace(o.Source)) { PrintUsage(); return null; }
        return o;
    }

    private static string? Next(string[] args, ref int i) => ++i < args.Length ? args[i] : null;

    private static void PrintUsage()
    {
        Console.Error.WriteLine(
            """
            Usage: migrate-auth (--source <auth0|supertokens|supertokens-pg|supertokens-mysql> | --manifest <path>) [options]
              --source <id>     one importer (auth0, supertokens, supertokens-pg, supertokens-mysql)
              --file <path>     export file (auth0, supertokens)
              --conn <string>   SuperTokens DB connection string (supertokens-pg, supertokens-mysql)
              --app-id <id>     SuperTokens app id (default: public)
              --tenant <id>     import the single source into this Klassd.Auth tenant (default: public)
              --manifest <path> JSON array of source databases, each pinned to a tenant — folds many
                                databases into one multi-tenant Klassd.Auth. Overrides --source.
              --apply           write changes (omit for a dry run)
              --merge           attach missing login methods to existing users (default: skip)

            Manifest entry: { "tenant": "acme", "source": "supertokens-pg",
                              "conn": "Host=…;Database=acme_st;…", "appId": "public" }
            """);
    }

    private struct Options
    {
        public string? Source;
        public string? File;
        public string? Conn;
        public string AppId = "public";
        public string? Tenant;
        public string? Manifest;
        public bool Apply;
        public bool Merge;
        public Options() { }
    }

    /// <summary>One source database in a multi-tenant manifest. <c>file</c> or <c>conn</c> per the source kind.</summary>
    private sealed record ManifestEntry(string? Tenant, string? Source, string? Conn, string? File, string? AppId);
}
