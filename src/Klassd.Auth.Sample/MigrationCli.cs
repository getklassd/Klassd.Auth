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
        foreach (var init in sp.GetServices<IAuthStorageInitializer>())
            await init.InitializeAsync();

        IMigrationSource source;
        try
        {
            source = BuildSource(opts.Value);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Cannot build source: {ex.Message}");
            return 2;
        }

        var runner = sp.GetRequiredService<MigrationRunner>();
        var report = await runner.RunAsync(source, new MigrationOptions
        {
            DryRun = !opts.Value.Apply,
            OnConflict = opts.Value.Merge ? ConflictPolicy.Merge : ConflictPolicy.Skip,
        });

        Console.WriteLine();
        Console.WriteLine($"{source.Name} migration {(opts.Value.Apply ? "applied" : "DRY RUN (pass --apply to write)")}:");
        Console.WriteLine($"  created : {report.Created}");
        Console.WriteLine($"  merged  : {report.Merged}");
        Console.WriteLine($"  skipped : {report.Skipped}");
        Console.WriteLine($"  failed  : {report.Failed}");
        Console.WriteLine($"  passwords needing reset: {report.PasswordsDropped}");

        foreach (var item in report.Items.Where(i => i.Outcome == MigrationOutcome.Failed))
            Console.Error.WriteLine($"  FAILED {item.Email ?? item.ExternalId}: {item.Error}");

        return report.Failed == 0 ? 0 : 1;
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
                case "--apply": o.Apply = true; break;
                case "--merge": o.Merge = true; break;
                default:
                    Console.Error.WriteLine($"Unknown argument '{args[i]}'.");
                    PrintUsage();
                    return null;
            }
        }

        if (string.IsNullOrWhiteSpace(o.Source)) { PrintUsage(); return null; }
        return o;
    }

    private static string? Next(string[] args, ref int i) => ++i < args.Length ? args[i] : null;

    private static void PrintUsage()
    {
        Console.Error.WriteLine(
            """
            Usage: migrate-auth --source <auth0|supertokens|supertokens-pg|supertokens-mysql> [options]
              --file <path>     export file (auth0, supertokens)
              --conn <string>   SuperTokens DB connection string (supertokens-pg, supertokens-mysql)
              --app-id <id>     SuperTokens app id (default: public)
              --apply           write changes (omit for a dry run)
              --merge           attach missing login methods to existing users (default: skip)
            """);
    }

    private struct Options
    {
        public string? Source;
        public string? File;
        public string? Conn;
        public string AppId = "public";
        public bool Apply;
        public bool Merge;
        public Options() { }
    }
}
