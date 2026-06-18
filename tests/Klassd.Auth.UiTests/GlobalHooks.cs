using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using TUnit.Core;

namespace Klassd.Auth.UiTests;

/// <summary>
/// Boots the Klassd.Auth Sample once for the whole test run on a free port, backed by a throwaway
/// SQLite database. Captures the app's stdout so tests can read the passwordless one-time code the
/// console "email"/"sms" senders print (there's no real mailbox in tests). TUnit.Playwright owns
/// the browser; we only own the app under test.
/// </summary>
public static class GlobalHooks
{
    private static Process? _process;
    private static string _dbPath = "";
    private static readonly ConcurrentQueue<string> _lines = new();

    /// <summary>Base URL of the running Sample, e.g. http://127.0.0.1:5173.</summary>
    public static string BaseUrl { get; private set; } = "";

    [Before(HookType.TestSession)]
    public static async Task StartSampleAsync()
    {
        var repoRoot = FindRepoRoot();
        var sampleProject = Path.Combine(repoRoot, "src", "Klassd.Auth.Sample", "Klassd.Auth.Sample.csproj");
        if (!File.Exists(sampleProject))
            throw new FileNotFoundException($"Sample project not found at {sampleProject}");

        var port = GetFreePort();
        // Use "localhost" (not 127.0.0.1): WebAuthn rejects a bare IP as an RP ID, but treats
        // localhost as a valid, secure-context-exempt relying party.
        BaseUrl = $"http://localhost:{port}";
        _dbPath = Path.Combine(Path.GetTempPath(), $"klassd-auth-uitests-{Guid.NewGuid():N}.db");

        var psi = new ProcessStartInfo("dotnet", $"run --project \"{sampleProject}\" --no-launch-profile")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        psi.Environment["ASPNETCORE_URLS"] = BaseUrl;
        psi.Environment["ASPNETCORE_ENVIRONMENT"] = "Development";
        psi.Environment["Auth__Sqlite__ConnectionString"] = $"Data Source={_dbPath}";
        // Passkey RP must match the origin the browser uses.
        psi.Environment["Auth__Passkeys__ServerDomain"] = "localhost";
        psi.Environment["Auth__Passkeys__Origin"] = BaseUrl;

        _process = new Process { StartInfo = psi };

        var listening = new TaskCompletionSource();
        void OnLine(string? line)
        {
            if (line is null) return;
            _lines.Enqueue(line);
            Console.WriteLine($"[sample] {line}");
            if (line.Contains("Now listening on", StringComparison.OrdinalIgnoreCase))
                listening.TrySetResult();
        }
        _process.OutputDataReceived += (_, e) => OnLine(e.Data);
        _process.ErrorDataReceived += (_, e) => OnLine(e.Data);

        _process.Start();
        _process.BeginOutputReadLine();
        _process.BeginErrorReadLine();

        var startup = await Task.WhenAny(listening.Task, Task.Delay(TimeSpan.FromSeconds(180)));
        if (startup != listening.Task)
            throw new TimeoutException("Sample app did not start within 180s.");
    }

    /// <summary>Polls captured stdout for the most recent line matching <paramref name="pattern"/>.</summary>
    public static async Task<Match> WaitForConsoleLineAsync(Regex pattern, TimeSpan? timeout = null)
    {
        var deadline = DateTime.UtcNow + (timeout ?? TimeSpan.FromSeconds(10));
        while (DateTime.UtcNow < deadline)
        {
            var match = _lines.Select(l => pattern.Match(l)).LastOrDefault(m => m.Success);
            if (match is { Success: true }) return match;
            await Task.Delay(100);
        }
        throw new TimeoutException($"No console line matched /{pattern}/ within the timeout.");
    }

    [After(HookType.TestSession)]
    public static void StopSample()
    {
        try
        {
            if (_process is { HasExited: false })
            {
                _process.Kill(entireProcessTree: true);
                _process.WaitForExit(10_000);
            }
        }
        catch { /* best effort */ }
        finally
        {
            _process?.Dispose();
            foreach (var f in new[] { _dbPath, _dbPath + "-wal", _dbPath + "-shm" })
                try { if (File.Exists(f)) File.Delete(f); } catch { }
        }
    }

    private static int GetFreePort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "Klassd.Auth.slnx")))
            dir = dir.Parent;
        return dir?.FullName ?? throw new DirectoryNotFoundException("Could not locate Klassd.Auth.slnx above the test output directory.");
    }
}
