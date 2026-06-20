using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Klassd.Auth.Migration;

/// <summary>
/// Reads a user export as a stream of JSON objects, auto-detecting the two shapes these tools emit:
/// a single JSON array (<c>[ {...}, {...} ]</c>, used by import templates) or newline-delimited JSON
/// (one object per line, used by bulk-export jobs). NDJSON is streamed line-by-line so huge exports
/// don't load whole; an array is parsed once.
/// </summary>
public static class JsonExportReader
{
    public static async IAsyncEnumerable<JsonObject> ReadAsync(
        Stream stream, [EnumeratorCancellation] CancellationToken ct = default)
    {
        using var reader = new StreamReader(stream);

        // Accumulate lines until the buffer parses as a complete JSON value, then emit and reset.
        // This handles all three shapes the same way: compact NDJSON (each line parses on its own),
        // a pretty-printed object or array (accumulates across lines), and concatenated objects.
        var buffer = new StringBuilder();
        while (await reader.ReadLineAsync(ct) is { } line)
        {
            ct.ThrowIfCancellationRequested();
            buffer.Append(line).Append('\n');
            if (string.IsNullOrWhiteSpace(buffer.ToString())) { buffer.Clear(); continue; }

            if (TryParse(buffer.ToString(), out var node))
            {
                foreach (var obj in Flatten(node)) yield return obj;
                buffer.Clear();
            }
        }

        if (!string.IsNullOrWhiteSpace(buffer.ToString()))
        {
            if (!TryParse(buffer.ToString(), out var node))
                throw new FormatException("Export ended with incomplete or malformed JSON.");
            foreach (var obj in Flatten(node)) yield return obj;
        }
    }

    private static bool TryParse(string text, out JsonNode? node)
    {
        try { node = JsonNode.Parse(text); return true; }
        catch (JsonException) { node = null; return false; }  // likely a not-yet-complete multi-line value
    }

    private static IEnumerable<JsonObject> Flatten(JsonNode? node)
    {
        switch (node)
        {
            case JsonArray array:
                foreach (var n in array) if (n is JsonObject o) yield return o;
                break;
            case JsonObject obj:
                yield return obj;
                break;
        }
    }

    // ---- small JsonObject accessors used by the sources ----

    public static string? Str(this JsonObject o, string key) =>
        o.TryGetPropertyValue(key, out var n) && n is not null ? n.GetValue<string?>() : null;

    public static bool Bool(this JsonObject o, string key, bool fallback = false) =>
        o.TryGetPropertyValue(key, out var n) && n is JsonValue v && v.TryGetValue<bool>(out var b) ? b : fallback;

    public static DateTimeOffset Date(this JsonObject o, string key) =>
        o.Str(key) is { } s && DateTimeOffset.TryParse(s, out var d) ? d : default;
}
