using System.Text.Json;
using Klassd.Auth.OAuth;
using TUnit.Assertions;
using TUnit.Assertions.Extensions;
using TUnit.Core;

namespace Klassd.Auth.Tests;

/// <summary>Unit tests for TikTok's non-standard bits, isolated from the HTTP handler.</summary>
public sealed class TikTokProfileTests
{
    [Test]
    public async Task RewriteAuthorizeUrl_renames_client_id_to_client_key()
    {
        const string url = "https://www.tiktok.com/v2/auth/authorize/?client_id=abc&scope=user.info.basic&response_type=code";
        var rewritten = TikTokProfile.RewriteAuthorizeUrl(url);
        await Assert.That(rewritten).Contains("client_key=abc");
        await Assert.That(rewritten).DoesNotContain("client_id=");
    }

    private static JsonElement Root(string json) => JsonDocument.Parse(json).RootElement;

    [Test]
    public async Task Parse_prefers_union_id_over_open_id()
    {
        var (subject, name) = TikTokProfile.Parse(Root(
            """{"data":{"user":{"open_id":"OPEN","union_id":"UNION","display_name":"Tara"}}}"""));
        await Assert.That(subject).IsEqualTo("UNION");
        await Assert.That(name).IsEqualTo("Tara");
    }

    [Test]
    public async Task Parse_falls_back_to_open_id_when_no_union_id()
    {
        var (subject, _) = TikTokProfile.Parse(Root("""{"data":{"user":{"open_id":"OPEN"}}}"""));
        await Assert.That(subject).IsEqualTo("OPEN");
    }

    [Test]
    public async Task Parse_returns_null_subject_when_neither_id_present()
    {
        var (subject, name) = TikTokProfile.Parse(Root("""{"data":{"user":{"display_name":"NoIds"}}}"""));
        await Assert.That(subject).IsNull();
        await Assert.That(name).IsEqualTo("NoIds");
    }
}
