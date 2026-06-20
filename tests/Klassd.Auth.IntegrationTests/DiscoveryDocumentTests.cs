using System.Security.Cryptography;
using System.Text.Json;
using Klassd.Auth.AspNetCore;
using Klassd.Auth.Core.DependencyInjection;
using Klassd.Auth.Core.Sessions;
using Klassd.Auth.Data.Sqlite;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using TUnit.Assertions;
using TUnit.Assertions.Extensions;

namespace Klassd.Auth.IntegrationTests;

/// <summary>
/// Klassd.Auth serves an OpenID Connect discovery document at
/// <c>{base}/.well-known/openid-configuration</c> so resource servers can auto-discover the issuer +
/// jwks_uri (point <c>AddJwtBearer</c> at the auth base URL as its Authority) rather than hard-coding.
/// </summary>
public class DiscoveryDocumentTests
{
    [Test]
    public async Task Discovery_advertises_issuer_jwks_and_alg_and_jwks_is_reachable()
    {
        using var rsa = RSA.Create(2048);
        await using var app = await BuildAsync(auth => auth.UseRsaSigning(rsa, "test-key"));
        var client = app.GetTestClient();

        var doc = await client.GetFromJsonElementAsync("/auth/.well-known/openid-configuration");

        await Assert.That(doc.GetProperty("issuer").GetString()).IsEqualTo("klassd.auth");
        var jwksUri = doc.GetProperty("jwks_uri").GetString()!;
        await Assert.That(jwksUri).EndsWith("/auth/jwks.json");
        await Assert.That(jwksUri).StartsWith("http");                       // absolute, not relative
        await Assert.That(doc.GetProperty("id_token_signing_alg_values_supported")[0].GetString()).IsEqualTo("RS256");

        // The advertised jwks_uri actually serves the signing key.
        var jwks = await client.GetFromJsonElementAsync(new Uri(jwksUri).PathAndQuery);
        await Assert.That(jwks.GetProperty("keys").GetArrayLength()).IsGreaterThan(0);
        await Assert.That(jwks.GetProperty("keys")[0].GetProperty("kid").GetString()).IsEqualTo("test-key");
    }

    [Test]
    public async Task Default_with_a_db_adapter_is_rotating_rs256_with_keys()
    {
        // No explicit signing call: a Data.* adapter supplies a key store, so RS256 + JWKS is the default.
        await using var app = await BuildAsync(_ => { });
        var client = app.GetTestClient();

        var doc = await client.GetFromJsonElementAsync("/auth/.well-known/openid-configuration");
        await Assert.That(doc.GetProperty("id_token_signing_alg_values_supported")[0].GetString()).IsEqualTo("RS256");

        var jwks = await client.GetFromJsonElementAsync("/auth/jwks.json");
        await Assert.That(jwks.GetProperty("keys").GetArrayLength()).IsGreaterThan(0);   // auto-generated, persisted
    }

    [Test]
    public async Task Shared_secret_opt_out_reports_hs256()
    {
        await using var app = await BuildAsync(auth => auth.UseSharedSecretSigning());
        var client = app.GetTestClient();

        var doc = await client.GetFromJsonElementAsync("/auth/.well-known/openid-configuration");
        await Assert.That(doc.GetProperty("id_token_signing_alg_values_supported")[0].GetString()).IsEqualTo("HS256");
        var jwks = await client.GetFromJsonElementAsync("/auth/jwks.json");
        await Assert.That(jwks.GetProperty("keys").GetArrayLength()).IsEqualTo(0);   // no public keys under HS256
    }

    private static async Task<WebApplication> BuildAsync(Action<Klassd.Auth.Abstractions.IAuthBuilder> configureSigning)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Logging.ClearProviders();

        var auth = builder.Services.AddKlassdAuth(new SessionConfig
        {
            SigningKey = "test-signing-key-that-is-at-least-32-chars",
        });
        auth.UseSqlite($"Data Source={Path.Combine(Path.GetTempPath(), $"klassd-disco-{Guid.NewGuid():n}.db")}");
        configureSigning(auth);

        var app = builder.Build();
        app.MapKlassdAuth();
        await app.StartAsync();
        return app;
    }
}

internal static class HttpJsonExtensions
{
    public static async Task<JsonElement> GetFromJsonElementAsync(this HttpClient client, string url)
    {
        using var resp = await client.GetAsync(url);
        resp.EnsureSuccessStatusCode();
        return JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement.Clone();
    }
}
