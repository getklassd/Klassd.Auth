using System.Text.Json;
using System.Text.Json.Serialization;
using Klassd.Auth.Abstractions;
using Klassd.Auth.Core.Modules.Users;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Klassd.Auth.Webhooks;

public sealed class WebhookOptions
{
    /// <summary>Accepted HMAC signing secrets (multiple to allow rotation). At least one is required.</summary>
    public List<string> SigningSecrets { get; } = [];

    /// <summary>Allowed clock skew (seconds) between the request timestamp and now. Default 300.</summary>
    public int ToleranceSeconds { get; set; } = 300;
}

/// <summary>A customer-service command to act on a user account.</summary>
public sealed record UserWebhookCommand(
    [property: JsonPropertyName("action")] string Action,
    [property: JsonPropertyName("userId")] string? UserId = null,
    [property: JsonPropertyName("email")] string? Email = null,
    [property: JsonPropertyName("reason")] string? Reason = null);

public static class WebhookExtensions
{
    /// <summary>Registers inbound webhook handling. Configure at least one <c>SigningSecret</c>.</summary>
    public static IAuthBuilder AddKlassdAuthWebhooks(this IAuthBuilder auth, Action<WebhookOptions> configure)
    {
        var options = new WebhookOptions();
        configure(options);
        auth.Services.AddSingleton(options);
        return auth;
    }

    /// <summary>
    /// Maps <c>POST {basePath}/users</c> — an HMAC-signed command to disable/enable/delete/anonymize a
    /// user (by <c>userId</c> or <c>email</c>). Anonymous to the app's auth (the HMAC signature is the
    /// credential); rejects unsigned/forged/stale requests with 401.
    /// </summary>
    public static IEndpointRouteBuilder MapKlassdAuthWebhooks(
        this IEndpointRouteBuilder app, string basePath = "/auth/webhooks")
    {
        var json = new JsonSerializerOptions(JsonSerializerDefaults.Web);

        app.MapPost($"{basePath}/users", async (
            HttpContext http, WebhookOptions options,
            UserAccountService accounts, AccountLifecycleService lifecycle, ILoggerFactory loggerFactory) =>
        {
            var log = loggerFactory.CreateLogger("Klassd.Auth.Webhooks");

            using var reader = new StreamReader(http.Request.Body);
            var body = await reader.ReadToEndAsync(http.RequestAborted);

            if (!WebhookSignature.Verify(http.Request.Headers, body, options, DateTimeOffset.UtcNow.ToUnixTimeSeconds(), out var why))
            {
                log.LogWarning("Rejected webhook: {Reason}", why);
                return Results.Json(new { error = "invalid_signature", detail = why }, statusCode: StatusCodes.Status401Unauthorized);
            }

            UserWebhookCommand? cmd;
            try { cmd = JsonSerializer.Deserialize<UserWebhookCommand>(body, json); }
            catch (JsonException) { return Results.BadRequest(new { error = "invalid_payload" }); }
            if (cmd is null || string.IsNullOrWhiteSpace(cmd.Action))
                return Results.BadRequest(new { error = "invalid_payload" });

            var user = cmd.UserId is { Length: > 0 } id ? await accounts.GetByIdAsync(id)
                     : cmd.Email is { Length: > 0 } email ? await accounts.FindByEmailAsync(email)
                     : null;
            if (user is null) return Results.NotFound(new { error = "user_not_found" });

            bool? applied = cmd.Action.ToLowerInvariant() switch
            {
                "disable"   => await lifecycle.DisableAsync(user.Id),
                "enable"    => await lifecycle.EnableAsync(user.Id),
                "delete"    => await lifecycle.DeleteAsync(user.Id),
                "anonymize" => await lifecycle.AnonymizeAsync(user.Id),
                _ => null,
            };
            if (applied is null) return Results.BadRequest(new { error = "unknown_action", action = cmd.Action });

            log.LogInformation("Webhook applied {Action} to user {UserId} (reason: {Reason})",
                cmd.Action, user.Id, cmd.Reason ?? "—");
            return Results.Ok(new { action = cmd.Action, userId = user.Id, applied });
        }).AllowAnonymous();

        return app;
    }
}
