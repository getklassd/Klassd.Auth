using Klassd.Auth.Abstractions;
using Klassd.Auth.Core.Modules.Users;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace Klassd.Auth.AspNetCore;

/// <summary>
/// Admin user-management HTTP API (list/get/create/disable/reset-password/roles). These mutate
/// accounts, so protect them: pass an <paramref name="authorizationPolicy"/> requiring an admin
/// role, or at minimum they require an authenticated caller.
/// </summary>
public static class AdminEndpoints
{
    public static IEndpointRouteBuilder MapKlassdAuthAdmin(
        this IEndpointRouteBuilder app, string basePath = "/auth/admin", string? authorizationPolicy = null)
    {
        var g = app.MapGroup(basePath);
        if (authorizationPolicy is null) g.RequireAuthorization();
        else g.RequireAuthorization(authorizationPolicy);

        g.MapGet("/users", async (UserAccountService accounts, RolesService roles, CancellationToken ct) =>
        {
            var users = await accounts.GetAllAsync(ct);
            var summaries = new List<UserSummary>(users.Count);
            foreach (var u in users)
                summaries.Add(await ToSummary(u, roles, ct));
            return Results.Ok(summaries);
        });

        g.MapGet("/users/{id}", async (string id, UserAccountService accounts, RolesService roles, CancellationToken ct) =>
        {
            var user = await accounts.GetByIdAsync(id, ct);
            return user is null ? Results.NotFound() : Results.Ok(await ToSummary(user, roles, ct));
        });

        g.MapPost("/users", async (CreateUser req, UserAccountService accounts, RolesService roles, CancellationToken ct) =>
        {
            try
            {
                var user = await accounts.CreateLocalAsync(req.Username, req.Email, req.Password, ct);
                if (req.Roles is { Count: > 0 }) await roles.SetRolesAsync(user.Id, req.Roles, ct);
                return Results.Created($"{basePath}/users/{user.Id}", await ToSummary(user, roles, ct));
            }
            catch (ArgumentException ex) { return Results.BadRequest(new { error = ex.Message }); }
        });

        g.MapPost("/users/{id}/disable", async (string id, SetDisabled req, UserAccountService accounts, CancellationToken ct) =>
            await accounts.SetDisabledAsync(id, req.Disabled, ct) ? Results.NoContent() : Results.NotFound());

        g.MapPost("/users/{id}/reset-password", async (string id, ResetPassword req, UserAccountService accounts, CancellationToken ct) =>
            await accounts.ResetPasswordAsync(id, req.NewPassword, ct) ? Results.NoContent() : Results.NotFound());

        g.MapGet("/users/{id}/roles", async (string id, RolesService roles, CancellationToken ct) =>
            Results.Ok(await roles.GetRolesAsync(id, ct)));

        g.MapPut("/users/{id}/roles", async (string id, SetRoles req, UserAccountService accounts, RolesService roles, CancellationToken ct) =>
        {
            if (await accounts.GetByIdAsync(id, ct) is null) return Results.NotFound();
            await roles.SetRolesAsync(id, req.Roles, ct);
            return Results.NoContent();
        });

        return app;
    }

    private static async Task<UserSummary> ToSummary(User u, RolesService roles, CancellationToken ct) => new(
        u.Id, u.Username, u.PrimaryEmail, u.Disabled, u.CreatedAt,
        u.LoginMethods.Select(m => new LoginMethodSummary(m.Kind.ToString(), m.ProviderId, m.Email, m.EmailVerified)).ToList(),
        await roles.GetRolesAsync(u.Id, ct));

    // Response/request DTOs — note no password hashes are ever exposed.
    public sealed record UserSummary(
        string Id, string? Username, string? Email, bool Disabled, DateTimeOffset CreatedAt,
        IReadOnlyList<LoginMethodSummary> LoginMethods, IReadOnlyList<string> Roles);
    public sealed record LoginMethodSummary(string Kind, string? ProviderId, string? Email, bool EmailVerified);

    public sealed record CreateUser(string? Username, string? Email, string Password, List<string>? Roles);
    public sealed record SetDisabled(bool Disabled);
    public sealed record ResetPassword(string NewPassword);
    public sealed record SetRoles(List<string> Roles);
}
