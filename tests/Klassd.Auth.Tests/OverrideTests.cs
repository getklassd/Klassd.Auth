using Klassd.Auth.Abstractions;
using Klassd.Auth.Core.DependencyInjection;
using Klassd.Auth.Core.Modules.EmailPassword;
using Klassd.Auth.Core.Modules.Users;
using Klassd.Auth.Core.Sessions;
using Microsoft.Extensions.DependencyInjection;
using TUnit.Assertions;
using TUnit.Assertions.Extensions;
using TUnit.Core;

namespace Klassd.Auth.Tests;

public sealed class OverrideTests
{
    // Builds a real DI container with the fake stores so the Core services resolve like in production.
    private static ServiceProvider Build(Action<IAuthBuilder> configure)
    {
        var services = new ServiceCollection();
        var auth = services.AddKlassdAuth(new SessionConfig { SigningKey = "0123456789abcdef0123456789abcdef" });
        services.AddScoped<IUserStore, FakeUserStore>();
        services.AddScoped<ISessionStore, FakeSessionStore>();
        services.AddScoped<IUserMetadataStore, FakeMetadataStore>();
        configure(auth);
        return services.BuildServiceProvider();
    }

    // ---- An override that blocks a disposable-email domain, then defers to the original. ----
    private sealed class NoDisposableEmailOverride(IEmailPasswordService inner) : EmailPasswordServiceDecorator(inner)
    {
        public override Task<AuthResult> SignUpAsync(string email, string password, CancellationToken ct = default) =>
            email.EndsWith("@tempmail.com", StringComparison.OrdinalIgnoreCase)
                ? Task.FromResult(new AuthResult(false, Error: "DISPOSABLE_EMAIL_BLOCKED"))
                : base.SignUpAsync(email, password, ct);   // original behavior
    }

    [Test]
    public async Task Override_intercepts_and_can_short_circuit()
    {
        var sp = Build(a => a.Override<IEmailPasswordService>((inner, _) => new NoDisposableEmailOverride(inner)));
        await using var scope = sp.CreateAsyncScope();
        var svc = scope.ServiceProvider.GetRequiredService<IEmailPasswordService>();

        var blocked = await svc.SignUpAsync("evil@tempmail.com", "password123");
        await Assert.That(blocked.Success).IsFalse();
        await Assert.That(blocked.Error).IsEqualTo("DISPOSABLE_EMAIL_BLOCKED");
    }

    [Test]
    public async Task Override_falls_through_to_original_behavior()
    {
        var sp = Build(a => a.Override<IEmailPasswordService>((inner, _) => new NoDisposableEmailOverride(inner)));
        await using var scope = sp.CreateAsyncScope();
        var svc = scope.ServiceProvider.GetRequiredService<IEmailPasswordService>();

        var ok = await svc.SignUpAsync("real@example.com", "password123");   // not disposable → base runs
        await Assert.That(ok.Success).IsTrue();
        await Assert.That(ok.UserId).IsNotNull();

        // And the original side effects happened: the user can sign in.
        var signin = await svc.SignInAsync("real@example.com", "password123");
        await Assert.That(signin.Success).IsTrue();
    }

    // ---- Two overrides stack; the last-registered wraps the previous. ----
    private sealed class TaggingOverride(IEmailPasswordService inner, List<string> log, string tag)
        : EmailPasswordServiceDecorator(inner)
    {
        public override Task<AuthResult> SignUpAsync(string email, string password, CancellationToken ct = default)
        {
            log.Add(tag);
            return base.SignUpAsync(email, password, ct);
        }
    }

    [Test]
    public async Task Overrides_stack_outermost_first()
    {
        var log = new List<string>();
        var sp = Build(a => a
            .Override<IEmailPasswordService>((inner, _) => new TaggingOverride(inner, log, "inner"))
            .Override<IEmailPasswordService>((inner, _) => new TaggingOverride(inner, log, "outer")));

        await using var scope = sp.CreateAsyncScope();
        var svc = scope.ServiceProvider.GetRequiredService<IEmailPasswordService>();
        await svc.SignUpAsync("a@example.com", "password123");

        // Last registered runs first, then delegates inward.
        await Assert.That(log).IsEquivalentTo(new[] { "outer", "inner" });
    }

    [Test]
    public async Task Override_can_resolve_dependencies_from_the_provider()
    {
        // The decorate factory gets the IServiceProvider, so an override can pull other services.
        var sp = Build(a => a.Override<IUserAccountService>((inner, provider) =>
            new RolesAwareUserAccount(inner, provider.GetRequiredService<IRolesService>())));

        await using var scope = sp.CreateAsyncScope();
        var svc = scope.ServiceProvider.GetRequiredService<IUserAccountService>();
        var user = await svc.CreateLocalAsync("alice", "alice@example.com", "password123");

        var roles = await scope.ServiceProvider.GetRequiredService<IRolesService>().GetRolesAsync(user.Id);
        await Assert.That(roles).Contains("member");   // the override granted a default role
    }

    private sealed class RolesAwareUserAccount(IUserAccountService inner, IRolesService roles)
        : UserAccountServiceDecorator(inner)
    {
        public override async Task<User> CreateLocalAsync(string? username, string? email, string password, CancellationToken ct = default)
        {
            var user = await base.CreateLocalAsync(username, email, password, ct);
            await roles.SetRolesAsync(user.Id, ["member"], ct);
            return user;
        }
    }

    [Test]
    public async Task Override_of_unregistered_service_throws_clear_error()
    {
        var services = new ServiceCollection();
        var auth = new TestAuthBuilder(services);   // empty — nothing registered
        await Assert.That(() => auth.Override<IEmailPasswordService>((inner, _) => inner))
            .Throws<InvalidOperationException>();
    }

    private sealed class TestAuthBuilder(IServiceCollection services) : IAuthBuilder
    {
        public IServiceCollection Services { get; } = services;
    }
}
