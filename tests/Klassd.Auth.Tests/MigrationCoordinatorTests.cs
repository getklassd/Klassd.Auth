using System.Runtime.CompilerServices;
using Klassd.Auth.Core.Modules.UserMetadata;
using Klassd.Auth.Core.Modules.Users;
using Klassd.Auth.Migration;
using TUnit.Assertions;
using TUnit.Assertions.Extensions;
using TUnit.Core;

namespace Klassd.Auth.Tests;

public sealed class MigrationCoordinatorTests
{
    private static (MigrationCoordinator coord, FakeUserStore users, FakeMigrationStateStore state) New()
    {
        var users = new FakeUserStore();
        var meta = new UserMetadataService(new FakeMetadataStore());
        var runner = new MigrationRunner(users, meta, new RolesService(meta));
        var state = new FakeMigrationStateStore();
        return (new MigrationCoordinator(runner, state), users, state);
    }

    private static IMigrationSource Source(params string[] emails) => new ArraySource(emails);

    private sealed class ArraySource(string[] emails) : IMigrationSource
    {
        public string Name => "Test";
        public async IAsyncEnumerable<MigratedUser> ReadAsync([EnumeratorCancellation] CancellationToken ct = default)
        {
            foreach (var e in emails) { yield return new MigratedUser { Email = e }; await Task.Yield(); }
        }
    }

    [Test]
    public async Task Runs_marks_completed_and_writes_users()
    {
        var (coord, users, state) = New();
        var result = await coord.RunOnceAsync("import-1", Source("a@x.com", "b@x.com"));

        await Assert.That(result.Outcome).IsEqualTo(MigrationRunOutcome.Completed);
        await Assert.That(result.Report!.Created).IsEqualTo(2);
        await Assert.That((await users.GetAllAsync()).Count).IsEqualTo(2);
        await Assert.That(await state.IsCompletedAsync("import-1")).IsTrue();
    }

    [Test]
    public async Task Second_run_after_completion_is_skipped_without_re_importing()
    {
        var (coord, users, _) = New();
        await coord.RunOnceAsync("import-1", Source("a@x.com"));

        var second = await coord.RunOnceAsync("import-1", Source("a@x.com", "c@x.com"));

        await Assert.That(second.Outcome).IsEqualTo(MigrationRunOutcome.AlreadyCompleted);
        await Assert.That(second.Report).IsNull();
        await Assert.That((await users.GetAllAsync()).Count).IsEqualTo(1);   // c@x.com never imported
    }

    [Test]
    public async Task Skips_when_another_instance_holds_the_lease()
    {
        var (coord, users, state) = New();
        // Simulate a concurrent replica already holding the lease (handle kept undisposed).
        await using var held = await state.TryAcquireLockAsync("import-1", TimeSpan.FromMinutes(5));
        await Assert.That(held).IsNotNull();

        var result = await coord.RunOnceAsync("import-1", Source("a@x.com"));

        await Assert.That(result.Outcome).IsEqualTo(MigrationRunOutcome.LockHeldByAnother);
        await Assert.That((await users.GetAllAsync()).Count).IsEqualTo(0);
    }

    [Test]
    public async Task RunOnce_without_a_state_store_throws_a_clear_error()
    {
        var users = new FakeUserStore();
        var meta = new UserMetadataService(new FakeMetadataStore());
        var coord = new MigrationCoordinator(new MigrationRunner(users, meta, new RolesService(meta)), state: null);

        await Assert.That(async () => await coord.RunOnceAsync("x", Source("a@x.com")))
            .Throws<InvalidOperationException>();
    }
}
