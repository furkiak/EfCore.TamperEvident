using EfCore.TamperEvident.Configuration;
using EfCore.TamperEvident.Extensions;
using EfCore.TamperEvident.Services;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;

namespace EfCore.TamperEvident.Tests;

public sealed class SqlServerIntegrationTests
{
    private static string? ServerConnection => Environment.GetEnvironmentVariable("EFCORE_AUDIT_SQLSERVER");

    private static (string Connection, DbContextOptions<TestDbContext> DbOptions, TamperEvidentOptions AuditOptions) CreateOptions(
        string server, Action<TamperEvidentOptions>? configure = null, bool enableRetry = false)
    {
        var connection = new SqlConnectionStringBuilder(server)
        {
            InitialCatalog = "AuditIt_" + Guid.NewGuid().ToString("N"),
            TrustServerCertificate = true,
            ConnectTimeout = 10
        }.ConnectionString;
        var audit = new TamperEvidentOptions { HmacSecretKey = TestKeys.Key, AnchorThreshold = 2 };
        configure?.Invoke(audit);
        var builder = new DbContextOptionsBuilder<TestDbContext>()
            .UseSqlServer(connection, sql => { if (enableRetry) sql.EnableRetryOnFailure(); });
        builder.UseTamperEvidentAudit(x =>
            {
                x.HmacSecretKey = audit.HmacSecretKey;
                x.AnchorThreshold = audit.AnchorThreshold;
                x.UserIdProvider = audit.UserIdProvider;
                x.CustomAnchorPublisher = audit.CustomAnchorPublisher;
            });
        return (connection, builder.Options, audit);
    }

    [Fact]
    [Trait("Category", "SqlServer")]
    public async Task SyncAndAsyncSavesProduceVerifiableChainAndDurableAnchor()
    {
        var server = ServerConnection ?? throw new InvalidOperationException("Set EFCORE_AUDIT_SQLSERVER for SQL integration tests.");
        var setup = CreateOptions(server, x => x.UserIdProvider = _ => "operator-42");
        await using var context = new TestDbContext(setup.DbOptions);
        await context.Database.EnsureCreatedAsync();
        try
        {
            context.TestEntities.Add(new TestEntity { Name = "first", Price = 10, ApiKey = "top-secret-example" });
            context.SaveChanges();
            Assert.Null(context.Database.CurrentTransaction);
            context.TestEntities.Add(new TestEntity { Name = "second", Price = 20 });
            await context.SaveChangesAsync();
            Assert.Null(context.Database.CurrentTransaction);

            await using var check = new TestDbContext(setup.DbOptions);
            var logs = await check.AuditLogs.OrderBy(x => x.TimestampTicks).ToListAsync();
            Assert.Equal(2, logs.Count);
            Assert.All(logs, x => Assert.Equal("operator-42", x.UserId));
            Assert.All(logs, x => Assert.StartsWith("v2:", x.CurrentHash));
            Assert.DoesNotContain("top-secret-example", logs[0].NewValues);
            Assert.Contains("[REDACTED]", logs[0].NewValues);
            Assert.Contains("\"Id\":1", logs[0].RecordId);
            Assert.Single(await check.PendingAnchors.ToListAsync());
            var externalAnchors = new List<string> { logs[1].CurrentHash };
            var result = await new AuditVerifier(check, setup.AuditOptions)
                .VerifyTableIntegrityAsync("TestEntities", externalAnchors);
            Assert.True(result.IsValid, result.Message);
            Assert.Equal(logs[1].CurrentHash, Assert.Single(externalAnchors));
            Assert.True((await new AuditVerifier(check, setup.AuditOptions)
                .VerifyTableIntegrityAsync("TestEntities", externalAnchors)).IsValid);
            Assert.Equal(logs[1].CurrentHash, Assert.Single(externalAnchors));
            var reversed = new List<string> { logs[1].CurrentHash, logs[0].CurrentHash };
            Assert.False((await new AuditVerifier(check, setup.AuditOptions)
                .VerifyTableIntegrityAsync("TestEntities", reversed)).IsValid);
            Assert.Equal(2, reversed.Count);
            logs[0].UserId = "forged-operator";
            await check.SaveChangesAsync();
            var tampered = await new AuditVerifier(check, setup.AuditOptions)
                .VerifyTableIntegrityAsync("TestEntities", externalAnchors);
            Assert.False(tampered.IsValid);
        }
        finally { await context.Database.EnsureDeletedAsync(); }
    }

    [Fact]
    [Trait("Category", "SqlServer")]
    public async Task RetryingStrategyRequiresWholeSaveDelegate()
    {
        var server = ServerConnection ?? throw new InvalidOperationException("Set EFCORE_AUDIT_SQLSERVER for SQL integration tests.");
        var setup = CreateOptions(server, enableRetry: true);
        await using var owner = new TestDbContext(setup.DbOptions);
        await owner.Database.EnsureCreatedAsync();
        try
        {
            owner.TestEntities.Add(new TestEntity { Name = "direct", Price = 1 });
            await Assert.ThrowsAsync<InvalidOperationException>(() => owner.SaveChangesAsync());
            await using (var check = new TestDbContext(setup.DbOptions))
            {
                Assert.Empty(await check.TestEntities.ToListAsync());
                Assert.Empty(await check.AuditLogs.ToListAsync());
            }

            var strategy = owner.Database.CreateExecutionStrategy();
            await strategy.ExecuteAsync(async () =>
            {
                await using var attempt = new TestDbContext(setup.DbOptions);
                attempt.TestEntities.Add(new TestEntity { Name = "wrapped", Price = 2 });
                await attempt.SaveChangesAsync();
            });
            await using var finalCheck = new TestDbContext(setup.DbOptions);
            Assert.Equal("wrapped", (await finalCheck.TestEntities.SingleAsync()).Name);
            Assert.True((await new AuditVerifier(finalCheck, setup.AuditOptions)
                .VerifyTableIntegrityAsync("TestEntities")).IsValid);
        }
        finally { await owner.Database.EnsureDeletedAsync(); }
    }

    [Fact]
    [Trait("Category", "SqlServer")]
    public async Task SaveWithoutAcceptingChangesIsRejectedAndRolledBack()
    {
        var server = ServerConnection ?? throw new InvalidOperationException("Set EFCORE_AUDIT_SQLSERVER for SQL integration tests.");
        var setup = CreateOptions(server);
        await using var context = new TestDbContext(setup.DbOptions);
        await context.Database.EnsureCreatedAsync();
        try
        {
            context.TestEntities.Add(new TestEntity { Name = "unsupported-sync", Price = 1 });
            var syncError = Assert.Throws<NotSupportedException>(() => context.SaveChanges(false));
            Assert.Contains("acceptAllChangesOnSuccess", syncError.Message);
            Assert.Null(context.Database.CurrentTransaction);

            await using var check = new TestDbContext(setup.DbOptions);
            Assert.Empty(await check.TestEntities.ToListAsync());
            Assert.Empty(await check.AuditLogs.ToListAsync());

            await using var asyncContext = new TestDbContext(setup.DbOptions);
            asyncContext.TestEntities.Add(new TestEntity { Name = "unsupported-async", Price = 2 });
            var asyncError = await Assert.ThrowsAsync<NotSupportedException>(
                () => asyncContext.SaveChangesAsync(false));
            Assert.Contains("acceptAllChangesOnSuccess", asyncError.Message);
            Assert.Null(asyncContext.Database.CurrentTransaction);
            Assert.Empty(await check.TestEntities.ToListAsync());
            Assert.Empty(await check.AuditLogs.ToListAsync());

            await using var externalContext = new TestDbContext(setup.DbOptions);
            await using (var transaction = await externalContext.Database.BeginTransactionAsync())
            {
                externalContext.TestEntities.Add(new TestEntity { Name = "unsupported-external", Price = 3 });
                await Assert.ThrowsAsync<NotSupportedException>(() => externalContext.SaveChangesAsync(false));
                Assert.Null(externalContext.Database.CurrentTransaction);
            }
            Assert.Empty(await check.TestEntities.ToListAsync());
            Assert.Empty(await check.AuditLogs.ToListAsync());
        }
        finally { await context.Database.EnsureDeletedAsync(); }
    }

    [Fact]
    [Trait("Category", "SqlServer")]
    public async Task InsertUpdateDeleteWorkOnBothSavePaths()
    {
        var server = ServerConnection ?? throw new InvalidOperationException("Set EFCORE_AUDIT_SQLSERVER for SQL integration tests.");
        var setup = CreateOptions(server, x => x.AnchorThreshold = 100);
        await using var context = new TestDbContext(setup.DbOptions);
        await context.Database.EnsureCreatedAsync();
        try
        {
            var sync = new TestEntity { Name = "sync", Price = 1 };
            context.TestEntities.Add(sync);
            context.SaveChanges();
            sync.Price = 2;
            context.SaveChanges();
            context.TestEntities.Remove(sync);
            context.SaveChanges();

            var asyncEntity = new TestEntity { Name = "async", Price = 3 };
            context.TestEntities.Add(asyncEntity);
            await context.SaveChangesAsync();
            asyncEntity.Price = 4;
            await context.SaveChangesAsync();
            context.TestEntities.Remove(asyncEntity);
            await context.SaveChangesAsync();

            await using var check = new TestDbContext(setup.DbOptions);
            var logs = await check.AuditLogs.OrderBy(x => x.TimestampTicks).ToListAsync();
            Assert.Equal(new[] { "Added", "Modified", "Deleted", "Added", "Modified", "Deleted" },
                logs.Select(x => x.ActionType));
            Assert.Contains("\"Price\":1", logs[1].OldValues);
            Assert.Contains("\"Price\":2", logs[1].NewValues);
            Assert.True((await new AuditVerifier(check, setup.AuditOptions)
                .VerifyTableIntegrityAsync("TestEntities")).IsValid);
        }
        finally { await context.Database.EnsureDeletedAsync(); }
    }

    [Fact]
    [Trait("Category", "SqlServer")]
    public async Task ExternalTransactionRemainsOpenAndRollbackRemovesBusinessAndAudit()
    {
        var server = ServerConnection ?? throw new InvalidOperationException("Set EFCORE_AUDIT_SQLSERVER for SQL integration tests.");
        var setup = CreateOptions(server);
        await using var context = new TestDbContext(setup.DbOptions);
        await context.Database.EnsureCreatedAsync();
        try
        {
            await using (var transaction = await context.Database.BeginTransactionAsync())
            {
                context.TestEntities.Add(new TestEntity { Name = "rollback", Price = 1 });
                await context.SaveChangesAsync();
                Assert.Same(transaction, context.Database.CurrentTransaction);
                Assert.Single(await context.AuditLogs.ToListAsync());
                await transaction.RollbackAsync();
            }
            await using var check = new TestDbContext(setup.DbOptions);
            Assert.Empty(await check.TestEntities.ToListAsync());
            Assert.Empty(await check.AuditLogs.ToListAsync());
            context.TestEntities.Add(new TestEntity { Name = "after-rollback", Price = 2 });
            await context.SaveChangesAsync();
            var surviving = await check.AuditLogs.AsNoTracking().SingleAsync();
            Assert.Equal("GENESIS", surviving.PreviousHash);
            Assert.True((await new AuditVerifier(check, setup.AuditOptions)
                .VerifyTableIntegrityAsync("TestEntities")).IsValid);
        }
        finally { await context.Database.EnsureDeletedAsync(); }
    }

    [Fact]
    [Trait("Category", "SqlServer")]
    public async Task EmptySaveDoesNotOpenOrLeakATransaction()
    {
        var server = ServerConnection ?? throw new InvalidOperationException("Set EFCORE_AUDIT_SQLSERVER for SQL integration tests.");
        var setup = CreateOptions(server);
        await using var context = new TestDbContext(setup.DbOptions);
        await context.Database.EnsureCreatedAsync();
        try
        {
            Assert.Equal(0, context.SaveChanges());
            Assert.Null(context.Database.CurrentTransaction);
            Assert.Equal(0, await context.SaveChangesAsync());
            Assert.Null(context.Database.CurrentTransaction);
            Assert.Empty(await context.AuditLogs.ToListAsync());
        }
        finally { await context.Database.EnsureDeletedAsync(); }
    }

    [Fact]
    [Trait("Category", "SqlServer")]
    public async Task AuditFailureRollsBackAlreadyWrittenBusinessRow()
    {
        var server = ServerConnection ?? throw new InvalidOperationException("Set EFCORE_AUDIT_SQLSERVER for SQL integration tests.");
        var setup = CreateOptions(server, x => x.UserIdProvider = _ => throw new InvalidOperationException("audit unavailable"));
        await using var context = new TestDbContext(setup.DbOptions);
        await context.Database.EnsureCreatedAsync();
        try
        {
            context.TestEntities.Add(new TestEntity { Name = "must-not-persist", Price = 1 });
            Assert.Throws<InvalidOperationException>(() => context.SaveChanges());
            await using var check = new TestDbContext(setup.DbOptions);
            Assert.Empty(await check.TestEntities.ToListAsync());
            Assert.Empty(await check.AuditLogs.ToListAsync());
        }
        finally { await context.Database.EnsureDeletedAsync(); }
    }

    [Fact]
    [Trait("Category", "SqlServer")]
    public async Task AuditFailureRollsBackExternalTransactionToo()
    {
        var server = ServerConnection ?? throw new InvalidOperationException("Set EFCORE_AUDIT_SQLSERVER for SQL integration tests.");
        var setup = CreateOptions(server, x => x.UserIdProvider = _ => throw new InvalidOperationException("audit unavailable"));
        await using var context = new TestDbContext(setup.DbOptions);
        await context.Database.EnsureCreatedAsync();
        try
        {
            await using (var transaction = await context.Database.BeginTransactionAsync())
            {
                context.TestEntities.Add(new TestEntity { Name = "external-failure", Price = 1 });
                await Assert.ThrowsAsync<InvalidOperationException>(() => context.SaveChangesAsync());
            }
            await using var check = new TestDbContext(setup.DbOptions);
            Assert.Empty(await check.TestEntities.ToListAsync());
            Assert.Empty(await check.AuditLogs.ToListAsync());
        }
        finally { await context.Database.EnsureDeletedAsync(); }
    }

    [Fact]
    [Trait("Category", "SqlServer")]
    public async Task CancellationDuringAuditRollsBackBusinessWrite()
    {
        var server = ServerConnection ?? throw new InvalidOperationException("Set EFCORE_AUDIT_SQLSERVER for SQL integration tests.");
        using var cancel = new CancellationTokenSource();
        var setup = CreateOptions(server, x => x.UserIdProvider = _ =>
        {
            cancel.Cancel();
            return "operator";
        });
        await using var context = new TestDbContext(setup.DbOptions);
        await context.Database.EnsureCreatedAsync();
        try
        {
            context.TestEntities.Add(new TestEntity { Name = "cancelled", Price = 1 });
            await Assert.ThrowsAnyAsync<OperationCanceledException>(
                () => context.SaveChangesAsync(cancel.Token));
            await using var check = new TestDbContext(setup.DbOptions);
            Assert.Empty(await check.TestEntities.ToListAsync());
            Assert.Empty(await check.AuditLogs.ToListAsync());
        }
        finally { await context.Database.EnsureDeletedAsync(); }
    }

    [Fact]
    [Trait("Category", "SqlServer")]
    public async Task DispatcherKeepsFailedAnchorAndRetries()
    {
        var server = ServerConnection ?? throw new InvalidOperationException("Set EFCORE_AUDIT_SQLSERVER for SQL integration tests.");
        var publisher = new TestPublisher { Fail = true };
        var setup = CreateOptions(server, x => { x.AnchorThreshold = 1; x.CustomAnchorPublisher = publisher; });
        await using var context = new TestDbContext(setup.DbOptions);
        await context.Database.EnsureCreatedAsync();
        try
        {
            context.TestEntities.Add(new TestEntity { Name = "anchor", Price = 1 });
            await context.SaveChangesAsync();
            await using var dispatchContext = new TestDbContext(setup.DbOptions);
            var dispatcher = new AnchorDispatcher(dispatchContext, setup.AuditOptions);
            Assert.Equal(0, await dispatcher.DispatchPendingAsync());
            var pending = await dispatchContext.PendingAnchors.SingleAsync();
            Assert.Null(pending.DeliveredAtUtc);
            Assert.Equal(1, pending.AttemptCount);
            publisher.Fail = false;
            await using var afterRestart = new TestDbContext(setup.DbOptions);
            Assert.Equal(1, await new AnchorDispatcher(afterRestart, setup.AuditOptions)
                .DispatchPendingAsync());
            var delivered = await afterRestart.PendingAnchors.SingleAsync();
            Assert.NotNull(delivered.DeliveredAtUtc);
            Assert.Equal(2, delivered.AttemptCount);
            Assert.Equal(1, publisher.Sent);
        }
        finally { await context.Database.EnsureDeletedAsync(); }
    }

    [Fact]
    [Trait("Category", "SqlServer")]
    public async Task ConcurrentWritersDoNotForkTheChain()
    {
        var server = ServerConnection ?? throw new InvalidOperationException("Set EFCORE_AUDIT_SQLSERVER for SQL integration tests.");
        var setup = CreateOptions(server, x => x.AnchorThreshold = 100);
        await using var owner = new TestDbContext(setup.DbOptions);
        await owner.Database.EnsureCreatedAsync();
        try
        {
            var saves = Enumerable.Range(0, 6).Select(async n =>
            {
                await using var context = new TestDbContext(setup.DbOptions);
                context.TestEntities.Add(new TestEntity { Name = "parallel-" + n, Price = n });
                await context.SaveChangesAsync();
            });
            await Task.WhenAll(saves);
            await using var check = new TestDbContext(setup.DbOptions);
            Assert.Equal(6, await check.TestEntities.CountAsync());
            Assert.Equal(6, await check.AuditLogs.CountAsync());
            var result = await new AuditVerifier(check, setup.AuditOptions).VerifyTableIntegrityAsync("TestEntities");
            Assert.True(result.IsValid, result.Message);
        }
        finally { await owner.Database.EnsureDeletedAsync(); }
    }

    [Fact]
    [Trait("Category", "SqlServer")]
    public async Task CompositeKeysAndSchemasHaveIndependentChains()
    {
        var server = ServerConnection ?? throw new InvalidOperationException("Set EFCORE_AUDIT_SQLSERVER for SQL integration tests.");
        var setup = CreateOptions(server);
        await using var context = new TestDbContext(setup.DbOptions);
        await context.Database.EnsureCreatedAsync();
        try
        {
            context.SalesEntries.Add(new SalesEntry
            {
                TenantId = "north", ExternalId = "42", Value = "sale"
            });
            context.SupportEntries.Add(new SupportEntry
            {
                TenantId = "north", ExternalId = "42", Value = "ticket"
            });
            await context.SaveChangesAsync();
            await using var check = new TestDbContext(setup.DbOptions);
            var logs = await check.AuditLogs.ToListAsync();
            Assert.Equal(2, logs.Count);
            Assert.Contains(logs, x => x.TableName == "sales.Entries");
            Assert.Contains(logs, x => x.TableName == "support.Entries");
            Assert.All(logs, x =>
            {
                Assert.Equal("GENESIS", x.PreviousHash);
                Assert.Contains("\"ExternalId\":\"42\"", x.RecordId);
                Assert.Contains("\"TenantId\":\"north\"", x.RecordId);
            });
            Assert.True((await new AuditVerifier(check, setup.AuditOptions)
                .VerifyTableIntegrityAsync("sales.Entries")).IsValid);
            Assert.True((await new AuditVerifier(check, setup.AuditOptions)
                .VerifyTableIntegrityAsync("support.Entries")).IsValid);
        }
        finally { await context.Database.EnsureDeletedAsync(); }
    }

    private sealed class TestPublisher : IAnchorPublisher
    {
        public bool Fail { get; set; }
        public int Sent { get; private set; }
        public Task SendAnchorAsync(string tableName, string currentHash, int recordCount)
        {
            if (Fail) throw new InvalidOperationException("simulated delivery failure");
            Sent++;
            return Task.CompletedTask;
        }
    }
}
