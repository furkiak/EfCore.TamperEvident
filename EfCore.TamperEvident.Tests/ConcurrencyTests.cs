using EfCore.TamperEvident.Configuration;
using EfCore.TamperEvident.Extensions;
using EfCore.TamperEvident.Models;
using EfCore.TamperEvident.Services;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;

namespace EfCore.TamperEvident.Tests
{
    /// <summary>
    /// Real concurrent writers on a file database: every connection has its own transaction, like separate app servers.
    /// </summary>
    public sealed class ConcurrencyTests : IDisposable
    {
        private readonly string _directory = Path.Combine(Path.GetTempPath(), "te-concurrency-" + Guid.NewGuid().ToString("N"));
        private readonly string _connectionString;
        private readonly TamperEvidentOptions _options = new() { HmacSecretKey = Harness.SecretKey };

        public ConcurrencyTests()
        {
            Directory.CreateDirectory(_directory);
            _connectionString = new SqliteConnectionStringBuilder
            {
                DataSource = Path.Combine(_directory, "audit.db"),
                DefaultTimeout = 60,
                Pooling = false
            }.ToString();

            using var context = CreateContext();
            context.Database.EnsureCreated();
        }

        private TestDbContext CreateContext(Action<DbContextOptionsBuilder<TestDbContext>>? configure = null)
        {
            var builder = new DbContextOptionsBuilder<TestDbContext>()
                .UseSqlite(_connectionString)
                .UseTamperEvidentAudit(_options);
            configure?.Invoke(builder);
            return new TestDbContext(builder.Options);
        }

        [Fact]
        public async Task ParallelWriters_ProduceOneUnbrokenChain()
        {
            const int writers = 8;
            const int savesPerWriter = 15;

            var tasks = Enumerable.Range(0, writers).Select(w => Task.Run(async () =>
            {
                for (var i = 0; i < savesPerWriter; i++)
                {
                    await using var db = CreateContext();
                    db.Customers.Add(new Customer { Name = $"w{w}-{i}" });
                    await db.SaveChangesAsync();
                }
            })).ToArray();
            await Task.WhenAll(tasks);

            await using var verify = CreateContext();
            var result = await new AuditVerifier(verify, _options).VerifyTableIntegrityAsync("Customers");

            Assert.True(result.IsValid, result.Message);
            Assert.Equal(writers * savesPerWriter, result.RecordsChecked);
            Assert.Equal(writers * savesPerWriter, result.HeadSequence);
            Assert.Equal(writers * savesPerWriter, await verify.Customers.CountAsync());

            var sequences = await verify.AuditLogs.Select(l => l.SequenceNumber).OrderBy(s => s).ToListAsync();
            Assert.Equal(Enumerable.Range(1, writers * savesPerWriter).Select(i => (long)i), sequences);
        }

        [Fact]
        public async Task ParallelFirstWriters_OfAFreshTable_DoNotFailOrFork()
        {
            // The very first write to a table creates its chain head: concurrent first writers must queue up.
            var tasks = Enumerable.Range(0, 6).Select(w => Task.Run(async () =>
            {
                await using var db = CreateContext();
                db.Documents.Add(new Document { Title = $"first-{w}" });
                await db.SaveChangesAsync();
            })).ToArray();
            await Task.WhenAll(tasks);

            await using var verify = CreateContext();
            var result = await new AuditVerifier(verify, _options).VerifyTableIntegrityAsync("Documents");
            Assert.True(result.IsValid, result.Message);
            Assert.Equal(6, result.RecordsChecked);
            Assert.Single(await verify.AuditChainStates.Where(s => s.TableName == "Documents").ToListAsync());
        }

        [Fact]
        public async Task TheUniqueIndexOnPreviousHash_RefusesAFork()
        {
            // Defence in depth: even if locking failed, two entries can never claim the same predecessor.
            await using (var db = CreateContext())
            {
                db.Customers.Add(new Customer { Name = "x" });
                await db.SaveChangesAsync();
            }

            await using var attacker = CreateContext(b => { });
            var first = await attacker.AuditLogs.AsNoTracking().SingleAsync();
            attacker.AuditLogs.Add(new AuditLog
            {
                TableName = first.TableName,
                RecordId = "2",
                ActionType = "Added",
                UserId = "x",
                PreviousHash = first.PreviousHash,
                CurrentHash = new string('0', 64)
            });

            await Assert.ThrowsAsync<DbUpdateException>(() => attacker.SaveChangesAsync());
        }

        [Fact]
        public async Task ParallelWritersToDifferentTables_DoNotDeadlock()
        {
            var tasks = Enumerable.Range(0, 6).Select(w => Task.Run(async () =>
            {
                for (var i = 0; i < 8; i++)
                {
                    await using var db = CreateContext();

                    // Alternate the order in which the two tables are touched.
                    if (w % 2 == 0)
                    {
                        db.Customers.Add(new Customer { Name = "c" });
                        db.Documents.Add(new Document { Title = "d" });
                    }
                    else
                    {
                        db.Documents.Add(new Document { Title = "d" });
                        db.Customers.Add(new Customer { Name = "c" });
                    }

                    await db.SaveChangesAsync();
                }
            })).ToArray();
            await Task.WhenAll(tasks);

            await using var verify = CreateContext();
            var report = await new AuditVerifier(verify, _options).VerifyAllAsync();
            Assert.True(report.IsValid, report.Message);
            Assert.Equal(96, report.RecordsChecked);
        }

        // The strategy of an application that calls EnableRetryOnFailure(): SaveChanges runs inside it, and it refuses
        // a nested SaveChanges or a transaction that exists when it starts.
        private TestDbContext CreateRetryingContext(Func<RetryingStrategy, RetryingStrategy>? decorate = null, params Microsoft.EntityFrameworkCore.Diagnostics.IInterceptor[] extra)
        {
            var builder = new DbContextOptionsBuilder<TestDbContext>()
                .UseSqlite(_connectionString, o => o.ExecutionStrategy(deps => new RetryingStrategy(deps)))
                .UseTamperEvidentAudit(_options);
            if (extra.Length > 0)
            {
                builder.AddInterceptors(extra);
            }

            return new TestDbContext(builder.Options);
        }

        [Fact]
        public async Task ExecutionStrategyThatRetriesOnFailure_IsSupported()
        {
            // Regression: a nested SaveChanges used to make every save fail with such a strategy.
            await using (var db = CreateRetryingContext())
            {
                db.Customers.Add(new Customer { Name = "retry" });
                await db.SaveChangesAsync();
                db.Customers.First().Name = "retry (changed)";
                await db.SaveChangesAsync();
            }

            await using var verify = CreateContext();
            var result = await new AuditVerifier(verify, _options).VerifyTableIntegrityAsync("Customers");
            Assert.True(result.IsValid, result.Message);
            Assert.Equal(2, result.RecordsChecked);
        }

        [Fact]
        public async Task ExecutionStrategyThatRetriesOnFailure_SupportsSynchronousSaves()
        {
            using var db = CreateRetryingContext();
            db.Customers.Add(new Customer { Name = "sync retry" });
            db.SaveChanges();

            await using var verify = CreateContext();
            Assert.True((await new AuditVerifier(verify, _options).VerifyTableIntegrityAsync("Customers")).IsValid);
        }

        [Fact]
        public async Task TransientFailureWhileSavingTheData_IsRetried_WithoutDuplicatingTheAudit()
        {
            var failures = new FailingCommands(c => c.CommandText.Contains("INSERT INTO \"Customers\"", StringComparison.Ordinal), times: 1);
            await using (var db = CreateRetryingContext(extra: failures))
            {
                db.Customers.Add(new Customer { Name = "survives a transient failure" });
                await db.SaveChangesAsync();
            }

            Assert.Equal(1, failures.Failed);
            await using var verify = CreateContext();
            Assert.Equal(1, await verify.Customers.CountAsync());
            Assert.Single(await verify.AuditLogs.ToListAsync());
            Assert.True((await new AuditVerifier(verify, _options).VerifyTableIntegrityAsync("Customers")).IsValid);
        }

        [Fact]
        public async Task TransientFailureWhileWritingTheAudit_IsNeverSwallowedByTheStrategy()
        {
            // The data was saved and accepted when the audit entry fails. A retry would find nothing left to save and
            // report success while the transaction is gone, so the failure must surface and nothing may persist.
            var failures = new FailingCommands(c => c.CommandText.Contains("INSERT INTO \"AuditLogs\"", StringComparison.Ordinal), times: 1);
            await using (var db = CreateRetryingContext(extra: failures))
            {
                db.Customers.Add(new Customer { Name = "must not be saved without its audit entry" });

                var ex = await Assert.ThrowsAsync<AuditTrailException>(() => db.SaveChangesAsync());
                Assert.IsType<TransientTestException>(ex.InnerException);
                Assert.Null(db.Database.CurrentTransaction);
            }

            await using var verify = CreateContext();
            Assert.Equal(0, await verify.Customers.CountAsync());
            Assert.Empty(await verify.AuditLogs.ToListAsync());
            Assert.Empty(await verify.AuditChainStates.ToListAsync());
        }

        [Fact]
        public async Task AuditWriteFailure_RollsBackTheOwnedTransaction_WithoutAStrategy()
        {
            var failures = new FailingCommands(c => c.CommandText.Contains("UPDATE \"AuditChainStates\"", StringComparison.Ordinal), times: 1);
            var builder = new DbContextOptionsBuilder<TestDbContext>()
                .UseSqlite(_connectionString)
                .UseTamperEvidentAudit(_options)
                .AddInterceptors(failures);

            await using (var db = new TestDbContext(builder.Options))
            {
                db.Customers.Add(new Customer { Name = "rolled back" });
                await Assert.ThrowsAsync<AuditTrailException>(() => db.SaveChangesAsync());
                Assert.Null(db.Database.CurrentTransaction);
            }

            await using var verify = CreateContext();
            Assert.Equal(0, await verify.Customers.CountAsync());
            Assert.Empty(await verify.AuditLogs.ToListAsync());
        }

        public void Dispose()
        {
            SqliteConnection.ClearAllPools();
            try
            {
                Directory.Delete(_directory, recursive: true);
            }
            catch (IOException)
            {
                // best effort cleanup of the temp database
            }
        }

        private sealed class TransientTestException : Exception
        {
        }

        private sealed class RetryingStrategy : ExecutionStrategy
        {
            public RetryingStrategy(ExecutionStrategyDependencies dependencies)
                : base(dependencies, maxRetryCount: 3, maxRetryDelay: TimeSpan.FromMilliseconds(10))
            {
            }

            protected override bool ShouldRetryOn(Exception exception) => exception is TransientTestException;
        }

        /// <summary>Throws a transient error when a matching command is about to run.</summary>
        private sealed class FailingCommands : Microsoft.EntityFrameworkCore.Diagnostics.DbCommandInterceptor
        {
            private readonly Func<System.Data.Common.DbCommand, bool> _matches;
            private int _remaining;

            public FailingCommands(Func<System.Data.Common.DbCommand, bool> matches, int times)
            {
                _matches = matches;
                _remaining = times;
            }

            public int Failed { get; private set; }

            private void MaybeFail(System.Data.Common.DbCommand command)
            {
                if (_matches(command) && _remaining > 0)
                {
                    _remaining--;
                    Failed++;
                    throw new TransientTestException();
                }
            }

            public override Microsoft.EntityFrameworkCore.Diagnostics.InterceptionResult<int> NonQueryExecuting(
                System.Data.Common.DbCommand command,
                Microsoft.EntityFrameworkCore.Diagnostics.CommandEventData eventData,
                Microsoft.EntityFrameworkCore.Diagnostics.InterceptionResult<int> result)
            {
                MaybeFail(command);
                return result;
            }

            public override ValueTask<Microsoft.EntityFrameworkCore.Diagnostics.InterceptionResult<int>> NonQueryExecutingAsync(
                System.Data.Common.DbCommand command,
                Microsoft.EntityFrameworkCore.Diagnostics.CommandEventData eventData,
                Microsoft.EntityFrameworkCore.Diagnostics.InterceptionResult<int> result,
                CancellationToken cancellationToken = default)
            {
                MaybeFail(command);
                return new ValueTask<Microsoft.EntityFrameworkCore.Diagnostics.InterceptionResult<int>>(result);
            }

            public override Microsoft.EntityFrameworkCore.Diagnostics.InterceptionResult<System.Data.Common.DbDataReader> ReaderExecuting(
                System.Data.Common.DbCommand command,
                Microsoft.EntityFrameworkCore.Diagnostics.CommandEventData eventData,
                Microsoft.EntityFrameworkCore.Diagnostics.InterceptionResult<System.Data.Common.DbDataReader> result)
            {
                MaybeFail(command);
                return result;
            }

            public override ValueTask<Microsoft.EntityFrameworkCore.Diagnostics.InterceptionResult<System.Data.Common.DbDataReader>> ReaderExecutingAsync(
                System.Data.Common.DbCommand command,
                Microsoft.EntityFrameworkCore.Diagnostics.CommandEventData eventData,
                Microsoft.EntityFrameworkCore.Diagnostics.InterceptionResult<System.Data.Common.DbDataReader> result,
                CancellationToken cancellationToken = default)
            {
                MaybeFail(command);
                return new ValueTask<Microsoft.EntityFrameworkCore.Diagnostics.InterceptionResult<System.Data.Common.DbDataReader>>(result);
            }
        }
    }
}
