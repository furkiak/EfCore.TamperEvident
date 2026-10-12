using System.Text.Json;
using EfCore.TamperEvident.Configuration;
using EfCore.TamperEvident.Extensions;
using EfCore.TamperEvident.Models;
using EfCore.TamperEvident.Services;
using Microsoft.EntityFrameworkCore;

namespace EfCore.TamperEvident.IntegrationTests
{
    /// <summary>
    /// The same scenarios against every real database server. Each concrete class below only names the provider.
    /// </summary>
    public abstract class ConformanceTests
    {
        protected abstract Provider Provider { get; }

        private Task<Database> OpenAsync(Naming naming = Naming.Default, bool retry = false, Action<TamperEvidentOptions>? configure = null) =>
            Database.CreateAsync(Provider, naming, retry, configure);

        private static AuditVerifier VerifierFor(ConformanceDb db, Database database) => new(db, database.Options);

        [SkippableFact]
        public async Task InsertUpdateDelete_AreChained_AndVerify()
        {
            await using var database = await OpenAsync();
            await using (var db = database.CreateContext())
            {
                var account = new Account { Name = "Ada", Balance = 100.50m, Photo = new byte[] { 1, 2, 3 } };
                db.Accounts.Add(account);
                await db.SaveChangesAsync();

                account.Balance = 250.75m;
                account.Name = "Ada Lovelace";
                await db.SaveChangesAsync();

                account.IsDeleted = true;
                await db.SaveChangesAsync();

                db.Accounts.Remove(account);
                await db.SaveChangesAsync();
            }

            await using var verify = database.CreateContext();
            var logs = await verify.Set<AuditLog>().OrderBy(l => l.SequenceNumber).ToListAsync();
            Assert.Equal(new[] { "Added", "Modified", "SoftDelete", "Deleted" }, logs.Select(l => l.ActionType));
            Assert.Equal(new long[] { 1, 2, 3, 4 }, logs.Select(l => l.SequenceNumber));
            Assert.Equal("1", logs[0].RecordId);

            using var added = JsonDocument.Parse(logs[0].NewValues!);
            Assert.Equal(1, added.RootElement.GetProperty("Id").GetInt32());
            Assert.Equal(100.50m, added.RootElement.GetProperty("Balance").GetDecimal());

            var result = await VerifierFor(verify, database).VerifyTableIntegrityAsync("Accounts");
            Assert.True(result.IsValid, result.Message);
            Assert.Equal(4, result.RecordsChecked);
        }

        [SkippableFact]
        public async Task SynchronousSaves_AreAudited()
        {
            await using var database = await OpenAsync();
            using (var db = database.CreateContext())
            {
                db.Accounts.Add(new Account { Name = "sync" });
                db.SaveChanges();
                db.Accounts.First().Balance = 5;
                db.SaveChanges();
            }

            await using var verify = database.CreateContext();
            var result = await VerifierFor(verify, database).VerifyTableIntegrityAsync("Accounts");
            Assert.True(result.IsValid, result.Message);
            Assert.Equal(2, result.RecordsChecked);
        }

        [SkippableFact]
        public async Task GuidAndCompositeKeys_AreAudited()
        {
            await using var database = await OpenAsync();
            var ticket = new Ticket { Title = "guid" };
            await using (var db = database.CreateContext())
            {
                db.Tickets.Add(ticket);
                db.Lines.Add(new Line { OrderId = 7, LineNo = 3, Product = "widget" });
                await db.SaveChangesAsync();
            }

            await using var verify = database.CreateContext();
            var logs = await verify.Set<AuditLog>().ToListAsync();
            Assert.Contains(logs, l => l.TableName == "Tickets" && l.RecordId == ticket.Id.ToString());
            Assert.Contains(logs, l => l.TableName == "Lines" && l.RecordId == "7|3");
            Assert.True((await VerifierFor(verify, database).VerifyAllAsync()).IsValid);
        }

        [SkippableFact]
        public async Task UnicodeAndLongValues_RoundTripAndVerify()
        {
            await using var database = await OpenAsync();
            var name = "Çiğdem Öztürk – 日本語 – 😀 " + new string('ğ', 6000);
            await using (var db = database.CreateContext())
            {
                db.Accounts.Add(new Account { Name = name });
                await db.SaveChangesAsync();
            }

            await using var verify = database.CreateContext();
            var log = await verify.Set<AuditLog>().SingleAsync();
            using var json = JsonDocument.Parse(log.NewValues!);
            Assert.Equal(name, json.RootElement.GetProperty("Name").GetString());
            Assert.True((await VerifierFor(verify, database).VerifyTableIntegrityAsync("Accounts")).IsValid);
        }

        [SkippableFact]
        public async Task ParallelWriters_ProduceOneUnbrokenChain()
        {
            // Real row locks: every writer has its own connection and transaction.
            await using var database = await OpenAsync();
            await SeedOnceAsync(database);

            const int writers = 8;
            const int savesPerWriter = 10;
            await Task.WhenAll(Enumerable.Range(0, writers).Select(w => Task.Run(async () =>
            {
                for (var i = 0; i < savesPerWriter; i++)
                {
                    await using var db = database.CreateContext();
                    db.Accounts.Add(new Account { Name = $"w{w}-{i}" });
                    await db.SaveChangesAsync();
                }
            })));

            await using var verify = database.CreateContext();
            var result = await VerifierFor(verify, database).VerifyTableIntegrityAsync("Accounts");
            Assert.True(result.IsValid, result.Message);
            Assert.Equal(1 + writers * savesPerWriter, result.RecordsChecked);
            Assert.Equal(1 + writers * savesPerWriter, await verify.Accounts.CountAsync());

            var sequences = await verify.Set<AuditLog>().Select(l => l.SequenceNumber).OrderBy(s => s).ToListAsync();
            Assert.Equal(Enumerable.Range(1, 1 + writers * savesPerWriter).Select(i => (long)i), sequences);
        }

        [SkippableFact]
        public async Task ParallelFirstWriters_OfAFreshTable_QueueUpInsteadOfFailing()
        {
            await using var database = await OpenAsync();

            await Task.WhenAll(Enumerable.Range(0, 8).Select(w => Task.Run(async () =>
            {
                await using var db = database.CreateContext();
                db.Tickets.Add(new Ticket { Title = "first-" + w });
                await db.SaveChangesAsync();
            })));

            await using var verify = database.CreateContext();
            var result = await VerifierFor(verify, database).VerifyTableIntegrityAsync("Tickets");
            Assert.True(result.IsValid, result.Message);
            Assert.Equal(8, result.RecordsChecked);
            Assert.Single(await verify.Set<AuditChainState>().Where(s => s.TableName == "Tickets").ToListAsync());
        }

        [SkippableFact]
        public async Task ParallelWritersOfSeveralTables_DoNotDeadlock()
        {
            await using var database = await OpenAsync();
            await Task.WhenAll(Enumerable.Range(0, 12).Select(w => Task.Run(async () =>
            {
                for (var i = 0; i < 6; i++)
                {
                    await using var db = database.CreateContext();
                    if (w % 2 == 0)
                    {
                        db.Accounts.Add(new Account { Name = "a" });
                        db.Tickets.Add(new Ticket { Title = "t" });
                    }
                    else
                    {
                        db.Tickets.Add(new Ticket { Title = "t" });
                        db.Accounts.Add(new Account { Name = "a" });
                    }

                    await db.SaveChangesAsync();
                }
            })));

            await using var verify = database.CreateContext();
            var report = await VerifierFor(verify, database).VerifyAllAsync();
            Assert.True(report.IsValid, report.Message);
            Assert.Equal(144, report.RecordsChecked);
        }

        [SkippableFact]
        public async Task ExecutionStrategyThatRetriesOnFailure_IsSupported()
        {
            await using var database = await OpenAsync(retry: true);
            await using (var db = database.CreateContext())
            {
                db.Accounts.Add(new Account { Name = "retry" });
                await db.SaveChangesAsync();
                db.Accounts.First().Balance = 1;
                await db.SaveChangesAsync();
            }

            using (var db = database.CreateContext())
            {
                db.Accounts.Add(new Account { Name = "retry (sync)" });
                db.SaveChanges();
            }

            await using var verify = database.CreateContext();
            var result = await VerifierFor(verify, database).VerifyTableIntegrityAsync("Accounts");
            Assert.True(result.IsValid, result.Message);
            Assert.Equal(3, result.RecordsChecked);
        }

        [SkippableFact]
        public async Task CallerTransaction_RollbackDiscardsDataAndAudit()
        {
            await using var database = await OpenAsync();
            await using (var db = database.CreateContext())
            {
                await using var transaction = await db.Database.BeginTransactionAsync();
                db.Accounts.Add(new Account { Name = "rolled back" });
                await db.SaveChangesAsync();
                await transaction.RollbackAsync();
            }

            await using var verify = database.CreateContext();
            Assert.Equal(0, await verify.Accounts.CountAsync());
            Assert.Empty(await verify.Set<AuditLog>().ToListAsync());
            Assert.Empty(await verify.Set<AuditChainState>().ToListAsync());
        }

        [SkippableFact]
        public async Task LargeBatch_IsChainedInOneSave()
        {
            await using var database = await OpenAsync();
            await using (var db = database.CreateContext())
            {
                db.Accounts.AddRange(Enumerable.Range(0, 500).Select(i => new Account { Name = "bulk-" + i, Balance = i }));
                await db.SaveChangesAsync();
            }

            await using var verify = database.CreateContext();
            var result = await VerifierFor(verify, database).VerifyTableIntegrityAsync("Accounts");
            Assert.True(result.IsValid, result.Message);
            Assert.Equal(500, result.RecordsChecked);
        }

        [SkippableFact]
        public async Task Tampering_IsDetected()
        {
            await using var database = await OpenAsync();
            await using (var db = database.CreateContext())
            {
                for (var i = 0; i < 5; i++)
                {
                    db.Accounts.Add(new Account { Name = "n" + i });
                    await db.SaveChangesAsync();
                }
            }

            await using (var attacker = database.CreateUnauditedContext())
            {
                await attacker.Set<AuditLog>().Where(l => l.SequenceNumber == 3)
                    .ExecuteUpdateAsync(s => s.SetProperty(l => l.UserId, "mallory"));
            }

            await using var verify = database.CreateContext();
            var result = await VerifierFor(verify, database).VerifyTableIntegrityAsync("Accounts");
            Assert.Equal(AuditFailureKind.DataManipulated, result.Failure);
            Assert.Equal(3, result.FailedSequence);
        }

        [SkippableFact]
        public async Task DeletedTail_IsDetected_ThroughTheSignedChainHead()
        {
            await using var database = await OpenAsync();
            await using (var db = database.CreateContext())
            {
                for (var i = 0; i < 4; i++)
                {
                    db.Accounts.Add(new Account { Name = "n" + i });
                    await db.SaveChangesAsync();
                }
            }

            await using (var attacker = database.CreateUnauditedContext())
            {
                await attacker.Set<AuditLog>().Where(l => l.SequenceNumber > 2).ExecuteDeleteAsync();
            }

            await using var verify = database.CreateContext();
            var result = await VerifierFor(verify, database).VerifyTableIntegrityAsync("Accounts");
            Assert.Equal(AuditFailureKind.RecordsMissing, result.Failure);
        }

        [SkippableFact]
        public async Task ForkedChain_IsRefusedByTheUniqueIndex()
        {
            await using var database = await OpenAsync();
            await using (var db = database.CreateContext())
            {
                db.Accounts.Add(new Account { Name = "x" });
                await db.SaveChangesAsync();
            }

            await using var attacker = database.CreateUnauditedContext();
            var first = await attacker.Set<AuditLog>().AsNoTracking().SingleAsync();
            attacker.Set<AuditLog>().Add(new AuditLog
            {
                Id = Guid.NewGuid(), TableName = first.TableName, RecordId = "2", ActionType = "Added", UserId = "x",
                PreviousHash = first.PreviousHash, CurrentHash = new string('0', 64)
            });
            await Assert.ThrowsAsync<DbUpdateException>(() => attacker.SaveChangesAsync());
        }

        [SkippableFact]
        public async Task SnakeCaseColumnsAndCustomTableNames_Work()
        {
            await using var database = await OpenAsync(Naming.SnakeCase);
            await using (var db = database.CreateContext())
            {
                db.Accounts.Add(new Account { Name = "snake" });
                await db.SaveChangesAsync();
                db.Accounts.First().Balance = 9;
                await db.SaveChangesAsync();
            }

            await using var verify = database.CreateContext();
            var result = await VerifierFor(verify, database).VerifyTableIntegrityAsync("Accounts");
            Assert.True(result.IsValid, result.Message);
            Assert.Equal(2, result.RecordsChecked);
        }

        [SkippableFact]
        public async Task TablesInASchema_Work()
        {
            await using var database = await OpenAsync(Naming.Schema);
            await Task.WhenAll(Enumerable.Range(0, 4).Select(w => Task.Run(async () =>
            {
                await using var db = database.CreateContext();
                db.Accounts.Add(new Account { Name = "schema-" + w });
                await db.SaveChangesAsync();
            })));

            await using var verify = database.CreateContext();
            var result = await VerifierFor(verify, database).VerifyTableIntegrityAsync("Accounts");
            Assert.True(result.IsValid, result.Message);
            Assert.Equal(4, result.RecordsChecked);
        }

        [SkippableFact]
        public async Task KeyRotation_WorksAgainstTheRealDatabase()
        {
            await using var database = await OpenAsync(configure: o => o.HmacKeyId = "k1");
            await using (var db = database.CreateContext())
            {
                db.Accounts.Add(new Account { Name = "k1" });
                await db.SaveChangesAsync();
            }

            var rotated = new TamperEvidentOptions { HmacSecretKey = "rotated-integration-key-0123456789abcdef", HmacKeyId = "k2" };
            rotated.AdditionalHmacKeys["k1"] = Database.Key;
            await using var verify = database.CreateContext();
            var result = await new AuditVerifier(verify, rotated).VerifyTableIntegrityAsync("Accounts");
            Assert.True(result.IsValid, result.Message);
        }

        [SkippableFact]
        public async Task LargeSaveOfSeveralTables_IsWrittenInFewCommands()
        {
            // More rows than fit into one command for every provider, two tables: the head updates ride on the last command.
            await using var database = await OpenAsync();
            await using (var db = database.CreateContext())
            {
                db.Accounts.AddRange(Enumerable.Range(0, 450).Select(i => new Account { Name = "a" + i }));
                db.Tickets.AddRange(Enumerable.Range(0, 230).Select(i => new Ticket { Title = "t" + i }));
                await db.SaveChangesAsync();
            }

            await using var verify = database.CreateContext();
            var report = await VerifierFor(verify, database).VerifyAllAsync();
            Assert.True(report.IsValid, report.Message);
            Assert.Equal(680, report.RecordsChecked);
        }

        [SkippableFact]
        public async Task MetadataAndReasons_AreSealed()
        {
            await using var database = await OpenAsync(configure: o => o.MetadataProvider = _ => new Dictionary<string, object?> { ["ip"] = "203.0.113.7" });
            await using (var db = database.CreateContext())
            using (AuditScope.Begin("auditor", "Ticket #42 — çözüldü"))
            {
                db.Accounts.Add(new Account { Name = "meta" });
                await db.SaveChangesAsync();
            }

            await using (var verify = database.CreateContext())
            {
                var log = await verify.Set<AuditLog>().SingleAsync();
                Assert.Equal("{\"ip\":\"203.0.113.7\",\"reason\":\"Ticket #42 — çözüldü\"}", log.Metadata);
                Assert.True((await VerifierFor(verify, database).VerifyTableIntegrityAsync("Accounts")).IsValid);
            }

            await using (var attacker = database.CreateUnauditedContext())
            {
                var log = await attacker.Set<AuditLog>().SingleAsync();
                log.Metadata = log.Metadata!.Replace("42", "43");
                await attacker.SaveChangesAsync();
            }

            await using var tampered = database.CreateContext();
            Assert.Equal(AuditFailureKind.DataManipulated, (await VerifierFor(tampered, database).VerifyTableIntegrityAsync("Accounts")).Failure);
        }

        [SkippableFact]
        public async Task Redaction_KeepsTheChainValid()
        {
            await using var database = await OpenAsync();
            await using (var db = database.CreateContext())
            {
                var account = new Account { Name = "Ayşe Yılmaz", Balance = 10 };
                db.Accounts.Add(account);
                await db.SaveChangesAsync();
                account.Name = "Ayşe Demir";
                await db.SaveChangesAsync();

                var result = await db.RedactAuditTrailAsync(account, new AuditRedactionRequest
                {
                    Reason = "GDPR Art. 17",
                    Properties = new[] { "Name" },
                    RedactRecordId = true
                });
                Assert.Equal(2, result.EntriesRedacted);
            }

            await using var verify = database.CreateContext();
            var logs = await verify.Set<AuditLog>().OrderBy(l => l.SequenceNumber).ToListAsync();
            Assert.Equal(new[] { "Added", "Modified", "Redacted" }, logs.Select(l => l.ActionType));
            Assert.DoesNotContain("Ayşe", string.Concat(logs.Select(l => l.OldValues + l.NewValues + l.RecordId)));
            var verification = await VerifierFor(verify, database).VerifyTableIntegrityAsync("Accounts");
            Assert.True(verification.IsValid, verification.Message);
            Assert.Equal(2, verification.RedactedRecords);
        }

        [SkippableFact]
        public async Task IncrementalVerification_ReadsOnlyNewEntries()
        {
            await using var database = await OpenAsync();
            await SeedOnceAsync(database);
            await SeedOnceAsync(database);
            AuditCheckpoint checkpoint;
            await using (var verify = database.CreateContext())
            {
                checkpoint = (await VerifierFor(verify, database).VerifyTableIntegrityAsync("Accounts")).Checkpoint!;
            }

            await SeedOnceAsync(database);
            await using (var verify = database.CreateContext())
            {
                var result = await VerifierFor(verify, database).VerifyFromCheckpointAsync(checkpoint);
                Assert.True(result.IsValid, result.Message);
                Assert.Equal(1, result.RecordsChecked);
            }

            await using (var attacker = database.CreateUnauditedContext())
            {
                (await attacker.Set<AuditLog>().SingleAsync(l => l.SequenceNumber == 3)).UserId = "mallory";
                await attacker.SaveChangesAsync();
            }

            await using (var verify = database.CreateContext())
            {
                Assert.Equal(AuditFailureKind.DataManipulated, (await VerifierFor(verify, database).VerifyFromCheckpointAsync(checkpoint)).Failure);
            }
        }

        [SkippableFact]
        public async Task EvidenceBundles_VerifyOffline()
        {
            await using var database = await OpenAsync();
            await SeedOnceAsync(database);
            await SeedOnceAsync(database);

            using var bundle = new MemoryStream();
            await using (var db = database.CreateContext())
            {
                await AuditExporter.WriteEvidenceBundleAsync(bundle, db, VerifierFor(db, database));
            }

            bundle.Position = 0;
            var report = await AuditEvidence.VerifyBundleAsync(bundle, database.Options);
            Assert.True(report.IsValid, report.Message);
            Assert.Equal(2, report.RecordsChecked);
        }

        private async Task SeedOnceAsync(Database database)
        {
            await using var db = database.CreateContext();
            db.Accounts.Add(new Account { Name = "seed" });
            await db.SaveChangesAsync();
        }
    }

    public class PostgresTests : ConformanceTests
    {
        protected override Provider Provider => Provider.Postgres;
    }

    public class MySqlTests : ConformanceTests
    {
        protected override Provider Provider => Provider.MySql;
    }

    public class SqlServerTests : ConformanceTests
    {
        protected override Provider Provider => Provider.SqlServer;
    }
}
