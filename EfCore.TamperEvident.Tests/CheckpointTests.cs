using EfCore.TamperEvident.Models;
using EfCore.TamperEvident.Services;
using Microsoft.EntityFrameworkCore;

namespace EfCore.TamperEvident.Tests
{
    /// <summary>Incremental verification: only the entries appended since a checkpoint are read.</summary>
    public class CheckpointTests
    {
        private static async Task AddCustomersAsync(Harness harness, int count)
        {
            await using var db = harness.CreateContext();
            for (var i = 0; i < count; i++)
            {
                db.Customers.Add(new Customer { Name = "c" + i });
                await db.SaveChangesAsync();
            }
        }

        private static async Task<AuditVerificationResult> FullAsync(Harness harness)
        {
            await using var db = harness.CreateContext();
            return await harness.CreateVerifier(db).VerifyTableIntegrityAsync("Customers");
        }

        private static async Task<AuditVerificationResult> FromAsync(Harness harness, AuditCheckpoint checkpoint, params string[] anchors)
        {
            await using var db = harness.CreateContext();
            return await harness.CreateVerifier(db).VerifyFromCheckpointAsync(checkpoint, anchors);
        }

        [Fact]
        public async Task ASuccessfulVerification_ProducesACheckpoint()
        {
            using var harness = new Harness();
            await AddCustomersAsync(harness, 3);

            var result = await FullAsync(harness);
            Assert.False(result.IsIncremental);
            Assert.Equal(new AuditCheckpoint("Customers", 3, result.HeadHash!), result.Checkpoint);
        }

        [Fact]
        public async Task OnlyNewEntries_AreVerified()
        {
            using var harness = new Harness();
            await AddCustomersAsync(harness, 5);
            var checkpoint = (await FullAsync(harness)).Checkpoint!;
            await AddCustomersAsync(harness, 2);

            var result = await FromAsync(harness, checkpoint);
            Assert.True(result.IsValid, result.Message);
            Assert.True(result.IsIncremental);
            Assert.Equal(2, result.RecordsChecked);
            Assert.Equal(7, result.HeadSequence);
            Assert.Equal(checkpoint, result.StartedAfter);
            Assert.Equal(7, result.Checkpoint!.SequenceNumber);
        }

        [Fact]
        public async Task NoNewEntries_IsValid()
        {
            using var harness = new Harness();
            await AddCustomersAsync(harness, 2);
            var checkpoint = (await FullAsync(harness)).Checkpoint!;

            var result = await FromAsync(harness, checkpoint);
            Assert.True(result.IsValid, result.Message);
            Assert.Equal(0, result.RecordsChecked);
            Assert.Equal(checkpoint, result.Checkpoint);
        }

        [Fact]
        public async Task ChangingTheCheckpointEntry_IsDetected()
        {
            using var harness = new Harness();
            await AddCustomersAsync(harness, 3);
            var checkpoint = (await FullAsync(harness)).Checkpoint!;
            harness.Execute("UPDATE AuditLogs SET CurrentHash = {0} WHERE SequenceNumber = 3", new string('f', 64));

            Assert.Equal(AuditFailureKind.CheckpointMismatch, (await FromAsync(harness, checkpoint)).Failure);
        }

        [Fact]
        public async Task DeletingEntriesAfterTheCheckpoint_IsDetected()
        {
            using var harness = new Harness();
            await AddCustomersAsync(harness, 3);
            var checkpoint = (await FullAsync(harness)).Checkpoint!;
            await AddCustomersAsync(harness, 3);
            harness.Execute("DELETE FROM AuditLogs WHERE SequenceNumber = 5");

            var result = await FromAsync(harness, checkpoint);
            Assert.False(result.IsValid);
            Assert.Equal(AuditFailureKind.ChainBroken, result.Failure);
        }

        [Fact]
        public async Task RewindingTheHeadBehindTheCheckpoint_IsDetected()
        {
            using var harness = new Harness();
            await AddCustomersAsync(harness, 4);
            var checkpoint = (await FullAsync(harness)).Checkpoint!;
            harness.Execute("UPDATE AuditChainStates SET LastSequence = 2");

            Assert.Equal(AuditFailureKind.RecordsMissing, (await FromAsync(harness, checkpoint)).Failure);
        }

        [Fact]
        public async Task ManipulatingANewEntry_IsDetected()
        {
            using var harness = new Harness();
            await AddCustomersAsync(harness, 2);
            var checkpoint = (await FullAsync(harness)).Checkpoint!;
            await AddCustomersAsync(harness, 2);
            harness.Execute("UPDATE AuditLogs SET UserId = 'mallory' WHERE SequenceNumber = 4");

            Assert.Equal(AuditFailureKind.DataManipulated, (await FromAsync(harness, checkpoint)).Failure);
        }

        [Fact]
        public async Task AnchorsOlderThanTheCheckpoint_StillMatch()
        {
            using var harness = new Harness();
            await AddCustomersAsync(harness, 3);
            string anchor;
            await using (var db = harness.CreateContext())
            {
                anchor = await db.AuditLogs.Where(l => l.SequenceNumber == 2).Select(l => l.CurrentHash).SingleAsync();
            }

            var checkpoint = (await FullAsync(harness)).Checkpoint!;
            await AddCustomersAsync(harness, 1);

            var result = await FromAsync(harness, checkpoint, anchor.ToUpperInvariant());
            Assert.True(result.IsValid, result.Message);
            Assert.Equal(1, result.AnchorsMatched);
            Assert.Equal(AuditFailureKind.AnchorMismatch, (await FromAsync(harness, checkpoint, new string('0', 64))).Failure);
        }

        [Fact]
        public async Task VerifyAll_UsesCheckpointsPerTable()
        {
            using var harness = new Harness();
            await AddCustomersAsync(harness, 3);
            await using (var db = harness.CreateContext())
            {
                db.Documents.Add(new Document { Title = "d" });
                await db.SaveChangesAsync();
            }

            IReadOnlyDictionary<string, AuditCheckpoint> checkpoints;
            await using (var db = harness.CreateContext())
            {
                var first = await harness.CreateVerifier(db).VerifyAllAsync();
                checkpoints = first.Checkpoints;
                Assert.Equal(2, checkpoints.Count);
            }

            await AddCustomersAsync(harness, 1);
            await using (var db = harness.CreateContext())
            {
                var second = await harness.CreateVerifier(db).VerifyAllAsync(null, checkpoints);
                Assert.True(second.IsValid, second.Message);
                Assert.Equal(1, second.RecordsChecked);
                Assert.All(second.Tables, t => Assert.True(t.IsIncremental));
            }
        }

        [Fact]
        public async Task InvalidCheckpoints_AreRejected()
        {
            using var harness = new Harness();
            await using var db = harness.CreateContext();
            var verifier = harness.CreateVerifier(db);

            await Assert.ThrowsAsync<ArgumentNullException>(() => verifier.VerifyFromCheckpointAsync(null!));
            await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => verifier.VerifyFromCheckpointAsync(new AuditCheckpoint("Customers", 0, "x")));
        }

        [Fact]
        public async Task AFailedVerification_HasNoCheckpoint()
        {
            using var harness = new Harness();
            await AddCustomersAsync(harness, 2);
            harness.Execute("UPDATE AuditLogs SET UserId = 'mallory' WHERE SequenceNumber = 1");
            Assert.Null((await FullAsync(harness)).Checkpoint);
        }
    }
}
