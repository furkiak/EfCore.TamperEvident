using EfCore.TamperEvident.Configuration;
using EfCore.TamperEvident.Internal;
using EfCore.TamperEvident.Models;
using EfCore.TamperEvident.Services;
using Microsoft.EntityFrameworkCore;

namespace EfCore.TamperEvident.Tests
{
    /// <summary>
    /// Plays the attacker: someone with direct access to the database (no interceptor, no secret key).
    /// </summary>
    public class VerifierTests
    {
        private static async Task<Harness> SeededAsync(int customers = 5, Action<TamperEvidentOptions>? configure = null)
        {
            var harness = new Harness(configure);
            await using var db = harness.CreateContext();
            for (var i = 1; i <= customers; i++)
            {
                db.Customers.Add(new Customer { Name = $"customer-{i}" });
                await db.SaveChangesAsync();
            }

            return harness;
        }

        private static async Task<AuditVerificationResult> VerifyAsync(Harness harness, params string[] anchors)
        {
            await using var db = harness.CreateContext();
            return await harness.CreateVerifier(db).VerifyTableIntegrityAsync("Customers", anchors);
        }

        [Fact]
        public async Task IntactChain_Verifies()
        {
            using var harness = await SeededAsync();
            var result = await VerifyAsync(harness);

            Assert.True(result.IsValid, result.Message);
            Assert.Equal(AuditFailureKind.None, result.Failure);
            Assert.Equal(5, result.RecordsChecked);
            Assert.Equal(5, result.HeadSequence);
            Assert.Contains("passed successfully", result.Message);
        }

        [Fact]
        public async Task TableWithoutAuditEntries_IsValid()
        {
            using var harness = new Harness();
            await using var db = harness.CreateContext();
            var result = await harness.CreateVerifier(db).VerifyTableIntegrityAsync("Customers");

            Assert.True(result.IsValid);
            Assert.Equal(0, result.RecordsChecked);
        }

        [Fact]
        public async Task AnEmptyChainHead_IsValid()
        {
            // A save that failed after its chain head was created leaves a head without entries behind.
            using var harness = new Harness();
            await using (var db = harness.CreateUnauditedContext())
            {
                db.AuditChainStates.Add(new AuditChainState { TableName = "Customers", LastHash = "GENESIS" });
                await db.SaveChangesAsync();
            }

            var result = await VerifyAsync(harness);

            Assert.True(result.IsValid, result.Message);
            Assert.Equal(0, result.RecordsChecked);
        }

        [Fact]
        public async Task ModifiedPayload_IsDetected()
        {
            using var harness = await SeededAsync();
            harness.Execute("UPDATE AuditLogs SET NewValues = replace(NewValues, 'customer-3', 'someone-else') WHERE SequenceNumber = 3");

            var result = await VerifyAsync(harness);

            Assert.False(result.IsValid);
            Assert.Equal(AuditFailureKind.DataManipulated, result.Failure);
            Assert.Equal(3, result.FailedSequence);
            Assert.Contains("DATA MANIPULATION", result.Message);
        }

        [Fact]
        public async Task ModifiedUserId_IsDetected()
        {
            // Regression: the user used to be outside of the hash, so the author of a change could be rewritten.
            using var harness = await SeededAsync();
            harness.Execute("UPDATE AuditLogs SET UserId = 'mallory' WHERE SequenceNumber = 2");

            var result = await VerifyAsync(harness);

            Assert.Equal(AuditFailureKind.DataManipulated, result.Failure);
            Assert.Equal(2, result.FailedSequence);
        }

        [Fact]
        public async Task ModifiedTimestamp_IsDetected()
        {
            using var harness = await SeededAsync();
            harness.Execute("UPDATE AuditLogs SET TimestampTicks = TimestampTicks - 1000000000 WHERE SequenceNumber = 4");

            Assert.Equal(AuditFailureKind.DataManipulated, (await VerifyAsync(harness)).Failure);
        }

        [Fact]
        public async Task ShiftedFieldBoundaries_AreDetected()
        {
            // Regression: with plain concatenation, moving characters between neighbouring fields kept the hash valid.
            using var harness = new Harness();
            await using (var db = harness.CreateContext())
            {
                db.OrderLines.Add(new OrderLine { OrderId = 12, LineNo = 1, Product = "p" });
                await db.SaveChangesAsync();
            }

            harness.Execute("UPDATE AuditLogs SET RecordId = '1', ActionType = '2' || ActionType");

            await using var verify = harness.CreateContext();
            var result = await harness.CreateVerifier(verify).VerifyTableIntegrityAsync("OrderLines");
            Assert.Equal(AuditFailureKind.DataManipulated, result.Failure);
        }

        [Fact]
        public async Task DeletedMiddleEntry_IsDetected()
        {
            using var harness = await SeededAsync();
            harness.Execute("DELETE FROM AuditLogs WHERE SequenceNumber = 3");

            var result = await VerifyAsync(harness);

            Assert.False(result.IsValid);
            Assert.Equal(AuditFailureKind.ChainBroken, result.Failure);
            Assert.Contains("CHAIN BROKEN", result.Message);
        }

        [Fact]
        public async Task DeletedNewestEntries_AreDetected()
        {
            // Regression: removing the tail of the chain left a perfectly linked (but shorter) chain.
            using var harness = await SeededAsync();
            harness.Execute("DELETE FROM AuditLogs WHERE SequenceNumber > 3");

            var result = await VerifyAsync(harness);

            Assert.False(result.IsValid);
            Assert.Equal(AuditFailureKind.RecordsMissing, result.Failure);
        }

        [Fact]
        public async Task WipedAuditLogs_AreDetected_ThroughTheChainHead()
        {
            using var harness = await SeededAsync();
            harness.Execute("DELETE FROM AuditLogs");

            var result = await VerifyAsync(harness);
            Assert.Equal(AuditFailureKind.RecordsMissing, result.Failure);

            await using var db = harness.CreateContext();
            var report = await harness.CreateVerifier(db).VerifyAllAsync();
            Assert.False(report.IsValid);
            Assert.Equal("Customers", Assert.Single(report.Failures).TableName);
        }

        [Fact]
        public async Task DeletedChainHead_IsDetected()
        {
            using var harness = await SeededAsync();
            harness.Execute("DELETE FROM AuditChainStates");

            Assert.Equal(AuditFailureKind.ChainStateMissing, (await VerifyAsync(harness)).Failure);
        }

        [Fact]
        public async Task ForgedChainHead_IsDetected()
        {
            // An attacker truncates the chain AND fixes the unsigned head to match: the signature gives it away.
            using var harness = await SeededAsync();
            harness.Execute(
                "UPDATE AuditChainStates SET LastHash = (SELECT CurrentHash FROM AuditLogs WHERE SequenceNumber = 3), LastSequence = 3");
            harness.Execute("DELETE FROM AuditLogs WHERE SequenceNumber > 3");

            Assert.Equal(AuditFailureKind.ChainStateTampered, (await VerifyAsync(harness)).Failure);
        }

        [Fact]
        public async Task StrippedChainHeadSignature_IsDetected()
        {
            using var harness = await SeededAsync();
            harness.Execute("UPDATE AuditChainStates SET Mac = NULL");

            Assert.Equal(AuditFailureKind.ChainStateTampered, (await VerifyAsync(harness)).Failure);
        }

        [Fact]
        public async Task EntryInsertedBehindTheHead_IsDetected()
        {
            using var harness = await SeededAsync();
            var last = await ReadLastAsync(harness);
            harness.Execute(
                "INSERT INTO AuditLogs (Id, TableName, RecordId, ActionType, UserId, TimestampTicks, SequenceNumber, HashVersion, PreviousHash, CurrentHash) " +
                "VALUES ({0}, 'Customers', '99', 'Deleted', 'mallory', 1, 6, 2, {1}, 'ffff')",
                Guid.NewGuid().ToString().ToUpperInvariant(), last.CurrentHash);

            Assert.Equal(AuditFailureKind.RecordsBeyondHead, (await VerifyAsync(harness)).Failure);
        }

        [Fact]
        public async Task ReorderedSequence_IsDetected()
        {
            using var harness = await SeededAsync();
            harness.Execute("UPDATE AuditLogs SET SequenceNumber = 99 WHERE SequenceNumber = 2");

            var result = await VerifyAsync(harness);
            Assert.False(result.IsValid);
        }

        [Fact]
        public async Task EntriesWrittenAfterTheVerifierReadTheHead_AreNotAFalseAlarm()
        {
            using var harness = await SeededAsync();
            await using var db = harness.CreateContext();
            var verifier = harness.CreateVerifier(db);

            var first = await verifier.VerifyTableIntegrityAsync("Customers");
            await using (var writer = harness.CreateContext())
            {
                writer.Customers.Add(new Customer { Name = "late" });
                await writer.SaveChangesAsync();
            }

            var second = await verifier.VerifyTableIntegrityAsync("Customers");
            Assert.True(first.IsValid);
            Assert.True(second.IsValid, second.Message);
            Assert.Equal(6, second.RecordsChecked);
        }

        [Fact]
        public async Task Anchors_AreMatched_AndTheCallersListIsNotModified()
        {
            // Regression: the verifier used to remove matched anchors from the list the caller passed in.
            using var harness = await SeededAsync();
            var hashes = await ReadHashesAsync(harness);
            var anchors = new List<string> { hashes[1], hashes[4] };

            await using var db = harness.CreateContext();
            var result = await harness.CreateVerifier(db).VerifyTableIntegrityAsync("Customers", anchors);

            Assert.True(result.IsValid, result.Message);
            Assert.Equal(2, result.AnchorsMatched);
            Assert.Equal(2, anchors.Count);
            Assert.Contains("2 anchors", result.Message);
        }

        [Fact]
        public async Task Anchors_AreCaseInsensitive_AndIgnoreBlanks()
        {
            using var harness = await SeededAsync();
            var hash = (await ReadHashesAsync(harness))[0];

            var result = await VerifyAsync(harness, hash.ToUpperInvariant() + " ", "", "  ");
            Assert.True(result.IsValid, result.Message);
            Assert.Equal(1, result.AnchorsMatched);
        }

        [Fact]
        public async Task UnknownAnchor_MeansTheHistoryWasRewritten()
        {
            using var harness = await SeededAsync();
            var result = await VerifyAsync(harness, new string('a', 64));

            Assert.False(result.IsValid);
            Assert.Equal(AuditFailureKind.AnchorMismatch, result.Failure);
            Assert.Contains("ANCHOR MISMATCH", result.Message);
        }

        [Fact]
        public async Task RewrittenHistory_IsCaughtByAnchors_EvenWhenTheAttackerKnowsTheSecretKey()
        {
            // Worst case: the key leaked. The attacker rebuilds a perfectly valid chain with forged content.
            using var harness = await SeededAsync();
            var anchor = (await ReadHashesAsync(harness))[2];
            var key = System.Text.Encoding.UTF8.GetBytes(Harness.SecretKey);

            await using (var db = harness.CreateUnauditedContext())
            {
                var logs = await db.AuditLogs.OrderBy(l => l.SequenceNumber).ToListAsync();
                var previous = "GENESIS";
                foreach (var log in logs)
                {
                    log.UserId = "forged";
                    log.PreviousHash = previous;
                    log.CurrentHash = AuditHasher.ComputeRecordHash(key, log);
                    previous = log.CurrentHash;
                }

                var state = await db.AuditChainStates.SingleAsync();
                state.LastHash = previous;
                state.Mac = AuditHasher.ComputeStateMac(key, state.TableName, state.LastHash, state.LastSequence, state.KeyId);
                await db.SaveChangesAsync();
            }

            // Inside the database alone the forgery is undetectable ...
            Assert.True((await VerifyAsync(harness)).IsValid);

            // ... but the anchor that was e-mailed earlier no longer occurs in the chain.
            var result = await VerifyAsync(harness, anchor);
            Assert.Equal(AuditFailureKind.AnchorMismatch, result.Failure);
        }

        [Fact]
        public async Task ChainRebuiltWithAnotherKey_IsInvalid()
        {
            using var harness = await SeededAsync();
            var attackerKey = System.Text.Encoding.UTF8.GetBytes("attacker-guessed-key-0123456789abcdef");

            await using (var db = harness.CreateUnauditedContext())
            {
                var previous = "GENESIS";
                foreach (var log in await db.AuditLogs.OrderBy(l => l.SequenceNumber).ToListAsync())
                {
                    log.UserId = "forged";
                    log.PreviousHash = previous;
                    log.CurrentHash = AuditHasher.ComputeRecordHash(attackerKey, log);
                    previous = log.CurrentHash;
                }

                await db.SaveChangesAsync();
            }

            Assert.Equal(AuditFailureKind.DataManipulated, (await VerifyAsync(harness)).Failure);
        }

        [Fact]
        public async Task VerifyAll_ChecksEveryTable()
        {
            using var harness = new Harness();
            await using (var db = harness.CreateContext())
            {
                db.Customers.Add(new Customer { Name = "A" });
                db.Documents.Add(new Document { Title = "D" });
                await db.SaveChangesAsync();
            }

            await using var verify = harness.CreateContext();
            var report = await harness.CreateVerifier(verify).VerifyAllAsync();

            Assert.True(report.IsValid, report.Message);
            Assert.Equal(new[] { "Customers", "Documents" }, report.Tables.Select(t => t.TableName));
            Assert.Equal(2, report.RecordsChecked);
        }

        [Fact]
        public async Task VerifyAll_ReportsTheFailingTable()
        {
            using var harness = new Harness();
            await using (var db = harness.CreateContext())
            {
                db.Customers.Add(new Customer { Name = "A" });
                db.Documents.Add(new Document { Title = "D" });
                await db.SaveChangesAsync();
            }

            harness.Execute("UPDATE AuditLogs SET UserId = 'x' WHERE TableName = 'Documents'");

            await using var verify = harness.CreateContext();
            var report = await harness.CreateVerifier(verify).VerifyAllAsync();

            Assert.False(report.IsValid);
            Assert.Equal("Documents", Assert.Single(report.Failures).TableName);
            Assert.Contains("Documents", report.Message);
        }

        [Fact]
        public async Task Result_CanBeDeconstructed_LikeTheTupleOfVersionOne()
        {
            using var harness = await SeededAsync(1);
            var (isValid, message) = await VerifyAsync(harness);

            Assert.True(isValid);
            Assert.NotEmpty(message);
        }

        [Fact]
        public async Task Cancellation_IsHonoured()
        {
            using var harness = await SeededAsync(3);
            await using var db = harness.CreateContext();
            using var cts = new CancellationTokenSource();
            cts.Cancel();

            await Assert.ThrowsAnyAsync<OperationCanceledException>(
                () => harness.CreateVerifier(db).VerifyTableIntegrityAsync("Customers", null, cts.Token));
        }

        [Fact]
        public async Task KeyRotation_OldEntriesStayVerifiable()
        {
            const string oldKey = "the-original-secret-key-0123456789abcdef";
            const string newKey = "the-rotated-secret-key-0123456789abcdefg";

            using var oldHarness = new Harness(o => { o.HmacSecretKey = oldKey; o.HmacKeyId = "k1"; });
            await using (var db = oldHarness.CreateContext())
            {
                db.Customers.Add(new Customer { Name = "sealed with k1" });
                await db.SaveChangesAsync();
            }

            // Rotate: the new key seals new entries, the old key is kept for verification only.
            var rotated = new TamperEvidentOptions { HmacSecretKey = newKey, HmacKeyId = "k2" };
            rotated.AdditionalHmacKeys["k1"] = oldKey;

            await using (var db = oldHarness.CreateContextWith(rotated))
            {
                db.Customers.Add(new Customer { Name = "sealed with k2" });
                await db.SaveChangesAsync();

                var result = await new AuditVerifier(db, rotated).VerifyTableIntegrityAsync("Customers");
                Assert.True(result.IsValid, result.Message);
                Assert.Equal(2, result.RecordsChecked);

                var keyIds = await db.AuditLogs.OrderBy(l => l.SequenceNumber).Select(l => l.KeyId).ToListAsync();
                Assert.Equal(new[] { "k1", "k2" }, keyIds);

                // Without the retired key the old entries cannot be verified any more.
                var withoutOld = await new AuditVerifier(db, new TamperEvidentOptions { HmacSecretKey = newKey, HmacKeyId = "k2" })
                    .VerifyTableIntegrityAsync("Customers");
                Assert.Equal(AuditFailureKind.UnknownKey, withoutOld.Failure);
            }
        }

        [Fact]
        public async Task WrongSecretKey_FailsVerification()
        {
            using var harness = await SeededAsync(2);
            await using var db = harness.CreateContext();

            var result = await new AuditVerifier(db, new TamperEvidentOptions { HmacSecretKey = "another-secret-key-that-is-long-enough" })
                .VerifyTableIntegrityAsync("Customers");

            Assert.Equal(AuditFailureKind.DataManipulated, result.Failure);
        }

        [Fact]
        public async Task LegacyEntries_FromVersionOne_StayVerifiable_AndNewEntriesContinueTheChain()
        {
            using var harness = new Harness();
            var key = System.Text.Encoding.UTF8.GetBytes(Harness.SecretKey);

            // Rows exactly as 1.x wrote them: no sequence, no user in the hash, plain concatenation.
            var first = LegacyLog("GENESIS", "Customers", "1", "Added", null, "{\"Name\":\"old\"}", 1000, key);
            var second = LegacyLog(first.CurrentHash, "Customers", "1", "Modified", "{\"Name\":\"old\"}", "{\"Name\":\"older\"}", 2000, key);

            await using (var db = harness.CreateUnauditedContext())
            {
                db.AuditLogs.AddRange(first, second);
                db.AuditChainStates.Add(new AuditChainState { TableName = "Customers", LastHash = second.CurrentHash, UnanchoredCount = 2 });
                await db.SaveChangesAsync();
            }

            await using (var db = harness.CreateContext())
            {
                var legacyOnly = await harness.CreateVerifier(db).VerifyTableIntegrityAsync("Customers");
                Assert.True(legacyOnly.IsValid, legacyOnly.Message);
                Assert.Equal(2, legacyOnly.RecordsChecked);

                db.Customers.Add(new Customer { Name = "new" });
                await db.SaveChangesAsync();
            }

            await using (var db = harness.CreateContext())
            {
                var mixed = await harness.CreateVerifier(db).VerifyTableIntegrityAsync("Customers");
                Assert.True(mixed.IsValid, mixed.Message);
                Assert.Equal(3, mixed.RecordsChecked);

                var newest = await db.AuditLogs.OrderByDescending(l => l.SequenceNumber).FirstAsync();
                Assert.Equal(1, newest.SequenceNumber);
                Assert.Equal(second.CurrentHash, newest.PreviousHash);
            }
        }

        [Fact]
        public async Task LegacyEntries_TamperingIsStillDetected()
        {
            using var harness = new Harness();
            var key = System.Text.Encoding.UTF8.GetBytes(Harness.SecretKey);
            var first = LegacyLog("GENESIS", "Customers", "1", "Added", null, "{\"Name\":\"old\"}", 1000, key);

            await using (var db = harness.CreateUnauditedContext())
            {
                db.AuditLogs.Add(first);
                db.AuditChainStates.Add(new AuditChainState { TableName = "Customers", LastHash = first.CurrentHash });
                await db.SaveChangesAsync();
            }

            harness.Execute("UPDATE AuditLogs SET NewValues = {0}", "{\"Name\":\"evil\"}");

            Assert.Equal(AuditFailureKind.DataManipulated, (await VerifyAsync(harness)).Failure);
        }

        [Fact]
        public async Task VersionOneDefaultKey_CanStillVerifyOldChains_ThroughAdditionalKeys()
        {
            // 1.x shipped a public default key. Upgrading means configuring a new key and keeping the old one for verification.
            const string legacyDefault = TamperEvidentOptions.Version1DefaultKey;
            using var harness = new Harness();
            var first = LegacyLog("GENESIS", "Customers", "1", "Added", null, "{}", 1000, System.Text.Encoding.UTF8.GetBytes(legacyDefault));

            await using (var db = harness.CreateUnauditedContext())
            {
                db.AuditLogs.Add(first);
                db.AuditChainStates.Add(new AuditChainState { TableName = "Customers", LastHash = first.CurrentHash });
                await db.SaveChangesAsync();
            }

            var upgraded = new TamperEvidentOptions { HmacSecretKey = Harness.SecretKey };
            upgraded.AdditionalHmacKeys["v1"] = legacyDefault;

            await using var verify = harness.CreateContext();
            var result = await new AuditVerifier(verify, upgraded).VerifyTableIntegrityAsync("Customers");
            Assert.True(result.IsValid, result.Message);
        }

        private static AuditLog LegacyLog(
            string previousHash, string table, string recordId, string action, string? oldValues, string? newValues, long ticks, byte[] key)
        {
            var log = new AuditLog
            {
                Id = Guid.NewGuid(),
                TableName = table,
                RecordId = recordId,
                ActionType = action,
                OldValues = oldValues,
                NewValues = newValues,
                UserId = "System",
                TimestampTicks = ticks,
                SequenceNumber = 0,
                HashVersion = AuditHashVersion.Legacy,
                PreviousHash = previousHash,
                CurrentHash = string.Empty
            };
            log.CurrentHash = SecurityHelper.ComputeHash(
                $"{previousHash}{table}{recordId}{action}{oldValues}{newValues}{ticks}", System.Text.Encoding.UTF8.GetString(key));
            return log;
        }

        private static async Task<AuditLog> ReadLastAsync(Harness harness)
        {
            await using var db = harness.CreateUnauditedContext();
            return await db.AuditLogs.OrderByDescending(l => l.SequenceNumber).FirstAsync();
        }

        private static async Task<List<string>> ReadHashesAsync(Harness harness)
        {
            await using var db = harness.CreateUnauditedContext();
            return await db.AuditLogs.OrderBy(l => l.SequenceNumber).Select(l => l.CurrentHash).ToListAsync();
        }
    }
}
