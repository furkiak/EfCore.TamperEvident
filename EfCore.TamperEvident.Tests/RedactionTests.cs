using System.Text.Json;
using EfCore.TamperEvident.Extensions;
using EfCore.TamperEvident.Internal;
using EfCore.TamperEvident.Models;
using EfCore.TamperEvident.Services;
using Microsoft.EntityFrameworkCore;

namespace EfCore.TamperEvident.Tests
{
    /// <summary>
    /// Erasing personal data from the audit trail without breaking it (GDPR Art. 17, KVKK Art. 7).
    /// </summary>
    public class RedactionTests
    {
        private static async Task<(Harness Harness, Customer Customer)> CustomerWithHistoryAsync()
        {
            var harness = new Harness(o => o.MetadataProvider = _ => new Dictionary<string, object?> { ["ip"] = "203.0.113.7" });
            await using var db = harness.CreateContext();

            var customer = new Customer { Name = "Ayşe Yılmaz", Email = "ayse@example.com", Balance = 10 };
            db.Customers.Add(customer);
            db.Customers.Add(new Customer { Name = "Bystander", Email = "other@example.com" });
            await db.SaveChangesAsync();

            customer.Email = "ayse.yilmaz@example.com";
            customer.Balance = 25;
            await db.SaveChangesAsync();

            return (harness, customer);
        }

        private static async Task<AuditVerificationResult> VerifyAsync(Harness harness)
        {
            await using var db = harness.CreateContext();
            return await harness.CreateVerifier(db).VerifyTableIntegrityAsync("Customers");
        }

        private static async Task<List<AuditLog>> EntriesOfAsync(Harness harness, string recordId)
        {
            await using var db = harness.CreateContext();
            return await db.AuditLogs.Where(l => l.TableName == "Customers" && l.RecordId == recordId).OrderBy(l => l.SequenceNumber).ToListAsync();
        }

        [Fact]
        public async Task RedactingProperties_KeepsTheChainValid_AndRemovesThePersonalData()
        {
            var (harness, customer) = await CustomerWithHistoryAsync();
            using var _ = harness;
            var before = await EntriesOfAsync(harness, customer.Id.ToString(System.Globalization.CultureInfo.InvariantCulture));

            AuditRedactionResult result;
            await using (var db = harness.CreateContext())
            {
                result = await db.RedactAuditTrailAsync(customer, new AuditRedactionRequest
                {
                    Reason = "Erasure request #4711",
                    Properties = new[] { "Name", "Email" }
                });
            }

            Assert.Equal(2, result.EntriesRedacted);
            Assert.Equal(4, result.ValuesRedacted); // insert: Name + Email, update: old Email + new Email
            Assert.Single(result.RedactionEntryIds);
            Assert.Empty(result.NotRedactable);

            var after = await EntriesOfAsync(harness, customer.Id.ToString(System.Globalization.CultureInfo.InvariantCulture));
            Assert.Equal(3, after.Count); // insert, update and the redaction entry
            var all = string.Join("\n", after.Select(l => l.OldValues + l.NewValues));
            Assert.DoesNotContain("Ayşe", all);
            Assert.DoesNotContain("ayse", all);
            Assert.Contains("\"Balance\":25", all); // values that were not selected stay readable
            Assert.Contains("{\"$redacted\":\"", after[0].NewValues);

            // The hashes did not change, so the chain, its head and every anchor stay valid.
            Assert.Equal(before.Select(l => l.CurrentHash), after.Take(2).Select(l => l.CurrentHash));

            var verification = await VerifyAsync(harness);
            Assert.True(verification.IsValid, verification.Message);
            Assert.Equal(2, verification.RedactedRecords);
        }

        [Fact]
        public async Task TheRedactionEntry_RecordsWhoRedactedWhatAndWhy()
        {
            var (harness, customer) = await CustomerWithHistoryAsync();
            using var _ = harness;

            await using (var db = harness.CreateContext())
            using (AuditScope.Begin("dpo@example.com"))
            {
                await db.RedactAuditTrailAsync(customer, new AuditRedactionRequest { Reason = "KVKK başvurusu 2026/18", Properties = new[] { "Email" } });
            }

            var redaction = (await EntriesOfAsync(harness, customer.Id.ToString(System.Globalization.CultureInfo.InvariantCulture))).Last();
            Assert.Equal(AuditActions.Redacted, redaction.ActionType);
            Assert.Equal("dpo@example.com", redaction.UserId);
            Assert.Contains("\"reason\":\"KVKK başvurusu 2026/18\"", redaction.Metadata);

            using var document = JsonDocument.Parse(redaction.NewValues!);
            var entries = document.RootElement.GetProperty("entries");
            Assert.Equal(2, entries.EnumerateObject().Count());
            Assert.Contains(entries.EnumerateObject(), e => e.Value.EnumerateArray().Select(f => f.GetString()).SequenceEqual(new[] { "n:Email", "o:Email" }));
        }

        [Fact]
        public async Task RedactingTheRecordId_UserAndMetadata_Works()
        {
            var (harness, customer) = await CustomerWithHistoryAsync();
            using var _ = harness;
            var recordId = customer.Id.ToString(System.Globalization.CultureInfo.InvariantCulture);
            var ids = (await EntriesOfAsync(harness, recordId)).Select(l => l.Id).ToList();

            await using (var db = harness.CreateContext())
            {
                var result = await db.RedactAuditTrailAsync("Customers", recordId, new AuditRedactionRequest
                {
                    Reason = "Full erasure",
                    Properties = new[] { AuditRedactionRequest.All },
                    MetadataKeys = new[] { "ip" },
                    RedactRecordId = true,
                    RedactUserId = true
                });
                Assert.Equal(2, result.EntriesRedacted);
            }

            await using (var db = harness.CreateContext())
            {
                var entries = await db.AuditLogs.Where(l => ids.Contains(l.Id)).ToListAsync();
                Assert.All(entries, e =>
                {
                    Assert.StartsWith("[REDACTED:", e.RecordId);
                    Assert.StartsWith("[REDACTED:", e.UserId);
                    Assert.DoesNotContain("203.0.113.7", e.Metadata);
                    Assert.DoesNotContain("\"Balance\":", e.NewValues!.Replace("\"Balance\":{\"$redacted\"", string.Empty));
                });

                // The digests are salted with the entry id: equal values do not produce equal markers.
                Assert.NotEqual(entries[0].RecordId, entries[1].RecordId);
                Assert.Empty(await db.AuditLogs().ForRecord("Customers", recordId).Where(l => l.ActionType != AuditActions.Redacted).ToListAsync());
            }

            var verification = await VerifyAsync(harness);
            Assert.True(verification.IsValid, verification.Message);
        }

        [Fact]
        public async Task RedactingAUser_RemovesTheUserFromEveryTable()
        {
            using var harness = new Harness();
            await using (var db = harness.CreateContext())
            using (AuditScope.Begin("leaver@example.com"))
            {
                db.Customers.Add(new Customer { Name = "c" });
                db.Documents.Add(new Document { Title = "d" });
                await db.SaveChangesAsync();
            }

            await using (var db = harness.CreateContext())
            {
                db.Customers.Add(new Customer { Name = "kept" });
                await db.SaveChangesAsync();

                var result = await db.RedactAuditUserAsync("leaver@example.com", "Former employee");
                Assert.Equal(2, result.EntriesRedacted);
                Assert.Equal(2, result.RedactionEntryIds.Count); // one per table
            }

            await using (var db = harness.CreateContext())
            {
                Assert.Empty(await db.AuditLogs().ByUser("leaver@example.com").ToListAsync());
                Assert.Contains(await db.AuditLogs.Select(l => l.NewValues).ToListAsync(), v => v != null && v.Contains("\"Name\":\"c\""));

                var report = await harness.CreateVerifier(db).VerifyAllAsync();
                Assert.True(report.IsValid, report.Message);
            }
        }

        [Fact]
        public async Task ARedactedValueWithoutAuthorization_IsDetected()
        {
            var (harness, customer) = await CustomerWithHistoryAsync();
            using var _ = harness;

            await using (var db = harness.CreateContext())
            {
                await db.RedactAuditTrailAsync(customer, new AuditRedactionRequest { Reason = "r", Properties = new[] { "Email" } });
            }

            // Somebody with database access removes the authorizing entry and rewinds the head... which the MAC prevents,
            // so instead they copy a redacted value into an entry that was never redacted.
            await using (var db = harness.CreateUnauditedContext())
            {
                var redacted = await db.AuditLogs.FirstAsync(l => l.NewValues!.Contains("$redacted"));
                var bystander = await db.AuditLogs.FirstAsync(l => l.NewValues!.Contains("Bystander"));
                var marker = JsonDocument.Parse(redacted.NewValues!).RootElement.GetProperty("Email").GetRawText();
                bystander.NewValues = bystander.NewValues!.Replace("\"other@example.com\"", marker);
                await db.SaveChangesAsync();
            }

            var result = await VerifyAsync(harness);
            Assert.False(result.IsValid);
            Assert.Equal(AuditFailureKind.DataManipulated, result.Failure); // the digest is salted with the entry id
        }

        [Fact]
        public async Task ARedactionThatIsNotAuthorized_IsDetected_EvenWithTheKey()
        {
            // Someone who holds the key but bypasses the API: the values are redacted correctly, but no entry says so.
            var (harness, customer) = await CustomerWithHistoryAsync();
            using var _ = harness;
            var keys = AuditKeyRing.Create(harness.Options);

            await using (var db = harness.CreateUnauditedContext())
            {
                var entry = await db.AuditLogs.OrderBy(l => l.SequenceNumber).FirstAsync(l => l.RecordId == customer.Id.ToString(System.Globalization.CultureInfo.InvariantCulture));
                entry.NewValues = AuditHasher.RedactPayload(keys.Current, entry.Id, AuditHasher.NewValuesKind, entry.NewValues, n => n == "Email", new List<string>());
                await db.SaveChangesAsync();
            }

            var result = await VerifyAsync(harness);
            Assert.Equal(AuditFailureKind.UnauthorizedRedaction, result.Failure);
            Assert.Contains("n:Email", result.Message);
        }

        [Fact]
        public async Task AManipulatedEntry_IsNotRedacted()
        {
            var (harness, customer) = await CustomerWithHistoryAsync();
            using var _ = harness;
            harness.Execute("UPDATE AuditLogs SET NewValues = REPLACE(NewValues, 'Ayşe', 'Fatma')");

            await using var db = harness.CreateContext();
            await Assert.ThrowsAsync<AuditTrailException>(() =>
                db.RedactAuditTrailAsync(customer, new AuditRedactionRequest { Reason = "r", Properties = new[] { "Name" } }));

            // Nothing was written: the chain still ends with the update.
            Assert.DoesNotContain(await db.AuditLogs.Select(l => l.ActionType).ToListAsync(), a => a == AuditActions.Redacted);
        }

        [Fact]
        public async Task RedactingTwice_OnlyAuthorizesNewValues_AndStaysValid()
        {
            var (harness, customer) = await CustomerWithHistoryAsync();
            using var _ = harness;

            await using (var db = harness.CreateContext())
            {
                await db.RedactAuditTrailAsync(customer, new AuditRedactionRequest { Reason = "first", Properties = new[] { "Email" } });
                var again = await db.RedactAuditTrailAsync(customer, new AuditRedactionRequest { Reason = "second", Properties = new[] { "Email" } });
                Assert.Equal(0, again.EntriesRedacted);
                Assert.Empty(again.RedactionEntryIds);

                var more = await db.RedactAuditTrailAsync(customer, new AuditRedactionRequest { Reason = "third", Properties = new[] { "Name" } });
                Assert.Equal(1, more.EntriesRedacted);
            }

            Assert.True((await VerifyAsync(harness)).IsValid);
        }

        [Fact]
        public async Task EntriesOfVersionTwo_AreReportedAsNotRedactable()
        {
            using var harness = new Harness();
            await using (var db = harness.CreateContext())
            {
                db.Customers.Add(new Customer { Name = "old" });
                await db.SaveChangesAsync();
            }

            // Downgrade the entry to the 2.0 preview format, sealed correctly.
            var keys = AuditKeyRing.Create(harness.Options);
            await using (var db = harness.CreateUnauditedContext())
            {
                var entry = await db.AuditLogs.SingleAsync();
                entry.HashVersion = AuditHashVersion.Canonical;
                entry.Metadata = null;
                entry.CurrentHash = AuditHasher.ComputeRecordHash(keys.Current, entry);
                var head = await db.AuditChainStates.SingleAsync();
                head.LastHash = entry.CurrentHash;
                head.Mac = AuditHasher.ComputeStateMac(keys.Current, head.TableName, head.LastHash, head.LastSequence, head.KeyId);
                await db.SaveChangesAsync();
            }

            await using (var db = harness.CreateContext())
            {
                var result = await db.RedactAuditTrailAsync("Customers", "1", new AuditRedactionRequest { Reason = "r" });
                Assert.Equal(0, result.EntriesRedacted);
                Assert.Single(result.NotRedactable);
            }
        }

        [Fact]
        public async Task ValuesThatLookLikeARedactionMarker_AreRefused()
        {
            using var harness = new Harness();
            await using var db = harness.CreateContext();
            db.Customers.Add(new Customer { Name = "[REDACTED:" + new string('a', 64) + "]" });

            // The name is a value inside the JSON, not a marker there: only the record id and user use the text marker.
            await db.SaveChangesAsync();

            using (AuditScope.Begin("[REDACTED:" + new string('b', 64) + "]"))
            {
                db.Customers.Add(new Customer { Name = "x" });
                await Assert.ThrowsAsync<AuditTrailException>(() => db.SaveChangesAsync());
            }
        }

        [Fact]
        public async Task RedactionWorks_OnTheInMemoryProvider()
        {
            var options = new Configuration.TamperEvidentOptions { HmacSecretKey = Harness.SecretKey };
            var dbOptions = new DbContextOptionsBuilder<TestDbContext>()
                .UseInMemoryDatabase("redaction-" + Guid.NewGuid())
                .UseTamperEvidentAudit(options)
                .Options;

            string table;
            await using (var db = new TestDbContext(dbOptions))
            {
                var customer = new Customer { Id = 1, Name = "Secret Name", Email = "a@b.c" };
                db.Customers.Add(customer);
                await db.SaveChangesAsync();
                var result = await db.RedactAuditTrailAsync(customer, new AuditRedactionRequest { Reason = "r", Properties = new[] { "Name" } });
                Assert.Equal(1, result.EntriesRedacted);
                table = (await db.AuditLogs.FirstAsync()).TableName;
            }

            await using (var db = new TestDbContext(dbOptions))
            {
                Assert.DoesNotContain("Secret Name", string.Concat(await db.AuditLogs.Select(l => l.NewValues).ToListAsync()));
                var verification = await new AuditVerifier(db, options).VerifyTableIntegrityAsync(table);
                Assert.True(verification.IsValid, verification.Message);
                Assert.Equal(2, verification.RecordsChecked);
                Assert.Equal(1, verification.RedactedRecords);
            }
        }

        [Fact]
        public async Task Redacting_WithoutTheInterceptor_ExplainsWhatIsMissing()
        {
            using var harness = new Harness();
            await using var db = harness.CreateUnauditedContext();
            var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
                db.RedactAuditTrailAsync("Customers", "1", new AuditRedactionRequest { Reason = "r" }));
            Assert.Contains("UseTamperEvidentAudit", error.Message);
        }
    }
}
