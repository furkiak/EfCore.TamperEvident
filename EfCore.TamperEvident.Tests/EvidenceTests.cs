using System.Text;
using System.Text.Json;
using EfCore.TamperEvident.Configuration;
using EfCore.TamperEvident.Extensions;
using EfCore.TamperEvident.Services;

namespace EfCore.TamperEvident.Tests
{
    /// <summary>Evidence bundles are verified again, offline, by whoever receives them.</summary>
    public class EvidenceTests
    {
        private static async Task<Harness> SeededAsync()
        {
            var harness = new Harness();
            await using var db = harness.CreateContext();
            using (AuditScope.WithReason("seed"))
            {
                for (var i = 0; i < 3; i++)
                {
                    db.Customers.Add(new Customer { Name = "Ayşe " + i, Email = $"c{i}@example.com" });
                    await db.SaveChangesAsync();
                }
            }

            db.Documents.Add(new Document { Title = "contract" });
            await db.SaveChangesAsync();
            (await db.Customers.FindAsync(1))!.Email = "changed@example.com";
            await db.SaveChangesAsync();
            return harness;
        }

        private static async Task<byte[]> BundleAsync(Harness harness)
        {
            await using var db = harness.CreateContext();
            using var stream = new MemoryStream();
            await AuditExporter.WriteEvidenceBundleAsync(stream, db, harness.CreateVerifier(db));
            return stream.ToArray();
        }

        private static Task<AuditVerificationReport> VerifyAsync(Harness harness, byte[] bundle, IReadOnlyDictionary<string, IEnumerable<string>>? anchors = null) =>
            AuditEvidence.VerifyBundleAsync(new MemoryStream(bundle), harness.Options, anchors);

        private static byte[] Edit(byte[] bundle, Action<System.Text.Json.Nodes.JsonObject> edit)
        {
            var node = System.Text.Json.Nodes.JsonNode.Parse(bundle)!.AsObject();
            edit(node);
            return Encoding.UTF8.GetBytes(node.ToJsonString());
        }

        [Fact]
        public async Task AFreshBundle_VerifiesOffline()
        {
            using var harness = await SeededAsync();
            var bundle = await BundleAsync(harness);

            var report = await VerifyAsync(harness, bundle);
            Assert.True(report.IsValid, report.Message);
            Assert.Equal(new[] { "Customers", "Documents" }, report.Tables.Select(t => t.TableName));
            Assert.Equal(5, report.RecordsChecked);

            using var json = JsonDocument.Parse(bundle);
            Assert.Equal(2, json.RootElement.GetProperty("format").GetInt32());
            var customers = json.RootElement.GetProperty("tables")[0];
            Assert.Equal(4, customers.GetProperty("head").GetProperty("lastSequence").GetInt64());
            Assert.Contains("seed", customers.GetProperty("records")[0].GetProperty("metadata").GetString());
        }

        [Fact]
        public async Task ABundleWithRedactions_Verifies()
        {
            using var harness = await SeededAsync();
            await using (var db = harness.CreateContext())
            {
                await db.RedactAuditTrailAsync("Customers", "1", new AuditRedactionRequest { Reason = "GDPR", Properties = new[] { "Name", "Email" } });
            }

            var report = await VerifyAsync(harness, await BundleAsync(harness));
            Assert.True(report.IsValid, report.Message);
            Assert.Equal(2, report.Tables[0].RedactedRecords);
        }

        [Theory]
        [InlineData("payload", "DataManipulated")]
        [InlineData("removed", "ChainBroken")]
        [InlineData("truncated", "RecordsMissing")]
        [InlineData("head", "ChainStateTampered")]
        [InlineData("moved", "ChainBroken")]
        public async Task AnEditedBundle_IsDetected(string edit, string failure)
        {
            using var harness = await SeededAsync();
            var bundle = Edit(await BundleAsync(harness), root =>
            {
                var customers = root["tables"]![0]!;
                var records = customers["records"]!.AsArray();
                switch (edit)
                {
                    case "payload": records[1]!["newValues"] = records[1]!["newValues"]!.GetValue<string>().Replace("Ayşe", "Fatma"); break;
                    case "removed": records.RemoveAt(1); break;
                    case "truncated": records.RemoveAt(records.Count - 1); break;
                    case "head": customers["head"]!["lastSequence"] = 3; break;
                    case "moved": records[0]!["tableName"] = "Documents"; break;
                }
            });

            var report = await VerifyAsync(harness, bundle);
            Assert.False(report.IsValid);
            Assert.Equal(failure, report.Failures.Single().Failure.ToString());
        }

        [Fact]
        public async Task TheStoredVerdict_IsIgnored()
        {
            using var harness = await SeededAsync();
            var bundle = Edit(await BundleAsync(harness), root =>
            {
                var customers = root["tables"]![0]!;
                customers["records"]![2]!["userId"] = "mallory";
                customers["verification"]!["isValid"] = true;
            });

            Assert.False((await VerifyAsync(harness, bundle)).IsValid);
        }

        [Fact]
        public async Task Anchors_AreLookedUpInTheBundle()
        {
            using var harness = await SeededAsync();
            var bundle = await BundleAsync(harness);
            using var json = JsonDocument.Parse(bundle);
            var anchor = json.RootElement.GetProperty("tables")[0].GetProperty("records")[1].GetProperty("currentHash").GetString()!;

            var matched = await VerifyAsync(harness, bundle, new Dictionary<string, IEnumerable<string>> { ["Customers"] = new[] { anchor } });
            Assert.True(matched.IsValid, matched.Message);
            Assert.Equal(1, matched.Tables[0].AnchorsMatched);

            var missing = await VerifyAsync(harness, bundle, new Dictionary<string, IEnumerable<string>> { ["Customers"] = new[] { new string('9', 64) } });
            Assert.Equal(AuditFailureKind.AnchorMismatch, missing.Tables[0].Failure);
        }

        [Fact]
        public async Task TheWrongKey_FailsTheVerification()
        {
            using var harness = await SeededAsync();
            var report = await AuditEvidence.VerifyBundleAsync(new MemoryStream(await BundleAsync(harness)),
                new TamperEvidentOptions { HmacSecretKey = "a-completely-different-secret-0123456789" });
            Assert.False(report.IsValid);
        }

        [Fact]
        public async Task LargeBundles_AreStreamed()
        {
            using var harness = new Harness();
            await using (var db = harness.CreateContext())
            {
                for (var i = 0; i < 1500; i++)
                {
                    db.Customers.Add(new Customer { Name = new string('n', 200) + i });
                }

                await db.SaveChangesAsync();
            }

            // A small buffer forces many refills in the middle of entries.
            var report = await AuditEvidence.VerifyBundleAsync(new SlowStream(await BundleAsync(harness)), harness.Options);
            Assert.True(report.IsValid, report.Message);
            Assert.Equal(1500, report.RecordsChecked);
        }

        [Theory]
        [InlineData("[]")]
        [InlineData("{\"format\":1,\"tables\":[]}")]
        [InlineData("{\"tables\":[]}")]
        [InlineData("{\"format\":2,\"tables\":[{\"table\":\"T\",\"records\":[]}]}")]
        [InlineData("{\"format\":2,\"tables\":[{\"table\":\"T\",\"head\":null,\"records\":[")]
        public async Task SomethingElse_IsRejected(string content)
        {
            using var harness = new Harness();
            await Assert.ThrowsAsync<InvalidDataException>(() =>
                AuditEvidence.VerifyBundleAsync(new MemoryStream(Encoding.UTF8.GetBytes(content)), harness.Options));
        }

        [Fact]
        public async Task JsonLinesAndCsv_CarryTheMetadata()
        {
            using var harness = await SeededAsync();
            await using var db = harness.CreateContext();
            using var lines = new MemoryStream();
            await AuditExporter.WriteJsonLinesAsync(lines, db.AuditLogs().InChainOrder());
            var first = JsonDocument.Parse(Encoding.UTF8.GetString(lines.ToArray()).Split('\n')[0]).RootElement;
            Assert.Equal("{\"reason\":\"seed\"}", first.GetProperty("metadata").GetString());
            Assert.True(first.GetProperty("timestampTicks").GetInt64() > 0);

            using var csv = new MemoryStream();
            await AuditExporter.WriteCsvAsync(csv, db.AuditLogs().InChainOrder());
            Assert.EndsWith(",NewValues,Metadata", Encoding.UTF8.GetString(csv.ToArray()).Split("\r\n")[0]);
        }

        /// <summary>Returns at most 37 bytes per read.</summary>
        private sealed class SlowStream : MemoryStream
        {
            public SlowStream(byte[] buffer) : base(buffer) { }

            public override int Read(byte[] buffer, int offset, int count) => base.Read(buffer, offset, Math.Min(count, 37));

            public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
                base.ReadAsync(buffer[..Math.Min(buffer.Length, 37)], cancellationToken);
        }
    }
}
