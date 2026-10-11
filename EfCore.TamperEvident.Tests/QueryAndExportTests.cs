using System.Text;
using System.Text.Json;
using EfCore.TamperEvident.Extensions;
using EfCore.TamperEvident.Models;
using EfCore.TamperEvident.Services;
using Microsoft.EntityFrameworkCore;

namespace EfCore.TamperEvident.Tests
{
    public class QueryAndExportTests
    {
        private static async Task<Harness> SeededAsync()
        {
            var harness = new Harness(o => o.UserIdProvider = _ => "alice");
            await using var db = harness.CreateContext();
            var ada = new Customer { Name = "Ada" };
            db.Customers.Add(ada);
            db.Customers.Add(new Customer { Name = "=HYPERLINK(\"http://evil\")" });
            db.Documents.Add(new Document { Title = "Spec" });
            await db.SaveChangesAsync();

            ada.Name = "Ada Lovelace";
            await db.SaveChangesAsync();

            using (AuditScope.Begin("bob"))
            {
                db.Customers.Remove(await db.Customers.SingleAsync(c => c.Id == 2));
                await db.SaveChangesAsync();
            }

            return harness;
        }

        [Fact]
        public async Task QueryHelpers_FilterTheTrail()
        {
            using var harness = await SeededAsync();
            await using var db = harness.CreateContext();

            Assert.Equal(5, await db.AuditLogs().CountAsync());
            Assert.Equal(4, await db.AuditLogs().ForTable("Customers").CountAsync());
            Assert.Equal(2, await db.AuditLogs().ForRecord("Customers", "1").CountAsync());
            Assert.Equal(1, await db.AuditLogs().ByUser("bob").CountAsync());
            Assert.Equal(1, await db.AuditLogs().OfAction(AuditActions.Deleted).CountAsync());
            Assert.Equal(5, await db.AuditLogs().Between(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddMinutes(5)).CountAsync());
            Assert.Equal(0, await db.AuditLogs().Between(DateTimeOffset.UtcNow.AddMinutes(5), null).CountAsync());
            Assert.Equal(0, await db.AuditLogs().Between(null, DateTimeOffset.UtcNow.AddMinutes(-5)).CountAsync());
        }

        [Fact]
        public async Task Ordering_FollowsTheChain()
        {
            using var harness = await SeededAsync();
            await using var db = harness.CreateContext();

            var chain = await db.AuditLogs().ForTable("Customers").InChainOrder().Select(l => l.SequenceNumber).ToListAsync();
            Assert.Equal(new long[] { 1, 2, 3, 4 }, chain);

            var newest = await db.AuditLogs().ForTable("Customers").Newest().Select(l => l.SequenceNumber).FirstAsync();
            Assert.Equal(4, newest);
        }

        [Fact]
        public async Task GetAuditHistory_ReturnsTheHistoryOfOneEntity()
        {
            using var harness = await SeededAsync();
            await using var db = harness.CreateContext();
            var ada = await db.Customers.SingleAsync(c => c.Id == 1);

            var history = await db.GetAuditHistoryAsync(ada);

            Assert.Equal(new[] { AuditActions.Added, AuditActions.Modified }, history.Select(h => h.ActionType));
            Assert.All(history, h => Assert.Equal("1", h.RecordId));
        }

        [Fact]
        public async Task JsonLines_AreOneObjectPerEntry()
        {
            using var harness = await SeededAsync();
            await using var db = harness.CreateContext();
            using var stream = new MemoryStream();

            await AuditExporter.WriteJsonLinesAsync(stream, db.AuditLogs().InChainOrder());

            var lines = Encoding.UTF8.GetString(stream.ToArray()).Split('\n', StringSplitOptions.RemoveEmptyEntries);
            Assert.Equal(5, lines.Length);
            using var first = JsonDocument.Parse(lines[0]);
            Assert.Equal("Customers", first.RootElement.GetProperty("tableName").GetString());
            Assert.Equal(64, first.RootElement.GetProperty("currentHash").GetString()!.Length);
        }

        [Fact]
        public async Task Csv_IsEscaped_AndNeutralisesSpreadsheetFormulas()
        {
            using var harness = await SeededAsync();
            await using var db = harness.CreateContext();
            using var stream = new MemoryStream();

            await AuditExporter.WriteCsvAsync(stream, db.AuditLogs().ForTable("Customers").InChainOrder());

            var csv = Encoding.UTF8.GetString(stream.ToArray());
            var lines = csv.Split("\r\n", StringSplitOptions.RemoveEmptyEntries);
            Assert.StartsWith("Id,TableName,RecordId,ActionType,UserId,TimestampUtc,SequenceNumber", lines[0]);
            Assert.Equal(5, lines.Length);

            // The JSON payload contains commas and quotes, so the cell is quoted and the quotes are doubled.
            Assert.Contains("\"{\"\"Balance\"\"", csv);

            // A value that starts with '=' must never reach a spreadsheet as a formula.
            Assert.DoesNotContain(",=HYPERLINK", csv);
            Assert.DoesNotContain(",\"=HYPERLINK", csv);
        }

        [Fact]
        public async Task EvidenceBundle_ContainsVerificationAndEveryEntry()
        {
            using var harness = await SeededAsync();
            await using var db = harness.CreateContext();
            using var stream = new MemoryStream();

            await AuditExporter.WriteEvidenceBundleAsync(stream, db, harness.CreateVerifier(db));

            using var json = JsonDocument.Parse(stream.ToArray());
            var root = json.RootElement;
            Assert.StartsWith("EfCore.TamperEvident", root.GetProperty("generator").GetString());
            var tables = root.GetProperty("tables").EnumerateArray().ToList();
            Assert.Equal(new[] { "Customers", "Documents" }, tables.Select(t => t.GetProperty("table").GetString()));

            var customers = tables[0];
            Assert.True(customers.GetProperty("verification").GetProperty("isValid").GetBoolean());
            Assert.Equal("None", customers.GetProperty("verification").GetProperty("result").GetString());
            Assert.Equal(4, customers.GetProperty("records").GetArrayLength());
            Assert.Equal(4, customers.GetProperty("verification").GetProperty("headSequence").GetInt64());
        }

        [Fact]
        public async Task EvidenceBundle_OfATamperedTable_SaysSo()
        {
            using var harness = await SeededAsync();
            harness.Execute("UPDATE AuditLogs SET UserId = 'mallory' WHERE SequenceNumber = 1 AND TableName = 'Customers'");
            await using var db = harness.CreateContext();
            using var stream = new MemoryStream();

            await AuditExporter.WriteEvidenceBundleAsync(stream, db, harness.CreateVerifier(db), "Customers");

            using var json = JsonDocument.Parse(stream.ToArray());
            var table = json.RootElement.GetProperty("tables")[0];
            Assert.False(table.GetProperty("verification").GetProperty("isValid").GetBoolean());
            Assert.Equal("DataManipulated", table.GetProperty("verification").GetProperty("result").GetString());
        }
    }
}
