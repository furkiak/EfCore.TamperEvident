using System.Diagnostics;
using System.Text.Json;
using EfCore.TamperEvident.Models;
using EfCore.TamperEvident.Services;
using Microsoft.EntityFrameworkCore;

namespace EfCore.TamperEvident.Tests
{
    /// <summary>The reason, the trace id and custom metadata that are sealed into every entry.</summary>
    public class MetadataTests
    {
        private static async Task<AuditLog> SaveOneAsync(Harness harness)
        {
            await using (var db = harness.CreateContext())
            {
                db.Customers.Add(new Customer { Name = "x" });
                await db.SaveChangesAsync();
            }

            await using var read = harness.CreateContext();
            return await read.AuditLogs.OrderByDescending(l => l.SequenceNumber).FirstAsync();
        }

        [Fact]
        public async Task WithoutContext_NoMetadataIsStored()
        {
            using var harness = new Harness();
            Assert.Null((await SaveOneAsync(harness)).Metadata);
        }

        [Fact]
        public async Task TheReasonAndScopeMetadata_AreStored()
        {
            using var harness = new Harness();
            AuditLog log;
            using (AuditScope.Begin("alice", "Customer called (ticket #42)"))
            using (AuditScope.WithMetadata("ticket", 42))
            {
                Assert.Equal("alice", AuditScope.CurrentUserId);
                Assert.Equal("Customer called (ticket #42)", AuditScope.CurrentReason);
                log = await SaveOneAsync(harness);
            }

            Assert.Equal("alice", log.UserId);
            Assert.Equal("{\"reason\":\"Customer called (ticket #42)\",\"ticket\":42}", log.Metadata);
            Assert.Null(AuditScope.CurrentReason);
            Assert.Empty(AuditScope.CurrentMetadata);
        }

        [Fact]
        public async Task ScopesNest_AndInnerValuesWin()
        {
            using var harness = new Harness();
            using (AuditScope.Begin("outer", "outer reason"))
            {
                using (AuditScope.WithReason("inner reason"))
                {
                    Assert.Equal("outer", AuditScope.CurrentUserId);
                    var log = await SaveOneAsync(harness);
                    Assert.Contains("inner reason", log.Metadata);
                }

                Assert.Equal("outer reason", AuditScope.CurrentReason);
            }
        }

        [Fact]
        public async Task TheProvider_AddsMetadata_AndTheScopeOverridesIt()
        {
            using var harness = new Harness(o => o.MetadataProvider = _ => new Dictionary<string, object?>
            {
                ["tenant"] = "acme",
                ["app"] = "1.0"
            });

            using (AuditScope.WithMetadata("tenant", "override"))
            {
                var log = await SaveOneAsync(harness);
                using var document = JsonDocument.Parse(log.Metadata!);
                Assert.Equal("override", document.RootElement.GetProperty("tenant").GetString());
                Assert.Equal("1.0", document.RootElement.GetProperty("app").GetString());
            }
        }

        [Fact]
        public async Task TheTraceId_IsCaptured_WhenAnActivityIsRunning()
        {
            using var harness = new Harness();
            using var activity = new Activity("test").SetIdFormat(ActivityIdFormat.W3C).Start();

            var log = await SaveOneAsync(harness);
            Assert.Equal($"{{\"traceId\":\"{activity.TraceId.ToHexString()}\"}}", log.Metadata);
        }

        [Fact]
        public async Task CapturingTheTraceId_CanBeTurnedOff()
        {
            using var harness = new Harness(o => o.CaptureTraceId = false);
            using var activity = new Activity("test").SetIdFormat(ActivityIdFormat.W3C).Start();
            Assert.Null((await SaveOneAsync(harness)).Metadata);
        }

        [Fact]
        public async Task ChangingTheMetadata_IsDetected()
        {
            using var harness = new Harness();
            using (AuditScope.WithReason("legitimate"))
            {
                await SaveOneAsync(harness);
            }

            harness.Execute("UPDATE AuditLogs SET Metadata = REPLACE(Metadata, 'legitimate', 'forged')");

            await using var db = harness.CreateContext();
            var result = await harness.CreateVerifier(db).VerifyTableIntegrityAsync("Customers");
            Assert.Equal(AuditFailureKind.DataManipulated, result.Failure);
        }

        [Fact]
        public async Task RemovingTheMetadata_IsDetected()
        {
            using var harness = new Harness();
            using (AuditScope.WithReason("legitimate"))
            {
                await SaveOneAsync(harness);
            }

            harness.Execute("UPDATE AuditLogs SET Metadata = NULL");

            await using var db = harness.CreateContext();
            Assert.Equal(AuditFailureKind.DataManipulated, (await harness.CreateVerifier(db).VerifyTableIntegrityAsync("Customers")).Failure);
        }

        [Fact]
        public void BlankKeysAndReasons_AreRejected()
        {
            Assert.Throws<ArgumentException>(() => AuditScope.WithReason(" "));
            Assert.Throws<ArgumentException>(() => AuditScope.WithMetadata("", 1));
            Assert.Throws<ArgumentException>(() => AuditScope.Begin(" "));
        }
    }
}
