using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using EfCore.TamperEvident.Configuration;
using EfCore.TamperEvident.Models;
using EfCore.TamperEvident.Services;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace EfCore.TamperEvident.Tests
{
    public class AuditVerifierTests
    {
        private DbContextOptions<TestDbContext> GetMemoryOptions(string dbName)
        {
            return new DbContextOptionsBuilder<TestDbContext>()
                .UseInMemoryDatabase(databaseName: dbName)
                .Options;
        }

        private TamperEvidentOptions GetTestOptions()
        {
            return new TamperEvidentOptions
            {
                HmacSecretKey = TestKeys.Key
            };
        }

        [Fact]
        public async Task EmptyHistoryWithExternalAnchorIsInvalid()
        {
            await using var context = new TestDbContext(GetMemoryOptions(Guid.NewGuid().ToString()));
            var anchors = new List<string> { "v2:trusted-external-hash" };
            var result = await new AuditVerifier(context, GetTestOptions())
                .VerifyTableIntegrityAsync("Customers", anchors);
            Assert.False(result.IsValid);
            Assert.Contains("ANCHOR MISMATCH", result.Message);
            Assert.Single(anchors);
        }

        [Fact]
        public async Task EmptyHistoryWithoutTrustRootIsInconclusive()
        {
            await using var context = new TestDbContext(GetMemoryOptions(Guid.NewGuid().ToString()));
            var result = await new AuditVerifier(context, GetTestOptions())
                .VerifyTableIntegrityAsync("Customers");
            Assert.False(result.IsValid);
            Assert.Contains("INCONCLUSIVE", result.Message);
        }

        [Fact]
        public async Task VerifyTableIntegrityAsync_WithValidChain_ReturnsTrue()
        {
            // Arrange
            var options = GetTestOptions();
            var dbOptions = GetMemoryOptions(Guid.NewGuid().ToString());

            using (var context = new TestDbContext(dbOptions))
            {
                // genesis log
                string hash1 = "";

                var log = new AuditLog
                {
                    Id = Guid.NewGuid(),
                    TableName = "Customers",
                    RecordId = "user1",
                    ActionType = "Inserted",
                    OldValues = "Old",
                    NewValues = "New",
                    TimestampTicks = 1000,
                    PreviousHash = "GENESIS",
                    CurrentHash = hash1,
                    UserId = "Sys"
                };
                log.CurrentHash = hash1 = SecurityHelper.ComputeAuditHash(log, options.HmacSecretKey);
                context.AuditLogs.Add(log);

                // second log
                string hash2 = "";

                var log2 = new AuditLog
                {
                    Id = Guid.NewGuid(),
                    TableName = "Customers",
                    RecordId = "user2",
                    ActionType = "Updated",
                    OldValues = "Old2",
                    NewValues = "New2",
                    TimestampTicks = 2000,
                    PreviousHash = hash1,
                    CurrentHash = hash2,
                    UserId = "Sys"
                };
                log2.CurrentHash = hash2 = SecurityHelper.ComputeAuditHash(log2, options.HmacSecretKey);
                context.AuditLogs.Add(log2);
                context.AuditChainStates.Add(new AuditChainState
                {
                    TableName = "Customers", LastHash = hash2, LastTimestampTicks = 2000
                });

                await context.SaveChangesAsync();
            }

            // Act
            using (var context = new TestDbContext(dbOptions))
            {
                var verifier = new AuditVerifier(context, options);
                var result = await verifier.VerifyTableIntegrityAsync("Customers");

                // Assert
                Assert.True(result.IsValid);
                Assert.Contains("passed successfully", result.Message);
            }
        }

        [Fact]
        public async Task VerifyTableIntegrityAsync_WithBrokenChain_ReturnsFalse()
        {
            // Arrange
            var options = GetTestOptions();
            var dbOptions = GetMemoryOptions(Guid.NewGuid().ToString());

            using (var context = new TestDbContext(dbOptions))
            {
                string hash1 = "";

                var log = new AuditLog
                {
                    Id = Guid.NewGuid(),
                    TableName = "Customers",
                    RecordId = "user1",
                    ActionType = "Inserted",
                    OldValues = "Old",
                    NewValues = "New",
                    TimestampTicks = 1000,
                    PreviousHash = "GENESIS",
                    CurrentHash = hash1,
                    UserId = "Sys"
                };
                log.CurrentHash = hash1 = SecurityHelper.ComputeAuditHash(log, options.HmacSecretKey);
                context.AuditLogs.Add(log);

                // second log has wrong previous hash intentionally
                context.AuditLogs.Add(new AuditLog
                {
                    Id = Guid.NewGuid(),
                    TableName = "Customers",
                    RecordId = "user2",
                    ActionType = "Updated",
                    OldValues = "Old",
                    NewValues = "New",
                    TimestampTicks = 2000,
                    PreviousHash = "WRONG_HASH", // should be hash1
                    CurrentHash = "FAKE_HASH_2",
                    UserId = "Sys"
                });

                await context.SaveChangesAsync();
            }

            // Act
            using (var context = new TestDbContext(dbOptions))
            {
                var verifier = new AuditVerifier(context, options);
                var result = await verifier.VerifyTableIntegrityAsync("Customers");

                // Assert
                Assert.False(result.IsValid);
                Assert.Contains("CHAIN BROKEN", result.Message);
            }
        }
    }
}
