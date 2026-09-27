using System.Collections.Generic;
using System.Globalization;
using EfCore.TamperEvident.Configuration;
using EfCore.TamperEvident.Models;
using EfCore.TamperEvident.Services;
using EfCore.TamperEvident.Extensions;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace EfCore.TamperEvident.Tests
{
    public class SecurityHelperTests
    {
        [Fact]
        public void ComputeHash_WithSameDataAndKey_ReturnsSameHash()
        {
            // Arrange
            string data = "TestPayload";
            string key = TestKeys.Key;

            // Act
            string hash1 = SecurityHelper.ComputeHash(data, key);
            string hash2 = SecurityHelper.ComputeHash(data, key);

            // Assert
            Assert.Equal(hash1, hash2);
            Assert.NotEmpty(hash1);
        }

        [Fact]
        public void ComputeHash_WithDifferentKey_ReturnsDifferentHash()
        {
            // Arrange
            string data = "TestPayload";
            string key1 = TestKeys.Key;
            string key2 = TestKeys.Other;

            // Act
            string hash1 = SecurityHelper.ComputeHash(data, key1);
            string hash2 = SecurityHelper.ComputeHash(data, key2);

            // Assert
            Assert.NotEqual(hash1, hash2);
        }

        [Fact]
        public void SerializeDeterministic_SortsKeysConsistently()
        {
            // Arrange
            var dict1 = new Dictionary<string, object>
            {
                { "Z_Key", "Value1" },
                { "A_Key", 42 }
            };

            var dict2 = new Dictionary<string, object>
            {
                { "A_Key", 42 },
                { "Z_Key", "Value1" }
            };

            // Act
            var json1 = SecurityHelper.SerializeDeterministic(dict1);
            var json2 = SecurityHelper.SerializeDeterministic(dict2);

            // Assert
            Assert.Equal(json1, json2);
            Assert.Contains("\"A_Key\":42", json1);
            Assert.Contains("\"Z_Key\":\"Value1\"", json1);
        }

        [Fact]
        public void SerializeDeterministic_SortsNestedObjects()
        {
            var first = new { Outer = new Dictionary<string, object>
                { ["z"] = new Dictionary<string, int> { ["b"] = 2, ["a"] = 1 }, ["a"] = 0 } };
            var second = new { Outer = new Dictionary<string, object>
                { ["a"] = 0, ["z"] = new Dictionary<string, int> { ["a"] = 1, ["b"] = 2 } } };
            Assert.Equal(SecurityHelper.SerializeDeterministic(first), SecurityHelper.SerializeDeterministic(second));
        }

        [Fact]
        public void AuditHashFramesFieldsAndProtectsIdentity()
        {
            var log = new AuditLog
            {
                TableName = "a", RecordId = "bc", ActionType = "Added", UserId = "user",
                PreviousHash = "GENESIS", CurrentHash = "", TimestampTicks = 1
            };
            var original = SecurityHelper.ComputeAuditHash(log, TestKeys.Key);
            log.TableName = "ab";
            log.RecordId = "c";
            Assert.NotEqual(original, SecurityHelper.ComputeAuditHash(log, TestKeys.Key));
            log.TableName = "a";
            log.RecordId = "bc";
            log.UserId = "other";
            Assert.NotEqual(original, SecurityHelper.ComputeAuditHash(log, TestKeys.Key));
        }

        [Fact]
        public void DefaultAndShortKeysAreRejected()
        {
            Assert.Throws<InvalidOperationException>(() => new TamperEvidentOptions().Validate());
            Assert.Throws<InvalidOperationException>(() => new TamperEvidentOptions { HmacSecretKey = "abc" }.Validate());
            Assert.Throws<InvalidOperationException>(() => new TamperEvidentOptions
            {
                HmacSecretKey = System.Convert.ToBase64String(new byte[32])
            }.Validate());
        }

        [Fact]
        public void AuditRegistrationRejectsMissingWeakAndUniformKeysWithoutPrintingThem()
        {
            foreach (var key in new[] { "", "not-base64", Convert.ToBase64String(new byte[16]),
                Convert.ToBase64String(Enumerable.Repeat((byte)17, 32).ToArray()) })
            {
                var error = Assert.Throws<InvalidOperationException>(() =>
                    new DbContextOptionsBuilder<TestDbContext>().UseTamperEvidentAudit(x => x.HmacSecretKey = key));
                if (key.Length > 0) Assert.DoesNotContain(key, error.Message);
            }
            new DbContextOptionsBuilder<TestDbContext>().UseTamperEvidentAudit(x => x.HmacSecretKey = TestKeys.Key);
        }

        [Fact]
        public void CanonicalJsonDoesNotDependOnProcessCulture()
        {
            var value = new { Amount = 1234.56m, Nested = new { Date = new System.DateTime(2026, 9, 22, 12, 0, 0, System.DateTimeKind.Utc) } };
            var previous = CultureInfo.CurrentCulture;
            try
            {
                CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("tr-TR");
                var turkish = SecurityHelper.SerializeDeterministic(value);
                CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("en-US");
                var english = SecurityHelper.SerializeDeterministic(value);
                Assert.Equal(turkish, english);
                Assert.Contains("1234.56", turkish);
            }
            finally { CultureInfo.CurrentCulture = previous; }
        }
    }
}
