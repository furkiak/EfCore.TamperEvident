using System.Globalization;
using EfCore.TamperEvident.Internal;
using EfCore.TamperEvident.Models;
using EfCore.TamperEvident.Services;

namespace EfCore.TamperEvident.Tests
{
    public class SecurityHelperTests
    {
        [Fact]
        public void ComputeHash_WithSameDataAndKey_ReturnsSameHash()
        {
            string hash1 = SecurityHelper.ComputeHash("TestPayload", "MySecretKey123");
            string hash2 = SecurityHelper.ComputeHash("TestPayload", "MySecretKey123");

            Assert.Equal(hash1, hash2);
            Assert.Equal(64, hash1.Length);
            Assert.Equal(hash1, hash1.ToLowerInvariant());
        }

        [Fact]
        public void ComputeHash_WithDifferentKey_ReturnsDifferentHash()
        {
            Assert.NotEqual(
                SecurityHelper.ComputeHash("TestPayload", "MySecretKey123"),
                SecurityHelper.ComputeHash("TestPayload", "DifferentKey456"));
        }

        [Fact]
        public void ComputeHash_MatchesTheRfc4231Vector()
        {
            // RFC 4231 test case 2: key "Jefe", data "what do ya want for nothing?"
            Assert.Equal(
                "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
                SecurityHelper.ComputeHash("what do ya want for nothing?", "Jefe"));
        }

        [Fact]
        public void SerializeDeterministic_SortsKeysConsistently()
        {
            var dict1 = new Dictionary<string, object> { { "Z_Key", "Value1" }, { "A_Key", 42 } };
            var dict2 = new Dictionary<string, object> { { "A_Key", 42 }, { "Z_Key", "Value1" } };

            var json1 = SecurityHelper.SerializeDeterministic(dict1);
            var json2 = SecurityHelper.SerializeDeterministic(dict2);

            Assert.Equal(json1, json2);
            Assert.Equal("{\"A_Key\":42,\"Z_Key\":\"Value1\"}", json1);
        }

        [Fact]
        public void SerializeDeterministic_IsIndependentOfTheCurrentCulture()
        {
            // Regression: keys were sorted with the culture dependent default comparer, so the same data produced
            // different JSON (and therefore different hashes) on a Turkish and an invariant machine.
            var data = new Dictionary<string, object?> { ["I"] = 1, ["ı"] = 2, ["a"] = 3, ["B"] = 4, ["i"] = 5 };

            string Serialize(string culture)
            {
                var previous = CultureInfo.CurrentCulture;
                try
                {
                    CultureInfo.CurrentCulture = new CultureInfo(culture);
                    return SecurityHelper.SerializeDeterministic(data)!;
                }
                finally
                {
                    CultureInfo.CurrentCulture = previous;
                }
            }

            var turkish = Serialize("tr-TR");
            Assert.Equal(Serialize(""), turkish);
            Assert.Equal(Serialize("en-US"), turkish);

            // Ordinal order: uppercase before lowercase, dotless i after every ASCII letter.
            Assert.Equal("{\"B\":4,\"I\":1,\"a\":3,\"i\":5,\"ı\":2}".Replace("ı", "ı"), turkish);
        }

        [Fact]
        public void SerializeDeterministic_SortsNestedObjectsAndKeepsArrayOrder()
        {
            var json = SecurityHelper.SerializeDeterministic(new { z = new { b = 2, a = 1 }, a = new[] { 3, 1, 2 } });
            Assert.Equal("{\"a\":[3,1,2],\"z\":{\"a\":1,\"b\":2}}", json);
        }

        [Fact]
        public void SerializeDeterministic_KeepsNonAsciiTextReadable()
        {
            Assert.Equal("{\"name\":\"Çiğdem Öztürk\"}", SecurityHelper.SerializeDeterministic(new { name = "Çiğdem Öztürk" }));
        }

        [Fact]
        public void SerializeDeterministic_OfNull_IsNull()
        {
            Assert.Null(SecurityHelper.SerializeDeterministic(null));
        }

        [Fact]
        public void Serializer_WritesEnumsAsNames_AndBytesAsBase64()
        {
            var json = AuditSerializer.Serialize(new Dictionary<string, object?>
            {
                ["Day"] = DayOfWeek.Friday,
                ["Bytes"] = new byte[] { 1, 2, 3 },
                ["Nothing"] = null,
                ["When"] = new DateTime(2026, 5, 17, 12, 30, 0, DateTimeKind.Utc),
                ["Id"] = Guid.Parse("11111111-2222-3333-4444-555555555555")
            });

            Assert.Equal(
                "{\"Bytes\":\"AQID\",\"Day\":\"Friday\",\"Id\":\"11111111-2222-3333-4444-555555555555\",\"Nothing\":null,\"When\":\"2026-05-17T12:30:00Z\"}",
                json);
        }

        [Fact]
        public void Serializer_HandlesNonFiniteNumbers()
        {
            var json = AuditSerializer.Serialize(new Dictionary<string, object?> { ["n"] = double.NaN, ["i"] = double.PositiveInfinity });
            Assert.Equal("{\"i\":\"Infinity\",\"n\":\"NaN\"}", json);
        }
    }

    public class HasherTests
    {
        private static readonly AuditKey Key = new(null, System.Text.Encoding.UTF8.GetBytes("hasher-test-key-0123456789abcdef"));

        private static AuditLog Log() => new()
        {
            TableName = "Customers",
            RecordId = "1",
            ActionType = "Added",
            OldValues = null,
            NewValues = "{}",
            UserId = "alice",
            KeyId = null,
            TimestampTicks = 638000000000000000,
            SequenceNumber = 1,
            HashVersion = AuditHashVersion.Canonical,
            PreviousHash = "GENESIS",
            CurrentHash = string.Empty
        };

        [Fact]
        public void CanonicalHash_IsStable()
        {
            Assert.Equal(AuditHasher.ComputeRecordHash(Key, Log()), AuditHasher.ComputeRecordHash(Key, Log()));
        }

        [Theory]
        [InlineData("TableName")]
        [InlineData("RecordId")]
        [InlineData("ActionType")]
        [InlineData("OldValues")]
        [InlineData("NewValues")]
        [InlineData("UserId")]
        [InlineData("KeyId")]
        [InlineData("TimestampTicks")]
        [InlineData("SequenceNumber")]
        [InlineData("PreviousHash")]
        public void EveryFieldIsPartOfTheCanonicalHash(string field)
        {
            var original = AuditHasher.ComputeRecordHash(Key, Log());
            var changed = Log();
            switch (field)
            {
                case "TableName": changed.TableName = "Other"; break;
                case "RecordId": changed.RecordId = "2"; break;
                case "ActionType": changed.ActionType = "Deleted"; break;
                case "OldValues": changed.OldValues = "{}"; break;
                case "NewValues": changed.NewValues = "{\"a\":1}"; break;
                case "UserId": changed.UserId = "bob"; break;
                case "KeyId": changed.KeyId = "k1"; break;
                case "TimestampTicks": changed.TimestampTicks++; break;
                case "SequenceNumber": changed.SequenceNumber++; break;
                case "PreviousHash": changed.PreviousHash = "other"; break;
            }

            Assert.NotEqual(original, AuditHasher.ComputeRecordHash(Key, changed));
        }

        [Fact]
        public void NullAndEmptyAreDifferentValues()
        {
            var withNull = Log();
            var withEmpty = Log();
            withNull.OldValues = null;
            withEmpty.OldValues = string.Empty;

            Assert.NotEqual(AuditHasher.ComputeRecordHash(Key, withNull), AuditHasher.ComputeRecordHash(Key, withEmpty));
        }

        [Fact]
        public void MovingCharactersBetweenFields_ChangesTheHash()
        {
            var a = Log();
            var b = Log();
            a.RecordId = "12";
            a.ActionType = "Added";
            b.RecordId = "1";
            b.ActionType = "2Added";

            Assert.NotEqual(AuditHasher.ComputeRecordHash(Key, a), AuditHasher.ComputeRecordHash(Key, b));
        }

        [Fact]
        public void LegacyHash_KeepsTheOldConcatenationFormat()
        {
            var log = Log();
            log.HashVersion = AuditHashVersion.Legacy;
            log.UserId = "ignored in the legacy format";

            var expected = SecurityHelper.ComputeHash(
                $"GENESISCustomers1Added{null}{{}}638000000000000000", System.Text.Encoding.UTF8.GetString(Key.Secret));
            Assert.Equal(expected, AuditHasher.ComputeRecordHash(Key, log));
        }

        [Fact]
        public void UnknownHashVersion_IsRejected()
        {
            var log = Log();
            log.HashVersion = 99;
            Assert.Throws<NotSupportedException>(() => AuditHasher.ComputeRecordHash(Key, log));
        }

        [Fact]
        public void StateMac_CoversTheHeadAndTheSequence()
        {
            var mac = AuditHasher.ComputeStateMac(Key, "Customers", new string('a', 64), 5, null);

            Assert.NotEqual(mac, AuditHasher.ComputeStateMac(Key, "Customers", new string('b', 64), 5, null));
            Assert.NotEqual(mac, AuditHasher.ComputeStateMac(Key, "Customers", new string('a', 64), 6, null));
            Assert.NotEqual(mac, AuditHasher.ComputeStateMac(Key, "Orders", new string('a', 64), 5, null));
            Assert.NotEqual(mac, AuditHasher.ComputeStateMac(Key, "Customers", new string('a', 64), 5, "k1"));
        }

        [Fact]
        public void RecordHash_AndStateMac_AreNotInterchangeable()
        {
            // Domain separation: a record hash can never be replayed as a chain head signature.
            var log = Log();
            var recordHash = AuditHasher.ComputeRecordHash(Key, log);
            var mac = AuditHasher.ComputeStateMac(Key, log.TableName, log.PreviousHash, log.SequenceNumber, log.KeyId);
            Assert.NotEqual(recordHash, mac);
        }

        [Fact]
        public void MaskToken_IsDeterministic_AndDependsOnTheKeyAndTheContext()
        {
            var token = AuditHasher.ComputeMaskToken(Key, "Customers", "CardNumber", "4111");

            Assert.Matches("^\\[MASKED:[0-9a-f]{8}\\]$", token);
            Assert.Equal(token, AuditHasher.ComputeMaskToken(Key, "Customers", "CardNumber", "4111"));
            Assert.NotEqual(token, AuditHasher.ComputeMaskToken(Key, "Customers", "CardNumber", "4112"));
            Assert.NotEqual(token, AuditHasher.ComputeMaskToken(Key, "Customers", "Iban", "4111"));
            Assert.NotEqual(token, AuditHasher.ComputeMaskToken(new AuditKey(null, System.Text.Encoding.UTF8.GetBytes("another-key-0123456789")), "Customers", "CardNumber", "4111"));
        }

        [Fact]
        public void HexEquals_ComparesWithoutThrowingOnNullOrDifferentLength()
        {
            Assert.True(AuditHasher.HexEquals("abc", "abc"));
            Assert.False(AuditHasher.HexEquals("abc", "abd"));
            Assert.False(AuditHasher.HexEquals("abc", "abcd"));
            Assert.False(AuditHasher.HexEquals(null, "abc"));
            Assert.False(AuditHasher.HexEquals("abc", null));
        }
    }
}
