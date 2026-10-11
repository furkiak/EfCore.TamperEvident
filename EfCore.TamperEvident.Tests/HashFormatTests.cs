using EfCore.TamperEvident.Internal;
using EfCore.TamperEvident.Models;

namespace EfCore.TamperEvident.Tests
{
    /// <summary>The redactable (version 3) hash format.</summary>
    public class HashFormatTests
    {
        private static readonly AuditKey Key = new(null, System.Text.Encoding.UTF8.GetBytes("hash-format-test-key-0123456789abcdef"));

        private static AuditLog Log() => new()
        {
            Id = new Guid("6f9619ff-8b86-d011-b42d-00c04fc964ff"),
            TableName = "Customers",
            RecordId = "42",
            ActionType = AuditActions.Modified,
            OldValues = "{\"Email\":\"old@example.com\",\"Name\":\"Ayşe\"}",
            NewValues = "{\"Email\":\"new@example.com\",\"Name\":\"Ayşe\"}",
            Metadata = "{\"ip\":\"203.0.113.7\",\"reason\":\"ticket\"}",
            UserId = "alice",
            KeyId = "k1",
            TimestampTicks = 638000000000000000,
            SequenceNumber = 7,
            HashVersion = AuditHashVersion.Redactable,
            PreviousHash = new string('a', 64),
            CurrentHash = string.Empty
        };

        private static AuditLog Sealed()
        {
            var log = Log();
            log.CurrentHash = AuditHasher.ComputeRecordHash(Key, log);
            return log;
        }

        [Fact]
        public void TheHash_IsStable_AndVerifies()
        {
            var log = Sealed();
            Assert.Equal(log.CurrentHash, AuditHasher.ComputeRecordHash(Key, Log()));
            Assert.Matches("^[0-9a-f]{64}$", log.CurrentHash);
            Assert.True(AuditHasher.Verify(Key, log));
        }

        [Theory]
        [InlineData("Id")]
        [InlineData("TableName")]
        [InlineData("RecordId")]
        [InlineData("ActionType")]
        [InlineData("OldValues")]
        [InlineData("NewValues")]
        [InlineData("Metadata")]
        [InlineData("UserId")]
        [InlineData("KeyId")]
        [InlineData("TimestampTicks")]
        [InlineData("SequenceNumber")]
        [InlineData("PreviousHash")]
        [InlineData("PropertyOrder")]
        [InlineData("ValueMovedToAnotherProperty")]
        public void EveryFieldIsCovered(string field)
        {
            var log = Sealed();
            switch (field)
            {
                case "Id": log.Id = Guid.NewGuid(); break;
                case "TableName": log.TableName = "Orders"; break;
                case "RecordId": log.RecordId = "43"; break;
                case "ActionType": log.ActionType = AuditActions.Deleted; break;
                case "OldValues": log.OldValues = log.OldValues!.Replace("old@", "odd@"); break;
                case "NewValues": log.NewValues = log.NewValues!.Replace("new@", "neu@"); break;
                case "Metadata": log.Metadata = null; break;
                case "UserId": log.UserId = "bob"; break;
                case "KeyId": log.KeyId = "k2"; break;
                case "TimestampTicks": log.TimestampTicks++; break;
                case "SequenceNumber": log.SequenceNumber++; break;
                case "PreviousHash": log.PreviousHash = new string('b', 64); break;
                case "PropertyOrder": log.NewValues = "{\"Name\":\"Ayşe\",\"Email\":\"new@example.com\"}"; break;
                case "ValueMovedToAnotherProperty": log.NewValues = "{\"Email\":\"Ayşe\",\"Name\":\"new@example.com\"}"; break;
            }

            Assert.False(AuditHasher.Verify(Key, log));
        }

        [Theory]
        [InlineData("not json")]
        [InlineData("[1,2]")]
        [InlineData("{\"a\":1} {\"b\":2}")]
        [InlineData("{\"a\":1,}")]
        public void PayloadsThatAreNotASingleObject_DoNotVerify(string payload)
        {
            var log = Sealed();
            log.NewValues = payload;
            Assert.False(AuditHasher.Verify(Key, log));
        }

        [Fact]
        public void NestedValues_AreCoveredByteForByte()
        {
            var log = Log();
            log.NewValues = "{\"Address\":{\"City\":\"İzmir\",\"Zip\":\"35000\"},\"Tags\":[\"a\",\"b\"]}";
            log.CurrentHash = AuditHasher.ComputeRecordHash(Key, log);
            Assert.True(AuditHasher.Verify(Key, log));

            log.NewValues = "{\"Address\":{\"City\":\"Izmir\",\"Zip\":\"35000\"},\"Tags\":[\"a\",\"b\"]}";
            Assert.False(AuditHasher.Verify(Key, log));
        }

        [Fact]
        public void EscapedPropertyNames_AreHandled()
        {
            var log = Log();
            log.NewValues = "{\"Na\\u006de\":\"x\"}";
            log.CurrentHash = AuditHasher.ComputeRecordHash(Key, log);
            Assert.True(AuditHasher.Verify(Key, log));
        }

        [Fact]
        public void RedactingAValue_KeepsTheHash_AndIsReported()
        {
            var log = Sealed();
            var fields = new List<string>();
            log.NewValues = AuditHasher.RedactPayload(Key, log.Id, AuditHasher.NewValuesKind, log.NewValues, n => n == "Email", fields);
            log.UserId = AuditHasher.RedactText(Key, log.Id, AuditHasher.UserIdField, log.UserId);

            Assert.Equal(new[] { "n:Email" }, fields);
            Assert.Matches("^\\{\"Email\":\\{\"\\$redacted\":\"[0-9a-f]{64}\"\\},\"Name\":\"Ayşe\"\\}$", log.NewValues);
            Assert.Matches("^\\[REDACTED:[0-9a-f]{64}\\]$", log.UserId);

            var reported = new List<string>();
            Assert.True(AuditHasher.Verify(Key, log, reported));
            Assert.Equal(new[] { "u", "n:Email" }, reported);
        }

        [Fact]
        public void TheSameValue_HasDifferentDigests_InDifferentEntriesAndFields()
        {
            var other = Guid.NewGuid();
            var a = AuditHasher.RedactText(Key, Log().Id, AuditHasher.UserIdField, "alice");
            var b = AuditHasher.RedactText(Key, other, AuditHasher.UserIdField, "alice");
            var c = AuditHasher.RedactText(Key, Log().Id, AuditHasher.RecordIdField, "alice");
            Assert.NotEqual(a, b);
            Assert.NotEqual(a, c);
        }

        [Fact]
        public void AMarkerWithAWrongDigest_DoesNotVerify()
        {
            var log = Sealed();
            log.UserId = "[REDACTED:" + new string('0', 64) + "]";
            Assert.False(AuditHasher.Verify(Key, log));
        }

        [Fact]
        public void Markers_AreRecognizedExactly()
        {
            Assert.True(AuditHasher.IsTextMarker("[REDACTED:" + new string('a', 64) + "]"));
            Assert.False(AuditHasher.IsTextMarker("[REDACTED:" + new string('A', 64) + "]"));
            Assert.False(AuditHasher.IsTextMarker("[REDACTED:" + new string('a', 63) + "]"));
            Assert.False(AuditHasher.IsTextMarker(null));

            Assert.True(AuditHasher.IsJsonMarker(System.Text.Encoding.UTF8.GetBytes("{\"$redacted\":\"" + new string('1', 64) + "\"}")));
            Assert.False(AuditHasher.IsJsonMarker(System.Text.Encoding.UTF8.GetBytes("{\"$redacted\":\"" + new string('g', 64) + "\"}")));
            Assert.False(AuditHasher.IsJsonMarker(System.Text.Encoding.UTF8.GetBytes("{\"$redacted\": \"" + new string('1', 64) + "\"}")));
        }

        [Fact]
        public void NewEntriesWithAJsonMarker_AreRefused()
        {
            var log = Log();
            log.NewValues = "{\"Email\":{\"$redacted\":\"" + new string('1', 64) + "\"}}";
            Assert.Throws<AuditTrailException>(() => AuditHasher.ComputeRecordHash(Key, log));
        }

        [Fact]
        public void LargePayloads_AreHashed()
        {
            var log = Log();
            log.NewValues = "{\"Blob\":\"" + new string('x', 200_000) + "\",\"Name\":\"" + new string('ğ', 5_000) + "\"}";
            log.CurrentHash = AuditHasher.ComputeRecordHash(Key, log);
            Assert.True(AuditHasher.Verify(Key, log));
        }

        [Fact]
        public void TheStateMac_VerifiesInConstantTime()
        {
            var state = new AuditChainState { TableName = "Customers", LastHash = new string('c', 64), LastSequence = 3, KeyId = "k1" };
            state.Mac = AuditHasher.ComputeStateMac(Key, state.TableName, state.LastHash, state.LastSequence, state.KeyId);
            Assert.True(AuditHasher.VerifyStateMac(Key, state));

            state.LastSequence = 4;
            Assert.False(AuditHasher.VerifyStateMac(Key, state));
            state.Mac = "not hex";
            Assert.False(AuditHasher.VerifyStateMac(Key, state));
        }

        [Fact]
        public void Hex_RoundTrips()
        {
            var bytes = Enumerable.Range(0, 32).Select(i => (byte)(i * 7)).ToArray();
            var hex = Hex.ToLower(bytes);
            Assert.Equal(Convert.ToHexString(bytes).ToLowerInvariant(), hex);

            var decoded = new byte[32];
            Assert.True(Hex.TryDecode(hex.ToUpperInvariant().AsSpan(), decoded));
            Assert.Equal(bytes, decoded);
            Assert.False(Hex.TryDecode("zz".AsSpan(), new byte[1]));
            Assert.False(Hex.TryDecode("abc".AsSpan(), new byte[1]));
        }
    }
}
