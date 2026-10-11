using System.Buffers;
using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using EfCore.TamperEvident.Models;

namespace EfCore.TamperEvident.Internal
{
    /// <summary>
    /// Computes the HMAC-SHA256 values that seal audit entries and chain heads.
    /// </summary>
    internal static class AuditHasher
    {
        private static ReadOnlySpan<byte> RecordMagic => "EFTE"u8;

        private static ReadOnlySpan<byte> StateMagic => "EFTS"u8;

        public static string ComputeRecordHash(byte[] key, AuditLog log)
        {
            return log.HashVersion switch
            {
                AuditHashVersion.Legacy => ComputeLegacy(key, log),
                AuditHashVersion.Canonical => ComputeCanonical(key, log),
                _ => throw new NotSupportedException($"Unknown audit hash version {log.HashVersion}.")
            };
        }

        /// <summary>The 1.x format: plain concatenation without separators and without the user.</summary>
        private static string ComputeLegacy(byte[] key, AuditLog log)
        {
            var raw = $"{log.PreviousHash}{log.TableName}{log.RecordId}{log.ActionType}{log.OldValues}{log.NewValues}{log.TimestampTicks}";
            return ToHex(HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(raw)));
        }

        /// <summary>Length-prefixed encoding of every field, so no field boundary can be shifted.</summary>
        private static string ComputeCanonical(byte[] key, AuditLog log)
        {
            var buffer = new ArrayBufferWriter<byte>(512);
            Write(buffer, RecordMagic);
            WriteByte(buffer, (byte)AuditHashVersion.Canonical);
            WriteString(buffer, log.PreviousHash);
            WriteString(buffer, log.TableName);
            WriteString(buffer, log.RecordId);
            WriteString(buffer, log.ActionType);
            WriteString(buffer, log.OldValues);
            WriteString(buffer, log.NewValues);
            WriteString(buffer, log.UserId);
            WriteString(buffer, log.KeyId);
            WriteInt64(buffer, log.SequenceNumber);
            WriteInt64(buffer, log.TimestampTicks);
            return ToHex(HMACSHA256.HashData(key, buffer.WrittenSpan));
        }

        /// <summary>Authenticates the head of a chain, which makes removing the newest entries detectable.</summary>
        public static string ComputeStateMac(byte[] key, string tableName, string lastHash, long lastSequence, string? keyId)
        {
            var buffer = new ArrayBufferWriter<byte>(256);
            Write(buffer, StateMagic);
            WriteByte(buffer, 1);
            WriteString(buffer, tableName);
            WriteString(buffer, lastHash);
            WriteString(buffer, keyId);
            WriteInt64(buffer, lastSequence);
            return ToHex(HMACSHA256.HashData(key, buffer.WrittenSpan));
        }

        /// <summary>A short keyed fingerprint that replaces a masked value.</summary>
        public static string ComputeMaskToken(byte[] key, string tableName, string propertyName, object value)
        {
            var text = value switch
            {
                byte[] bytes => Convert.ToBase64String(bytes),
                IFormattable formattable => formattable.ToString(null, CultureInfo.InvariantCulture),
                _ => value.ToString() ?? string.Empty
            };

            var buffer = new ArrayBufferWriter<byte>(128);
            WriteString(buffer, tableName);
            WriteString(buffer, propertyName);
            WriteString(buffer, text);
            return "[MASKED:" + ToHex(HMACSHA256.HashData(key, buffer.WrittenSpan))[..8] + "]";
        }

        /// <summary>Compares two hex strings without leaking where they differ.</summary>
        public static bool HexEquals(string? left, string? right)
        {
            if (left is null || right is null)
            {
                return false;
            }

            return CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(left), Encoding.ASCII.GetBytes(right));
        }

        private static string ToHex(byte[] bytes) => Convert.ToHexString(bytes).ToLowerInvariant();

        private static void Write(ArrayBufferWriter<byte> buffer, ReadOnlySpan<byte> data)
        {
            data.CopyTo(buffer.GetSpan(data.Length));
            buffer.Advance(data.Length);
        }

        private static void WriteByte(ArrayBufferWriter<byte> buffer, byte value)
        {
            buffer.GetSpan(1)[0] = value;
            buffer.Advance(1);
        }

        private static void WriteInt64(ArrayBufferWriter<byte> buffer, long value)
        {
            BinaryPrimitives.WriteInt64BigEndian(buffer.GetSpan(8), value);
            buffer.Advance(8);
        }

        // A null string is encoded as length -1 so that it differs from an empty string.
        private static void WriteString(ArrayBufferWriter<byte> buffer, string? value)
        {
            if (value is null)
            {
                BinaryPrimitives.WriteInt32BigEndian(buffer.GetSpan(4), -1);
                buffer.Advance(4);
                return;
            }

            var byteCount = Encoding.UTF8.GetByteCount(value);
            BinaryPrimitives.WriteInt32BigEndian(buffer.GetSpan(4), byteCount);
            buffer.Advance(4);

            var span = buffer.GetSpan(byteCount);
            Encoding.UTF8.GetBytes(value, span);
            buffer.Advance(byteCount);
        }
    }
}
