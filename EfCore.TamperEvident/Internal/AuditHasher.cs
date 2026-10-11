using System.Buffers;
using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using EfCore.TamperEvident.Models;

namespace EfCore.TamperEvident.Internal
{
    /// <summary>
    /// Computes the HMAC-SHA256 values that seal audit entries and chain heads.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A <see cref="AuditHashVersion.Redactable"/> entry is hashed over a canonical, length-prefixed encoding in which
    /// the record id, the user and every single value (old values, new values and metadata) is represented by its own
    /// keyed digest: <c>HMAC(fieldKey, entryId ‖ field ‖ value)</c>. Redacting a value replaces it with that digest,
    /// so the entry hash stays the same and the chain stays intact. The digest is keyed and salted with the entry id:
    /// without the secret it cannot be brute forced back to a short value (a phone number, a name), and the same value
    /// in two entries does not produce the same digest.
    /// </para>
    /// <para>All methods are thread-safe and allocate little more than the resulting hex string.</para>
    /// </remarks>
    internal static class AuditHasher
    {
        public const int HashSize = 32;

        /// <summary>The field name of <see cref="AuditLog.RecordId"/> in redaction lists.</summary>
        public const string RecordIdField = "r";

        /// <summary>The field name of <see cref="AuditLog.UserId"/> in redaction lists.</summary>
        public const string UserIdField = "u";

        public const char OldValuesKind = 'o';
        public const char NewValuesKind = 'n';
        public const char MetadataKind = 'm';

        private const string TextMarkerPrefix = "[REDACTED:";
        private const int TextMarkerLength = 10 + HashSize * 2 + 1;
        private const int JsonMarkerLength = 14 + HashSize * 2 + 2;
        private const int StackLimit = 512;

        private static readonly SearchValues<char> LowerHexDigits = SearchValues.Create("0123456789abcdef");

        private static readonly JsonReaderOptions ReaderOptions = new() { CommentHandling = JsonCommentHandling.Disallow, MaxDepth = 128 };

        private static ReadOnlySpan<byte> RecordMagic => "EFTE"u8;

        private static ReadOnlySpan<byte> StateMagic => "EFTS"u8;

        private static ReadOnlySpan<byte> JsonMarkerPrefix => "{\"$redacted\":\""u8;

        private static ReadOnlySpan<byte> JsonMarkerSuffix => "\"}"u8;

        [ThreadStatic]
        private static ArrayBufferWriter<byte>? _canonical;

        #region Record hashes

        /// <summary>Seals a new entry. Values that look like a redaction marker are refused.</summary>
        /// <exception cref="AuditTrailException">A value collides with the redaction marker.</exception>
        public static string ComputeRecordHash(AuditKey key, AuditLog log)
        {
            Span<byte> hash = stackalloc byte[HashSize];
            switch (Compute(key, log, hash, allowRedacted: false, redacted: null))
            {
                case Outcome.Ok:
                    return Hex.ToLower(hash);
                case Outcome.UnknownVersion:
                    throw new NotSupportedException($"Unknown audit hash version {log.HashVersion}.");
                case Outcome.RedactionMarker:
                    throw new AuditTrailException(
                        $"A value of the audit entry for table '{log.TableName}' looks like a redaction marker " +
                        $"({TextMarkerPrefix}...] or {{\"$redacted\":\"...\"}}), which is reserved for redacted values.");
                default:
                    throw new InvalidOperationException($"The audit entry for table '{log.TableName}' holds values that are not a JSON object.");
            }
        }

        /// <summary>
        /// Recomputes the hash of a stored entry and compares it, in constant time, with <see cref="AuditLog.CurrentHash"/>.
        /// </summary>
        /// <param name="key">The key the entry was sealed with.</param>
        /// <param name="log">The entry.</param>
        /// <param name="redacted">Receives the fields of the entry that are redacted (see <see cref="FieldName"/>), if any.</param>
        public static bool Verify(AuditKey key, AuditLog log, List<string>? redacted = null)
        {
            Span<byte> stored = stackalloc byte[HashSize];
            if (log.CurrentHash is null || !Hex.TryDecode(log.CurrentHash.AsSpan(), stored))
            {
                return false;
            }

            Span<byte> computed = stackalloc byte[HashSize];
            var mark = redacted?.Count ?? 0;
            if (Compute(key, log, computed, allowRedacted: true, redacted) != Outcome.Ok
                || !CryptographicOperations.FixedTimeEquals(computed, stored))
            {
                redacted?.RemoveRange(mark, redacted.Count - mark);
                return false;
            }

            return true;
        }

        private enum Outcome
        {
            Ok,
            Malformed,
            RedactionMarker,
            UnknownVersion
        }

        private static Outcome Compute(AuditKey key, AuditLog log, Span<byte> hash, bool allowRedacted, List<string>? redacted)
        {
            switch (log.HashVersion)
            {
                case AuditHashVersion.Legacy:
                    ComputeLegacy(key.Secret, log, hash);
                    return Outcome.Ok;
                case AuditHashVersion.Canonical:
                    return ComputeCanonical(key.Secret, log, hash);
                case AuditHashVersion.Redactable:
                    return ComputeRedactable(key, log, hash, allowRedacted, redacted);
                default:
                    return Outcome.UnknownVersion;
            }
        }

        /// <summary>The 1.x format: plain concatenation without separators and without the user.</summary>
        private static void ComputeLegacy(byte[] key, AuditLog log, Span<byte> hash)
        {
            var raw = $"{log.PreviousHash}{log.TableName}{log.RecordId}{log.ActionType}{log.OldValues}{log.NewValues}{log.TimestampTicks}";
            HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(raw), hash);
        }

        /// <summary>The 2.0 preview format: length-prefixed encoding of every field.</summary>
        private static Outcome ComputeCanonical(byte[] key, AuditLog log, Span<byte> hash)
        {
            var buffer = RentCanonical();
            Write(buffer, RecordMagic);
            WriteByte(buffer, AuditHashVersion.Canonical);
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
            Hmac(key, buffer.WrittenSpan, hash);
            return Outcome.Ok;
        }

        private static Outcome ComputeRedactable(AuditKey key, AuditLog log, Span<byte> hash, bool allowRedacted, List<string>? redacted)
        {
            var buffer = RentCanonical();
            Write(buffer, RecordMagic);
            WriteByte(buffer, AuditHashVersion.Redactable);
            WriteGuid(buffer, log.Id);
            WriteString(buffer, log.PreviousHash);
            WriteString(buffer, log.TableName);

            var outcome = WriteTextField(buffer, key, log.Id, RecordIdField, log.RecordId, allowRedacted, redacted);
            if (outcome != Outcome.Ok)
            {
                return outcome;
            }

            WriteString(buffer, log.ActionType);

            outcome = WriteTextField(buffer, key, log.Id, UserIdField, log.UserId, allowRedacted, redacted);
            if (outcome != Outcome.Ok)
            {
                return outcome;
            }

            WriteString(buffer, log.KeyId);
            WriteInt64(buffer, log.SequenceNumber);
            WriteInt64(buffer, log.TimestampTicks);

            foreach (var (kind, json) in new[] { (OldValuesKind, log.OldValues), (NewValuesKind, log.NewValues), (MetadataKind, log.Metadata) })
            {
                outcome = WritePayload(buffer, key, log.Id, kind, json, allowRedacted, redacted);
                if (outcome != Outcome.Ok)
                {
                    return outcome;
                }
            }

            Hmac(key.Secret, buffer.WrittenSpan, hash);
            return Outcome.Ok;
        }

        private static Outcome WriteTextField(
            ArrayBufferWriter<byte> buffer, AuditKey key, Guid id, string field, string? value, bool allowRedacted, List<string>? redacted)
        {
            Span<byte> digest = stackalloc byte[HashSize];
            if (value is null)
            {
                WriteByte(buffer, 0xFF);
                return Outcome.Ok;
            }

            if (IsTextMarker(value))
            {
                if (!allowRedacted || !Hex.TryDecode(value.AsSpan(TextMarkerPrefix.Length, HashSize * 2), digest))
                {
                    return Outcome.RedactionMarker;
                }

                redacted?.Add(field);
            }
            else
            {
                Span<byte> tag = stackalloc byte[1];
                tag[0] = (byte)field[0];
                ComputeFieldDigest(key, id, tag, value, digest);
            }

            WriteByte(buffer, 0x01);
            Write(buffer, digest);
            return Outcome.Ok;
        }

        // A JSON object is written as: for every property 0x01, the length-prefixed name and the 32 byte digest of its
        // value; then 0x00. A missing payload is 0xFF. The raw value bytes are digested, so the stored JSON has to stay
        // byte for byte identical (only whitespace between top-level tokens is not covered).
        private static Outcome WritePayload(
            ArrayBufferWriter<byte> buffer, AuditKey key, Guid id, char kind, string? json, bool allowRedacted, List<string>? redacted)
        {
            if (json is null)
            {
                WriteByte(buffer, 0xFF);
                return Outcome.Ok;
            }

            byte[]? rented = null;
            var length = Encoding.UTF8.GetMaxByteCount(json.Length);
            Span<byte> utf8 = length <= StackLimit ? stackalloc byte[StackLimit] : (rented = ArrayPool<byte>.Shared.Rent(length));
            utf8 = utf8[..Encoding.UTF8.GetBytes(json, utf8)];

            try
            {
                var outcome = Outcome.Ok;
                var completed = ForEachProperty(utf8, (name, _, value) =>
                {
                    Span<byte> digest = stackalloc byte[HashSize];
                    if (IsJsonMarker(value))
                    {
                        if (!allowRedacted)
                        {
                            outcome = Outcome.RedactionMarker;
                            return false;
                        }

                        Hex.TryDecode(value.Slice(JsonMarkerPrefix.Length, HashSize * 2), digest);
                        redacted?.Add(FieldName(kind, name));
                    }
                    else
                    {
                        Span<byte> tag = name.Length + 2 <= 256 ? stackalloc byte[name.Length + 2] : new byte[name.Length + 2];
                        tag[0] = (byte)kind;
                        tag[1] = (byte)':';
                        name.CopyTo(tag[2..]);
                        ComputeFieldDigest(key, id, tag, value, digest);
                    }

                    WriteByte(buffer, 0x01);
                    WriteBytes(buffer, name);
                    Write(buffer, digest);
                    return true;
                });

                if (!completed)
                {
                    return outcome == Outcome.Ok ? Outcome.Malformed : outcome;
                }

                WriteByte(buffer, 0x00);
                return Outcome.Ok;
            }
            finally
            {
                if (rented is not null)
                {
                    ArrayPool<byte>.Shared.Return(rented);
                }
            }
        }

        #endregion

        #region Field digests and redaction

        /// <param name="name">The unescaped property name.</param>
        /// <param name="rawName">The property name token as stored, quotes and escapes included.</param>
        /// <param name="rawValue">The value as stored.</param>
        internal delegate bool PropertyVisitor(ReadOnlySpan<byte> name, ReadOnlySpan<byte> rawName, ReadOnlySpan<byte> rawValue);

        /// <summary>
        /// Calls <paramref name="visitor"/> for every top-level property of a JSON object with its unescaped name and the
        /// raw bytes of its value. Returns <c>false</c> when the JSON is not a single object or the visitor stopped.
        /// </summary>
        internal static bool ForEachProperty(ReadOnlySpan<byte> utf8Json, PropertyVisitor visitor)
        {
            try
            {
                var reader = new Utf8JsonReader(utf8Json, ReaderOptions);
                if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
                {
                    return false;
                }

                Span<byte> nameBuffer = stackalloc byte[256];
                while (reader.Read())
                {
                    if (reader.TokenType == JsonTokenType.EndObject)
                    {
                        return !reader.Read();
                    }

                    if (reader.TokenType != JsonTokenType.PropertyName)
                    {
                        return false;
                    }

                    var rawName = utf8Json.Slice((int)reader.TokenStartIndex, reader.ValueSpan.Length + 2);
                    scoped ReadOnlySpan<byte> name;
                    if (!reader.ValueIsEscaped)
                    {
                        name = reader.ValueSpan;
                    }
                    else
                    {
                        var target = reader.ValueSpan.Length <= nameBuffer.Length ? nameBuffer : new byte[reader.ValueSpan.Length];
                        name = target[..reader.CopyString(target)];
                    }

                    if (!reader.Read())
                    {
                        return false;
                    }

                    var start = (int)reader.TokenStartIndex;
                    if (reader.TokenType is JsonTokenType.StartObject or JsonTokenType.StartArray)
                    {
                        reader.Skip();
                    }

                    if (!visitor(name, rawName, utf8Json[start..(int)reader.BytesConsumed]))
                    {
                        return false;
                    }
                }

                return false;
            }
            catch (JsonException)
            {
                return false;
            }
        }

        /// <summary>The digest a value is replaced with when it is redacted.</summary>
        internal static void ComputeFieldDigest(AuditKey key, Guid id, ReadOnlySpan<byte> tag, ReadOnlySpan<byte> value, Span<byte> digest)
        {
            var size = 16 + 4 + tag.Length + value.Length;
            byte[]? rented = null;
            Span<byte> input = size <= StackLimit ? stackalloc byte[StackLimit] : (rented = ArrayPool<byte>.Shared.Rent(size));
            try
            {
                id.TryWriteBytes(input);
                BinaryPrimitives.WriteInt32BigEndian(input[16..], tag.Length);
                tag.CopyTo(input[20..]);
                value.CopyTo(input[(20 + tag.Length)..]);
                Hmac(key.FieldKey, input[..size], digest);
            }
            finally
            {
                if (rented is not null)
                {
                    ArrayPool<byte>.Shared.Return(rented);
                }
            }
        }

        private static void ComputeFieldDigest(AuditKey key, Guid id, ReadOnlySpan<byte> tag, string value, Span<byte> digest)
        {
            byte[]? rented = null;
            var length = Encoding.UTF8.GetMaxByteCount(value.Length);
            Span<byte> utf8 = length <= StackLimit ? stackalloc byte[StackLimit] : (rented = ArrayPool<byte>.Shared.Rent(length));
            try
            {
                ComputeFieldDigest(key, id, tag, utf8[..Encoding.UTF8.GetBytes(value, utf8)], digest);
            }
            finally
            {
                if (rented is not null)
                {
                    ArrayPool<byte>.Shared.Return(rented);
                }
            }
        }

        /// <summary>The name of a JSON value in redaction lists: <c>o:Email</c>, <c>n:Email</c> or <c>m:ip</c>.</summary>
        public static string FieldName(char kind, ReadOnlySpan<byte> name) => kind + ":" + Encoding.UTF8.GetString(name);

        /// <summary>The redaction marker of <see cref="AuditLog.RecordId"/> or <see cref="AuditLog.UserId"/>.</summary>
        public static string RedactText(AuditKey key, Guid id, string field, string value)
        {
            if (IsTextMarker(value))
            {
                return value;
            }

            Span<byte> tag = stackalloc byte[1];
            tag[0] = (byte)field[0];
            Span<byte> digest = stackalloc byte[HashSize];
            ComputeFieldDigest(key, id, tag, value, digest);
            return TextMarkerPrefix + Hex.ToLower(digest) + "]";
        }

        /// <summary>
        /// Replaces the selected values of a JSON payload with their digests. The other values keep their exact bytes,
        /// so the entry hash does not change.
        /// </summary>
        /// <param name="key">The key the entry was sealed with.</param>
        /// <param name="id">The entry id.</param>
        /// <param name="kind">Which payload this is.</param>
        /// <param name="json">The payload.</param>
        /// <param name="select">Decides which property names are redacted.</param>
        /// <param name="redacted">Receives the field names that were redacted by this call.</param>
        public static string? RedactPayload(AuditKey key, Guid id, char kind, string? json, Func<string, bool> select, List<string> redacted)
        {
            if (json is null)
            {
                return null;
            }

            var utf8 = Encoding.UTF8.GetBytes(json);
            var output = new ArrayBufferWriter<byte>(utf8.Length + 128);
            var changed = false;
            var first = true;
            Write(output, "{"u8);

            var ok = ForEachProperty(utf8, (name, rawName, value) =>
            {
                if (!first)
                {
                    Write(output, ","u8);
                }

                first = false;
                Write(output, rawName);
                Write(output, ":"u8);

                if (IsJsonMarker(value) || !select(Encoding.UTF8.GetString(name)))
                {
                    Write(output, value);
                    return true;
                }

                Span<byte> tag = new byte[name.Length + 2];
                tag[0] = (byte)kind;
                tag[1] = (byte)':';
                name.CopyTo(tag[2..]);
                Span<byte> digest = stackalloc byte[HashSize];
                ComputeFieldDigest(key, id, tag, value, digest);
                Write(output, JsonMarkerPrefix);
                Write(output, Encoding.ASCII.GetBytes(Hex.ToLower(digest)));
                Write(output, JsonMarkerSuffix);
                redacted.Add(FieldName(kind, name));
                changed = true;
                return true;
            });

            if (!ok)
            {
                throw new InvalidOperationException("The audit payload is not a JSON object.");
            }

            Write(output, "}"u8);
            return changed ? Encoding.UTF8.GetString(output.WrittenSpan) : json;
        }

        /// <summary>Whether a value of a JSON payload is a redaction marker.</summary>
        public static bool IsJsonMarker(ReadOnlySpan<byte> rawValue) =>
            rawValue.Length == JsonMarkerLength
            && rawValue.StartsWith(JsonMarkerPrefix)
            && rawValue.EndsWith(JsonMarkerSuffix)
            && Hex.IsLowerHex(rawValue.Slice(JsonMarkerPrefix.Length, HashSize * 2));

        /// <summary>Whether <see cref="AuditLog.RecordId"/> or <see cref="AuditLog.UserId"/> holds a redaction marker.</summary>
        public static bool IsTextMarker(string? value) =>
            value is { Length: TextMarkerLength }
            && value.StartsWith(TextMarkerPrefix, StringComparison.Ordinal)
            && value[^1] == ']'
            && value.AsSpan(TextMarkerPrefix.Length, HashSize * 2).IndexOfAnyExcept(LowerHexDigits) < 0;

        #endregion

        #region Chain heads and masks

        /// <summary>Authenticates the head of a chain, which makes removing the newest entries detectable.</summary>
        public static string ComputeStateMac(AuditKey key, string tableName, string lastHash, long lastSequence, string? keyId)
        {
            Span<byte> mac = stackalloc byte[HashSize];
            ComputeStateMac(key, tableName, lastHash, lastSequence, keyId, mac);
            return Hex.ToLower(mac);
        }

        public static bool VerifyStateMac(AuditKey key, AuditChainState state)
        {
            Span<byte> stored = stackalloc byte[HashSize];
            if (state.Mac is null || !Hex.TryDecode(state.Mac.AsSpan(), stored))
            {
                return false;
            }

            Span<byte> computed = stackalloc byte[HashSize];
            ComputeStateMac(key, state.TableName, state.LastHash, state.LastSequence, state.KeyId, computed);
            return CryptographicOperations.FixedTimeEquals(computed, stored);
        }

        private static void ComputeStateMac(AuditKey key, string tableName, string lastHash, long lastSequence, string? keyId, Span<byte> mac)
        {
            var buffer = RentCanonical();
            Write(buffer, StateMagic);
            WriteByte(buffer, 1);
            WriteString(buffer, tableName);
            WriteString(buffer, lastHash);
            WriteString(buffer, keyId);
            WriteInt64(buffer, lastSequence);
            Hmac(key.Secret, buffer.WrittenSpan, mac);
        }

        /// <summary>A short keyed fingerprint that replaces a masked value.</summary>
        public static string ComputeMaskToken(AuditKey key, string tableName, string propertyName, object value)
        {
            var text = value switch
            {
                byte[] bytes => Convert.ToBase64String(bytes),
                IFormattable formattable => formattable.ToString(null, CultureInfo.InvariantCulture),
                _ => value.ToString() ?? string.Empty
            };

            var buffer = RentCanonical();
            WriteString(buffer, tableName);
            WriteString(buffer, propertyName);
            WriteString(buffer, text);
            Span<byte> mac = stackalloc byte[HashSize];
            Hmac(key.Secret, buffer.WrittenSpan, mac);
            return "[MASKED:" + Hex.ToLower(mac[..4]) + "]";
        }

        /// <summary>Compares two hex strings without leaking where they differ.</summary>
        public static bool HexEquals(string? left, string? right)
        {
            if (left is null || right is null || left.Length != right.Length)
            {
                return false;
            }

            return CryptographicOperations.FixedTimeEquals(
                System.Runtime.InteropServices.MemoryMarshal.AsBytes(left.AsSpan()),
                System.Runtime.InteropServices.MemoryMarshal.AsBytes(right.AsSpan()));
        }

        #endregion

        #region HMAC

        // Keyed HMAC instances are reused per thread: setting up the key costs as much as hashing a short field, and an
        // audited save hashes a dozen fields per entry. A few slots cover the current and the field key of a key ring.
        [ThreadStatic]
        private static (byte[]? Key, IncrementalHash? Hmac)[]? _hmacs;

        [ThreadStatic]
        private static int _nextSlot;

        private static void Hmac(byte[] key, ReadOnlySpan<byte> data, Span<byte> destination)
        {
            var slots = _hmacs ??= new (byte[]?, IncrementalHash?)[4];
            IncrementalHash? hmac = null;
            foreach (var (slotKey, slotHmac) in slots)
            {
                if (ReferenceEquals(slotKey, key))
                {
                    hmac = slotHmac;
                    break;
                }
            }

            if (hmac is null)
            {
                var slot = _nextSlot;
                _nextSlot = (slot + 1) % slots.Length;
                slots[slot].Hmac?.Dispose();
                hmac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, key);
                slots[slot] = (key, hmac);
            }

            hmac.AppendData(data);
            hmac.TryGetHashAndReset(destination, out _);
        }

        #endregion

        #region Encoding

        // One buffer per thread: every caller fills and consumes it synchronously.
        private static ArrayBufferWriter<byte> RentCanonical()
        {
            var buffer = _canonical;
            if (buffer is null || buffer.Capacity > 256 * 1024)
            {
                _canonical = buffer = new ArrayBufferWriter<byte>(1024);
            }

            buffer.ResetWrittenCount();
            return buffer;
        }

        private static void Write(ArrayBufferWriter<byte> buffer, ReadOnlySpan<byte> data)
        {
            data.CopyTo(buffer.GetSpan(data.Length));
            buffer.Advance(data.Length);
        }

        private static void WriteBytes(ArrayBufferWriter<byte> buffer, ReadOnlySpan<byte> data)
        {
            BinaryPrimitives.WriteInt32BigEndian(buffer.GetSpan(4), data.Length);
            buffer.Advance(4);
            Write(buffer, data);
        }

        private static void WriteByte(ArrayBufferWriter<byte> buffer, int value)
        {
            buffer.GetSpan(1)[0] = (byte)value;
            buffer.Advance(1);
        }

        private static void WriteGuid(ArrayBufferWriter<byte> buffer, Guid value)
        {
            value.TryWriteBytes(buffer.GetSpan(16));
            buffer.Advance(16);
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

        #endregion
    }
}
