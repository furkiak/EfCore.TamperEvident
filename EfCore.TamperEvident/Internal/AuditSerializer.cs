using System.Buffers;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace EfCore.TamperEvident.Internal
{
    /// <summary>
    /// Writes JSON whose bytes depend only on the data: property names are sorted with an ordinal
    /// comparison (never culture dependent), nested objects are sorted as well, and no whitespace is emitted.
    /// </summary>
    internal static class AuditSerializer
    {
        private static readonly JsonWriterOptions WriterOptions = new()
        {
            // Keeps non-ASCII text such as "Çiğdem" readable in the database instead of Çiğdem.
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
            Indented = false
        };

        private static readonly JsonSerializerOptions ValueOptions = new()
        {
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
            NumberHandling = JsonNumberHandling.AllowNamedFloatingPointLiterals,
            Converters = { new JsonStringEnumConverter() }
        };

        [ThreadStatic]
        private static ArrayBufferWriter<byte>? _buffer;

        [ThreadStatic]
        private static Utf8JsonWriter? _writer;

        [ThreadStatic]
        private static bool _inUse;

        /// <summary>Serializes a flat set of values (the audited properties of an entity).</summary>
        public static string Serialize(IEnumerable<KeyValuePair<string, object?>> values)
        {
            var writer = Rent(out var buffer);
            try
            {
                writer.WriteStartObject();
                foreach (var pair in values.OrderBy(p => p.Key, StringComparer.Ordinal))
                {
                    writer.WritePropertyName(pair.Key);
                    WriteValue(writer, pair.Value);
                }

                writer.WriteEndObject();
                return Complete(writer, buffer);
            }
            finally
            {
                Return(buffer);
            }
        }

        /// <summary>Serializes any object; the result is identical for equal data on every machine.</summary>
        public static string? SerializeObject(object? value)
        {
            if (value is null)
            {
                return null;
            }

            var writer = Rent(out var buffer);
            try
            {
                WriteSorted(writer, JsonSerializer.SerializeToElement(value, value.GetType(), ValueOptions));
                return Complete(writer, buffer);
            }
            finally
            {
                Return(buffer);
            }
        }

        /// <summary>
        /// A writer for one JSON object whose properties the caller writes in ordinal order. Hand the buffer back with
        /// <see cref="Complete"/> and <see cref="Return"/>. The writer and its buffer are reused by the calling thread.
        /// </summary>
        public static Utf8JsonWriter Rent(out ArrayBufferWriter<byte> buffer)
        {
            if (_inUse)
            {
                // Re-entered, for example by a custom converter: use a private writer.
                buffer = new ArrayBufferWriter<byte>(256);
                return new Utf8JsonWriter(buffer, WriterOptions);
            }

            _inUse = true;
            buffer = _buffer ??= new ArrayBufferWriter<byte>(1024);
            buffer.ResetWrittenCount();
            if (_writer is null)
            {
                _writer = new Utf8JsonWriter(buffer, WriterOptions);
            }
            else
            {
                _writer.Reset(buffer);
            }

            return _writer;
        }

        public static string Complete(Utf8JsonWriter writer, ArrayBufferWriter<byte> buffer)
        {
            writer.Flush();
            return System.Text.Encoding.UTF8.GetString(buffer.WrittenSpan);
        }

        public static void Return(ArrayBufferWriter<byte> buffer)
        {
            if (!ReferenceEquals(buffer, _buffer))
            {
                return;
            }

            // Do not keep a huge buffer alive after an unusually large entity.
            if (buffer.Capacity > 1024 * 1024)
            {
                _buffer = null;
                _writer = null;
            }

            _inUse = false;
        }

        /// <summary>Writes a value the same way <see cref="Serialize"/> does.</summary>
        public static void WriteValue(Utf8JsonWriter writer, object? value)
        {
            switch (value)
            {
                case null:
                    writer.WriteNullValue();
                    break;
                case string text:
                    writer.WriteStringValue(text);
                    break;
                case bool flag:
                    writer.WriteBooleanValue(flag);
                    break;
                case int number:
                    writer.WriteNumberValue(number);
                    break;
                case long number:
                    writer.WriteNumberValue(number);
                    break;
                case short number:
                    writer.WriteNumberValue(number);
                    break;
                case byte number:
                    writer.WriteNumberValue(number);
                    break;
                case decimal number:
                    writer.WriteNumberValue(number);
                    break;
                case Guid guid:
                    writer.WriteStringValue(guid);
                    break;
                case DateTime dateTime:
                    writer.WriteStringValue(dateTime);
                    break;
                case DateTimeOffset dateTimeOffset:
                    writer.WriteStringValue(dateTimeOffset);
                    break;
                case byte[] bytes:
                    writer.WriteBase64StringValue(bytes);
                    break;
                case Enum enumValue:
                    writer.WriteStringValue(enumValue.ToString());
                    break;
                default:
                    WriteSorted(writer, JsonSerializer.SerializeToElement(value, value.GetType(), ValueOptions));
                    break;
            }
        }

        private static void WriteSorted(Utf8JsonWriter writer, JsonElement element)
        {
            switch (element.ValueKind)
            {
                case JsonValueKind.Object:
                    writer.WriteStartObject();
                    foreach (var property in element.EnumerateObject().OrderBy(p => p.Name, StringComparer.Ordinal))
                    {
                        writer.WritePropertyName(property.Name);
                        WriteSorted(writer, property.Value);
                    }

                    writer.WriteEndObject();
                    break;
                case JsonValueKind.Array:
                    writer.WriteStartArray();
                    foreach (var item in element.EnumerateArray())
                    {
                        WriteSorted(writer, item);
                    }

                    writer.WriteEndArray();
                    break;
                default:
                    element.WriteTo(writer);
                    break;
            }
        }
    }
}
