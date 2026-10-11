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

        /// <summary>Serializes a flat set of values (the audited properties of an entity).</summary>
        public static string Serialize(IEnumerable<KeyValuePair<string, object?>> values)
        {
            using var stream = new MemoryStream();
            using (var writer = new Utf8JsonWriter(stream, WriterOptions))
            {
                writer.WriteStartObject();
                foreach (var pair in values.OrderBy(p => p.Key, StringComparer.Ordinal))
                {
                    writer.WritePropertyName(pair.Key);
                    WriteValue(writer, pair.Value);
                }

                writer.WriteEndObject();
            }

            return System.Text.Encoding.UTF8.GetString(stream.GetBuffer(), 0, (int)stream.Length);
        }

        /// <summary>Serializes any object; the result is identical for equal data on every machine.</summary>
        public static string? SerializeObject(object? value)
        {
            if (value is null)
            {
                return null;
            }

            using var stream = new MemoryStream();
            using (var writer = new Utf8JsonWriter(stream, WriterOptions))
            {
                WriteSorted(writer, JsonSerializer.SerializeToElement(value, value.GetType(), ValueOptions));
            }

            return System.Text.Encoding.UTF8.GetString(stream.GetBuffer(), 0, (int)stream.Length);
        }

        private static void WriteValue(Utf8JsonWriter writer, object? value)
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
