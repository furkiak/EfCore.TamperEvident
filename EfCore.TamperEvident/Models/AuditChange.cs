using System.Text.Json;
using System.Text.Json.Serialization;

namespace EfCore.TamperEvident.Models
{
    /// <summary>
    /// One entry of the history of a row, ready to display: who changed what, when and why, property by property.
    /// </summary>
    public sealed class AuditChange
    {
        /// <summary>The audit entry.</summary>
        public required Guid EntryId { get; init; }

        /// <summary>The position of the entry in the chain of its table.</summary>
        public required long SequenceNumber { get; init; }

        /// <summary>The audited table.</summary>
        public required string TableName { get; init; }

        /// <summary>The primary key of the row.</summary>
        public required string RecordId { get; init; }

        /// <summary>One of the <see cref="AuditActions"/> values.</summary>
        public required string Action { get; init; }

        /// <summary>The user the change is attributed to.</summary>
        public required string UserId { get; init; }

        /// <summary>When the change was made (UTC).</summary>
        public required DateTime TimestampUtc { get; init; }

        /// <summary>The reason given through <see cref="AuditScope"/>, if any.</summary>
        public string? Reason { get; init; }

        /// <summary>The metadata of the change (reason, trace id, custom entries).</summary>
        public IReadOnlyDictionary<string, AuditValue> Metadata { get; init; } = new Dictionary<string, AuditValue>();

        /// <summary>
        /// The properties that changed, in alphabetical order. An insert lists every value as new, a delete every value as
        /// old; an update only the properties that changed.
        /// </summary>
        public IReadOnlyList<AuditPropertyChange> Changes { get; init; } = Array.Empty<AuditPropertyChange>();
    }

    /// <summary>The old and the new value of one property.</summary>
    /// <param name="Property">The property name.</param>
    /// <param name="OldValue">The value before the change (<see cref="AuditValue.Missing"/> for inserts).</param>
    /// <param name="NewValue">The value after the change (<see cref="AuditValue.Missing"/> for deletes).</param>
    public sealed record AuditPropertyChange(string Property, AuditValue OldValue, AuditValue NewValue);

    /// <summary>
    /// A value from the audit trail as it was stored: JSON, possibly masked or redacted.
    /// </summary>
    public readonly struct AuditValue : IEquatable<AuditValue>
    {
        private AuditValue(JsonElement? json, AuditValueKind kind)
        {
            Json = json;
            Kind = kind;
        }

        /// <summary>No value (the property did not exist before an insert or after a delete).</summary>
        public static AuditValue Missing => default;

        /// <summary>What kind of value this is.</summary>
        public AuditValueKind Kind { get; }

        /// <summary>The stored JSON (for redacted values the redaction marker), or <c>null</c> when <see cref="IsMissing"/>.</summary>
        public JsonElement? Json { get; }

        /// <summary><c>true</c> when there is no value.</summary>
        public bool IsMissing => Kind == AuditValueKind.Missing;

        /// <summary><c>true</c> when the value was redacted.</summary>
        public bool IsRedacted => Kind == AuditValueKind.Redacted;

        /// <summary><c>true</c> when the value was masked when it was recorded (<see cref="AuditMaskAttribute"/>).</summary>
        public bool IsMasked => Kind == AuditValueKind.Masked;

        /// <summary>Creates a value from stored JSON.</summary>
        /// <param name="json">The JSON value.</param>
        public static AuditValue From(JsonElement json)
        {
            var copy = json.Clone();
            if (copy.ValueKind == JsonValueKind.Object
                && copy.TryGetProperty("$redacted", out var marker)
                && marker.ValueKind == JsonValueKind.String
                && copy.EnumerateObject().Count() == 1)
            {
                return new AuditValue(copy, AuditValueKind.Redacted);
            }

            if (copy.ValueKind == JsonValueKind.String && copy.GetString() is { } text
                && (text.StartsWith("[MASKED:", StringComparison.Ordinal) || text.StartsWith("[REDACTED:", StringComparison.Ordinal)))
            {
                return new AuditValue(copy, text[1] == 'M' ? AuditValueKind.Masked : AuditValueKind.Redacted);
            }

            return new AuditValue(copy, copy.ValueKind == JsonValueKind.Null ? AuditValueKind.Null : AuditValueKind.Value);
        }

        /// <summary>Reads the value as <typeparamref name="T"/>; <c>default</c> for missing, null, masked and redacted values.</summary>
        /// <typeparam name="T">The target type.</typeparam>
        /// <param name="options">Serializer options (enums are read as names by default).</param>
        public T? As<T>(JsonSerializerOptions? options = null) =>
            Kind == AuditValueKind.Value && Json is { } json ? json.Deserialize<T>(options ?? DefaultOptions) : default;

        /// <summary>A short display form: the raw value, <c>null</c>, <c>[masked]</c> or <c>[redacted]</c>.</summary>
        public override string ToString() => Kind switch
        {
            AuditValueKind.Missing => string.Empty,
            AuditValueKind.Null => "null",
            AuditValueKind.Masked => "[masked]",
            AuditValueKind.Redacted => "[redacted]",
            _ => Json!.Value.ValueKind == JsonValueKind.String ? Json.Value.GetString()! : Json.Value.GetRawText()
        };

        /// <inheritdoc />
        public bool Equals(AuditValue other) =>
            Kind == other.Kind && (Json?.GetRawText() ?? string.Empty) == (other.Json?.GetRawText() ?? string.Empty);

        /// <inheritdoc />
        public override bool Equals(object? obj) => obj is AuditValue other && Equals(other);

        /// <inheritdoc />
        public override int GetHashCode() => HashCode.Combine(Kind, Json?.GetRawText());

        /// <summary>Compares two values.</summary>
        public static bool operator ==(AuditValue left, AuditValue right) => left.Equals(right);

        /// <summary>Compares two values.</summary>
        public static bool operator !=(AuditValue left, AuditValue right) => !left.Equals(right);

        internal static readonly JsonSerializerOptions DefaultOptions = new() { Converters = { new JsonStringEnumConverter() } };
    }

    /// <summary>What an <see cref="AuditValue"/> holds.</summary>
    public enum AuditValueKind
    {
        /// <summary>No value.</summary>
        Missing = 0,

        /// <summary>A JSON <c>null</c>.</summary>
        Null = 1,

        /// <summary>A recorded value.</summary>
        Value = 2,

        /// <summary>A keyed fingerprint recorded instead of the value (<see cref="AuditMaskAttribute"/>).</summary>
        Masked = 3,

        /// <summary>The value was redacted later.</summary>
        Redacted = 4
    }

    /// <summary>
    /// The values of a row at a point in time, rebuilt from its audit history.
    /// </summary>
    public sealed class AuditSnapshot
    {
        /// <summary>The point in time (UTC).</summary>
        public required DateTime AsOfUtc { get; init; }

        /// <summary><c>false</c> when the row did not exist yet, or was deleted, at that time.</summary>
        public required bool Exists { get; init; }

        /// <summary>The newest audit entry at that time, or <c>null</c> when there was none.</summary>
        public Guid? EntryId { get; init; }

        /// <summary>The values of the row, by property name.</summary>
        public IReadOnlyDictionary<string, AuditValue> Values { get; init; } = new Dictionary<string, AuditValue>();

        /// <summary>
        /// Materializes the values as <typeparamref name="T"/> (best effort: masked and redacted values are left at their
        /// default, and properties that no longer exist are ignored). Returns <c>null</c> when the row did not exist.
        /// </summary>
        /// <typeparam name="T">The entity type.</typeparam>
        /// <param name="options">Serializer options (enums are read as names by default).</param>
        public T? ToObject<T>(JsonSerializerOptions? options = null)
            where T : class
        {
            if (!Exists)
            {
                return null;
            }

            var json = new System.Text.Json.Nodes.JsonObject();
            foreach (var (name, value) in Values)
            {
                if (value.Kind == AuditValueKind.Value || value.Kind == AuditValueKind.Null)
                {
                    json[name] = System.Text.Json.Nodes.JsonNode.Parse(value.Json!.Value.GetRawText());
                }
            }

            return json.Deserialize<T>(options ?? AuditValue.DefaultOptions);
        }
    }
}
