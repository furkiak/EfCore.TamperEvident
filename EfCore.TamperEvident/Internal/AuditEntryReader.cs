using System.Collections.Concurrent;
using System.Globalization;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using EfCore.TamperEvident.Configuration;
using EfCore.TamperEvident.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using Microsoft.EntityFrameworkCore.Metadata;

namespace EfCore.TamperEvident.Internal
{
    /// <summary>
    /// Turns tracked entities into the deterministic JSON stored in the audit trail.
    /// Only mapped properties are read, never navigations, so object cycles and lazy loading cannot interfere.
    /// </summary>
    internal sealed class AuditEntryReader
    {
        private const int MaxRecordIdLength = 256;

        private static readonly ConcurrentDictionary<Type, bool> IgnoredTypes = new();
        private static readonly ConcurrentDictionary<MemberInfo, PropertyMode> AttributeModes = new();

        private readonly TamperEvidentOptions _options;
        private readonly AuditKeyRing _keys;
        private readonly HashSet<string> _excludedTables;
        private readonly HashSet<string> _excludedProperties;
        private readonly HashSet<string> _maskedProperties;

        public AuditEntryReader(TamperEvidentOptions options, AuditKeyRing keys)
        {
            _options = options;
            _keys = keys;
            _excludedTables = new HashSet<string>(options.ExcludedTables, StringComparer.OrdinalIgnoreCase);
            _excludedProperties = new HashSet<string>(options.ExcludedProperties, StringComparer.OrdinalIgnoreCase);
            _maskedProperties = new HashSet<string>(options.MaskedProperties, StringComparer.OrdinalIgnoreCase);
        }

        private enum PropertyMode
        {
            Include,
            Ignore,
            Mask
        }

        /// <summary>Whether changes of this entry are audited at all.</summary>
        public bool ShouldAudit(EntityEntry entry, out string tableName)
        {
            tableName = string.Empty;
            var type = entry.Metadata.ClrType;
            if (type == typeof(AuditLog) || type == typeof(AuditChainState))
            {
                return false;
            }

            var table = entry.Metadata.GetTableName();
            if (string.IsNullOrEmpty(table) || _excludedTables.Contains(table))
            {
                return false;
            }

            if (IgnoredTypes.GetOrAdd(type, static t => t.GetCustomAttribute<AuditIgnoreAttribute>(inherit: true) is not null))
            {
                return false;
            }

            var operation = entry.State switch
            {
                EntityState.Added => AuditOperation.Insert,
                EntityState.Modified => AuditOperation.Update,
                EntityState.Deleted => AuditOperation.Delete,
                _ => AuditOperation.None
            };

            if (operation == AuditOperation.None || !_options.TrackedOperations.HasFlag(operation))
            {
                return false;
            }

            tableName = table;
            return true;
        }

        /// <summary>All audited values of an entity (inserts after the database generated its keys, deletes before).</summary>
        public string ReadAll(EntityEntry entry, string tableName, bool original)
        {
            var values = new List<KeyValuePair<string, object?>>();
            foreach (var property in entry.Properties)
            {
                var mode = GetMode(property.Metadata);
                if (mode == PropertyMode.Ignore)
                {
                    continue;
                }

                var value = original ? property.OriginalValue : property.CurrentValue;
                values.Add(new KeyValuePair<string, object?>(property.Metadata.Name, Apply(mode, tableName, property.Metadata.Name, value)));
            }

            return AuditSerializer.Serialize(values);
        }

        /// <summary>
        /// The changed values of an updated entity. The action is <see cref="AuditActions.SoftDelete"/> or
        /// <see cref="AuditActions.Restored"/> when the soft delete property flipped. Returns <c>null</c> when only
        /// properties that are excluded from the audit trail changed.
        /// </summary>
        public (string Action, string OldValues, string NewValues)? ReadModified(EntityEntry entry, string tableName)
        {
            var changed = new List<(PropertyEntry Entry, PropertyMode Mode, bool Differs)>();
            string? softDeleteAction = null;

            foreach (var property in entry.Properties)
            {
                if (!property.IsModified)
                {
                    continue;
                }

                var mode = GetMode(property.Metadata);
                var differs = !ValuesEqual(property, property.OriginalValue, property.CurrentValue);

                if (string.Equals(property.Metadata.Name, _options.SoftDeleteColumnName, StringComparison.OrdinalIgnoreCase))
                {
                    softDeleteAction ??= DetectSoftDelete(property.OriginalValue, property.CurrentValue);
                }

                if (mode != PropertyMode.Ignore)
                {
                    changed.Add((property, mode, differs));
                }
            }

            if (changed.Count == 0)
            {
                return null;
            }

            // Entities that are attached as "modified" (context.Update(entity)) have no meaningful original values:
            // every property is flagged and none differs. Record them all instead of an empty change set.
            var effective = changed.Any(c => c.Differs) ? changed.Where(c => c.Differs) : changed;

            var oldValues = new List<KeyValuePair<string, object?>>();
            var newValues = new List<KeyValuePair<string, object?>>();
            foreach (var (property, mode, _) in effective)
            {
                var name = property.Metadata.Name;
                oldValues.Add(new KeyValuePair<string, object?>(name, Apply(mode, tableName, name, property.OriginalValue)));
                newValues.Add(new KeyValuePair<string, object?>(name, Apply(mode, tableName, name, property.CurrentValue)));
            }

            return (softDeleteAction ?? AuditActions.Modified, AuditSerializer.Serialize(oldValues), AuditSerializer.Serialize(newValues));
        }

        /// <summary>The primary key of the entry as text. Composite keys are joined with <c>|</c>.</summary>
        public static string FormatRecordId(EntityEntry entry, bool original)
        {
            var key = entry.Metadata.FindPrimaryKey();
            if (key is null)
            {
                return "N/A";
            }

            var parts = new List<string>(key.Properties.Count);
            foreach (var keyProperty in key.Properties)
            {
                var property = entry.Property(keyProperty.Name);
                var value = original ? property.OriginalValue : property.CurrentValue;
                parts.Add(value switch
                {
                    null => string.Empty,
                    byte[] bytes => Convert.ToBase64String(bytes),
                    IFormattable formattable => formattable.ToString(null, CultureInfo.InvariantCulture),
                    _ => value.ToString() ?? string.Empty
                });
            }

            var text = string.Join("|", parts);
            if (text.Length <= MaxRecordIdLength)
            {
                return text;
            }

            // Very long keys keep a readable prefix and a fingerprint that preserves uniqueness.
            var digest = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text)))[..32].ToLowerInvariant();
            return text[..(MaxRecordIdLength - 33)] + "#" + digest;
        }

        private object? Apply(PropertyMode mode, string tableName, string propertyName, object? value)
        {
            if (mode != PropertyMode.Mask || value is null)
            {
                return value;
            }

            return AuditHasher.ComputeMaskToken(_keys.CurrentKey, tableName, propertyName, value);
        }

        private PropertyMode GetMode(IProperty property)
        {
            if (_excludedProperties.Contains(property.Name))
            {
                return PropertyMode.Ignore;
            }

            var attributeMode = PropertyMode.Include;
            MemberInfo? member = property.PropertyInfo ?? (MemberInfo?)property.FieldInfo;
            if (member is not null)
            {
                attributeMode = AttributeModes.GetOrAdd(member, static m =>
                    m.GetCustomAttribute<AuditIgnoreAttribute>(inherit: true) is not null ? PropertyMode.Ignore
                    : m.GetCustomAttribute<AuditMaskAttribute>(inherit: true) is not null ? PropertyMode.Mask
                    : PropertyMode.Include);
            }

            if (attributeMode == PropertyMode.Ignore)
            {
                return PropertyMode.Ignore;
            }

            return attributeMode == PropertyMode.Mask || _maskedProperties.Contains(property.Name)
                ? PropertyMode.Mask
                : PropertyMode.Include;
        }

        private static bool ValuesEqual(PropertyEntry property, object? original, object? current)
        {
            var comparer = property.Metadata.GetValueComparer();
            return comparer is not null ? comparer.Equals(original, current) : Equals(original, current);
        }

        private static string? DetectSoftDelete(object? original, object? current)
        {
            if (original is bool wasDeleted && current is bool isDeleted)
            {
                if (!wasDeleted && isDeleted)
                {
                    return AuditActions.SoftDelete;
                }

                return wasDeleted && !isDeleted ? AuditActions.Restored : null;
            }

            // A nullable date such as DeletedAt: null means "not deleted".
            if (IsNullableDate(original) && IsNullableDate(current))
            {
                if (original is null && current is not null)
                {
                    return AuditActions.SoftDelete;
                }

                return original is not null && current is null ? AuditActions.Restored : null;
            }

            return null;

            static bool IsNullableDate(object? value) => value is null or DateTime or DateTimeOffset;
        }
    }
}
