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
    /// <remarks>
    /// What to read from an entity type (its table, the audited properties in ordinal order, whether each one is masked,
    /// and its soft delete property) is worked out once per type and cached, so that reading an entity is a plain loop
    /// that writes straight into a reused JSON writer.
    /// </remarks>
    internal sealed class AuditEntryReader
    {
        private const int MaxRecordIdLength = 256;

        private readonly TamperEvidentOptions _options;
        private readonly AuditKeyRing _keys;
        private readonly HashSet<string> _excludedTables;
        private readonly HashSet<string> _excludedProperties;
        private readonly HashSet<string> _maskedProperties;
        private readonly ConcurrentDictionary<IEntityType, EntityPlan> _plans = new();

        public AuditEntryReader(TamperEvidentOptions options, AuditKeyRing keys)
        {
            _options = options;
            _keys = keys;
            _excludedTables = new HashSet<string>(options.ExcludedTables, StringComparer.OrdinalIgnoreCase);
            _excludedProperties = new HashSet<string>(options.ExcludedProperties, StringComparer.OrdinalIgnoreCase);
            _maskedProperties = new HashSet<string>(options.MaskedProperties, StringComparer.OrdinalIgnoreCase);
        }

        /// <summary>Whether changes of this entry are audited at all.</summary>
        public bool ShouldAudit(EntityEntry entry, out string tableName)
        {
            var plan = PlanOf(entry.Metadata);
            tableName = plan.TableName ?? string.Empty;
            if (plan.TableName is null)
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

            return operation != AuditOperation.None && _options.TrackedOperations.HasFlag(operation);
        }

        /// <summary>All audited values of an entity (inserts after the database generated its keys, deletes before).</summary>
        public string ReadAll(EntityEntry entry, string tableName, bool original)
        {
            var plan = PlanOf(entry.Metadata);
            var values = original ? entry.OriginalValues : entry.CurrentValues;

            var writer = AuditSerializer.Rent(out var buffer);
            try
            {
                writer.WriteStartObject();
                foreach (var property in plan.Properties)
                {
                    writer.WritePropertyName(property.Name);
                    AuditSerializer.WriteValue(writer, Apply(property, tableName, values[property.Property]));
                }

                writer.WriteEndObject();
                return AuditSerializer.Complete(writer, buffer);
            }
            finally
            {
                AuditSerializer.Return(buffer);
            }
        }

        /// <summary>
        /// The changed values of an updated entity. The action is <see cref="AuditActions.SoftDelete"/> or
        /// <see cref="AuditActions.Restored"/> when the soft delete property flipped. Returns <c>null</c> when only
        /// properties that are excluded from the audit trail changed.
        /// </summary>
        public (string Action, string OldValues, string NewValues)? ReadModified(EntityEntry entry, string tableName)
        {
            var plan = PlanOf(entry.Metadata);

            string? softDeleteAction = null;
            if (plan.SoftDelete is { } softDelete)
            {
                var flag = entry.Property(softDelete);
                if (flag.IsModified)
                {
                    softDeleteAction = DetectSoftDelete(flag.OriginalValue, flag.CurrentValue);
                }
            }

            var changed = new List<Change>();
            var anyDiffers = false;
            foreach (var property in plan.Properties)
            {
                var propertyEntry = entry.Property(property.Property);
                if (!propertyEntry.IsModified)
                {
                    continue;
                }

                var original = propertyEntry.OriginalValue;
                var current = propertyEntry.CurrentValue;
                var differs = !property.Comparer.Equals(original, current);
                anyDiffers |= differs;
                changed.Add(new Change(property, original, current, differs));
            }

            if (changed.Count == 0)
            {
                return null;
            }

            // Entities that are attached as "modified" (context.Update(entity)) have no meaningful original values:
            // every property is flagged and none differs. Record them all instead of an empty change set.
            var oldValues = WriteChanges(changed, anyDiffers, tableName, useOld: true);
            var newValues = WriteChanges(changed, anyDiffers, tableName, useOld: false);
            return (softDeleteAction ?? AuditActions.Modified, oldValues, newValues);
        }

        private string WriteChanges(List<Change> changed, bool onlyDiffering, string tableName, bool useOld)
        {
            var writer = AuditSerializer.Rent(out var buffer);
            try
            {
                writer.WriteStartObject();
                foreach (var change in changed)
                {
                    if (onlyDiffering && !change.Differs)
                    {
                        continue;
                    }

                    writer.WritePropertyName(change.Property.Name);
                    AuditSerializer.WriteValue(writer, Apply(change.Property, tableName, useOld ? change.Old : change.New));
                }

                writer.WriteEndObject();
                return AuditSerializer.Complete(writer, buffer);
            }
            finally
            {
                AuditSerializer.Return(buffer);
            }
        }

        /// <summary>The primary key of the entry as text. Composite keys are joined with <c>|</c>.</summary>
        public static string FormatRecordId(EntityEntry entry, bool original)
        {
            var key = entry.Metadata.FindPrimaryKey();
            if (key is null)
            {
                return "N/A";
            }

            if (key.Properties.Count == 1)
            {
                return Limit(Format(Value(entry, key.Properties[0], original)));
            }

            var parts = new string[key.Properties.Count];
            for (var i = 0; i < parts.Length; i++)
            {
                parts[i] = Format(Value(entry, key.Properties[i], original));
            }

            return Limit(string.Join("|", parts));

            static object? Value(EntityEntry entry, IProperty property, bool original)
            {
                var propertyEntry = entry.Property(property);
                return original ? propertyEntry.OriginalValue : propertyEntry.CurrentValue;
            }

            static string Format(object? value) => value switch
            {
                null => string.Empty,
                string text => text,
                byte[] bytes => Convert.ToBase64String(bytes),
                IFormattable formattable => formattable.ToString(null, CultureInfo.InvariantCulture),
                _ => value.ToString() ?? string.Empty
            };
        }

        // Very long keys keep a readable prefix and a fingerprint that preserves uniqueness.
        private static string Limit(string text)
        {
            if (text.Length <= MaxRecordIdLength)
            {
                return text;
            }

            var digest = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text)))[..32].ToLowerInvariant();
            return text[..(MaxRecordIdLength - 33)] + "#" + digest;
        }

        private object? Apply(PlannedProperty property, string tableName, object? value)
        {
            if (!property.Mask || value is null)
            {
                return value;
            }

            return AuditHasher.ComputeMaskToken(_keys.Current, tableName, property.Name, value);
        }

        private EntityPlan PlanOf(IEntityType entityType) => _plans.GetOrAdd(entityType, BuildPlan);

        private EntityPlan BuildPlan(IEntityType entityType)
        {
            var type = entityType.ClrType;
            var table = entityType.GetTableName();
            var audited = type != typeof(AuditLog)
                && type != typeof(AuditChainState)
                && !string.IsNullOrEmpty(table)
                && !_excludedTables.Contains(table)
                && type.GetCustomAttribute<AuditIgnoreAttribute>(inherit: true) is null;

            var properties = new List<PlannedProperty>();
            IProperty? softDelete = null;
            foreach (var property in entityType.GetProperties())
            {
                if (softDelete is null && string.Equals(property.Name, _options.SoftDeleteColumnName, StringComparison.OrdinalIgnoreCase))
                {
                    softDelete = property;
                }

                var mode = ModeOf(property);
                if (mode != PropertyMode.Ignore)
                {
                    properties.Add(new PlannedProperty(property, property.Name, mode == PropertyMode.Mask, property.GetValueComparer()));
                }
            }

            properties.Sort((a, b) => string.CompareOrdinal(a.Name, b.Name));
            return new EntityPlan(audited ? table : null, properties.ToArray(), softDelete);
        }

        private PropertyMode ModeOf(IProperty property)
        {
            if (_excludedProperties.Contains(property.Name))
            {
                return PropertyMode.Ignore;
            }

            MemberInfo? member = property.PropertyInfo ?? (MemberInfo?)property.FieldInfo;
            if (member?.GetCustomAttribute<AuditIgnoreAttribute>(inherit: true) is not null)
            {
                return PropertyMode.Ignore;
            }

            return member?.GetCustomAttribute<AuditMaskAttribute>(inherit: true) is not null || _maskedProperties.Contains(property.Name)
                ? PropertyMode.Mask
                : PropertyMode.Include;
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

        private enum PropertyMode
        {
            Include,
            Ignore,
            Mask
        }

        private sealed record PlannedProperty(IProperty Property, string Name, bool Mask, ValueComparer Comparer);

        private readonly record struct Change(PlannedProperty Property, object? Old, object? New, bool Differs);

        private sealed record EntityPlan(string? TableName, PlannedProperty[] Properties, IProperty? SoftDelete);
    }
}
