using System.Text.Json;
using EfCore.TamperEvident.Internal;
using EfCore.TamperEvident.Models;
using Microsoft.EntityFrameworkCore;

namespace EfCore.TamperEvident.Extensions
{
    /// <summary>
    /// The history of a row as a readable timeline, and its values at any point in time.
    /// </summary>
    public static class AuditHistoryExtensions
    {
        /// <summary>
        /// The history of an entity, oldest change first, with the old and new value of every changed property.
        /// </summary>
        /// <param name="context">The context that stores the audit trail.</param>
        /// <param name="entity">An entity of the audited model (it does not have to exist any more).</param>
        /// <param name="cancellationToken">A token to cancel the query.</param>
        /// <example>
        /// <code>
        /// foreach (var change in await db.GetAuditTrailAsync(order))
        /// {
        ///     Console.WriteLine($"{change.TimestampUtc:u} {change.UserId} {change.Action} {change.Reason}");
        ///     foreach (var p in change.Changes)
        ///         Console.WriteLine($"   {p.Property}: {p.OldValue} → {p.NewValue}");
        /// }
        /// </code>
        /// </example>
        public static Task<IReadOnlyList<AuditChange>> GetAuditTrailAsync(
            this DbContext context, object entity, CancellationToken cancellationToken = default)
        {
            var (table, recordId) = Identify(context, entity);
            return context.GetAuditTrailAsync(table, recordId, cancellationToken);
        }

        /// <summary>
        /// The history of one row, oldest change first, with the old and new value of every changed property.
        /// </summary>
        /// <param name="context">The context that stores the audit trail.</param>
        /// <param name="tableName">The audited table.</param>
        /// <param name="recordId">The primary key of the row (composite keys as <c>part1|part2</c>).</param>
        /// <param name="cancellationToken">A token to cancel the query.</param>
        public static async Task<IReadOnlyList<AuditChange>> GetAuditTrailAsync(
            this DbContext context, string tableName, string recordId, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(context);
            ArgumentException.ThrowIfNullOrEmpty(tableName);
            ArgumentException.ThrowIfNullOrEmpty(recordId);

            var logs = await context.AuditLogs().ForRecord(tableName, recordId)
                .OrderBy(x => x.SequenceNumber).ThenBy(x => x.TimestampTicks)
                .ToListAsync(cancellationToken).ConfigureAwait(false);
            return logs.Select(ToChange).ToList();
        }

        /// <summary>
        /// Rebuilds the values an entity had at <paramref name="pointInTime"/> from its audit history ("time travel").
        /// </summary>
        /// <param name="context">The context that stores the audit trail.</param>
        /// <param name="entity">An entity of the audited model; only its key is used.</param>
        /// <param name="pointInTime">The point in time.</param>
        /// <param name="cancellationToken">A token to cancel the query.</param>
        public static Task<AuditSnapshot> GetStateAsOfAsync(
            this DbContext context, object entity, DateTimeOffset pointInTime, CancellationToken cancellationToken = default)
        {
            var (table, recordId) = Identify(context, entity);
            return context.GetStateAsOfAsync(table, recordId, pointInTime, cancellationToken);
        }

        /// <summary>
        /// Rebuilds the values a row had at <paramref name="pointInTime"/> from its audit history ("time travel").
        /// Properties that are excluded from the audit trail are not part of the snapshot.
        /// </summary>
        /// <param name="context">The context that stores the audit trail.</param>
        /// <param name="tableName">The audited table.</param>
        /// <param name="recordId">The primary key of the row.</param>
        /// <param name="pointInTime">The point in time.</param>
        /// <param name="cancellationToken">A token to cancel the query.</param>
        public static async Task<AuditSnapshot> GetStateAsOfAsync(
            this DbContext context, string tableName, string recordId, DateTimeOffset pointInTime, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(context);
            ArgumentException.ThrowIfNullOrEmpty(tableName);
            ArgumentException.ThrowIfNullOrEmpty(recordId);

            var ticks = pointInTime.UtcTicks;
            var logs = await context.AuditLogs().ForRecord(tableName, recordId)
                .Where(x => x.TimestampTicks <= ticks)
                .OrderBy(x => x.SequenceNumber).ThenBy(x => x.TimestampTicks)
                .ToListAsync(cancellationToken).ConfigureAwait(false);

            var values = new SortedDictionary<string, AuditValue>(StringComparer.Ordinal);
            var exists = false;
            Guid? entryId = null;

            foreach (var log in logs)
            {
                switch (log.ActionType)
                {
                    case AuditActions.Redacted:
                        continue;
                    case AuditActions.Deleted:
                        values.Clear();
                        exists = false;
                        break;
                    case AuditActions.Added:
                        values.Clear();
                        Apply(values, log.NewValues);
                        exists = true;
                        break;
                    default:
                        Apply(values, log.NewValues);
                        exists = true;
                        break;
                }

                entryId = log.Id;
            }

            return new AuditSnapshot
            {
                AsOfUtc = pointInTime.UtcDateTime,
                Exists = exists,
                EntryId = entryId,
                Values = values
            };
        }

        /// <summary>Turns an audit entry into a readable change.</summary>
        /// <param name="log">The entry.</param>
        public static AuditChange ToChange(this AuditLog log)
        {
            ArgumentNullException.ThrowIfNull(log);

            var oldValues = Parse(log.OldValues);
            var newValues = Parse(log.NewValues);
            var changes = new List<AuditPropertyChange>();

            if (log.ActionType != AuditActions.Redacted)
            {
                foreach (var name in oldValues.Keys.Union(newValues.Keys, StringComparer.Ordinal).Order(StringComparer.Ordinal))
                {
                    changes.Add(new AuditPropertyChange(
                        name,
                        oldValues.TryGetValue(name, out var before) ? before : AuditValue.Missing,
                        newValues.TryGetValue(name, out var after) ? after : AuditValue.Missing));
                }
            }

            var metadata = Parse(log.Metadata);
            return new AuditChange
            {
                EntryId = log.Id,
                SequenceNumber = log.SequenceNumber,
                TableName = log.TableName,
                RecordId = log.RecordId,
                Action = log.ActionType,
                UserId = log.UserId,
                TimestampUtc = log.TimestampUtc,
                Reason = metadata.TryGetValue(AuditScope.ReasonKey, out var reason) && reason.Kind == AuditValueKind.Value
                    ? reason.ToString()
                    : null,
                Metadata = metadata,
                Changes = changes
            };
        }

        private static (string Table, string RecordId) Identify(DbContext context, object entity)
        {
            ArgumentNullException.ThrowIfNull(context);
            ArgumentNullException.ThrowIfNull(entity);

            var entry = context.Entry(entity);
            var table = entry.Metadata.GetTableName()
                ?? throw new InvalidOperationException($"{entry.Metadata.DisplayName()} is not mapped to a table.");
            return (table, AuditEntryReader.FormatRecordId(entry, original: false));
        }

        private static void Apply(SortedDictionary<string, AuditValue> values, string? json)
        {
            foreach (var (name, value) in Parse(json))
            {
                values[name] = value;
            }
        }

        private static Dictionary<string, AuditValue> Parse(string? json)
        {
            var result = new Dictionary<string, AuditValue>(StringComparer.Ordinal);
            if (string.IsNullOrEmpty(json))
            {
                return result;
            }

            try
            {
                using var document = JsonDocument.Parse(json);
                if (document.RootElement.ValueKind == JsonValueKind.Object)
                {
                    foreach (var property in document.RootElement.EnumerateObject())
                    {
                        result[property.Name] = AuditValue.From(property.Value);
                    }
                }
            }
            catch (JsonException)
            {
                // Not JSON (a manipulated entry): the verifier reports it; the history shows no values.
            }

            return result;
        }
    }
}
