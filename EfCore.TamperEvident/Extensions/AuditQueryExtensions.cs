using EfCore.TamperEvident.Internal;
using EfCore.TamperEvident.Models;
using Microsoft.EntityFrameworkCore;

namespace EfCore.TamperEvident.Extensions
{
    /// <summary>
    /// Convenient, composable queries over the audit trail.
    /// </summary>
    public static class AuditQueryExtensions
    {
        /// <summary>The audit entries of the context as a read-only query.</summary>
        /// <param name="context">The context that stores the audit trail.</param>
        public static IQueryable<AuditLog> AuditLogs(this DbContext context)
        {
            ArgumentNullException.ThrowIfNull(context);
            return context.Set<AuditLog>().AsNoTracking();
        }

        /// <summary>Only the entries of one table.</summary>
        /// <param name="logs">The query.</param>
        /// <param name="tableName">The audited table.</param>
        public static IQueryable<AuditLog> ForTable(this IQueryable<AuditLog> logs, string tableName) =>
            logs.Where(x => x.TableName == tableName);

        /// <summary>Only the entries of one row. Composite keys are written as <c>part1|part2</c>.</summary>
        /// <param name="logs">The query.</param>
        /// <param name="tableName">The audited table.</param>
        /// <param name="recordId">The primary key of the row.</param>
        public static IQueryable<AuditLog> ForRecord(this IQueryable<AuditLog> logs, string tableName, string recordId) =>
            logs.Where(x => x.TableName == tableName && x.RecordId == recordId);

        /// <summary>Only the entries attributed to one user.</summary>
        /// <param name="logs">The query.</param>
        /// <param name="userId">The user.</param>
        public static IQueryable<AuditLog> ByUser(this IQueryable<AuditLog> logs, string userId) =>
            logs.Where(x => x.UserId == userId);

        /// <summary>Only the entries of one action (see <see cref="AuditActions"/>).</summary>
        /// <param name="logs">The query.</param>
        /// <param name="action">The action.</param>
        public static IQueryable<AuditLog> OfAction(this IQueryable<AuditLog> logs, string action) =>
            logs.Where(x => x.ActionType == action);

        /// <summary>Only the entries inside a time range (both bounds are inclusive and optional).</summary>
        /// <param name="logs">The query.</param>
        /// <param name="from">The earliest time.</param>
        /// <param name="to">The latest time.</param>
        public static IQueryable<AuditLog> Between(this IQueryable<AuditLog> logs, DateTimeOffset? from, DateTimeOffset? to)
        {
            if (from is { } start)
            {
                var ticks = start.UtcTicks;
                logs = logs.Where(x => x.TimestampTicks >= ticks);
            }

            if (to is { } end)
            {
                var ticks = end.UtcTicks;
                logs = logs.Where(x => x.TimestampTicks <= ticks);
            }

            return logs;
        }

        /// <summary>Oldest first, in the order the entries were chained.</summary>
        /// <param name="logs">The query.</param>
        public static IOrderedQueryable<AuditLog> InChainOrder(this IQueryable<AuditLog> logs) =>
            logs.OrderBy(x => x.TableName).ThenBy(x => x.SequenceNumber).ThenBy(x => x.TimestampTicks);

        /// <summary>Newest first.</summary>
        /// <param name="logs">The query.</param>
        public static IOrderedQueryable<AuditLog> Newest(this IQueryable<AuditLog> logs) =>
            logs.OrderByDescending(x => x.TimestampTicks).ThenByDescending(x => x.SequenceNumber);

        /// <summary>
        /// The complete audit history of an entity, oldest entry first.
        /// </summary>
        /// <param name="context">The context that tracks or can track the entity.</param>
        /// <param name="entity">An entity of the audited model.</param>
        /// <param name="cancellationToken">A token to cancel the query.</param>
        public static async Task<IReadOnlyList<AuditLog>> GetAuditHistoryAsync(
            this DbContext context, object entity, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(context);
            ArgumentNullException.ThrowIfNull(entity);

            var entry = context.Entry(entity);
            var tableName = entry.Metadata.GetTableName()
                ?? throw new InvalidOperationException($"{entry.Metadata.DisplayName()} is not mapped to a table.");
            var recordId = AuditEntryReader.FormatRecordId(entry, original: false);

            return await context.AuditLogs()
                .ForRecord(tableName, recordId)
                .OrderBy(x => x.SequenceNumber).ThenBy(x => x.TimestampTicks)
                .ToListAsync(cancellationToken).ConfigureAwait(false);
        }
    }
}
