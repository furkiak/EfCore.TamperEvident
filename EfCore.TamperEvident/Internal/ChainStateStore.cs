using EfCore.TamperEvident.Models;
using Microsoft.EntityFrameworkCore;

namespace EfCore.TamperEvident.Internal
{
    /// <summary>
    /// Loads (and locks) the chain head of a table.
    /// </summary>
    /// <remarks>
    /// Relational providers get a detached copy that is updated with SQL (<see cref="AuditWriter"/>). The in-memory
    /// provider has no SQL, so there the head is tracked and saved through the change tracker.
    /// </remarks>
    internal static class ChainStateStore
    {
        public const string GenesisHash = "GENESIS";

        public static async Task<AuditChainState> LockAsync(
            DbContext context, AuditModelInfo info, string table, DateTime utcNow, CancellationToken cancellationToken)
        {
            if (info.Commands is not { } commands)
            {
                var existing = await context.Set<AuditChainState>().AsNoTracking()
                    .FirstOrDefaultAsync(s => s.TableName == table, cancellationToken).ConfigureAwait(false);
                return Track(context, table, existing, utcNow);
            }

            var fresh = await SelectForUpdateAsync(context, commands, table, cancellationToken).ConfigureAwait(false);
            if (fresh is null)
            {
                // The first write to a table: create the head idempotently, so that concurrent first writers
                // queue up behind each other instead of failing on the primary key.
                await context.Database.ExecuteSqlRawAsync(
                    commands.InsertIfMissing,
                    new object[] { table, GenesisHash, 0, utcNow, 0L },
                    cancellationToken).ConfigureAwait(false);
                fresh = await SelectForUpdateAsync(context, commands, table, cancellationToken).ConfigureAwait(false)
                    ?? throw new InvalidOperationException($"The audit chain head of table '{table}' could not be created.");
            }

            return fresh;
        }

        public static AuditChainState Lock(DbContext context, AuditModelInfo info, string table, DateTime utcNow)
        {
            if (info.Commands is not { } commands)
            {
                var existing = context.Set<AuditChainState>().AsNoTracking().FirstOrDefault(s => s.TableName == table);
                return Track(context, table, existing, utcNow);
            }

            var fresh = SelectForUpdate(context, commands, table);
            if (fresh is null)
            {
                context.Database.ExecuteSqlRaw(
                    commands.InsertIfMissing,
                    new object[] { table, GenesisHash, 0, utcNow, 0L });
                fresh = SelectForUpdate(context, commands, table)
                    ?? throw new InvalidOperationException($"The audit chain head of table '{table}' could not be created.");
            }

            return fresh;
        }

        private static async Task<AuditChainState?> SelectForUpdateAsync(
            DbContext context, AuditSqlCommands commands, string table, CancellationToken cancellationToken)
        {
            var rows = await context.Set<AuditChainState>()
                .FromSqlRaw(commands.SelectForUpdate, table)
                .AsNoTracking()
                .ToListAsync(cancellationToken).ConfigureAwait(false);
            return rows.FirstOrDefault();
        }

        private static AuditChainState? SelectForUpdate(DbContext context, AuditSqlCommands commands, string table)
        {
            return context.Set<AuditChainState>()
                .FromSqlRaw(commands.SelectForUpdate, table)
                .AsNoTracking()
                .ToList()
                .FirstOrDefault();
        }

        // Non-relational path: returns a tracked instance holding the current values.
        private static AuditChainState Track(DbContext context, string table, AuditChainState? fresh, DateTime utcNow)
        {
            var set = context.Set<AuditChainState>();
            var tracked = set.Local.FirstOrDefault(s => s.TableName == table);

            if (fresh is null)
            {
                if (tracked is not null)
                {
                    return tracked;
                }

                var created = new AuditChainState { TableName = table, LastHash = GenesisHash, LastModified = utcNow };
                set.Add(created);
                return created;
            }

            if (tracked is null)
            {
                set.Attach(fresh);
                return fresh;
            }

            var entry = context.Entry(tracked);
            entry.CurrentValues.SetValues(fresh);
            entry.OriginalValues.SetValues(fresh);
            entry.State = EntityState.Unchanged;
            return tracked;
        }
    }
}
