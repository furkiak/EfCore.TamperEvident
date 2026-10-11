using EfCore.TamperEvident.Models;
using Microsoft.EntityFrameworkCore;

namespace EfCore.TamperEvident.Internal
{
    /// <summary>
    /// Loads (and locks) the chain head of a table and keeps the change tracker in sync with the database.
    /// </summary>
    internal static class ChainStateStore
    {
        public const string GenesisHash = "GENESIS";

        public static async Task<AuditChainState> LockAsync(
            DbContext context, AuditModelInfo info, string table, DateTime utcNow, CancellationToken cancellationToken)
        {
            AuditChainState? fresh;
            if (info.Commands is null)
            {
                fresh = await context.Set<AuditChainState>().AsNoTracking()
                    .FirstOrDefaultAsync(s => s.TableName == table, cancellationToken).ConfigureAwait(false);
            }
            else
            {
                fresh = await SelectForUpdateAsync(context, info.Commands, table, cancellationToken).ConfigureAwait(false);
                if (fresh is null)
                {
                    // The first write to a table: create the head idempotently, so that concurrent first writers
                    // queue up behind each other instead of failing on the primary key.
                    await context.Database.ExecuteSqlRawAsync(
                        info.Commands.InsertIfMissing,
                        new object[] { table, GenesisHash, 0, utcNow, 0L },
                        cancellationToken).ConfigureAwait(false);
                    fresh = await SelectForUpdateAsync(context, info.Commands, table, cancellationToken).ConfigureAwait(false)
                        ?? throw new InvalidOperationException($"The audit chain head of table '{table}' could not be created.");
                }
            }

            return Track(context, table, fresh, utcNow);
        }

        public static AuditChainState Lock(DbContext context, AuditModelInfo info, string table, DateTime utcNow)
        {
            AuditChainState? fresh;
            if (info.Commands is null)
            {
                fresh = context.Set<AuditChainState>().AsNoTracking().FirstOrDefault(s => s.TableName == table);
            }
            else
            {
                fresh = SelectForUpdate(context, info.Commands, table);
                if (fresh is null)
                {
                    context.Database.ExecuteSqlRaw(
                        info.Commands.InsertIfMissing,
                        new object[] { table, GenesisHash, 0, utcNow, 0L });
                    fresh = SelectForUpdate(context, info.Commands, table)
                        ?? throw new InvalidOperationException($"The audit chain head of table '{table}' could not be created.");
                }
            }

            return Track(context, table, fresh, utcNow);
        }

        private static async Task<AuditChainState?> SelectForUpdateAsync(
            DbContext context, ChainStateCommands commands, string table, CancellationToken cancellationToken)
        {
            var rows = await context.Set<AuditChainState>()
                .FromSqlRaw(commands.SelectForUpdate, table)
                .AsNoTracking()
                .ToListAsync(cancellationToken).ConfigureAwait(false);
            return rows.FirstOrDefault();
        }

        private static AuditChainState? SelectForUpdate(DbContext context, ChainStateCommands commands, string table)
        {
            return context.Set<AuditChainState>()
                .FromSqlRaw(commands.SelectForUpdate, table)
                .AsNoTracking()
                .ToList()
                .FirstOrDefault();
        }

        /// <summary>
        /// Returns a tracked instance holding the freshly locked values. An instance that is already tracked by
        /// this context may be stale (another writer appended in the meantime), so its values are refreshed.
        /// </summary>
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
