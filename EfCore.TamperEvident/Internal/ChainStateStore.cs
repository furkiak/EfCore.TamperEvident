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

        // Chain heads that are known to exist, per database and table (a one-time cost per process).
        private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, byte> EnsuredHeads = new();

        /// <summary>
        /// Creates the chain heads of the tables that are about to be written, <em>before</em> any transaction starts.
        /// Each head is created by its own auto-committed statement. That matters on InnoDB (MySQL/MariaDB): two
        /// transactions that both find the head missing take gap locks and then deadlock on the insert, so the head has
        /// to exist by the time a transaction locks it. If the head is removed later, <see cref="Lock"/> still recreates it.
        /// </summary>
        public static async Task EnsureHeadsAsync(
            DbContext context, AuditModelInfo info, IEnumerable<string> tables, DateTime utcNow, CancellationToken cancellationToken)
        {
            if (info.Commands is not { } commands)
            {
                return;
            }

            foreach (var table in tables)
            {
                if (!EnsuredHeads.ContainsKey(HeadKey(context, commands, table)))
                {
                    await context.Database.ExecuteSqlRawAsync(
                        commands.InsertIfMissing, new object[] { table, GenesisHash, 0, utcNow, 0L }, cancellationToken).ConfigureAwait(false);
                    EnsuredHeads[HeadKey(context, commands, table)] = 0;
                }
            }
        }

        public static void EnsureHeads(DbContext context, AuditModelInfo info, IEnumerable<string> tables, DateTime utcNow)
        {
            if (info.Commands is not { } commands)
            {
                return;
            }

            foreach (var table in tables)
            {
                if (!EnsuredHeads.ContainsKey(HeadKey(context, commands, table)))
                {
                    context.Database.ExecuteSqlRaw(commands.InsertIfMissing, new object[] { table, GenesisHash, 0, utcNow, 0L });
                    EnsuredHeads[HeadKey(context, commands, table)] = 0;
                }
            }
        }

        private static string HeadKey(DbContext context, AuditSqlCommands commands, string table) =>
            context.Database.GetConnectionString() + "\u0000" + commands.InsertIfMissing + "\u0000" + table;

        public static async Task<AuditChainState> LockAsync(
            DbContext context, AuditModelInfo info, string table, DateTime utcNow, CancellationToken cancellationToken)
        {
            if (info.Commands is not { } commands)
            {
                var existing = await context.Set<AuditChainState>().AsNoTracking()
                    .FirstOrDefaultAsync(s => s.TableName == table, cancellationToken).ConfigureAwait(false);
                return Track(context, table, existing, utcNow);
            }

            var fresh = await info.Relational!.SelectForUpdateAsync(context, table, cancellationToken).ConfigureAwait(false);
            if (fresh is null)
            {
                // The first write to a table: create the head idempotently, so that concurrent first writers
                // queue up behind each other instead of failing on the primary key.
                await context.Database.ExecuteSqlRawAsync(
                    commands.InsertIfMissing,
                    new object[] { table, GenesisHash, 0, utcNow, 0L },
                    cancellationToken).ConfigureAwait(false);
                fresh = await info.Relational!.SelectForUpdateAsync(context, table, cancellationToken).ConfigureAwait(false)
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

            var fresh = info.Relational!.SelectForUpdate(context, table);
            if (fresh is null)
            {
                context.Database.ExecuteSqlRaw(
                    commands.InsertIfMissing,
                    new object[] { table, GenesisHash, 0, utcNow, 0L });
                fresh = info.Relational!.SelectForUpdate(context, table)
                    ?? throw new InvalidOperationException($"The audit chain head of table '{table}' could not be created.");
            }

            return fresh;
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
