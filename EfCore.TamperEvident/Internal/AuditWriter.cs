using EfCore.TamperEvident.Models;
using Microsoft.EntityFrameworkCore;

namespace EfCore.TamperEvident.Internal
{
    /// <summary>
    /// Appends audit entries and advances the chain heads with parameterized SQL, inside the current transaction.
    /// </summary>
    internal static class AuditWriter
    {
        // 40 rows x 13 columns = 520 parameters per statement: far below every provider's limit
        // (SQL Server allows 2100) while keeping the number of round trips small.
        private const int RowsPerStatement = 40;

        public static async Task WriteAsync(
            DbContext context, AuditSqlCommands commands, IReadOnlyList<AuditLog> logs, IReadOnlyList<AuditChainState> chains,
            CancellationToken cancellationToken)
        {
            for (var offset = 0; offset < logs.Count; offset += RowsPerStatement)
            {
                var count = Math.Min(RowsPerStatement, logs.Count - offset);
                await context.Database.ExecuteSqlRawAsync(
                    commands.InsertLogs(count), BuildInsertParameters(logs, offset, count), cancellationToken).ConfigureAwait(false);
            }

            foreach (var chain in chains)
            {
                var affected = await context.Database.ExecuteSqlRawAsync(
                    commands.UpdateChainState, BuildUpdateParameters(chain), cancellationToken).ConfigureAwait(false);
                EnsureHeadUpdated(chain, affected);
            }
        }

        public static void Write(
            DbContext context, AuditSqlCommands commands, IReadOnlyList<AuditLog> logs, IReadOnlyList<AuditChainState> chains)
        {
            for (var offset = 0; offset < logs.Count; offset += RowsPerStatement)
            {
                var count = Math.Min(RowsPerStatement, logs.Count - offset);
                context.Database.ExecuteSqlRaw(commands.InsertLogs(count), BuildInsertParameters(logs, offset, count));
            }

            foreach (var chain in chains)
            {
                EnsureHeadUpdated(chain, context.Database.ExecuteSqlRaw(commands.UpdateChainState, BuildUpdateParameters(chain)));
            }
        }

        private static object[] BuildInsertParameters(IReadOnlyList<AuditLog> logs, int offset, int count)
        {
            var parameters = new object?[count * AuditSqlCommands.LogColumnCount];
            for (var row = 0; row < count; row++)
            {
                AuditSqlCommands.AddLogParameters(logs[offset + row], parameters, row * AuditSqlCommands.LogColumnCount);
            }

            return parameters!;
        }

        private static object[] BuildUpdateParameters(AuditChainState chain) => new object?[]
        {
            chain.LastHash, chain.UnanchoredCount, chain.LastModified, chain.LastSequence, chain.KeyId, chain.Mac, chain.TableName
        }!;

        private static void EnsureHeadUpdated(AuditChainState chain, int affectedRows)
        {
            if (affectedRows != 1)
            {
                throw new InvalidOperationException(
                    $"The audit chain head of table '{chain.TableName}' could not be updated (it was removed while it was locked).");
            }
        }
    }
}
