using EfCore.TamperEvident.Models;
using Microsoft.EntityFrameworkCore;

namespace EfCore.TamperEvident.Internal
{
    /// <summary>
    /// Appends audit entries and advances the chain heads, inside the current transaction.
    /// </summary>
    internal static class AuditWriter
    {
        public static Task WriteAsync(
            DbContext context, AuditModelInfo info, IReadOnlyList<AuditLog> logs, IReadOnlyList<AuditChainState> chains,
            CancellationToken cancellationToken) =>
            info.Relational!.AppendAsync(context, logs, chains, cancellationToken);

        public static void Write(DbContext context, AuditModelInfo info, IReadOnlyList<AuditLog> logs, IReadOnlyList<AuditChainState> chains) =>
            info.Relational!.Append(context, logs, chains);
    }
}
