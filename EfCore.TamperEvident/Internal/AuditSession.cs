using Microsoft.EntityFrameworkCore.ChangeTracking;
using Microsoft.EntityFrameworkCore.Storage;

namespace EfCore.TamperEvident.Internal
{
    /// <summary>
    /// The state that connects the two phases of one <c>SaveChanges</c> call:
    /// phase one captures what is about to change, phase two seals it once the database generated its keys.
    /// </summary>
    internal sealed class AuditSession
    {
        public AuditSession(AuditModelInfo info, string userId, string? metadata, List<EntityEntry> pendingEntries)
        {
            Info = info;
            UserId = userId;
            Metadata = metadata;
            PendingEntries = pendingEntries;
        }

        public AuditModelInfo Info { get; }

        public string UserId { get; }

        /// <summary>The metadata shared by every entry of this save (deterministic JSON), or <c>null</c>.</summary>
        public string? Metadata { get; }

        /// <summary>Every entry that was pending when the save started (audited or not).</summary>
        public List<EntityEntry> PendingEntries { get; }

        public List<AuditPrep> Preps { get; } = new();

        /// <summary>The transaction the audit entries are written in (<c>null</c> for ambient or non-relational scenarios).</summary>
        public IDbContextTransaction? Transaction { get; set; }

        /// <summary><c>true</c> when the interceptor started the transaction and therefore commits or rolls it back.</summary>
        public bool OwnsTransaction { get; set; }

        /// <summary><c>true</c> when a <c>System.Transactions</c> ambient transaction is active.</summary>
        public bool UsesAmbientTransaction { get; set; }

        /// <summary>Set while the audit entries are written, so that the nested save is not audited again.</summary>
        public bool IsWritingAudit { get; set; }
    }

    internal sealed class AuditPrep
    {
        public AuditPrep(EntityEntry entry, string tableName, string action)
        {
            Entry = entry;
            TableName = tableName;
            Action = action;
        }

        public EntityEntry Entry { get; }

        public string TableName { get; }

        public string Action { get; set; }

        public string? RecordId { get; set; }

        public string? OldValues { get; set; }

        public string? NewValues { get; set; }
    }
}
