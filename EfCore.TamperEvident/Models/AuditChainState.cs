using System.ComponentModel.DataAnnotations;

namespace EfCore.TamperEvident.Models
{
    /// <summary>
    /// The head of the hash chain of one table. The row is locked while new entries are appended,
    /// which serialises writers and prevents chain forks.
    /// </summary>
    public class AuditChainState
    {
        /// <summary>Name of the audited table.</summary>
        [Key]
        [MaxLength(128)]
        public required string TableName { get; set; }

        /// <summary>Hash of the newest entry of the chain.</summary>
        [MaxLength(64)]
        public required string LastHash { get; set; }

        /// <summary>Number of entries written since the last anchor was published.</summary>
        public int UnanchoredCount { get; set; }

        /// <summary>UTC time of the last append.</summary>
        public DateTime LastModified { get; set; } = DateTime.UtcNow;

        /// <summary><see cref="AuditLog.SequenceNumber"/> of the newest entry.</summary>
        public long LastSequence { get; set; }

        /// <summary>Identifier of the key that authenticated this row.</summary>
        [MaxLength(64)]
        public string? KeyId { get; set; }

        /// <summary>
        /// HMAC over <see cref="TableName"/>, <see cref="LastHash"/> and <see cref="LastSequence"/>.
        /// It makes truncating the newest audit entries detectable.
        /// </summary>
        [MaxLength(64)]
        public string? Mac { get; set; }
    }
}
