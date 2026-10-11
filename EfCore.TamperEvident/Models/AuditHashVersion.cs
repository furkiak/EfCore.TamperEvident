namespace EfCore.TamperEvident.Models
{
    /// <summary>
    /// Identifies how <see cref="AuditLog.CurrentHash"/> was computed.
    /// </summary>
    public static class AuditHashVersion
    {
        /// <summary>
        /// The format used by 1.x releases: a plain string concatenation of the record fields.
        /// Rows written by 1.x keep this version so that they remain verifiable.
        /// </summary>
        public const int Legacy = 0;

        /// <summary>
        /// The canonical format: every field (including the user, the key id and the sequence number)
        /// is length-prefixed so that field boundaries can never be shifted without breaking the hash.
        /// </summary>
        public const int Canonical = 2;
    }
}
