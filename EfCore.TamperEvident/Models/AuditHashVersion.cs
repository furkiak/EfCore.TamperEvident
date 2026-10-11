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

        /// <summary>
        /// The canonical format in which the record id, the user, every value and every metadata entry is committed to
        /// through its own keyed digest, and which also covers the entry id and the metadata. A value can therefore be
        /// redacted (for example to honour an erasure request under GDPR or KVKK) by replacing it with its digest,
        /// without changing the hash of the entry or breaking the chain. Written since 2.0.
        /// </summary>
        public const int Redactable = 3;

        /// <summary>The version new entries are written with.</summary>
        public const int Current = Redactable;
    }
}
