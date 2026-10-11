namespace EfCore.TamperEvident.Services
{
    /// <summary>
    /// What to redact from the selected audit entries, and why.
    /// </summary>
    /// <remarks>
    /// Redacting replaces a value with its keyed digest (<c>{"$redacted":"…"}</c>, or <c>[REDACTED:…]</c> for the record
    /// id and the user). The hash of the entry does not change, so the chain, its head and every anchor stay valid. A
    /// <see cref="Models.AuditActions.Redacted"/> entry is appended to the chain of every affected table: it records who
    /// redacted what and why, and verification refuses redacted values that no such entry authorizes. Only entries written
    /// by 2.0 or later (<see cref="Models.AuditHashVersion.Redactable"/>) can be redacted.
    /// </remarks>
    public sealed class AuditRedactionRequest
    {
        /// <summary>Matches every property or metadata key.</summary>
        public const string All = "*";

        /// <summary>Why the values are redacted, for example "Erasure request #4711 (GDPR Art. 17)". Required.</summary>
        public required string Reason { get; init; }

        /// <summary>
        /// The entity properties whose old and new values are redacted. <c>null</c> or <see cref="All"/> redacts every
        /// value; an empty collection redacts none.
        /// </summary>
        public IReadOnlyCollection<string>? Properties { get; init; }

        /// <summary>
        /// The metadata entries that are redacted (for example <c>ip</c> or <c>userAgent</c>). <c>null</c> redacts none;
        /// <see cref="All"/> redacts every entry.
        /// </summary>
        public IReadOnlyCollection<string>? MetadataKeys { get; init; }

        /// <summary>Also redacts the record id (useful when the primary key itself is personal data, like an e-mail address).</summary>
        public bool RedactRecordId { get; init; }

        /// <summary>Also redacts the user the changes are attributed to.</summary>
        public bool RedactUserId { get; init; }
    }

    /// <summary>
    /// The outcome of a redaction.
    /// </summary>
    public sealed class AuditRedactionResult
    {
        /// <summary>How many audit entries had at least one value redacted.</summary>
        public int EntriesRedacted { get; init; }

        /// <summary>How many values were redacted in total.</summary>
        public int ValuesRedacted { get; init; }

        /// <summary>The <see cref="Models.AuditActions.Redacted"/> entries that were appended, one per affected table.</summary>
        public IReadOnlyList<Guid> RedactionEntryIds { get; init; } = Array.Empty<Guid>();

        /// <summary>
        /// Selected entries that were written before 2.0 and therefore cannot be redacted without breaking the chain.
        /// They are left untouched.
        /// </summary>
        public IReadOnlyList<Guid> NotRedactable { get; init; } = Array.Empty<Guid>();
    }
}
