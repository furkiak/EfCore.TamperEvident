namespace EfCore.TamperEvident.Services
{
    /// <summary>
    /// Why a verification failed.
    /// </summary>
    public enum AuditFailureKind
    {
        /// <summary>The verification succeeded.</summary>
        None = 0,

        /// <summary>An entry does not point to its predecessor: an entry was inserted, removed or reordered.</summary>
        ChainBroken = 1,

        /// <summary>The content of an entry does not match its hash.</summary>
        DataManipulated = 2,

        /// <summary>The sequence numbers are not consecutive.</summary>
        SequenceGap = 3,

        /// <summary>An entry was sealed with a key that is not configured.</summary>
        UnknownKey = 4,

        /// <summary>The chain head is not authentic (it was edited or its signature was removed).</summary>
        ChainStateTampered = 5,

        /// <summary>Audit entries exist for a table that has no chain head.</summary>
        ChainStateMissing = 6,

        /// <summary>The chain head expects entries that are gone: the newest entries were deleted.</summary>
        RecordsMissing = 7,

        /// <summary>Entries exist behind the chain head: they were added without going through the audit trail.</summary>
        RecordsBeyondHead = 8,

        /// <summary>An externally stored anchor does not occur in the database: the history was rewritten.</summary>
        AnchorMismatch = 9
    }

    /// <summary>
    /// The outcome of verifying the audit trail of one table.
    /// </summary>
    public sealed class AuditVerificationResult
    {
        /// <summary><c>true</c> when the chain is intact.</summary>
        public bool IsValid { get; init; }

        /// <summary>A human readable description.</summary>
        public string Message { get; init; } = string.Empty;

        /// <summary>The verified table.</summary>
        public string? TableName { get; init; }

        /// <summary>The reason of a failure, <see cref="AuditFailureKind.None"/> when valid.</summary>
        public AuditFailureKind Failure { get; init; }

        /// <summary>How many entries were verified.</summary>
        public long RecordsChecked { get; init; }

        /// <summary>How many of the supplied anchors were found in the chain.</summary>
        public int AnchorsMatched { get; init; }

        /// <summary>The entry the failure was detected at, when it can be attributed to one.</summary>
        public Guid? FailedRecordId { get; init; }

        /// <summary>The sequence number of that entry.</summary>
        public long? FailedSequence { get; init; }

        /// <summary>The hash of the newest verified entry.</summary>
        public string? HeadHash { get; init; }

        /// <summary>The sequence number of the newest verified entry (<c>0</c> for chains written by 1.x only).</summary>
        public long HeadSequence { get; init; }

        /// <summary>How long the verification took.</summary>
        public TimeSpan Duration { get; init; }

        /// <summary>Allows <c>var (isValid, message) = await verifier.VerifyTableIntegrityAsync(...)</c>.</summary>
        public void Deconstruct(out bool isValid, out string message)
        {
            isValid = IsValid;
            message = Message;
        }
    }

    /// <summary>
    /// The outcome of verifying every audited table.
    /// </summary>
    public sealed class AuditVerificationReport
    {
        /// <summary><c>true</c> when every table is intact.</summary>
        public bool IsValid { get; init; }

        /// <summary>A human readable summary.</summary>
        public string Message { get; init; } = string.Empty;

        /// <summary>The result of every table.</summary>
        public IReadOnlyList<AuditVerificationResult> Tables { get; init; } = Array.Empty<AuditVerificationResult>();

        /// <summary>The total number of verified entries.</summary>
        public long RecordsChecked => Tables.Sum(t => t.RecordsChecked);

        /// <summary>When the verification completed.</summary>
        public DateTimeOffset CompletedUtc { get; init; } = DateTimeOffset.UtcNow;

        /// <summary>The tables that failed.</summary>
        public IEnumerable<AuditVerificationResult> Failures => Tables.Where(t => !t.IsValid);
    }
}
