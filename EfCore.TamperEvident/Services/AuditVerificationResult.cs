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
        AnchorMismatch = 9,

        /// <summary>
        /// The entry a <see cref="AuditCheckpoint"/> points to was changed or removed after that checkpoint was taken.
        /// </summary>
        CheckpointMismatch = 10,

        /// <summary>A value was redacted without a <see cref="Models.AuditActions.Redacted"/> entry that authorizes it.</summary>
        UnauthorizedRedaction = 11
    }

    /// <summary>
    /// A position in the chain of a table that a previous verification found intact. Verifying again from a checkpoint
    /// only reads the entries that were appended since, which keeps scheduled verification cheap on large tables.
    /// </summary>
    /// <remarks>
    /// Keep checkpoints where an attacker with database access cannot change them (in memory, or in another store).
    /// An incremental verification proves that the new entries are authentic and correctly linked to the checkpoint, and
    /// that the checkpoint entry itself is still in place. Changes to the content of older entries are only found by a full
    /// verification, so run one regularly (the ASP.NET Core verification service does both).
    /// </remarks>
    /// <param name="TableName">The audited table.</param>
    /// <param name="SequenceNumber">The sequence number of the newest verified entry.</param>
    /// <param name="Hash">The hash of that entry.</param>
    public sealed record AuditCheckpoint(string TableName, long SequenceNumber, string Hash);

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

        /// <summary>How many of the verified entries hold redacted values (each one authorized by a redaction entry).</summary>
        public long RedactedRecords { get; init; }

        /// <summary>The entry the failure was detected at, when it can be attributed to one.</summary>
        public Guid? FailedRecordId { get; init; }

        /// <summary>The sequence number of that entry.</summary>
        public long? FailedSequence { get; init; }

        /// <summary>The hash of the newest verified entry.</summary>
        public string? HeadHash { get; init; }

        /// <summary>The sequence number of the newest verified entry (<c>0</c> for chains written by 1.x only).</summary>
        public long HeadSequence { get; init; }

        /// <summary>
        /// The checkpoint the verification started after, or <c>null</c> when the whole chain was verified.
        /// </summary>
        public AuditCheckpoint? StartedAfter { get; init; }

        /// <summary><c>true</c> when only the entries after <see cref="StartedAfter"/> were verified.</summary>
        public bool IsIncremental => StartedAfter is not null;

        /// <summary>
        /// Where the next verification can start (see <see cref="AuditVerifier.VerifyFromCheckpointAsync"/>).
        /// <c>null</c> when the verification failed or the chain has no sequenced entries yet.
        /// </summary>
        public AuditCheckpoint? Checkpoint =>
            IsValid && TableName is not null && HeadSequence > 0 && HeadHash is not null
                ? new AuditCheckpoint(TableName, HeadSequence, HeadHash)
                : null;

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

        /// <summary>
        /// The checkpoint of every table that verified successfully, ready for the next incremental verification
        /// (<see cref="AuditVerifier.VerifyAllAsync(IReadOnlyDictionary{string, IEnumerable{string}}?, IReadOnlyDictionary{string, AuditCheckpoint}?, CancellationToken)"/>).
        /// </summary>
        public IReadOnlyDictionary<string, AuditCheckpoint> Checkpoints =>
            Tables.Where(t => t.Checkpoint is not null).ToDictionary(t => t.TableName!, t => t.Checkpoint!, StringComparer.Ordinal);
    }
}
