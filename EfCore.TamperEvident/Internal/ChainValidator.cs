using System.Text.Json;
using EfCore.TamperEvident.Models;
using EfCore.TamperEvident.Services;

namespace EfCore.TamperEvident.Internal
{
    /// <summary>A verification failure, attributed to an entry when possible.</summary>
    internal readonly record struct ChainFailure(AuditFailureKind Kind, string Message, Guid? EntryId = null, long? Sequence = null);

    /// <summary>The outcome of recomputing the hash of one entry.</summary>
    /// <param name="UnknownKey">No configured key has the entry's key id.</param>
    /// <param name="Authentic">The entry matches its hash.</param>
    /// <param name="Redacted">The redacted fields of the entry, or <c>null</c>.</param>
    internal readonly record struct EntryCheck(bool UnknownKey, bool Authentic, string[]? Redacted);

    /// <summary>
    /// Checks the entries of one chain in order, wherever they come from (the database or an evidence bundle):
    /// the link to the predecessor, the sequence, the keyed hash, redactions and anchors, and finally the chain head.
    /// </summary>
    internal sealed class ChainValidator
    {
        private readonly AuditKeyRing _keys;
        private readonly HashSet<string>? _anchors;
        private readonly Dictionary<Guid, (long Sequence, HashSet<string> Fields)> _pendingRedactions = new();
        private string _expectedPreviousHash;

        public ChainValidator(string tableName, AuditKeyRing keys, AuditCheckpoint? start, IEnumerable<string>? anchors)
        {
            TableName = tableName;
            _keys = keys;
            _expectedPreviousHash = start?.Hash ?? ChainStateStore.GenesisHash;
            LastHash = start?.Hash;
            Sequence = start?.SequenceNumber ?? 0;

            foreach (var anchor in anchors ?? Array.Empty<string>())
            {
                if (!string.IsNullOrWhiteSpace(anchor))
                {
                    (_anchors ??= new HashSet<string>(StringComparer.OrdinalIgnoreCase)).Add(anchor.Trim());
                }
            }
        }

        public string TableName { get; }

        public long RecordsChecked { get; private set; }

        public int AnchorsMatched { get; private set; }

        public long RedactedRecords { get; private set; }

        /// <summary>The sequence number of the newest accepted entry (<c>0</c> while only 1.x entries were seen).</summary>
        public long Sequence { get; private set; }

        /// <summary>The hash of the newest accepted entry, or the checkpoint hash.</summary>
        public string? LastHash { get; private set; }

        /// <summary>The anchors that did not occur in the accepted entries.</summary>
        public IReadOnlyCollection<string> UnmatchedAnchors => (IReadOnlyCollection<string>?)_anchors ?? Array.Empty<string>();

        public void MatchAnchor(string hash)
        {
            if (_anchors?.Remove(hash) == true)
            {
                AnchorsMatched++;
            }
        }

        /// <summary>
        /// Recomputes the hash of an entry. It does not depend on the other entries, so it may run on any thread and in
        /// any order; <see cref="Accept(AuditLog, EntryCheck)"/> then checks the links in chain order.
        /// </summary>
        public static EntryCheck Check(AuditKeyRing keys, AuditLog log)
        {
            var candidates = keys.Candidates(log.KeyId);
            if (candidates.Count == 0)
            {
                return new EntryCheck(UnknownKey: true, Authentic: false, null);
            }

            List<string>? redacted = null;
            foreach (var key in candidates)
            {
                redacted?.Clear();
                if (AuditHasher.Verify(key, log, redacted ??= new List<string>()))
                {
                    return new EntryCheck(false, true, redacted.Count == 0 ? null : redacted.ToArray());
                }
            }

            return new EntryCheck(false, false, null);
        }

        /// <summary>Checks the next entry of the chain.</summary>
        public ChainFailure? Accept(AuditLog log) => Accept(log, Check(_keys, log));

        /// <summary>Checks the next entry of the chain, whose hash was already checked with <see cref="Check"/>.</summary>
        public ChainFailure? Accept(AuditLog log, EntryCheck check)
        {
            RecordsChecked++;
            var at = (Guid?)log.Id;

            if (!string.Equals(log.PreviousHash, _expectedPreviousHash, StringComparison.Ordinal))
            {
                return new(AuditFailureKind.ChainBroken,
                    $"CHAIN BROKEN! Tampering detected at record ID: {log.Id}. The previous hash does not match.", at, log.SequenceNumber);
            }

            if (log.HashVersion is AuditHashVersion.Canonical or AuditHashVersion.Redactable)
            {
                if (log.SequenceNumber != Sequence + 1)
                {
                    return new(AuditFailureKind.SequenceGap,
                        $"SEQUENCE GAP! Record ID: {log.Id} has sequence {log.SequenceNumber} but {Sequence + 1} was expected. Entries were removed or reordered.",
                        at, log.SequenceNumber);
                }

                Sequence++;
            }
            else if (log.HashVersion != AuditHashVersion.Legacy || Sequence > 0)
            {
                return new(AuditFailureKind.DataManipulated,
                    $"DATA MANIPULATION DETECTED! Record ID: {log.Id} has an unexpected hash version ({log.HashVersion}).", at, log.SequenceNumber);
            }

            if (check.UnknownKey)
            {
                return new(AuditFailureKind.UnknownKey,
                    $"UNKNOWN KEY! Record ID: {log.Id} was sealed with key '{log.KeyId}', which is not configured.", at, log.SequenceNumber);
            }

            if (!check.Authentic)
            {
                return new(AuditFailureKind.DataManipulated,
                    $"DATA MANIPULATION DETECTED! The payload of record ID: {log.Id} has been externally modified.", at, log.SequenceNumber);
            }

            if (check.Redacted is { } redacted)
            {
                RedactedRecords++;
                _pendingRedactions[log.Id] = (log.SequenceNumber, new HashSet<string>(redacted, StringComparer.Ordinal));
            }

            if (log.HashVersion == AuditHashVersion.Redactable
                && string.Equals(log.ActionType, AuditActions.Redacted, StringComparison.Ordinal)
                && _pendingRedactions.Count > 0)
            {
                Authorize(log.NewValues);
            }

            if (_anchors is { Count: > 0 })
            {
                MatchAnchor(log.CurrentHash);
            }

            _expectedPreviousHash = log.CurrentHash;
            LastHash = log.CurrentHash;
            return null;
        }

        /// <summary>Every redacted value has to be authorized by a later redaction entry of the same chain.</summary>
        public ChainFailure? CheckRedactions()
        {
            if (_pendingRedactions.Count == 0)
            {
                return null;
            }

            var (id, (sequence, fields)) = _pendingRedactions.MinBy(p => p.Value.Sequence);
            return new(AuditFailureKind.UnauthorizedRedaction,
                $"UNAUTHORIZED REDACTION! Values of record ID: {id} ({string.Join(", ", fields.Order(StringComparer.Ordinal))}) were redacted " +
                "without a redaction entry in the chain that authorizes it.", id, sequence);
        }

        /// <summary>
        /// Compares the authenticated chain head with the newest entry. Without this step the newest entries could be
        /// deleted and the remaining chain would still look perfect.
        /// </summary>
        public ChainFailure? CheckHead(AuditChainState? state)
        {
            if (state is null)
            {
                return RecordsChecked == 0 && Sequence == 0
                    ? null
                    : new(AuditFailureKind.ChainStateMissing,
                        $"CHAIN HEAD MISSING! Audit entries exist for table '{TableName}' but its chain head was removed.");
            }

            if (state.Mac is null)
            {
                if (Sequence > 0 || state.LastSequence > 0)
                {
                    return new(AuditFailureKind.ChainStateTampered,
                        $"CHAIN HEAD TAMPERED! The signature of the chain head of table '{TableName}' was removed.");
                }
            }
            else
            {
                var authentic = false;
                foreach (var key in _keys.Candidates(state.KeyId))
                {
                    if (AuditHasher.VerifyStateMac(key, state))
                    {
                        authentic = true;
                        break;
                    }
                }

                if (!authentic)
                {
                    return new(AuditFailureKind.ChainStateTampered,
                        $"CHAIN HEAD TAMPERED! The chain head of table '{TableName}' does not match its signature.");
                }
            }

            var expectedHash = _expectedPreviousHash;
            if (!string.Equals(state.LastHash, expectedHash, StringComparison.Ordinal) || state.LastSequence != Sequence)
            {
                return new(AuditFailureKind.RecordsMissing,
                    $"RECORDS MISSING! The chain head of table '{TableName}' expects sequence {state.LastSequence}, " +
                    $"but the newest audit entry has sequence {Sequence}. The newest entries were deleted.");
            }

            return null;
        }

        private void Authorize(string? json)
        {
            try
            {
                using var document = JsonDocument.Parse(json ?? "{}");
                if (!document.RootElement.TryGetProperty("entries", out var entries) || entries.ValueKind != JsonValueKind.Object)
                {
                    return;
                }

                foreach (var entry in entries.EnumerateObject())
                {
                    if (!Guid.TryParse(entry.Name, out var id) || !_pendingRedactions.TryGetValue(id, out var pending)
                        || entry.Value.ValueKind != JsonValueKind.Array)
                    {
                        continue;
                    }

                    foreach (var field in entry.Value.EnumerateArray())
                    {
                        if (field.ValueKind == JsonValueKind.String)
                        {
                            pending.Fields.Remove(field.GetString()!);
                        }
                    }

                    if (pending.Fields.Count == 0)
                    {
                        _pendingRedactions.Remove(id);
                    }
                }
            }
            catch (JsonException)
            {
                // A redaction entry whose list cannot be read authorizes nothing.
            }
        }
    }
}
