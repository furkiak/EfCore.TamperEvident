using System.Diagnostics;
using EfCore.TamperEvident.Configuration;
using EfCore.TamperEvident.Internal;
using EfCore.TamperEvident.Models;
using Microsoft.EntityFrameworkCore;

namespace EfCore.TamperEvident.Services
{
    /// <summary>
    /// Verifies the hash chains of the audit trail: every entry is recomputed with the secret key, the links between
    /// entries are followed, the authenticated chain head is compared with the newest entry, and externally stored
    /// anchors are looked up. Run it on a schedule and whenever tampering is suspected.
    /// </summary>
    public class AuditVerifier
    {
        private readonly DbContext _context;
        private readonly AuditKeyRing _keys;

        /// <summary>Creates a verifier.</summary>
        /// <param name="context">The context that stores the audit trail.</param>
        /// <param name="options">The options that hold the secret key(s) the trail was sealed with.</param>
        public AuditVerifier(DbContext context, TamperEvidentOptions options)
        {
            ArgumentNullException.ThrowIfNull(context);
            ArgumentNullException.ThrowIfNull(options);
            options.Validate();

            _context = context;
            _keys = AuditKeyRing.Create(options);
        }

        /// <summary>
        /// Verifies the chain of one table.
        /// </summary>
        /// <param name="tableName">The audited table.</param>
        /// <param name="providedAnchorKeys">
        /// Anchor hashes that were received outside of the database (e-mail, webhook, file). Every one of them has to
        /// occur in the chain. The collection is not modified.
        /// </param>
        /// <param name="cancellationToken">A token to cancel the verification.</param>
        public async Task<AuditVerificationResult> VerifyTableIntegrityAsync(
            string tableName,
            IEnumerable<string>? providedAnchorKeys = null,
            CancellationToken cancellationToken = default)
        {
            ArgumentException.ThrowIfNullOrEmpty(tableName);

            var stopwatch = Stopwatch.StartNew();
            var anchors = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (providedAnchorKeys is not null)
            {
                foreach (var anchor in providedAnchorKeys)
                {
                    if (!string.IsNullOrWhiteSpace(anchor))
                    {
                        anchors.Add(anchor.Trim());
                    }
                }
            }

            // The head is read first. Entries that are appended while the verification runs lie behind it and are
            // left for the next run, which keeps the check consistent on a busy system.
            var state = await ReadStateAsync(tableName, cancellationToken).ConfigureAwait(false);

            IQueryable<AuditLog> query = _context.Set<AuditLog>().AsNoTracking().Where(x => x.TableName == tableName);
            if (state is not null)
            {
                var headSequence = state.LastSequence;
                query = query.Where(x => x.SequenceNumber <= headSequence);
            }

            query = query.OrderBy(x => x.SequenceNumber).ThenBy(x => x.TimestampTicks);

            var expectedPreviousHash = ChainStateStore.GenesisHash;
            long canonicalSequence = 0;
            long checkedCount = 0;
            var matchedAnchors = 0;
            AuditLog? last = null;

            AuditVerificationResult Fail(AuditFailureKind kind, string message, AuditLog? at = null) => new()
            {
                IsValid = false,
                Failure = kind,
                Message = message,
                TableName = tableName,
                RecordsChecked = checkedCount,
                AnchorsMatched = matchedAnchors,
                FailedRecordId = at?.Id,
                FailedSequence = at?.SequenceNumber,
                HeadHash = last?.CurrentHash,
                HeadSequence = canonicalSequence,
                Duration = stopwatch.Elapsed
            };

            await foreach (var log in query.AsAsyncEnumerable().WithCancellation(cancellationToken).ConfigureAwait(false))
            {
                checkedCount++;

                if (!string.Equals(log.PreviousHash, expectedPreviousHash, StringComparison.Ordinal))
                {
                    return Fail(AuditFailureKind.ChainBroken,
                        $"CHAIN BROKEN! Tampering detected at record ID: {log.Id}. The previous hash does not match.", log);
                }

                if (log.HashVersion == AuditHashVersion.Canonical)
                {
                    canonicalSequence++;
                    if (log.SequenceNumber != canonicalSequence)
                    {
                        return Fail(AuditFailureKind.SequenceGap,
                            $"SEQUENCE GAP! Record ID: {log.Id} has sequence {log.SequenceNumber} but {canonicalSequence} was expected. Entries were removed or reordered.", log);
                    }
                }
                else if (log.HashVersion != AuditHashVersion.Legacy || canonicalSequence > 0)
                {
                    return Fail(AuditFailureKind.DataManipulated,
                        $"DATA MANIPULATION DETECTED! Record ID: {log.Id} has an unexpected hash version ({log.HashVersion}).", log);
                }

                var candidates = _keys.Candidates(log.KeyId);
                if (candidates.Count == 0)
                {
                    return Fail(AuditFailureKind.UnknownKey,
                        $"UNKNOWN KEY! Record ID: {log.Id} was sealed with key '{log.KeyId}', which is not configured.", log);
                }

                if (!MatchesAnyKey(candidates, log))
                {
                    return Fail(AuditFailureKind.DataManipulated,
                        $"DATA MANIPULATION DETECTED! The payload of record ID: {log.Id} has been externally modified.", log);
                }

                if (anchors.Remove(log.CurrentHash))
                {
                    matchedAnchors++;
                }

                expectedPreviousHash = log.CurrentHash;
                last = log;
            }

            var tailFailure = await CheckHeadAsync(tableName, state, last, canonicalSequence, checkedCount, cancellationToken).ConfigureAwait(false);
            if (tailFailure is not null)
            {
                return Fail(tailFailure.Value.Kind, tailFailure.Value.Message, last);
            }

            if (anchors.Count > 0)
            {
                return Fail(AuditFailureKind.AnchorMismatch,
                    "ANCHOR MISMATCH! The provided anchor keys were not found in the database. The database history has likely been regenerated (Hash Recalculation Attack).");
            }

            return new AuditVerificationResult
            {
                IsValid = true,
                Failure = AuditFailureKind.None,
                TableName = tableName,
                RecordsChecked = checkedCount,
                AnchorsMatched = matchedAnchors,
                HeadHash = last?.CurrentHash,
                HeadSequence = canonicalSequence,
                Duration = stopwatch.Elapsed,
                Message = checkedCount == 0
                    ? "No audit logs found for the specified table."
                    : $"All verifications passed successfully! The hash chain is intact, and {matchedAnchors} anchors were successfully verified."
            };
        }

        /// <summary>
        /// Verifies every audited table.
        /// </summary>
        /// <param name="anchors">Externally stored anchor hashes per table (optional).</param>
        /// <param name="cancellationToken">A token to cancel the verification.</param>
        public async Task<AuditVerificationReport> VerifyAllAsync(
            IReadOnlyDictionary<string, IEnumerable<string>>? anchors = null,
            CancellationToken cancellationToken = default)
        {
            var results = new List<AuditVerificationResult>();
            foreach (var table in await GetAuditedTablesAsync(cancellationToken).ConfigureAwait(false))
            {
                IEnumerable<string>? tableAnchors = null;
                anchors?.TryGetValue(table, out tableAnchors);
                results.Add(await VerifyTableIntegrityAsync(table, tableAnchors, cancellationToken).ConfigureAwait(false));
            }

            var failed = results.Count(r => !r.IsValid);
            return new AuditVerificationReport
            {
                IsValid = failed == 0,
                Tables = results,
                CompletedUtc = DateTimeOffset.UtcNow,
                Message = results.Count == 0
                    ? "No audit logs found."
                    : failed == 0
                        ? $"All {results.Count} audited tables are intact."
                        : $"TAMPERING SUSPECTED in {failed} of {results.Count} audited tables: " +
                          string.Join(", ", results.Where(r => !r.IsValid).Select(r => r.TableName))
            };
        }

        /// <summary>
        /// The names of all tables that have audit entries or a chain head, in alphabetical order.
        /// A table that lost all of its entries is still listed through its chain head.
        /// </summary>
        /// <param name="cancellationToken">A token to cancel the query.</param>
        public async Task<IReadOnlyList<string>> GetAuditedTablesAsync(CancellationToken cancellationToken = default)
        {
            var fromLogs = await _context.Set<AuditLog>().AsNoTracking().Select(x => x.TableName).Distinct().ToListAsync(cancellationToken).ConfigureAwait(false);
            var fromStates = await _context.Set<AuditChainState>().AsNoTracking().Select(x => x.TableName).ToListAsync(cancellationToken).ConfigureAwait(false);
            return fromLogs.Union(fromStates, StringComparer.Ordinal).OrderBy(x => x, StringComparer.Ordinal).ToList();
        }

        private Task<AuditChainState?> ReadStateAsync(string tableName, CancellationToken cancellationToken) =>
            _context.Set<AuditChainState>().AsNoTracking().FirstOrDefaultAsync(s => s.TableName == tableName, cancellationToken);

        private static bool MatchesAnyKey(IReadOnlyList<byte[]> candidates, AuditLog log)
        {
            foreach (var key in candidates)
            {
                if (AuditHasher.HexEquals(AuditHasher.ComputeRecordHash(key, log), log.CurrentHash))
                {
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Compares the authenticated chain head with the newest entry. Without this step the newest entries could be
        /// deleted and the remaining chain would still look perfect.
        /// </summary>
        private async Task<(AuditFailureKind Kind, string Message)?> CheckHeadAsync(
            string tableName, AuditChainState? state, AuditLog? last, long canonicalSequence, long checkedCount, CancellationToken cancellationToken)
        {
            if (state is null)
            {
                return checkedCount == 0
                    ? null
                    : (AuditFailureKind.ChainStateMissing,
                        $"CHAIN HEAD MISSING! Audit entries exist for table '{tableName}' but its chain head was removed.");
            }

            if (state.Mac is null)
            {
                if (canonicalSequence > 0 || state.LastSequence > 0)
                {
                    return (AuditFailureKind.ChainStateTampered,
                        $"CHAIN HEAD TAMPERED! The signature of the chain head of table '{tableName}' was removed.");
                }
            }
            else
            {
                var candidates = _keys.Candidates(state.KeyId);
                var authentic = candidates.Any(key => AuditHasher.HexEquals(
                    AuditHasher.ComputeStateMac(key, state.TableName, state.LastHash, state.LastSequence, state.KeyId), state.Mac));
                if (!authentic)
                {
                    return (AuditFailureKind.ChainStateTampered,
                        $"CHAIN HEAD TAMPERED! The chain head of table '{tableName}' does not match its signature.");
                }
            }

            var expectedHash = last?.CurrentHash ?? ChainStateStore.GenesisHash;
            if (!string.Equals(state.LastHash, expectedHash, StringComparison.Ordinal) || state.LastSequence != canonicalSequence)
            {
                return (AuditFailureKind.RecordsMissing,
                    $"RECORDS MISSING! The chain head of table '{tableName}' expects sequence {state.LastSequence}, " +
                    $"but the newest audit entry has sequence {canonicalSequence}. The newest entries were deleted.");
            }

            // Entries behind the head were not written by the interceptor. If the head moved in the meantime they are
            // simply newer writes, so the head is read again before judging.
            var headSequence = state.LastSequence;
            var behind = await _context.Set<AuditLog>().AsNoTracking()
                .AnyAsync(x => x.TableName == tableName && x.SequenceNumber > headSequence, cancellationToken).ConfigureAwait(false);
            if (behind)
            {
                var again = await ReadStateAsync(tableName, cancellationToken).ConfigureAwait(false);
                if (again is not null && again.LastSequence == state.LastSequence && again.LastHash == state.LastHash)
                {
                    return (AuditFailureKind.RecordsBeyondHead,
                        $"UNTRACKED RECORDS! Audit entries of table '{tableName}' exist behind the chain head. They were added without going through the audit trail.");
                }
            }

            return null;
        }
    }
}
