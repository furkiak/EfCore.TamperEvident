using System.Diagnostics;
using EfCore.TamperEvident.Configuration;
using EfCore.TamperEvident.Diagnostics;
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
        public Task<AuditVerificationResult> VerifyTableIntegrityAsync(
            string tableName,
            IEnumerable<string>? providedAnchorKeys = null,
            CancellationToken cancellationToken = default)
        {
            ArgumentException.ThrowIfNullOrEmpty(tableName);
            return VerifyAsync(tableName, null, providedAnchorKeys, cancellationToken);
        }

        /// <summary>
        /// Verifies only the entries that were appended to a chain since a checkpoint of an earlier, successful
        /// verification (<see cref="AuditVerificationResult.Checkpoint"/>), and makes sure that the checkpoint entry is
        /// still in place, unchanged. The cost depends on the number of new entries, not on the size of the table.
        /// </summary>
        /// <param name="checkpoint">The checkpoint; it names the table.</param>
        /// <param name="providedAnchorKeys">Anchor hashes received outside of the database (optional).</param>
        /// <param name="cancellationToken">A token to cancel the verification.</param>
        public Task<AuditVerificationResult> VerifyFromCheckpointAsync(
            AuditCheckpoint checkpoint,
            IEnumerable<string>? providedAnchorKeys = null,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(checkpoint);
            ArgumentException.ThrowIfNullOrEmpty(checkpoint.TableName);
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(checkpoint.SequenceNumber);
            return VerifyAsync(checkpoint.TableName, checkpoint, providedAnchorKeys, cancellationToken);
        }

        private async Task<AuditVerificationResult> VerifyAsync(
            string tableName, AuditCheckpoint? checkpoint, IEnumerable<string>? anchors, CancellationToken cancellationToken)
        {
            var stopwatch = Stopwatch.StartNew();
            var validator = new ChainValidator(tableName, _keys, checkpoint, anchors);
            using var activity = TamperEvidentTelemetry.Source.StartActivity(TamperEvidentTelemetry.Activities.Verify);
            activity?.SetTag(TamperEvidentTelemetry.Tags.Table, tableName);
            activity?.SetTag(TamperEvidentTelemetry.Tags.Incremental, checkpoint is not null);

            AuditVerificationResult Result(ChainFailure? failure) => Observe(activity, new AuditVerificationResult
            {
                IsValid = failure is null,
                Failure = failure?.Kind ?? AuditFailureKind.None,
                Message = failure?.Message ?? SuccessMessage(validator),
                TableName = tableName,
                RecordsChecked = validator.RecordsChecked,
                AnchorsMatched = validator.AnchorsMatched,
                RedactedRecords = validator.RedactedRecords,
                FailedRecordId = failure?.EntryId,
                FailedSequence = failure?.Sequence,
                HeadHash = validator.LastHash,
                HeadSequence = validator.Sequence,
                StartedAfter = checkpoint,
                Duration = stopwatch.Elapsed
            });

            // The head is read first. Entries that are appended while the verification runs lie behind it and are
            // left for the next run, which keeps the check consistent on a busy system.
            var state = await ReadStateAsync(tableName, cancellationToken).ConfigureAwait(false);

            IQueryable<AuditLog> query = _context.Set<AuditLog>().AsNoTracking().Where(x => x.TableName == tableName);
            if (checkpoint is not null)
            {
                var failure = await CheckCheckpointAsync(checkpoint, state, cancellationToken).ConfigureAwait(false);
                if (failure is not null)
                {
                    return Result(failure);
                }

                var after = checkpoint.SequenceNumber;
                query = query.Where(x => x.SequenceNumber > after);
            }

            if (state is not null)
            {
                var headSequence = state.LastSequence;
                query = query.Where(x => x.SequenceNumber <= headSequence);
            }

            query = query.OrderBy(x => x.SequenceNumber).ThenBy(x => x.TimestampTicks);

            // Entries are read in batches. Recomputing the hashes is the expensive part, and every entry can be checked on
            // its own: while the next batch is read, the previous one is hashed on all cores. The links between the entries
            // are then checked in chain order.
            using (var hashing = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
            {
                var batch = new List<AuditLog>(BatchSize);
                (List<AuditLog> Batch, Task<EntryCheck[]> Checks)? pending = null;
                try
                {
                    await foreach (var log in query.AsAsyncEnumerable().WithCancellation(cancellationToken).ConfigureAwait(false))
                    {
                        batch.Add(log);
                        if (batch.Count < BatchSize)
                        {
                            continue;
                        }

                        if (pending is { } previous && Link(validator, previous.Batch, await previous.Checks.ConfigureAwait(false)) is { } failure)
                        {
                            return Result(failure);
                        }

                        var full = batch;
                        pending = (full, Task.Run(() => HashAll(full, hashing.Token), hashing.Token));
                        batch = new List<AuditLog>(BatchSize);
                    }

                    if (pending is { } last && Link(validator, last.Batch, await last.Checks.ConfigureAwait(false)) is { } lastFailure)
                    {
                        return Result(lastFailure);
                    }

                    pending = null;
                    if (Link(validator, batch, HashAll(batch, cancellationToken)) is { } rest)
                    {
                        return Result(rest);
                    }
                }
                finally
                {
                    // A failure found early leaves the batch that is being hashed behind: stop it.
                    hashing.Cancel();
                    if (pending is { } abandoned)
                    {
                        await abandoned.Checks.ContinueWith(static _ => { }, CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default)
                            .ConfigureAwait(false);
                    }
                }
            }

            var tail = validator.CheckRedactions()
                ?? validator.CheckHead(state)
                ?? await CheckBeyondHeadAsync(tableName, state, cancellationToken).ConfigureAwait(false);
            if (tail is not null)
            {
                return Result(tail);
            }

            if (validator.UnmatchedAnchors.Count > 0 && checkpoint is not null)
            {
                // Anchors that are older than the checkpoint were verified as part of the chain before.
                await MatchOlderAnchorsAsync(validator, tableName, checkpoint.SequenceNumber, cancellationToken).ConfigureAwait(false);
            }

            if (validator.UnmatchedAnchors.Count > 0)
            {
                return Result(new ChainFailure(AuditFailureKind.AnchorMismatch,
                    "ANCHOR MISMATCH! The provided anchor keys were not found in the database. The database history has likely been regenerated (Hash Recalculation Attack)."));
            }

            return Result(null);
        }

        private const int BatchSize = 512;

        private static AuditVerificationResult Observe(Activity? activity, AuditVerificationResult result)
        {
            var outcome = result.IsValid ? "valid" : result.Failure.ToString();
            if (activity is not null)
            {
                activity.SetTag(TamperEvidentTelemetry.Tags.Entries, result.RecordsChecked);
                activity.SetTag(TamperEvidentTelemetry.Tags.Result, outcome);
                if (!result.IsValid)
                {
                    activity.SetStatus(ActivityStatusCode.Error, result.Message);
                }
            }

            var table = new KeyValuePair<string, object?>(TamperEvidentTelemetry.Tags.Table, result.TableName);
            TamperEvidentTelemetry.Verifications.Add(1, table, new KeyValuePair<string, object?>(TamperEvidentTelemetry.Tags.Result, outcome));
            TamperEvidentTelemetry.EntriesVerified.Add(result.RecordsChecked, table);
            TamperEvidentTelemetry.VerificationDuration.Record(result.Duration.TotalSeconds, table,
                new KeyValuePair<string, object?>(TamperEvidentTelemetry.Tags.Incremental, result.IsIncremental));
            return result;
        }

        private EntryCheck[] HashAll(List<AuditLog> batch, CancellationToken cancellationToken)
        {
            var checks = new EntryCheck[batch.Count];
            if (batch.Count >= 64 && Environment.ProcessorCount > 1)
            {
                Parallel.For(0, batch.Count, new ParallelOptions { CancellationToken = cancellationToken },
                    i => checks[i] = ChainValidator.Check(_keys, batch[i]));
            }
            else
            {
                for (var i = 0; i < batch.Count; i++)
                {
                    checks[i] = ChainValidator.Check(_keys, batch[i]);
                }
            }

            return checks;
        }

        private static ChainFailure? Link(ChainValidator validator, List<AuditLog> batch, EntryCheck[] checks)
        {
            for (var i = 0; i < batch.Count; i++)
            {
                if (validator.Accept(batch[i], checks[i]) is { } failure)
                {
                    return failure;
                }
            }

            return null;
        }

        private static string SuccessMessage(ChainValidator validator)
        {
            if (validator.RecordsChecked == 0)
            {
                return validator.Sequence == 0
                    ? "No audit logs found for the specified table."
                    : "No new audit entries since the checkpoint; the chain head still matches it.";
            }

            var anchors = validator.AnchorsMatched == 1 ? "1 anchor was" : $"{validator.AnchorsMatched} anchors were";
            return "All verifications passed successfully! The hash chain is intact, and " + anchors + " successfully verified.";
        }

        /// <summary>
        /// Verifies every audited table.
        /// </summary>
        /// <param name="anchors">Externally stored anchor hashes per table (optional).</param>
        /// <param name="cancellationToken">A token to cancel the verification.</param>
        public Task<AuditVerificationReport> VerifyAllAsync(
            IReadOnlyDictionary<string, IEnumerable<string>>? anchors = null,
            CancellationToken cancellationToken = default) =>
            VerifyAllAsync(anchors, null, cancellationToken);

        /// <summary>
        /// Verifies every audited table; the tables that have a checkpoint only from that checkpoint on
        /// (see <see cref="VerifyFromCheckpointAsync"/>).
        /// </summary>
        /// <param name="anchors">Externally stored anchor hashes per table (optional).</param>
        /// <param name="checkpoints">Checkpoints per table, usually <see cref="AuditVerificationReport.Checkpoints"/> of the previous run.</param>
        /// <param name="cancellationToken">A token to cancel the verification.</param>
        public async Task<AuditVerificationReport> VerifyAllAsync(
            IReadOnlyDictionary<string, IEnumerable<string>>? anchors,
            IReadOnlyDictionary<string, AuditCheckpoint>? checkpoints,
            CancellationToken cancellationToken = default)
        {
            var results = new List<AuditVerificationResult>();
            foreach (var table in await GetAuditedTablesAsync(cancellationToken).ConfigureAwait(false))
            {
                IEnumerable<string>? tableAnchors = null;
                anchors?.TryGetValue(table, out tableAnchors);
                AuditCheckpoint? checkpoint = null;
                checkpoints?.TryGetValue(table, out checkpoint);

                results.Add(await VerifyAsync(table, checkpoint, tableAnchors, cancellationToken).ConfigureAwait(false));
            }

            return Report(results);
        }

        internal static AuditVerificationReport Report(IReadOnlyList<AuditVerificationResult> results)
        {
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

        // The entry a checkpoint points to must still be there, unchanged, and must not lie behind the head.
        private async Task<ChainFailure?> CheckCheckpointAsync(AuditCheckpoint checkpoint, AuditChainState? state, CancellationToken cancellationToken)
        {
            var table = checkpoint.TableName;
            var sequence = checkpoint.SequenceNumber;
            var stored = await _context.Set<AuditLog>().AsNoTracking()
                .Where(x => x.TableName == table && x.SequenceNumber == sequence)
                .Select(x => new { x.Id, x.CurrentHash })
                .ToListAsync(cancellationToken).ConfigureAwait(false);

            if (stored.Count != 1 || !string.Equals(stored[0].CurrentHash, checkpoint.Hash, StringComparison.Ordinal))
            {
                return new ChainFailure(AuditFailureKind.CheckpointMismatch,
                    $"CHECKPOINT MISMATCH! The entry with sequence {sequence} of table '{table}' was changed or removed after it was verified.",
                    stored.Count == 1 ? stored[0].Id : null, sequence);
            }

            if (state is not null && state.LastSequence < sequence)
            {
                return new ChainFailure(AuditFailureKind.RecordsMissing,
                    $"RECORDS MISSING! The chain head of table '{table}' was moved back from sequence {sequence} to {state.LastSequence}.");
            }

            return null;
        }

        private async Task MatchOlderAnchorsAsync(ChainValidator validator, string table, long upToSequence, CancellationToken cancellationToken)
        {
            foreach (var chunk in validator.UnmatchedAnchors.ToList().Chunk(500))
            {
                var lowered = chunk.Select(a => a.ToLowerInvariant()).ToList();
                var found = await _context.Set<AuditLog>().AsNoTracking()
                    .Where(x => x.TableName == table && x.SequenceNumber <= upToSequence && lowered.Contains(x.CurrentHash))
                    .Select(x => x.CurrentHash)
                    .ToListAsync(cancellationToken).ConfigureAwait(false);
                foreach (var hash in found)
                {
                    validator.MatchAnchor(hash);
                }
            }
        }

        /// <summary>
        /// Entries behind the head were not written by the interceptor. If the head moved in the meantime they are
        /// simply newer writes, so the head is read again before judging.
        /// </summary>
        private async Task<ChainFailure?> CheckBeyondHeadAsync(string tableName, AuditChainState? state, CancellationToken cancellationToken)
        {
            if (state is null)
            {
                return null;
            }

            var headSequence = state.LastSequence;
            var behind = await _context.Set<AuditLog>().AsNoTracking()
                .AnyAsync(x => x.TableName == tableName && x.SequenceNumber > headSequence, cancellationToken).ConfigureAwait(false);
            if (!behind)
            {
                return null;
            }

            var again = await ReadStateAsync(tableName, cancellationToken).ConfigureAwait(false);
            return again is not null && again.LastSequence == state.LastSequence && again.LastHash == state.LastHash
                ? new ChainFailure(AuditFailureKind.RecordsBeyondHead,
                    $"UNTRACKED RECORDS! Audit entries of table '{tableName}' exist behind the chain head. They were added without going through the audit trail.")
                : null;
        }
    }
}
