using EfCore.TamperEvident.Diagnostics;
using EfCore.TamperEvident.Interceptors;
using EfCore.TamperEvident.Models;
using EfCore.TamperEvident.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;

namespace EfCore.TamperEvident.Internal
{
    /// <summary>
    /// Redacts values of audit entries without changing their hashes, and appends the entry that authorizes it.
    /// </summary>
    internal static class AuditRedactor
    {
        private const int IdsPerQuery = 500;

        public static async Task<AuditRedactionResult> RedactAsync(
            DbContext context, IQueryable<AuditLog> selection, AuditRedactionRequest request, CancellationToken cancellationToken)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(request.Reason, nameof(request));
            using var activity = TamperEvidentTelemetry.Source.StartActivity(TamperEvidentTelemetry.Activities.Redact);
            var result = await RedactCoreAsync(context, selection, request, cancellationToken).ConfigureAwait(false);
            activity?.SetTag(TamperEvidentTelemetry.Tags.Entries, result.EntriesRedacted);
            TamperEvidentTelemetry.ValuesRedacted.Add(result.ValuesRedacted);
            return result;
        }

        private static async Task<AuditRedactionResult> RedactCoreAsync(
            DbContext context, IQueryable<AuditLog> selection, AuditRedactionRequest request, CancellationToken cancellationToken)
        {

            var interceptor = FindInterceptor(context);
            var info = AuditModelInfo.Resolve(context, interceptor.Options);

            var targets = await selection.AsNoTracking()
                .Where(l => l.ActionType != AuditActions.Redacted)
                .Select(l => new { l.Id, l.TableName })
                .ToListAsync(cancellationToken).ConfigureAwait(false);
            if (targets.Count == 0)
            {
                return new AuditRedactionResult();
            }

            var byTable = targets
                .GroupBy(t => t.TableName, StringComparer.Ordinal)
                .OrderBy(g => g.Key, StringComparer.Ordinal)
                .Select(g => (Table: g.Key, Ids: g.Select(t => t.Id).Distinct().ToList()))
                .ToList();

            var now = interceptor.Options.TimeProvider.GetUtcNow();
            var userId = interceptor.ResolveUserId(context);
            string? metadata;
            using (AuditScope.WithReason(request.Reason))
            {
                metadata = interceptor.ResolveMetadata(context);
            }

            var work = new Work(context, info, interceptor.Keys, request, userId, metadata, now);

            if (!info.IsRelational || context.Database.CurrentTransaction is not null || System.Transactions.Transaction.Current is not null)
            {
                return await work.RunAsync(byTable, cancellationToken).ConfigureAwait(false);
            }

            await ChainStateStore.EnsureHeadsAsync(context, info, byTable.Select(t => t.Table), now.UtcDateTime, cancellationToken).ConfigureAwait(false);
            return await context.Database.CreateExecutionStrategy().ExecuteAsync(async ct =>
            {
                await using var transaction = await context.Database.BeginTransactionAsync(ct).ConfigureAwait(false);
                var result = await work.RunAsync(byTable, ct).ConfigureAwait(false);
                await transaction.CommitAsync(ct).ConfigureAwait(false);
                return result;
            }, cancellationToken).ConfigureAwait(false);
        }

        internal static TamperEvidentInterceptor FindInterceptor(DbContext context) =>
            context.GetService<IDbContextOptions>().FindExtension<CoreOptionsExtension>()?.Interceptors?
                .OfType<TamperEvidentInterceptor>().FirstOrDefault()
            ?? throw new InvalidOperationException(
                $"The tamper-evident audit trail is not enabled on {context.GetType().Name}. Call UseTamperEvidentAudit(...) on its options.");

        private sealed class Work
        {
            private readonly DbContext _context;
            private readonly AuditModelInfo _info;
            private readonly AuditKeyRing _keys;
            private readonly AuditRedactionRequest _request;
            private readonly string _userId;
            private readonly string? _metadata;
            private readonly DateTimeOffset _now;
            private readonly Func<string, bool> _redactProperty;
            private readonly Func<string, bool> _redactMetadata;

            public Work(
                DbContext context, AuditModelInfo info, AuditKeyRing keys, AuditRedactionRequest request,
                string userId, string? metadata, DateTimeOffset now)
            {
                _context = context;
                _info = info;
                _keys = keys;
                _request = request;
                _userId = userId;
                _metadata = metadata;
                _now = now;
                _redactProperty = Selector(request.Properties, nullMeansAll: true);
                _redactMetadata = Selector(request.MetadataKeys, nullMeansAll: false);
            }

            public async Task<AuditRedactionResult> RunAsync(List<(string Table, List<Guid> Ids)> tables, CancellationToken cancellationToken)
            {
                var redactedEntries = 0;
                var redactedValues = 0;
                var authorizations = new List<Guid>();
                var notRedactable = new List<Guid>();

                foreach (var (table, ids) in tables)
                {
                    // The head is locked first: the redaction entry is appended in chain order, like any other write.
                    var chain = await ChainStateStore.LockAsync(_context, _info, table, _now.UtcDateTime, cancellationToken).ConfigureAwait(false);

                    var entries = new List<AuditLog>(ids.Count);
                    foreach (var chunk in ids.Chunk(IdsPerQuery))
                    {
                        entries.AddRange(await _context.Set<AuditLog>().AsNoTracking().Where(l => chunk.Contains(l.Id))
                            .ToListAsync(cancellationToken).ConfigureAwait(false));
                    }

                    var authorized = new SortedDictionary<string, string[]>(StringComparer.Ordinal);
                    var recordIds = new HashSet<string>(StringComparer.Ordinal);
                    var changed = new List<AuditLog>();

                    // Everything is computed (and every entry verified) before anything is written.

                    foreach (var entry in entries.OrderBy(e => e.SequenceNumber))
                    {
                        if (entry.HashVersion != AuditHashVersion.Redactable)
                        {
                            notRedactable.Add(entry.Id);
                            continue;
                        }

                        var originalRecordId = entry.RecordId;
                        var fields = Redact(entry);
                        if (fields.Count == 0)
                        {
                            continue;
                        }

                        recordIds.Add(originalRecordId);
                        authorized[entry.Id.ToString("D")] = fields.Order(StringComparer.Ordinal).ToArray();
                        changed.Add(entry);
                        redactedValues += fields.Count;
                    }

                    if (changed.Count == 0)
                    {
                        continue;
                    }

                    var authorization = Authorize(table, chain, authorized, recordIds);
                    authorizations.Add(authorization.Id);
                    redactedEntries += changed.Count;

                    if (_info.Commands is { } commands)
                    {
                        foreach (var entry in changed)
                        {
                            await _context.Database.ExecuteSqlRawAsync(commands.UpdateRedacted, new object?[]
                            {
                                entry.RecordId, entry.UserId, entry.OldValues, entry.NewValues, entry.Metadata, entry.Id
                            }!, cancellationToken).ConfigureAwait(false);
                        }

                        await AuditWriter.WriteAsync(_context, _info, new[] { authorization }, new[] { chain }, cancellationToken).ConfigureAwait(false);
                    }
                    else
                    {
                        foreach (var entry in changed)
                        {
                            // The context may still track the entry since the save that wrote it.
                            var tracked = _context.ChangeTracker.Entries<AuditLog>().FirstOrDefault(e => e.Entity.Id == entry.Id);
                            if (tracked is null)
                            {
                                _context.Set<AuditLog>().Update(entry);
                            }
                            else
                            {
                                tracked.CurrentValues.SetValues(entry);
                            }
                        }

                        _context.Set<AuditLog>().Add(authorization);
                        await _context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
                    }
                }

                return new AuditRedactionResult
                {
                    EntriesRedacted = redactedEntries,
                    ValuesRedacted = redactedValues,
                    RedactionEntryIds = authorizations,
                    NotRedactable = notRedactable
                };
            }

            // Replaces the selected values of the entry (in place) and returns the names of the fields that changed.
            private List<string> Redact(AuditLog entry)
            {
                var key = KeyOf(entry);
                var fields = new List<string>();

                if (_request.RedactRecordId && !AuditHasher.IsTextMarker(entry.RecordId))
                {
                    entry.RecordId = AuditHasher.RedactText(key, entry.Id, AuditHasher.RecordIdField, entry.RecordId);
                    fields.Add(AuditHasher.RecordIdField);
                }

                if (_request.RedactUserId && !AuditHasher.IsTextMarker(entry.UserId))
                {
                    entry.UserId = AuditHasher.RedactText(key, entry.Id, AuditHasher.UserIdField, entry.UserId);
                    fields.Add(AuditHasher.UserIdField);
                }

                entry.OldValues = AuditHasher.RedactPayload(key, entry.Id, AuditHasher.OldValuesKind, entry.OldValues, _redactProperty, fields);
                entry.NewValues = AuditHasher.RedactPayload(key, entry.Id, AuditHasher.NewValuesKind, entry.NewValues, _redactProperty, fields);
                entry.Metadata = AuditHasher.RedactPayload(key, entry.Id, AuditHasher.MetadataKind, entry.Metadata, _redactMetadata, fields);

                // Redaction must never change the hash. If it did, writing it would break the chain.
                if (fields.Count > 0 && !AuditHasher.Verify(key, entry))
                {
                    throw new InvalidOperationException($"Redacting audit entry {entry.Id} would change its hash; nothing was redacted.");
                }

                return fields;
            }

            private AuditKey KeyOf(AuditLog entry)
            {
                foreach (var key in _keys.Candidates(entry.KeyId))
                {
                    if (AuditHasher.Verify(key, entry))
                    {
                        return key;
                    }
                }

                throw new AuditTrailException(
                    $"Audit entry {entry.Id} of table '{entry.TableName}' does not match its hash. A manipulated entry is not redacted: " +
                    "verify the table and investigate first.");
            }

            private AuditLog Authorize(string table, AuditChainState chain, SortedDictionary<string, string[]> authorized, HashSet<string> recordIds)
            {
                var key = _keys.Current;
                var sequence = chain.LastSequence + 1;
                var log = new AuditLog
                {
                    Id = Guid.NewGuid(),
                    TableName = table,
                    RecordId = recordIds.Count == 1 && !_request.RedactRecordId ? recordIds.First() : "*",
                    ActionType = AuditActions.Redacted,
                    OldValues = null,
                    NewValues = AuditSerializer.Serialize(new[] { KeyValuePair.Create("entries", (object?)authorized) }),
                    Metadata = _metadata,
                    UserId = _userId,
                    TimestampTicks = _now.UtcTicks,
                    SequenceNumber = sequence,
                    HashVersion = AuditHashVersion.Current,
                    KeyId = key.Id,
                    PreviousHash = chain.LastHash,
                    CurrentHash = string.Empty
                };
                log.CurrentHash = AuditHasher.ComputeRecordHash(key, log);

                chain.LastHash = log.CurrentHash;
                chain.LastSequence = sequence;
                chain.LastModified = _now.UtcDateTime;
                chain.UnanchoredCount++;
                chain.KeyId = key.Id;
                chain.Mac = AuditHasher.ComputeStateMac(key, chain.TableName, chain.LastHash, chain.LastSequence, key.Id);
                return log;
            }

            private static Func<string, bool> Selector(IReadOnlyCollection<string>? names, bool nullMeansAll)
            {
                if (names is null)
                {
                    return _ => nullMeansAll;
                }

                if (names.Contains(AuditRedactionRequest.All))
                {
                    return _ => true;
                }

                var set = new HashSet<string>(names, StringComparer.OrdinalIgnoreCase);
                return set.Contains;
            }
        }
    }
}
