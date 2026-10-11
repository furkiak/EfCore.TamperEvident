using System.Data.Common;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using EfCore.TamperEvident.Configuration;
using EfCore.TamperEvident.Diagnostics;
using EfCore.TamperEvident.Internal;
using EfCore.TamperEvident.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.Logging;

namespace EfCore.TamperEvident.Interceptors
{
    /// <summary>
    /// Seals every audited change into a per-table HMAC hash chain, atomically with the change itself.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Saving happens in two phases. Before the data is written the interceptor captures what is about to change and
    /// makes sure a transaction exists (it starts one unless the caller already has one). After the data is written,
    /// and the database has generated its keys, the chain head of every affected table is locked, the new entries are
    /// chained and written, and the transaction is committed. Both <c>SaveChanges</c> and <c>SaveChangesAsync</c> are supported.
    /// </para>
    /// <para>
    /// The interceptor is thread-safe and can be shared by many <see cref="DbContext"/> instances.
    /// The options are read when the interceptor is created.
    /// </para>
    /// </remarks>
    public class TamperEvidentInterceptor : SaveChangesInterceptor, IDbTransactionInterceptor
    {
        private readonly TamperEvidentOptions _options;
        private readonly AuditKeyRing _keys;
        private readonly AuditEntryReader _reader;
        private readonly AnchorDispatcher _dispatcher;
        private readonly ConditionalWeakTable<DbContext, AuditSession> _sessions = new();
        private readonly ConditionalWeakTable<DbContext, QueuedAnchors> _queuedAnchors = new();

        /// <summary>Creates the interceptor. The options are validated immediately.</summary>
        /// <param name="options">The configuration.</param>
        /// <exception cref="InvalidOperationException">The options cannot produce a trustworthy audit trail (for example no secret key).</exception>
        public TamperEvidentInterceptor(TamperEvidentOptions options)
        {
            ArgumentNullException.ThrowIfNull(options);
            options.Validate();

            _options = options;
            _keys = AuditKeyRing.Create(options);
            _reader = new AuditEntryReader(options, _keys);
            _dispatcher = new AnchorDispatcher(options);
        }

        /// <summary>The options the interceptor was created with.</summary>
        internal TamperEvidentOptions Options => _options;

        internal AuditKeyRing Keys => _keys;

        internal AuditEntryReader Reader => _reader;

        /// <summary>
        /// Waits until all anchors that are being delivered in the background reached their publisher.
        /// Call it before the process exits, for example from <c>IHostApplicationLifetime.ApplicationStopping</c>.
        /// </summary>
        /// <param name="cancellationToken">A token to stop waiting.</param>
        public Task FlushAnchorsAsync(CancellationToken cancellationToken = default) => _dispatcher.FlushAsync(cancellationToken);

        #region SaveChanges (phase one)

        /// <inheritdoc />
        public override InterceptionResult<int> SavingChanges(DbContextEventData eventData, InterceptionResult<int> result)
        {
            var context = eventData.Context;
            var session = context is null ? null : Prepare(context);
            if (session is null)
            {
                return result;
            }

            if (RequiresStrategyTakeover(context!, session))
            {
                _sessions.Remove(context!);
                var saved = context!.Database.CreateExecutionStrategy().Execute(() =>
                {
                    ChainStateStore.EnsureHeads(context, session.Info, TablesOf(session), NowUtc());
                    using var transaction = context.Database.BeginTransaction();
                    var count = context.SaveChanges();
                    transaction.Commit();
                    return count;
                });
                return InterceptionResult<int>.SuppressWithResult(saved);
            }

            try
            {
                BeginTransaction(context!, session);
            }
            catch
            {
                Abort(context!, session);
                throw;
            }

            return result;
        }

        /// <inheritdoc />
        public override async ValueTask<InterceptionResult<int>> SavingChangesAsync(
            DbContextEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            var context = eventData.Context;
            var session = context is null ? null : Prepare(context);
            if (session is null)
            {
                return result;
            }

            if (RequiresStrategyTakeover(context!, session))
            {
                _sessions.Remove(context!);
                var saved = await context!.Database.CreateExecutionStrategy().ExecuteAsync(async ct =>
                {
                    await ChainStateStore.EnsureHeadsAsync(context, session.Info, TablesOf(session), NowUtc(), ct).ConfigureAwait(false);
                    await using var transaction = await context.Database.BeginTransactionAsync(ct).ConfigureAwait(false);
                    var count = await context.SaveChangesAsync(ct).ConfigureAwait(false);
                    await transaction.CommitAsync(ct).ConfigureAwait(false);
                    return count;
                }, cancellationToken).ConfigureAwait(false);
                return InterceptionResult<int>.SuppressWithResult(saved);
            }

            try
            {
                await BeginTransactionAsync(context!, session, cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                await AbortAsync(context!, session).ConfigureAwait(false);
                throw;
            }

            return result;
        }

        /// <summary>
        /// EF Core calls this interceptor outside of the execution strategy but saves inside it. A strategy that retries
        /// on failure (<c>EnableRetryOnFailure</c>) refuses to start when a transaction already exists, so a transaction
        /// cannot simply be opened here. Instead the whole save, together with its transaction, is run as one retriable
        /// unit and the original save is suppressed. The nested save then runs inside that transaction, where the
        /// audit entries are written just like in a caller-owned transaction.
        /// </summary>
        private static bool RequiresStrategyTakeover(DbContext context, AuditSession session) =>
            session.Info.IsRelational
            && context.Database.CurrentTransaction is null
            && System.Transactions.Transaction.Current is null
            && context.Database.CreateExecutionStrategy().RetriesOnFailure;

        private AuditSession? Prepare(DbContext context)
        {
            if (_sessions.TryGetValue(context, out var existing))
            {
                if (existing.IsWritingAudit)
                {
                    // The nested save that writes the audit entries themselves.
                    return null;
                }

                // A session that was never completed (the earlier save was interrupted).
                Abort(context, existing);
            }

            var entries = context.ChangeTracker.Entries()
                .Where(e => e.State is EntityState.Added or EntityState.Modified or EntityState.Deleted)
                .ToList();
            if (entries.Count == 0)
            {
                return null;
            }

            var preps = new List<AuditPrep>();
            foreach (var entry in entries)
            {
                if (!_reader.ShouldAudit(entry, out var tableName))
                {
                    continue;
                }

                var prep = new AuditPrep(entry, tableName, entry.State.ToString());
                switch (entry.State)
                {
                    case EntityState.Modified:
                        var change = _reader.ReadModified(entry, tableName);
                        if (change is null)
                        {
                            continue;
                        }

                        prep.Action = change.Value.Action;
                        prep.OldValues = change.Value.OldValues;
                        prep.NewValues = change.Value.NewValues;
                        prep.RecordId = AuditEntryReader.FormatRecordId(entry, original: true);
                        break;
                    case EntityState.Deleted:
                        prep.OldValues = _reader.ReadAll(entry, tableName, original: true);
                        prep.RecordId = AuditEntryReader.FormatRecordId(entry, original: true);
                        break;
                    default:
                        // Inserts are read in phase two, when keys and defaults generated by the database are known.
                        break;
                }

                preps.Add(prep);
            }

            if (preps.Count == 0)
            {
                return null;
            }

            var session = new AuditSession(AuditModelInfo.Resolve(context, _options), ResolveUserId(context), ResolveMetadata(context), entries);
            session.Preps.AddRange(preps);
            _sessions.AddOrUpdate(context, session);
            return session;
        }

        internal string ResolveUserId(DbContext context)
        {
            var user = AuditScope.CurrentUserId ?? _options.UserIdProvider?.Invoke(context);
            if (string.IsNullOrWhiteSpace(user))
            {
                user = _options.DefaultUserId;
            }

            return user.Length > 256 ? user[..256] : user;
        }

        /// <summary>The trace id, the metadata of the provider and of the active scopes, as deterministic JSON.</summary>
        internal string? ResolveMetadata(DbContext context)
        {
            Dictionary<string, object?>? values = null;

            if (_options.CaptureTraceId && Activity.Current is { IdFormat: ActivityIdFormat.W3C } activity)
            {
                (values ??= new(StringComparer.Ordinal))["traceId"] = activity.TraceId.ToHexString();
            }

            if (_options.MetadataProvider?.Invoke(context) is { } provided)
            {
                foreach (var (key, value) in provided)
                {
                    if (!string.IsNullOrWhiteSpace(key))
                    {
                        (values ??= new(StringComparer.Ordinal))[key] = value;
                    }
                }
            }

            foreach (var (key, value) in AuditScope.CurrentMetadata)
            {
                (values ??= new(StringComparer.Ordinal))[key] = value;
            }

            return values is null ? null : AuditSerializer.Serialize(values);
        }

        private DateTime NowUtc() => _options.TimeProvider.GetUtcNow().UtcDateTime;

        private static List<string> TablesOf(AuditSession session) => OrderedTables(session);

        private void BeginTransaction(DbContext context, AuditSession session)
        {
            if (!session.Info.IsRelational)
            {
                return;
            }

            if (context.Database.CurrentTransaction is { } existing)
            {
                session.Transaction = existing;
            }
            else if (System.Transactions.Transaction.Current is not null)
            {
                session.UsesAmbientTransaction = true;
            }
            else
            {
                ChainStateStore.EnsureHeads(context, session.Info, TablesOf(session), NowUtc());
                session.Transaction = context.Database.BeginTransaction();
                session.OwnsTransaction = true;
            }
        }

        private async Task BeginTransactionAsync(DbContext context, AuditSession session, CancellationToken cancellationToken)
        {
            if (!session.Info.IsRelational)
            {
                return;
            }

            if (context.Database.CurrentTransaction is { } existing)
            {
                session.Transaction = existing;
            }
            else if (System.Transactions.Transaction.Current is not null)
            {
                session.UsesAmbientTransaction = true;
            }
            else
            {
                await ChainStateStore.EnsureHeadsAsync(context, session.Info, TablesOf(session), NowUtc(), cancellationToken).ConfigureAwait(false);
                session.Transaction = await context.Database.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
                session.OwnsTransaction = true;
            }
        }

        #endregion

        #region SaveChanges (phase two)

        /// <inheritdoc />
        public override int SavedChanges(SaveChangesCompletedEventData eventData, int result)
        {
            var context = eventData.Context;
            if (context is null || !_sessions.TryGetValue(context, out var session) || session.IsWritingAudit)
            {
                return result;
            }

            session.IsWritingAudit = true;
            using var activity = TamperEvidentTelemetry.Source.StartActivity(TamperEvidentTelemetry.Activities.Seal);
            var started = Stopwatch.GetTimestamp();
            try
            {
                var now = _options.TimeProvider.GetUtcNow();
                var chains = new Dictionary<string, AuditChainState>(StringComparer.Ordinal);
                foreach (var table in OrderedTables(session))
                {
                    chains[table] = ChainStateStore.Lock(context, session.Info, table, now.UtcDateTime);
                }

                var batch = Seal(session, chains, now);

                if (session.Info.IsRelational)
                {
                    AuditWriter.Write(context, session.Info, batch.Logs, chains.Values.ToList());
                }
                else
                {
                    SaveThroughChangeTracker(context, session, batch.Logs, () => context.SaveChanges());
                }

                if (session.OwnsTransaction)
                {
                    session.Transaction!.Commit();
                    session.Transaction.Dispose();
                    session.Transaction = null;
                }

                _sessions.Remove(context);
                Record(activity, batch.Logs, started);
                ScheduleAnchors(context, session, batch.Anchors).GetAwaiter().GetResult();
            }
            catch (Exception ex)
            {
                activity?.SetStatus(ActivityStatusCode.Error, ex.Message);
                Abort(context, session);
                throw Wrap(ex);
            }

            return result;
        }

        /// <inheritdoc />
        public override async ValueTask<int> SavedChangesAsync(
            SaveChangesCompletedEventData eventData, int result, CancellationToken cancellationToken = default)
        {
            var context = eventData.Context;
            if (context is null || !_sessions.TryGetValue(context, out var session) || session.IsWritingAudit)
            {
                return result;
            }

            session.IsWritingAudit = true;
            using var activity = TamperEvidentTelemetry.Source.StartActivity(TamperEvidentTelemetry.Activities.Seal);
            var started = Stopwatch.GetTimestamp();
            try
            {
                var now = _options.TimeProvider.GetUtcNow();
                var chains = new Dictionary<string, AuditChainState>(StringComparer.Ordinal);
                foreach (var table in OrderedTables(session))
                {
                    chains[table] = await ChainStateStore.LockAsync(context, session.Info, table, now.UtcDateTime, cancellationToken)
                        .ConfigureAwait(false);
                }

                var batch = Seal(session, chains, now);

                if (session.Info.IsRelational)
                {
                    await AuditWriter.WriteAsync(context, session.Info, batch.Logs, chains.Values.ToList(), cancellationToken).ConfigureAwait(false);
                }
                else
                {
                    var suspended = SuspendPending(session);
                    try
                    {
                        context.Set<AuditLog>().AddRange(batch.Logs);
                        await context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
                    }
                    finally
                    {
                        ResumePending(suspended);
                    }
                }

                if (session.OwnsTransaction)
                {
                    await session.Transaction!.CommitAsync(cancellationToken).ConfigureAwait(false);
                    await session.Transaction.DisposeAsync().ConfigureAwait(false);
                    session.Transaction = null;
                }

                _sessions.Remove(context);
                Record(activity, batch.Logs, started);
                await ScheduleAnchors(context, session, batch.Anchors, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                activity?.SetStatus(ActivityStatusCode.Error, ex.Message);
                await AbortAsync(context, session).ConfigureAwait(false);
                throw Wrap(ex);
            }

            return result;
        }

        private static void Record(Activity? activity, List<AuditLog> logs, long started)
        {
            if (activity is not null)
            {
                activity.SetTag(TamperEvidentTelemetry.Tags.Entries, logs.Count);
                activity.SetTag(TamperEvidentTelemetry.Tags.Table, string.Join(",", logs.Select(l => l.TableName).Distinct(StringComparer.Ordinal)));
            }

            if (TamperEvidentTelemetry.SealDuration.Enabled)
            {
                TamperEvidentTelemetry.SealDuration.Record(Stopwatch.GetElapsedTime(started).TotalSeconds);
            }

            if (TamperEvidentTelemetry.EntriesSealed.Enabled)
            {
                // The entries are grouped by table.
                for (var start = 0; start < logs.Count;)
                {
                    var end = start;
                    while (end < logs.Count && string.Equals(logs[end].TableName, logs[start].TableName, StringComparison.Ordinal))
                    {
                        end++;
                    }

                    TamperEvidentTelemetry.EntriesSealed.Add(end - start, new KeyValuePair<string, object?>(TamperEvidentTelemetry.Tags.Table, logs[start].TableName));
                    start = end;
                }
            }
        }

        // Cancellation is passed through; everything else becomes a non-transient AuditTrailException.
        private static Exception Wrap(Exception exception) => exception switch
        {
            OperationCanceledException or AuditTrailException => exception,
            _ => new AuditTrailException(
                "The audit trail could not be written, so the change was not persisted: " + exception.Message, exception)
        };

        // The in-memory provider has no SQL: the entries go through the change tracker like any other entity.
        private static void SaveThroughChangeTracker(DbContext context, AuditSession session, List<AuditLog> logs, Action save)
        {
            var suspended = SuspendPending(session);
            try
            {
                context.Set<AuditLog>().AddRange(logs);
                save();
            }
            finally
            {
                ResumePending(suspended);
            }
        }

        // Chain heads are always locked in the same order, which rules out deadlocks between concurrent saves.
        private static List<string> OrderedTables(AuditSession session) =>
            session.Preps.Select(p => p.TableName).Distinct(StringComparer.Ordinal).OrderBy(t => t, StringComparer.Ordinal).ToList();

        /// <summary>Chains the captured changes onto the (locked) chain heads.</summary>
        private SealedBatch Seal(AuditSession session, Dictionary<string, AuditChainState> chains, DateTimeOffset now)
        {
            var key = _keys.Current;
            var keyId = key.Id;
            var anchors = new List<AuditAnchor>();
            var logs = new List<AuditLog>(session.Preps.Count);

            foreach (var group in session.Preps.GroupBy(p => p.TableName, StringComparer.Ordinal).OrderBy(g => g.Key, StringComparer.Ordinal))
            {
                var chain = chains[group.Key];
                var previousHash = chain.LastHash;
                var sequence = chain.LastSequence;

                foreach (var prep in group)
                {
                    if (prep.RecordId is null)
                    {
                        prep.RecordId = AuditEntryReader.FormatRecordId(prep.Entry, original: false);
                        prep.NewValues = _reader.ReadAll(prep.Entry, prep.TableName, original: false);
                    }

                    sequence++;
                    var log = new AuditLog
                    {
                        Id = Guid.NewGuid(),
                        TableName = prep.TableName,
                        RecordId = prep.RecordId!,
                        ActionType = prep.Action,
                        OldValues = prep.OldValues,
                        NewValues = prep.NewValues,
                        Metadata = session.Metadata,
                        UserId = session.UserId,
                        TimestampTicks = now.UtcTicks,
                        SequenceNumber = sequence,
                        HashVersion = AuditHashVersion.Current,
                        KeyId = keyId,
                        PreviousHash = previousHash,
                        CurrentHash = string.Empty
                    };
                    log.CurrentHash = AuditHasher.ComputeRecordHash(key, log);
                    logs.Add(log);
                    previousHash = log.CurrentHash;

                    chain.UnanchoredCount++;
                    if (_options.AnchorThreshold > 0 && chain.UnanchoredCount >= _options.AnchorThreshold)
                    {
                        anchors.Add(new AuditAnchor(group.Key, log.CurrentHash, sequence, chain.UnanchoredCount, now));
                        chain.UnanchoredCount = 0;
                    }
                }

                chain.LastHash = previousHash;
                chain.LastSequence = sequence;
                chain.LastModified = now.UtcDateTime;
                chain.KeyId = keyId;
                chain.Mac = AuditHasher.ComputeStateMac(key, chain.TableName, chain.LastHash, chain.LastSequence, keyId);
            }

            return new SealedBatch(logs, anchors);
        }

        private sealed class SealedBatch
        {
            public SealedBatch(List<AuditLog> logs, List<AuditAnchor> anchors)
            {
                Logs = logs;
                Anchors = anchors;
            }

            public List<AuditLog> Logs { get; }

            public List<AuditAnchor> Anchors { get; }
        }

        // SaveChanges(acceptAllChangesOnSuccess: false) leaves the audited entities pending. They must not be saved
        // a second time by the nested save that writes the audit entries, so they are parked and restored afterwards.
        private static List<(EntityEntry Entry, EntityState State)>? SuspendPending(AuditSession session)
        {
            if (session.PendingEntries.Count == 0 || !IsPending(session.PendingEntries[0].State))
            {
                return null;
            }

            var suspended = session.PendingEntries
                .Where(e => IsPending(e.State))
                .Select(e => (e, e.State))
                .ToList();
            foreach (var (entry, _) in suspended)
            {
                entry.State = EntityState.Unchanged;
            }

            return suspended;
        }

        private static void ResumePending(List<(EntityEntry Entry, EntityState State)>? suspended)
        {
            if (suspended is null)
            {
                return;
            }

            foreach (var (entry, state) in suspended)
            {
                entry.State = state;
            }
        }

        private static bool IsPending(EntityState state) => state is EntityState.Added or EntityState.Modified or EntityState.Deleted;

        #endregion

        #region Failure handling

        /// <inheritdoc />
        public override void SaveChangesFailed(DbContextErrorEventData eventData)
        {
            if (eventData.Context is { } context)
            {
                Abort(context);
            }
        }

        /// <inheritdoc />
        public override async Task SaveChangesFailedAsync(DbContextErrorEventData eventData, CancellationToken cancellationToken = default)
        {
            if (eventData.Context is { } context)
            {
                await AbortAsync(context).ConfigureAwait(false);
            }
        }

        /// <inheritdoc />
        public override void SaveChangesCanceled(DbContextEventData eventData)
        {
            if (eventData.Context is { } context)
            {
                Abort(context);
            }
        }

        /// <inheritdoc />
        public override async Task SaveChangesCanceledAsync(DbContextEventData eventData, CancellationToken cancellationToken = default)
        {
            if (eventData.Context is { } context)
            {
                await AbortAsync(context).ConfigureAwait(false);
            }
        }

        // Rolls back the transaction this interceptor started. A transaction that belongs to the caller is left alone.
        private void Abort(DbContext context, AuditSession? session = null)
        {
            if (session is null && !_sessions.TryGetValue(context, out session))
            {
                return;
            }

            _sessions.Remove(context);
            var transaction = session.Transaction;
            if (!session.OwnsTransaction || transaction is null)
            {
                return;
            }

            session.Transaction = null;
            try
            {
                transaction.Rollback();
            }
            catch (Exception)
            {
                // The connection may be gone already; disposing below releases whatever is left.
            }

            transaction.Dispose();
        }

        private async Task AbortAsync(DbContext context, AuditSession? session = null)
        {
            if (session is null && !_sessions.TryGetValue(context, out session))
            {
                return;
            }

            _sessions.Remove(context);
            var transaction = session.Transaction;
            if (!session.OwnsTransaction || transaction is null)
            {
                return;
            }

            session.Transaction = null;
            try
            {
                await transaction.RollbackAsync().ConfigureAwait(false);
            }
            catch (Exception)
            {
                // The connection may be gone already; disposing below releases whatever is left.
            }

            await transaction.DisposeAsync().ConfigureAwait(false);
        }

        #endregion

        #region Anchors

        // An anchor must only leave the process once the entries it vouches for are committed.
        private Task ScheduleAnchors(DbContext context, AuditSession session, List<AuditAnchor> anchors, CancellationToken cancellationToken = default)
        {
            if (anchors.Count == 0 || !_dispatcher.IsEnabled)
            {
                return Task.CompletedTask;
            }

            // Created now, while the context is alive: delivery may happen after it was disposed.
            var logger = LoggerOf(context);

            if (session.OwnsTransaction || !session.Info.IsRelational)
            {
                return _dispatcher.DispatchAsync(anchors, logger, cancellationToken);
            }

            if (session.UsesAmbientTransaction)
            {
                System.Transactions.Transaction.Current!.TransactionCompleted += (_, e) =>
                {
                    if (e.Transaction?.TransactionInformation.Status == System.Transactions.TransactionStatus.Committed)
                    {
                        _ = _dispatcher.DispatchAsync(anchors, logger, CancellationToken.None);
                    }
                };
                return Task.CompletedTask;
            }

            // The caller owns the transaction: hold the anchors back until it commits (or drop them on rollback).
            var queue = _queuedAnchors.GetValue(context, _ => new QueuedAnchors(logger));
            queue.Anchors.AddRange(anchors);
            return Task.CompletedTask;
        }

        private ILogger? LoggerOf(DbContext context) =>
            (_options.LoggerFactory ?? context.GetService<ILoggerFactory>())?.CreateLogger("EfCore.TamperEvident.Anchors");

        private QueuedAnchors? TakeQueued(DbContext? context)
        {
            if (context is null || !_queuedAnchors.TryGetValue(context, out var queued))
            {
                return null;
            }

            _queuedAnchors.Remove(context);
            return queued.Anchors.Count == 0 ? null : queued;
        }

        private sealed class QueuedAnchors
        {
            public QueuedAnchors(ILogger? logger) => Logger = logger;

            public ILogger? Logger { get; }

            public List<AuditAnchor> Anchors { get; } = new();
        }

        /// <inheritdoc />
        public void TransactionCommitted(DbTransaction transaction, TransactionEndEventData eventData)
        {
            var queued = TakeQueued(eventData.Context);
            if (queued is not null)
            {
                _dispatcher.DispatchAsync(queued.Anchors, queued.Logger, CancellationToken.None).GetAwaiter().GetResult();
            }
        }

        /// <inheritdoc />
        public Task TransactionCommittedAsync(DbTransaction transaction, TransactionEndEventData eventData, CancellationToken cancellationToken = default)
        {
            var queued = TakeQueued(eventData.Context);
            return queued is null
                ? Task.CompletedTask
                : _dispatcher.DispatchAsync(queued.Anchors, queued.Logger, cancellationToken);
        }

        /// <inheritdoc />
        public void TransactionRolledBack(DbTransaction transaction, TransactionEndEventData eventData) => TakeQueued(eventData.Context);

        /// <inheritdoc />
        public Task TransactionRolledBackAsync(DbTransaction transaction, TransactionEndEventData eventData, CancellationToken cancellationToken = default)
        {
            TakeQueued(eventData.Context);
            return Task.CompletedTask;
        }

        #endregion
    }
}
