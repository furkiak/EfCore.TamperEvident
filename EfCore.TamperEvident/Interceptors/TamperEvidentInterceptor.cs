using EfCore.TamperEvident.Configuration;
using EfCore.TamperEvident.Models;
using EfCore.TamperEvident.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.EntityFrameworkCore.Storage;
using System.Runtime.CompilerServices;

namespace EfCore.TamperEvident.Interceptors
{
    internal class AuditContextState
    {
        public IDbContextTransaction Transaction { get; set; }
        public bool IsTransactionOwner { get; set; }
        public bool IsSavingLogs { get; set; }
        public List<AuditEntryPrep> Preps { get; set; } = new();
    }
    internal class AuditEntryPrep
    {
        public Microsoft.EntityFrameworkCore.ChangeTracking.EntityEntry Entry { get; set; }
        public string TableName { get; set; }
        public EntityState Action { get; set; }
        public string OldValues { get; set; }
        public string NewValues { get; set; }
    }
    public class TamperEvidentInterceptor : SaveChangesInterceptor
    {
        private readonly TamperEvidentOptions _options;
        private readonly AnchorService _anchorService;
        private static readonly ConditionalWeakTable<DbContext, AuditContextState> _stateMap = new();
        public TamperEvidentInterceptor(TamperEvidentOptions options)
        {
            _options = options;
            _anchorService = new AnchorService(options);
        }
        public override async ValueTask<InterceptionResult<int>> SavingChangesAsync(
            DbContextEventData eventData, InterceptionResult<int> result, CancellationToken ct = default)
        {
            var context = eventData.Context;
            if (context == null) return result;

            if (_stateMap.TryGetValue(context, out var existingState) && existingState.IsSavingLogs)
                return result;

            var entries = context.ChangeTracker.Entries()
                .Where(e => e.State == EntityState.Added || e.State == EntityState.Modified || e.State == EntityState.Deleted)
                .ToList();

            if (!entries.Any()) return result;


            var state = new AuditContextState();
            _stateMap.AddOrUpdate(context, state);


            state.Transaction = context.Database.CurrentTransaction?.GetDbTransaction() == null
                                ? await context.Database.BeginTransactionAsync(ct)
                                : context.Database.CurrentTransaction;
            state.IsTransactionOwner = context.Database.CurrentTransaction == state.Transaction;


            foreach (var entry in entries)
            {
                string tableName = entry.Metadata.GetTableName();
                if (tableName == "AuditLogs" || tableName == "AuditChainStates") continue;
                if (_options.ExcludedTables.Contains(tableName)) continue;

                if (entry.State == EntityState.Added && !_options.TrackedOperations.HasFlag(AuditOperation.Insert)) continue;
                if (entry.State == EntityState.Modified && !_options.TrackedOperations.HasFlag(AuditOperation.Update)) continue;
                if (entry.State == EntityState.Deleted && !_options.TrackedOperations.HasFlag(AuditOperation.Delete)) continue;

                state.Preps.Add(new AuditEntryPrep
                {
                    Entry = entry,
                    TableName = tableName,
                    Action = entry.State,
                    OldValues = entry.State == EntityState.Added ? null : SecurityHelper.SerializeDeterministic(entry.OriginalValues.ToObject()),
                    NewValues = entry.State == EntityState.Deleted ? null : SecurityHelper.SerializeDeterministic(entry.CurrentValues.ToObject())
                });
            }

            return result;
        }


        public override async ValueTask<int> SavedChangesAsync(
            SaveChangesCompletedEventData eventData, int result, CancellationToken ct = default)
        {
            var context = eventData.Context;
            if (!_stateMap.TryGetValue(context, out var state) || state.IsSavingLogs || !state.Preps.Any())
                return result;


            state.IsSavingLogs = true;
            var tablesToAnchor = new Dictionary<string, AuditChainState>();

            foreach (var prep in state.Preps)
            {

                string primaryKey = prep.Entry.Properties.FirstOrDefault(x => x.Metadata.IsPrimaryKey())?.CurrentValue?.ToString() ?? "N/A";

                string lockQuery = SecurityHelper.GetLockQuery(_options.DbProvider, prep.TableName);
                var chainState = await context.Set<AuditChainState>().FromSqlRaw(lockQuery).FirstOrDefaultAsync(ct);

                if (chainState == null)
                {
                    chainState = new AuditChainState { TableName = prep.TableName, LastHash = "GENESIS", UnanchoredCount = 0 };
                    context.Add(chainState);
                }

                long timeTicks = DateTime.UtcNow.Ticks;
                string rawData = $"{chainState.LastHash}{prep.TableName}{primaryKey}{prep.Action}{prep.OldValues}{prep.NewValues}{timeTicks}";
                string currentHash = SecurityHelper.ComputeHash(rawData);

                var auditLog = new AuditLog
                {
                    TableName = prep.TableName,
                    RecordId = primaryKey,
                    ActionType = prep.Action.ToString(),
                    OldValues = prep.OldValues,
                    NewValues = prep.NewValues,
                    TimestampTicks = timeTicks,
                    PreviousHash = chainState.LastHash,
                    CurrentHash = currentHash,
                    UserId = "System"
                };

                context.Add(auditLog);

                chainState.LastHash = currentHash;
                chainState.UnanchoredCount++;
                chainState.LastModified = DateTime.UtcNow;

                if (chainState.UnanchoredCount >= _options.AnchorThreshold)
                    tablesToAnchor[prep.TableName] = chainState;
            }


            await context.SaveChangesAsync(ct);


            if (state.IsTransactionOwner)
                await state.Transaction.CommitAsync(ct);

            _stateMap.Remove(context);


            if (tablesToAnchor.Any())
                _ = Task.Run(() => SendAnchorsAsync(tablesToAnchor.Values.ToList()));

            return result;
        }


        public override Task SaveChangesFailedAsync(
            DbContextErrorEventData eventData, CancellationToken ct = default)
        {
            if (eventData.Context != null && _stateMap.TryGetValue(eventData.Context, out var state))
            {
                if (state.IsTransactionOwner && state.Transaction != null)
                    state.Transaction.Dispose();

                _stateMap.Remove(eventData.Context);
            }

            return base.SaveChangesFailedAsync(eventData, ct);
        }

        private async Task SendAnchorsAsync(List<AuditChainState> states)
        {
            foreach (var state in states)
            {
                await _anchorService.SendAnchorEmailAsync(state.TableName, state.LastHash, state.UnanchoredCount);
            }
        }
    }
}