using EfCore.TamperEvident.Configuration;
using EfCore.TamperEvident.Models;
using EfCore.TamperEvident.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.Logging;
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
        public string Action { get; set; }
        public string OldValues { get; set; }
        public string NewValues { get; set; }
    }
    public class TamperEvidentInterceptor : SaveChangesInterceptor
    {
        private readonly TamperEvidentOptions _options;
        private static readonly ConditionalWeakTable<DbContext, AuditContextState> _stateMap = new();
        public TamperEvidentInterceptor(TamperEvidentOptions options)
        {
            _options = options;
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

                bool isSoftDelete = false;
                string oldJson = null;
                string newJson = null;

                if (entry.State == EntityState.Added)
                {
                    newJson = SecurityHelper.SerializeDeterministic(entry.CurrentValues.ToObject());
                }
                else if (entry.State == EntityState.Deleted)
                {
                    oldJson = SecurityHelper.SerializeDeterministic(entry.OriginalValues.ToObject());
                }
                else if (entry.State == EntityState.Modified)
                {
                    var oldValuesDict = new System.Collections.Generic.Dictionary<string, object>();
                    var newValuesDict = new System.Collections.Generic.Dictionary<string, object>();

                    foreach (var prop in entry.Properties)
                    {
                        if (prop.IsModified)
                        {
                            oldValuesDict[prop.Metadata.Name] = prop.OriginalValue;
                            newValuesDict[prop.Metadata.Name] = prop.CurrentValue;

                            if (prop.Metadata.Name == _options.SoftDeleteColumnName)
                            {
                                if (prop.OriginalValue is bool oldVal && oldVal == false &&
                                    prop.CurrentValue is bool newVal && newVal == true)
                                {
                                    isSoftDelete = true;
                                }
                            }
                        }
                    }

                    oldJson = SecurityHelper.SerializeDeterministic(oldValuesDict);
                    newJson = SecurityHelper.SerializeDeterministic(newValuesDict);
                }

                state.Preps.Add(new AuditEntryPrep
                {
                    Entry = entry,
                    TableName = tableName,
                    Action = isSoftDelete ? "SoftDelete" : entry.State.ToString(),
                    OldValues = oldJson,
                    NewValues = newJson
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

                string lockQuery = SecurityHelper.GetLockQuery(_options.DbProvider);
                var chainState = await context.Set<AuditChainState>().FromSqlRaw(lockQuery, prep.TableName).FirstOrDefaultAsync(ct);

                if (chainState == null)
                {
                    chainState = new AuditChainState { TableName = prep.TableName, LastHash = "GENESIS", UnanchoredCount = 0 };
                    context.Add(chainState);
                }

                long timeTicks = DateTime.UtcNow.Ticks;
                string rawData = $"{chainState.LastHash}{prep.TableName}{primaryKey}{prep.Action}{prep.OldValues}{prep.NewValues}{timeTicks}";
                string currentHash = SecurityHelper.ComputeHash(rawData, _options.HmacSecretKey);

                var auditLog = new AuditLog
                {
                    TableName = prep.TableName,
                    RecordId = primaryKey,
                    ActionType = prep.Action,
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
                {
                    tablesToAnchor[prep.TableName] = chainState;
                    chainState.UnanchoredCount = 0;
                }
            }


            await context.SaveChangesAsync(ct);


            if (state.IsTransactionOwner)
                await state.Transaction.CommitAsync(ct);

            _stateMap.Remove(context);


            if (tablesToAnchor.Any())
            {
                var logger = _options.LoggerFactory?.CreateLogger<TamperEvidentInterceptor>() 
                             ?? context.GetService<ILoggerFactory>()?.CreateLogger<TamperEvidentInterceptor>();
                             
                _ = Task.Run(async () => 
                {
                    try
                    {
                        await SendAnchorsAsync(tablesToAnchor.Values.ToList());
                    }
                    catch (Exception ex)
                    {
                        logger?.LogError(ex, "Failed to send anchors.");
                    }
                });
            }

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
            var publisher = _options.CustomAnchorPublisher ?? new SmtpAnchorPublisher(_options, _options.LoggerFactory);
            foreach (var state in states)
            {
                await publisher.SendAnchorAsync(state.TableName, state.LastHash, state.UnanchoredCount);
            }
        }
    }
}