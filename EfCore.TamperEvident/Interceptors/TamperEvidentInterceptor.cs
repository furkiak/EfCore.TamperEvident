using System.Runtime.CompilerServices;
using EfCore.TamperEvident.Configuration;
using EfCore.TamperEvident.Models;
using EfCore.TamperEvident.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.EntityFrameworkCore.Storage;

namespace EfCore.TamperEvident.Interceptors;

internal sealed class AuditState
{
    public IDbContextTransaction? Transaction { get; set; }
    public bool OwnsTransaction { get; set; }
    public bool IsSavingLogs { get; set; }
    public List<AuditPrep> Preps { get; } = new();
}

internal sealed class AuditPrep
{
    public required EntityEntry Entry { get; init; }
    public required string TableName { get; init; }
    public required string Action { get; init; }
    public string? OldValues { get; init; }
    public string? NewValues { get; init; }
}

public sealed class TamperEvidentInterceptor : SaveChangesInterceptor
{
    private readonly TamperEvidentOptions _options;
    private readonly ConditionalWeakTable<DbContext, AuditState> _states = new();

    public TamperEvidentInterceptor(TamperEvidentOptions options)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _options.Validate();
    }

    public override InterceptionResult<int> SavingChanges(DbContextEventData eventData, InterceptionResult<int> result)
    {
        var context = eventData.Context;
        if (context == null || IsSavingLogs(context)) return result;
        var state = Prepare(context);
        if (state.Preps.Count == 0) return result;
        try
        {
            state.Transaction = context.Database.CurrentTransaction;
            state.OwnsTransaction = state.Transaction == null;
            if (state.OwnsTransaction) state.Transaction = context.Database.BeginTransaction();
            _states.Add(context, state);
        }
        catch
        {
            if (state.OwnsTransaction) state.Transaction?.Dispose();
            throw;
        }
        return result;
    }

    public override async ValueTask<InterceptionResult<int>> SavingChangesAsync(
        DbContextEventData eventData, InterceptionResult<int> result, CancellationToken ct = default)
    {
        var context = eventData.Context;
        if (context == null || IsSavingLogs(context)) return result;
        var state = Prepare(context);
        if (state.Preps.Count == 0) return result;
        try
        {
            state.Transaction = context.Database.CurrentTransaction;
            state.OwnsTransaction = state.Transaction == null;
            if (state.OwnsTransaction) state.Transaction = await context.Database.BeginTransactionAsync(ct);
            _states.Add(context, state);
        }
        catch
        {
            if (state.OwnsTransaction && state.Transaction != null) await state.Transaction.DisposeAsync();
            throw;
        }
        return result;
    }

    public override int SavedChanges(SaveChangesCompletedEventData eventData, int result)
    {
        var context = eventData.Context;
        if (context == null || !_states.TryGetValue(context, out var state) || state.IsSavingLogs) return result;
        try
        {
            state.IsSavingLogs = true;
            WriteAudit(context, state);
            if (state.OwnsTransaction) state.Transaction!.Commit();
        }
        catch (Exception auditError)
        {
            try { state.Transaction?.Rollback(); }
            catch (Exception rollbackError)
            {
                throw new AggregateException("Audit failed and the transaction could not be rolled back.", auditError, rollbackError);
            }
            throw;
        }
        finally
        {
            _states.Remove(context);
            DetachAuditState(context);
            if (state.OwnsTransaction) state.Transaction?.Dispose();
        }
        return result;
    }

    public override async ValueTask<int> SavedChangesAsync(
        SaveChangesCompletedEventData eventData, int result, CancellationToken ct = default)
    {
        var context = eventData.Context;
        if (context == null || !_states.TryGetValue(context, out var state) || state.IsSavingLogs) return result;
        try
        {
            state.IsSavingLogs = true;
            await WriteAuditAsync(context, state, ct);
            if (state.OwnsTransaction) await state.Transaction!.CommitAsync(ct);
        }
        catch (Exception auditError)
        {
            try
            {
                if (state.Transaction != null) await state.Transaction.RollbackAsync(CancellationToken.None);
            }
            catch (Exception rollbackError)
            {
                throw new AggregateException("Audit failed and the transaction could not be rolled back.", auditError, rollbackError);
            }
            throw;
        }
        finally
        {
            _states.Remove(context);
            DetachAuditState(context);
            if (state.OwnsTransaction && state.Transaction != null) await state.Transaction.DisposeAsync();
        }
        return result;
    }

    public override void SaveChangesFailed(DbContextErrorEventData eventData) => CleanupFailed(eventData.Context);
    public override Task SaveChangesFailedAsync(DbContextErrorEventData eventData, CancellationToken ct = default)
        => CleanupFailedAsync(eventData.Context);
    public override void SaveChangesCanceled(DbContextEventData eventData) => CleanupFailed(eventData.Context);
    public override Task SaveChangesCanceledAsync(DbContextEventData eventData, CancellationToken ct = default)
        => CleanupFailedAsync(eventData.Context);

    private bool IsSavingLogs(DbContext context) =>
        _states.TryGetValue(context, out var state) && state.IsSavingLogs;

    private static void DetachAuditState(DbContext context)
    {
        // A caller may roll back an external transaction after SaveChanges returns.
        // The next save must read chain state from the database, not EF's stale identity map.
        foreach (var entry in context.ChangeTracker.Entries()
                     .Where(x => x.Entity is AuditLog or AuditChainState or PendingAnchor).ToList())
            entry.State = EntityState.Detached;
    }

    private void CleanupFailed(DbContext? context)
    {
        if (context == null || !_states.TryGetValue(context, out var state) || state.IsSavingLogs) return;
        try { if (state.OwnsTransaction) state.Transaction?.Rollback(); }
        finally
        {
            _states.Remove(context);
            if (state.OwnsTransaction) state.Transaction?.Dispose();
        }
    }

    private async Task CleanupFailedAsync(DbContext? context)
    {
        if (context == null || !_states.TryGetValue(context, out var state) || state.IsSavingLogs) return;
        try
        {
            if (state.OwnsTransaction && state.Transaction != null)
                await state.Transaction.RollbackAsync(CancellationToken.None);
        }
        finally
        {
            _states.Remove(context);
            if (state.OwnsTransaction && state.Transaction != null) await state.Transaction.DisposeAsync();
        }
    }

    private AuditState Prepare(DbContext context)
    {
        if (_states.TryGetValue(context, out _))
            throw new InvalidOperationException("An earlier audited SaveChanges has not completed.");
        if (context.Model.FindEntityType(typeof(AuditLog)) == null ||
            context.Model.FindEntityType(typeof(AuditChainState)) == null ||
            context.Model.FindEntityType(typeof(PendingAnchor)) == null)
            throw new InvalidOperationException("Register the audit models with modelBuilder.AddTamperEvidentModels() and apply a migration.");

        context.ChangeTracker.DetectChanges();
        var state = new AuditState();
        foreach (var entry in context.ChangeTracker.Entries())
        {
            if (entry.State is not (EntityState.Added or EntityState.Modified or EntityState.Deleted)) continue;
            var name = entry.Metadata.GetTableName();
            if (string.IsNullOrWhiteSpace(name)) continue;
            if (entry.Entity is AuditLog or AuditChainState or PendingAnchor) continue;
            var schema = entry.Metadata.GetSchema();
            var table = string.IsNullOrWhiteSpace(schema) ? name : schema + "." + name;
            if (_options.ExcludedTables.Contains(name, StringComparer.OrdinalIgnoreCase) ||
                _options.ExcludedTables.Contains(table, StringComparer.OrdinalIgnoreCase)) continue;
            if (entry.State == EntityState.Added && !_options.TrackedOperations.HasFlag(AuditOperation.Insert) ||
                entry.State == EntityState.Modified && !_options.TrackedOperations.HasFlag(AuditOperation.Update) ||
                entry.State == EntityState.Deleted && !_options.TrackedOperations.HasFlag(AuditOperation.Delete)) continue;

            string? before = null, after = null;
            var softDelete = false;
            if (entry.State == EntityState.Added) after = Snapshot(entry, original: false);
            else if (entry.State == EntityState.Deleted) before = Snapshot(entry, original: true);
            else
            {
                var oldValues = new Dictionary<string, object?>();
                var newValues = new Dictionary<string, object?>();
                foreach (var property in entry.Properties.Where(x => x.IsModified))
                {
                    oldValues[property.Metadata.Name] = Redact(property.Metadata.Name, property.OriginalValue);
                    newValues[property.Metadata.Name] = Redact(property.Metadata.Name, property.CurrentValue);
                    if (property.Metadata.Name == _options.SoftDeleteColumnName &&
                        property.OriginalValue is false && property.CurrentValue is true) softDelete = true;
                }
                before = SecurityHelper.SerializeDeterministic(oldValues);
                after = SecurityHelper.SerializeDeterministic(newValues);
            }
            state.Preps.Add(new AuditPrep
            {
                Entry = entry, TableName = table, Action = softDelete ? "SoftDelete" : entry.State.ToString(),
                OldValues = before, NewValues = after
            });
        }
        return state;
    }

    private object? Redact(string name, object? value) =>
        _options.RedactedProperties.Contains(name, StringComparer.OrdinalIgnoreCase) ? "[REDACTED]" : value;

    private string Snapshot(EntityEntry entry, bool original) =>
        SecurityHelper.SerializeDeterministic(entry.Properties.ToDictionary(
            x => x.Metadata.Name,
            x => Redact(x.Metadata.Name, original ? x.OriginalValue : x.CurrentValue)))!;

    private void WriteAudit(DbContext context, AuditState state)
    {
        var chains = LoadChains(context, state);
        AppendLogs(context, state, chains);
        context.SaveChanges();
    }

    private async Task WriteAuditAsync(DbContext context, AuditState state, CancellationToken ct)
    {
        var chains = await LoadChainsAsync(context, state, ct);
        AppendLogs(context, state, chains);
        await context.SaveChangesAsync(ct);
    }

    private Dictionary<string, AuditChainState> LoadChains(DbContext context, AuditState state)
    {
        var chains = new Dictionary<string, AuditChainState>(StringComparer.Ordinal);
        foreach (var table in state.Preps.Select(x => x.TableName).Distinct().OrderBy(x => x, StringComparer.Ordinal))
        {
            AcquireChainLock(context, table);
            var chain = context.Set<AuditChainState>().FromSqlRaw(SecurityHelper.GetLockQuery(_options.DbProvider), table).FirstOrDefault();
            if (chain == null)
            {
                chain = new AuditChainState { TableName = table, LastHash = "GENESIS" };
                context.Add(chain);
            }
            chains.Add(table, chain);
        }
        return chains;
    }

    private async Task<Dictionary<string, AuditChainState>> LoadChainsAsync(DbContext context, AuditState state, CancellationToken ct)
    {
        var chains = new Dictionary<string, AuditChainState>(StringComparer.Ordinal);
        foreach (var table in state.Preps.Select(x => x.TableName).Distinct().OrderBy(x => x, StringComparer.Ordinal))
        {
            await AcquireChainLockAsync(context, table, ct);
            var chain = await context.Set<AuditChainState>().FromSqlRaw(SecurityHelper.GetLockQuery(_options.DbProvider), table).FirstOrDefaultAsync(ct);
            if (chain == null)
            {
                chain = new AuditChainState { TableName = table, LastHash = "GENESIS" };
                context.Add(chain);
            }
            chains.Add(table, chain);
        }
        return chains;
    }

    private void AcquireChainLock(DbContext context, string table)
    {
        if (_options.DbProvider == DatabaseProvider.SqlServer)
            context.Database.ExecuteSqlRaw("DECLARE @result int; EXEC @result = sp_getapplock @Resource = {0}, @LockMode = 'Exclusive', @LockOwner = 'Transaction', @LockTimeout = 15000; IF @result < 0 THROW 51001, 'Audit chain lock failed', 1;", "EfCoreAudit:" + table);
    }

    private Task AcquireChainLockAsync(DbContext context, string table, CancellationToken ct)
    {
        if (_options.DbProvider == DatabaseProvider.SqlServer)
            return context.Database.ExecuteSqlRawAsync("DECLARE @result int; EXEC @result = sp_getapplock @Resource = {0}, @LockMode = 'Exclusive', @LockOwner = 'Transaction', @LockTimeout = 15000; IF @result < 0 THROW 51001, 'Audit chain lock failed', 1;", new object[] { "EfCoreAudit:" + table }, ct);
        return Task.CompletedTask;
    }

    private void AppendLogs(DbContext context, AuditState state, Dictionary<string, AuditChainState> chains)
    {
        foreach (var prep in state.Preps)
        {
            var chain = chains[prep.TableName];
            var key = prep.Entry.Properties.Where(x => x.Metadata.IsPrimaryKey())
                .ToDictionary(x => x.Metadata.Name, x => x.CurrentValue);
            var ticks = Math.Max(DateTime.UtcNow.Ticks, checked(chain.LastTimestampTicks + 1));
            var log = new AuditLog
            {
                TableName = prep.TableName,
                RecordId = SecurityHelper.SerializeDeterministic(key)!,
                ActionType = prep.Action,
                OldValues = prep.OldValues,
                NewValues = prep.Action == "Added" ? Snapshot(prep.Entry, original: false) : prep.NewValues,
                TimestampTicks = ticks,
                PreviousHash = chain.LastHash,
                CurrentHash = "",
                UserId = _options.UserIdProvider?.Invoke(context) ?? "System"
            };
            log.CurrentHash = SecurityHelper.ComputeAuditHash(log, _options.HmacSecretKey);
            context.Add(log);
            chain.LastHash = log.CurrentHash;
            chain.LastTimestampTicks = ticks;
            chain.LastModified = DateTime.UtcNow;
            chain.UnanchoredCount++;
            if (chain.UnanchoredCount >= _options.AnchorThreshold)
            {
                context.Add(new PendingAnchor
                {
                    TableName = prep.TableName,
                    AnchorHash = chain.LastHash,
                    RecordCount = chain.UnanchoredCount
                });
                chain.UnanchoredCount = 0;
            }
        }
    }
}
