using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using EfCore.TamperEvident.Configuration;
using EfCore.TamperEvident.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Storage;

namespace EfCore.TamperEvident.Internal
{
    /// <summary>
    /// What the interceptor needs to know about the configured model and provider. It is computed once per model.
    /// </summary>
    internal sealed class AuditModelInfo
    {
        private static readonly ConditionalWeakTable<IModel, AuditModelInfo> Cache = new();

        private AuditModelInfo(DatabaseProvider requestedProvider, DatabaseProvider provider, bool isRelational, AuditSqlCommands? commands)
        {
            RequestedProvider = requestedProvider;
            Provider = provider;
            IsRelational = isRelational;
            Commands = commands;
        }

        public DatabaseProvider RequestedProvider { get; }

        public DatabaseProvider Provider { get; }

        public bool IsRelational { get; }

        /// <summary>The SQL used to lock and create chain heads. <c>null</c> for non-relational providers.</summary>
        public AuditSqlCommands? Commands { get; }

        public static AuditModelInfo Resolve(DbContext context, TamperEvidentOptions options)
        {
            var model = context.Model;
            if (Cache.TryGetValue(model, out var cached) && cached.RequestedProvider == options.DbProvider)
            {
                return cached;
            }

            if (model.FindEntityType(typeof(AuditLog)) is null || model.FindEntityType(typeof(AuditChainState)) is null)
            {
                throw new InvalidOperationException(
                    $"The model of {context.GetType().Name} does not contain {nameof(AuditLog)} and {nameof(AuditChainState)}. " +
                    $"Add DbSet<{nameof(AuditLog)}> and DbSet<{nameof(AuditChainState)}> properties to the context " +
                    "or call modelBuilder.ApplyTamperEvidentAudit() in OnModelCreating, then add a migration.");
            }

            var isRelational = context.Database.IsRelational();
            var detected = ProviderDetector.Detect(context.Database.ProviderName);

            DatabaseProvider provider;
            if (detected is { } known)
            {
                provider = known;
            }
            else if (options.DbProvider != DatabaseProvider.Auto)
            {
                provider = options.DbProvider;
            }
            else
            {
                throw new NotSupportedException(
                    $"The database provider '{context.Database.ProviderName}' is not supported by EfCore.TamperEvident " +
                    "(supported: SQL Server, PostgreSQL, MySQL, SQLite and the in-memory provider).");
            }

            var commands = isRelational ? AuditSqlCommands.Build(context, provider) : null;

            var info = new AuditModelInfo(options.DbProvider, provider, isRelational, commands);
            Cache.AddOrUpdate(model, info);
            return info;
        }
    }

    internal static class ProviderDetector
    {
        public static DatabaseProvider? Detect(string? providerName)
        {
            if (string.IsNullOrEmpty(providerName))
            {
                return null;
            }

            if (providerName.Contains("SqlServer", StringComparison.OrdinalIgnoreCase))
            {
                return DatabaseProvider.SqlServer;
            }

            if (providerName.Contains("Npgsql", StringComparison.OrdinalIgnoreCase)
                || providerName.Contains("PostgreSQL", StringComparison.OrdinalIgnoreCase))
            {
                return DatabaseProvider.PostgreSql;
            }

            if (providerName.Contains("MySql", StringComparison.OrdinalIgnoreCase)
                || providerName.Contains("MariaDb", StringComparison.OrdinalIgnoreCase))
            {
                return DatabaseProvider.MySql;
            }

            if (providerName.Contains("Sqlite", StringComparison.OrdinalIgnoreCase))
            {
                return DatabaseProvider.Sqlite;
            }

            if (providerName.Contains("InMemory", StringComparison.OrdinalIgnoreCase))
            {
                return DatabaseProvider.InMemory;
            }

            return null;
        }
    }

    /// <summary>
    /// The statements that lock and update chain heads and append audit entries. Table and column names are taken
    /// from the EF Core model, so schemas, custom table names and naming conventions (for example snake_case) just work.
    /// The entries are written with plain parameterized SQL instead of a nested <c>SaveChanges</c>: that keeps the
    /// interceptor compatible with execution strategies that retry on failure (<c>EnableRetryOnFailure</c>), which refuse
    /// a second <c>SaveChanges</c> inside a running one.
    /// </summary>
    internal sealed class AuditSqlCommands
    {
        /// <summary>The audit log columns in the order of the parameters of <see cref="InsertLogs"/>.</summary>
        private static readonly (string Property, Func<AuditLog, object?> Get)[] LogColumns =
        {
            (nameof(AuditLog.Id), l => l.Id),
            (nameof(AuditLog.TableName), l => l.TableName),
            (nameof(AuditLog.RecordId), l => l.RecordId),
            (nameof(AuditLog.ActionType), l => l.ActionType),
            (nameof(AuditLog.OldValues), l => l.OldValues),
            (nameof(AuditLog.NewValues), l => l.NewValues),
            (nameof(AuditLog.Metadata), l => l.Metadata),
            (nameof(AuditLog.UserId), l => l.UserId),
            (nameof(AuditLog.TimestampTicks), l => l.TimestampTicks),
            (nameof(AuditLog.SequenceNumber), l => l.SequenceNumber),
            (nameof(AuditLog.HashVersion), l => l.HashVersion),
            (nameof(AuditLog.KeyId), l => l.KeyId),
            (nameof(AuditLog.PreviousHash), l => l.PreviousHash),
            (nameof(AuditLog.CurrentHash), l => l.CurrentHash)
        };

        private readonly string _insertLogsPrefix;
        private readonly ConcurrentDictionary<int, string> _insertLogsByRowCount = new();

        private AuditSqlCommands(
            string selectForUpdate, string insertIfMissing, string updateChainState, (string InsertLogsPrefix, string UpdateRedacted) logs)
        {
            SelectForUpdate = selectForUpdate;
            InsertIfMissing = insertIfMissing;
            UpdateChainState = updateChainState;
            _insertLogsPrefix = logs.InsertLogsPrefix;
            UpdateRedacted = logs.UpdateRedacted;
        }

        /// <summary>How many columns an audit entry has, which is how many parameters one row of <see cref="InsertLogs"/> takes.</summary>
        public static int LogColumnCount => LogColumns.Length;

        /// <summary>Selects the chain head of the table passed as <c>{0}</c> and locks the row until the transaction ends.</summary>
        public string SelectForUpdate { get; }

        /// <summary>
        /// Creates the chain head of the table passed as <c>{0}</c> unless it exists.
        /// Parameters: table name, last hash, unanchored count, last modified, last sequence.
        /// </summary>
        public string InsertIfMissing { get; }

        /// <summary>
        /// Updates a chain head. Parameters: last hash, unanchored count, last modified, last sequence, key id, mac, table name.
        /// </summary>
        public string UpdateChainState { get; }

        /// <summary>
        /// Replaces the values of a redacted entry. Parameters: record id, user id, old values, new values, metadata, entry id.
        /// </summary>
        public string UpdateRedacted { get; }

        /// <summary>Appends <paramref name="rowCount"/> audit entries with one statement.</summary>
        public string InsertLogs(int rowCount) => _insertLogsByRowCount.GetOrAdd(rowCount, rows =>
        {
            var rowSql = new List<string>(rows);
            for (var row = 0; row < rows; row++)
            {
                var placeholders = Enumerable.Range(0, LogColumns.Length).Select(c => "{" + (row * LogColumns.Length + c) + "}");
                rowSql.Add("(" + string.Join(", ", placeholders) + ")");
            }

            return _insertLogsPrefix + string.Join(", ", rowSql);
        });

        /// <summary>The parameter values of one audit entry, in the column order of <see cref="InsertLogs"/>.</summary>
        public static void AddLogParameters(AuditLog log, object?[] target, int offset)
        {
            for (var i = 0; i < LogColumns.Length; i++)
            {
                target[offset + i] = LogColumns[i].Get(log);
            }
        }

        public static AuditSqlCommands Build(DbContext context, DatabaseProvider provider)
        {
            var helper = context.GetService<ISqlGenerationHelper>();
            var chain = context.Model.FindEntityType(typeof(AuditChainState))!;
            var log = context.Model.FindEntityType(typeof(AuditLog))!;

            var chainColumns = new ColumnResolver(chain, helper);
            var logColumns = new ColumnResolver(log, helper);

            var chainTable = chainColumns.Table;
            var key = chainColumns.Column(nameof(AuditChainState.TableName));
            var written = string.Join(", ", new[]
            {
                key,
                chainColumns.Column(nameof(AuditChainState.LastHash)),
                chainColumns.Column(nameof(AuditChainState.UnanchoredCount)),
                chainColumns.Column(nameof(AuditChainState.LastModified)),
                chainColumns.Column(nameof(AuditChainState.LastSequence))
            });
            var values = "{0}, {1}, {2}, {3}, {4}";
            var selectColumns = string.Join(", ", chain.GetProperties().Select(p => chainColumns.Column(p.Name)));

            var update =
                $"UPDATE {chainTable} SET " +
                $"{chainColumns.Column(nameof(AuditChainState.LastHash))} = {{0}}, " +
                $"{chainColumns.Column(nameof(AuditChainState.UnanchoredCount))} = {{1}}, " +
                $"{chainColumns.Column(nameof(AuditChainState.LastModified))} = {{2}}, " +
                $"{chainColumns.Column(nameof(AuditChainState.LastSequence))} = {{3}}, " +
                $"{chainColumns.Column(nameof(AuditChainState.KeyId))} = {{4}}, " +
                $"{chainColumns.Column(nameof(AuditChainState.Mac))} = {{5}} " +
                $"WHERE {key} = {{6}}";

            var insertLogs = $"INSERT INTO {logColumns.Table} ({string.Join(", ", LogColumns.Select(c => logColumns.Column(c.Property)))}) VALUES ";
            var updateRedacted =
                $"UPDATE {logColumns.Table} SET " +
                $"{logColumns.Column(nameof(AuditLog.RecordId))} = {{0}}, " +
                $"{logColumns.Column(nameof(AuditLog.UserId))} = {{1}}, " +
                $"{logColumns.Column(nameof(AuditLog.OldValues))} = {{2}}, " +
                $"{logColumns.Column(nameof(AuditLog.NewValues))} = {{3}}, " +
                $"{logColumns.Column(nameof(AuditLog.Metadata))} = {{4}} " +
                $"WHERE {logColumns.Column(nameof(AuditLog.Id))} = {{5}}";
            var logs = (insertLogs, updateRedacted);

            return provider switch
            {
                DatabaseProvider.SqlServer => new AuditSqlCommands(
                    $"SELECT {selectColumns} FROM {chainTable} WITH (UPDLOCK, ROWLOCK) WHERE {key} = {{0}}",
                    // The existence check and the insert are one statement: outside a transaction a separate IF
                    // would release its range lock before the INSERT runs. Losing the race anyway (a duplicate key,
                    // error 2601/2627) just means another writer created the head first.
                    $"BEGIN TRY " +
                    $"INSERT INTO {chainTable} ({written}) SELECT {values} " +
                    $"WHERE NOT EXISTS (SELECT 1 FROM {chainTable} WITH (UPDLOCK, HOLDLOCK) WHERE {key} = {{0}}) " +
                    $"END TRY BEGIN CATCH IF ERROR_NUMBER() NOT IN (2601, 2627) THROW; END CATCH",
                    update, logs),

                DatabaseProvider.PostgreSql => new AuditSqlCommands(
                    $"SELECT {selectColumns} FROM {chainTable} WHERE {key} = {{0}} FOR UPDATE",
                    $"INSERT INTO {chainTable} ({written}) VALUES ({values}) ON CONFLICT ({key}) DO NOTHING",
                    update, logs),

                DatabaseProvider.MySql => new AuditSqlCommands(
                    $"SELECT {selectColumns} FROM {chainTable} WHERE {key} = {{0}} FOR UPDATE",
                    $"INSERT IGNORE INTO {chainTable} ({written}) VALUES ({values})",
                    update, logs),

                // SQLite has a single writer: the transaction that already wrote the audited rows owns the database lock.
                DatabaseProvider.Sqlite => new AuditSqlCommands(
                    $"SELECT {selectColumns} FROM {chainTable} WHERE {key} = {{0}}",
                    $"INSERT OR IGNORE INTO {chainTable} ({written}) VALUES ({values})",
                    update, logs),

                _ => throw new NotSupportedException($"The database provider {provider} is not supported for relational databases.")
            };
        }

        private sealed class ColumnResolver
        {
            private readonly IEntityType _entityType;
            private readonly ISqlGenerationHelper _helper;
            private readonly StoreObjectIdentifier _store;

            public ColumnResolver(IEntityType entityType, ISqlGenerationHelper helper)
            {
                _entityType = entityType;
                _helper = helper;

                var tableName = entityType.GetTableName()
                    ?? throw new InvalidOperationException($"{entityType.DisplayName()} is not mapped to a table.");
                _store = StoreObjectIdentifier.Table(tableName, entityType.GetSchema());
                Table = Escape(helper.DelimitIdentifier(tableName, entityType.GetSchema()));
            }

            public string Table { get; }

            public string Column(string property)
            {
                var column = _entityType.FindProperty(property)!.GetColumnName(_store)
                    ?? throw new InvalidOperationException($"{_entityType.DisplayName()}.{property} is not mapped to a column.");
                return Escape(_helper.DelimitIdentifier(column));
            }

            // Identifiers are embedded into a format string, so braces must be doubled.
            private static string Escape(string identifier) => identifier.Replace("{", "{{").Replace("}", "}}");
        }
    }
}
