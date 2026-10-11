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

        private AuditModelInfo(DatabaseProvider requestedProvider, DatabaseProvider provider, bool isRelational, ChainStateCommands? commands)
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
        public ChainStateCommands? Commands { get; }

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

            var commands = isRelational ? ChainStateCommands.Build(context, provider) : null;

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
    /// The provider specific statements that lock the head of a chain. Table and column names are taken from the
    /// EF Core model, so schemas, custom table names and naming conventions (for example snake_case) just work.
    /// </summary>
    internal sealed class ChainStateCommands
    {
        private ChainStateCommands(string selectForUpdate, string insertIfMissing)
        {
            SelectForUpdate = selectForUpdate;
            InsertIfMissing = insertIfMissing;
        }

        /// <summary>Selects the chain head of the table passed as <c>{0}</c> and locks the row until the transaction ends.</summary>
        public string SelectForUpdate { get; }

        /// <summary>
        /// Creates the chain head of the table passed as <c>{0}</c> unless it exists.
        /// Parameters: table name, last hash, unanchored count, last modified, last sequence.
        /// </summary>
        public string InsertIfMissing { get; }

        public static ChainStateCommands Build(DbContext context, DatabaseProvider provider)
        {
            var entityType = context.Model.FindEntityType(typeof(AuditChainState))!;
            var helper = context.GetService<ISqlGenerationHelper>();

            var tableName = entityType.GetTableName()
                ?? throw new InvalidOperationException($"{nameof(AuditChainState)} is not mapped to a table.");
            var store = StoreObjectIdentifier.Table(tableName, entityType.GetSchema());

            string Column(string property)
            {
                var column = entityType.FindProperty(property)!.GetColumnName(store)
                    ?? throw new InvalidOperationException($"{nameof(AuditChainState)}.{property} is not mapped to a column.");
                return Escape(helper.DelimitIdentifier(column));
            }

            var table = Escape(helper.DelimitIdentifier(tableName, entityType.GetSchema()));
            var key = Column(nameof(AuditChainState.TableName));
            var written = new[]
            {
                key,
                Column(nameof(AuditChainState.LastHash)),
                Column(nameof(AuditChainState.UnanchoredCount)),
                Column(nameof(AuditChainState.LastModified)),
                Column(nameof(AuditChainState.LastSequence))
            };
            var columns = string.Join(", ", written);
            var values = "{0}, {1}, {2}, {3}, {4}";
            var selectColumns = string.Join(", ", entityType.GetProperties().Select(p => Column(p.Name)));

            return provider switch
            {
                DatabaseProvider.SqlServer => new ChainStateCommands(
                    $"SELECT {selectColumns} FROM {table} WITH (UPDLOCK, ROWLOCK) WHERE {key} = {{0}}",
                    $"IF NOT EXISTS (SELECT 1 FROM {table} WITH (UPDLOCK, HOLDLOCK) WHERE {key} = {{0}}) " +
                    $"INSERT INTO {table} ({columns}) VALUES ({values})"),

                DatabaseProvider.PostgreSql => new ChainStateCommands(
                    $"SELECT {selectColumns} FROM {table} WHERE {key} = {{0}} FOR UPDATE",
                    $"INSERT INTO {table} ({columns}) VALUES ({values}) ON CONFLICT ({key}) DO NOTHING"),

                DatabaseProvider.MySql => new ChainStateCommands(
                    $"SELECT {selectColumns} FROM {table} WHERE {key} = {{0}} FOR UPDATE",
                    $"INSERT IGNORE INTO {table} ({columns}) VALUES ({values})"),

                // SQLite has a single writer: the transaction that already wrote the audited rows owns the database lock.
                DatabaseProvider.Sqlite => new ChainStateCommands(
                    $"SELECT {selectColumns} FROM {table} WHERE {key} = {{0}}",
                    $"INSERT OR IGNORE INTO {table} ({columns}) VALUES ({values})"),

                _ => throw new NotSupportedException($"The database provider {provider} is not supported for relational databases.")
            };
        }

        // Identifiers are embedded into a format string, so braces must be doubled.
        private static string Escape(string identifier) => identifier.Replace("{", "{{").Replace("}", "}}");
    }
}
