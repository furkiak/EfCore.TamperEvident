using EfCore.TamperEvident.Configuration;
using EfCore.TamperEvident.Extensions;
using EfCore.TamperEvident.Models;
using EfCore.TamperEvident.Services;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace EfCore.TamperEvident.Tests
{
    /// <summary>
    /// A real SQLite database (in memory, shared by every context created from the harness) with the audit trail enabled.
    /// </summary>
    public sealed class Harness : IDisposable
    {
        public const string SecretKey = "unit-test-secret-key-that-is-long-enough-0123456789";

        private readonly SqliteConnection _connection;
        private readonly Action<TamperEvidentOptions>? _configure;

        public Harness(Action<TamperEvidentOptions>? configure = null)
        {
            _configure = configure;
            _connection = new SqliteConnection("DataSource=:memory:");
            _connection.Open();
            Options = BuildOptions();
            using var context = CreateContext();
            context.Database.EnsureCreated();
        }

        public TamperEvidentOptions Options { get; }

        public TestDbContext CreateContext() => new(new DbContextOptionsBuilder<TestDbContext>()
            .UseSqlite(_connection)
            .UseTamperEvidentAudit(Options)
            .Options);

        public TestDbContext CreateContextWith(TamperEvidentOptions options) => new(new DbContextOptionsBuilder<TestDbContext>()
            .UseSqlite(_connection)
            .UseTamperEvidentAudit(options)
            .Options);

        /// <summary>A context without the interceptor: what an attacker with direct database access can do.</summary>
        public TestDbContext CreateUnauditedContext() => new(new DbContextOptionsBuilder<TestDbContext>()
            .UseSqlite(_connection)
            .Options);

        public AuditVerifier CreateVerifier(TestDbContext context) => new(context, Options);

        public int Execute(string sql, params object[] parameters)
        {
            using var context = CreateUnauditedContext();
            return context.Database.ExecuteSqlRaw(sql, parameters);
        }

        private TamperEvidentOptions BuildOptions()
        {
            var options = new TamperEvidentOptions { HmacSecretKey = SecretKey };
            options.ExcludedTables.Add("SystemLogs");
            _configure?.Invoke(options);
            return options;
        }

        public void Dispose() => _connection.Dispose();
    }
}
