using EfCore.TamperEvident.Configuration;
using EfCore.TamperEvident.Extensions;
using EfCore.TamperEvident.Models;
using Microsoft.EntityFrameworkCore;

namespace EfCore.TamperEvident.IntegrationTests
{
    public enum Provider
    {
        Postgres,
        MySql,
        SqlServer
    }

    public class Account
    {
        public int Id { get; set; }
        public required string Name { get; set; }
        public decimal Balance { get; set; }
        public bool IsDeleted { get; set; }
        public DateTime OpenedUtc { get; set; } = DateTime.UtcNow;
        public byte[]? Photo { get; set; }
    }

    public class Ticket
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public required string Title { get; set; }
    }

    public class Line
    {
        public int OrderId { get; set; }
        public int LineNo { get; set; }
        public required string Product { get; set; }
    }

    public enum Naming
    {
        Default,
        SnakeCase,
        Schema
    }

    public sealed class ConformanceDb : DbContext
    {
        private readonly Provider _provider;
        private readonly string _connectionString;
        private readonly TamperEvidentOptions _audit;
        private readonly Naming _naming;
        private readonly bool _retry;

        public ConformanceDb(Provider provider, string connectionString, TamperEvidentOptions audit, Naming naming, bool retry)
        {
            _provider = provider;
            _connectionString = connectionString;
            _audit = audit;
            _naming = naming;
            _retry = retry;
        }

        public DbSet<Account> Accounts => Set<Account>();

        public DbSet<Ticket> Tickets => Set<Ticket>();

        public DbSet<Line> Lines => Set<Line>();

        protected override void OnConfiguring(DbContextOptionsBuilder options)
        {
            switch (_provider)
            {
                case Provider.Postgres:
                    options.UseNpgsql(_connectionString, o => { if (_retry) o.EnableRetryOnFailure(); });
                    break;
                case Provider.MySql:
                    // TE_TEST_MYSQL_FLAVOR=mysql selects MySQL 8; the default is MariaDB.
                    var flavor = string.Equals(Environment.GetEnvironmentVariable("TE_TEST_MYSQL_FLAVOR"), "mysql", StringComparison.OrdinalIgnoreCase)
                        ? ServerVersion.Create(8, 4, 0, Pomelo.EntityFrameworkCore.MySql.Infrastructure.ServerType.MySql)
                        : ServerVersion.Create(10, 11, 0, Pomelo.EntityFrameworkCore.MySql.Infrastructure.ServerType.MariaDb);
                    options.UseMySql(_connectionString, flavor, o => { if (_retry) o.EnableRetryOnFailure(); });
                    break;
                default:
                    options.UseSqlServer(_connectionString, o => { if (_retry) o.EnableRetryOnFailure(); });
                    break;
            }

            options.UseTamperEvidentAudit(_audit);
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<Line>().HasKey(x => new { x.OrderId, x.LineNo });
            modelBuilder.Entity<Account>().Property(x => x.Balance).HasPrecision(18, 2);

            switch (_naming)
            {
                case Naming.Schema:
                    modelBuilder.ApplyTamperEvidentAudit(schema: "audit");
                    break;
                case Naming.SnakeCase:
                    modelBuilder.ApplyTamperEvidentAudit(auditLogTable: "audit_logs", chainStateTable: "audit_chain_states");
                    foreach (var entity in modelBuilder.Model.GetEntityTypes())
                    {
                        foreach (var property in entity.GetProperties())
                        {
                            property.SetColumnName(ToSnake(property.Name));
                        }
                    }

                    break;
                default:
                    modelBuilder.ApplyTamperEvidentAudit();
                    break;
            }
        }

        private static string ToSnake(string name) =>
            string.Concat(name.Select((c, i) => i > 0 && char.IsUpper(c) ? "_" + char.ToLowerInvariant(c) : char.ToLowerInvariant(c).ToString()));
    }

    /// <summary>One throw-away database on one provider.</summary>
    public sealed class Database : IAsyncDisposable
    {
        public const string Key = "integration-tests-secret-key-0123456789abcdef";

        private readonly Provider _provider;
        private readonly string _connectionString;
        private readonly Naming _naming;
        private readonly bool _retry;

        private Database(Provider provider, string connectionString, Naming naming, bool retry, TamperEvidentOptions options)
        {
            _provider = provider;
            _connectionString = connectionString;
            _naming = naming;
            _retry = retry;
            Options = options;
        }

        public TamperEvidentOptions Options { get; }

        public static string? ConnectionStringOf(Provider provider) => Environment.GetEnvironmentVariable(provider switch
        {
            Provider.Postgres => "TE_TEST_POSTGRES",
            Provider.MySql => "TE_TEST_MYSQL",
            _ => "TE_TEST_SQLSERVER"
        });

        public static async Task<Database> CreateAsync(
            Provider provider, Naming naming = Naming.Default, bool retry = false, Action<TamperEvidentOptions>? configure = null)
        {
            var baseConnection = ConnectionStringOf(provider);
            Skip.If(string.IsNullOrWhiteSpace(baseConnection), $"The connection string of {provider} is not configured.");
            Skip.If(provider == Provider.MySql && naming == Naming.Schema, "MySQL has no schemas besides the database.");

            var name = "te_" + Guid.NewGuid().ToString("N")[..12];
            var connection = baseConnection!.TrimEnd(';') + (provider == Provider.Postgres || provider == Provider.MySql ? ";Database=" : ";Initial Catalog=") + name;
            if (provider == Provider.Postgres)
            {
                connection += ";Maximum Pool Size=40;Include Error Detail=true";
            }

            var options = new TamperEvidentOptions { HmacSecretKey = Key };
            configure?.Invoke(options);

            var database = new Database(provider, connection, naming, retry, options);
            await using var context = database.CreateContext();
            await context.Database.EnsureCreatedAsync();
            return database;
        }

        public ConformanceDb CreateContext() => new(_provider, _connectionString, Options, _naming, _retry);

        public ConformanceDb CreateUnauditedContext() =>
            new(_provider, _connectionString, new TamperEvidentOptions { HmacSecretKey = Key, TrackedOperations = AuditOperation.None }, _naming, false);

        public async ValueTask DisposeAsync()
        {
            try
            {
                await using var context = CreateContext();
                await context.Database.EnsureDeletedAsync();
            }
            catch (Exception)
            {
                // best effort: the throw-away database may already be gone
            }
        }
    }
}
