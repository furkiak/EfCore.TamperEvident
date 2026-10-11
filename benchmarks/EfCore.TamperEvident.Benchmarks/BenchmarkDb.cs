using EfCore.TamperEvident.Configuration;
using EfCore.TamperEvident.Extensions;
using EfCore.TamperEvident.Models;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace EfCore.TamperEvident.Benchmarks
{
    public class Customer
    {
        public int Id { get; set; }
        public required string Name { get; set; }
        public string? Email { get; set; }
        public string? City { get; set; }
        public decimal Balance { get; set; }
        public bool IsActive { get; set; }
        public DateTime CreatedUtc { get; set; }
        public string? Notes { get; set; }
    }

    public sealed class BenchmarkContext : DbContext
    {
        public BenchmarkContext(DbContextOptions<BenchmarkContext> options) : base(options) { }

        public DbSet<Customer> Customers => Set<Customer>();

        protected override void OnModelCreating(ModelBuilder modelBuilder) => modelBuilder.ApplyTamperEvidentAudit();
    }

    /// <summary>An in-memory SQLite database that lives as long as the benchmark class.</summary>
    public sealed class BenchmarkDb : IDisposable
    {
        public const string Secret = "benchmark-secret-key-0123456789-abcdefghijklmnopqrstuvwxyz";

        private readonly SqliteConnection _connection;
        private readonly DbContextOptions<BenchmarkContext> _audited;
        private readonly DbContextOptions<BenchmarkContext> _plain;

        public BenchmarkDb()
        {
            _connection = new SqliteConnection("DataSource=:memory:");
            _connection.Open();

            Options = new TamperEvidentOptions { HmacSecretKey = Secret, AnchorThreshold = 0 };
            _audited = new DbContextOptionsBuilder<BenchmarkContext>().UseSqlite(_connection).UseTamperEvidentAudit(Options).Options;
            _plain = new DbContextOptionsBuilder<BenchmarkContext>().UseSqlite(_connection).Options;

            using var context = CreatePlain();
            context.Database.EnsureCreated();
        }

        public TamperEvidentOptions Options { get; }

        public BenchmarkContext CreateAudited() => new(_audited);

        public BenchmarkContext CreatePlain() => new(_plain);

        public static Customer NewCustomer(int i) => new()
        {
            Name = "Customer " + i,
            Email = $"customer{i}@example.com",
            City = (i % 3) switch { 0 => "İstanbul", 1 => "Ankara", _ => "İzmir" },
            Balance = i * 10.5m,
            IsActive = i % 2 == 0,
            CreatedUtc = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddMinutes(i),
            Notes = "Benchmark entity number " + i
        };

        public void Dispose() => _connection.Dispose();
    }
}
