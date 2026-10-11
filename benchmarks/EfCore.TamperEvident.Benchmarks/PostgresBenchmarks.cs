using BenchmarkDotNet.Attributes;
using EfCore.TamperEvident.Configuration;
using EfCore.TamperEvident.Extensions;
using Microsoft.EntityFrameworkCore;

namespace EfCore.TamperEvident.Benchmarks
{
    /// <summary>
    /// The same inserts against a real PostgreSQL server, where every round trip counts. Runs only when
    /// <c>TE_BENCH_POSTGRES</c> holds a connection string (without a database name; a throw-away database is created).
    /// </summary>
    [MemoryDiagnoser]
    public class PostgresBenchmarks
    {
        private DbContextOptions<BenchmarkContext> _audited = null!;
        private DbContextOptions<BenchmarkContext> _plain = null!;
        private int _next;

        [Params(1, 100)]
        public int Rows { get; set; }

        [GlobalSetup]
        public void Setup()
        {
            var server = Environment.GetEnvironmentVariable("TE_BENCH_POSTGRES")
                ?? throw new InvalidOperationException("Set TE_BENCH_POSTGRES to a PostgreSQL connection string to run these benchmarks.");
            var connection = server.TrimEnd(';') + ";Database=te_bench_" + Guid.NewGuid().ToString("N")[..10];

            var options = new TamperEvidentOptions { HmacSecretKey = BenchmarkDb.Secret, AnchorThreshold = 0 };
            _audited = new DbContextOptionsBuilder<BenchmarkContext>().UseNpgsql(connection).UseTamperEvidentAudit(options).Options;
            _plain = new DbContextOptionsBuilder<BenchmarkContext>().UseNpgsql(connection).Options;

            using var context = new BenchmarkContext(_plain);
            context.Database.EnsureCreated();
        }

        [GlobalCleanup]
        public void Cleanup()
        {
            using var context = new BenchmarkContext(_plain);
            context.Database.EnsureDeleted();
        }

        [Benchmark(Baseline = true, Description = "Insert, no audit")]
        public async Task<int> InsertPlain()
        {
            await using var context = new BenchmarkContext(_plain);
            return await InsertAsync(context);
        }

        [Benchmark(Description = "Insert, audited")]
        public async Task<int> InsertAudited()
        {
            await using var context = new BenchmarkContext(_audited);
            return await InsertAsync(context);
        }

        private Task<int> InsertAsync(BenchmarkContext context)
        {
            for (var i = 0; i < Rows; i++)
            {
                context.Customers.Add(BenchmarkDb.NewCustomer(_next++));
            }

            return context.SaveChangesAsync();
        }
    }
}
