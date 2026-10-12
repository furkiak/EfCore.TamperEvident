using BenchmarkDotNet.Attributes;

namespace EfCore.TamperEvident.Benchmarks
{
    /// <summary>
    /// What the audit trail adds to <c>SaveChanges</c>: inserting and updating <see cref="Rows"/> entities
    /// with and without the interceptor, against the same in-memory SQLite database.
    /// </summary>
    [MemoryDiagnoser]
    public class SaveChangesBenchmarks
    {
        private BenchmarkDb _db = null!;
        private int _next;

        [Params(1, 100, 1000)]
        public int Rows { get; set; }

        [GlobalSetup]
        public void Setup() => _db = new BenchmarkDb();

        [GlobalCleanup]
        public void Cleanup() => _db.Dispose();

        [Benchmark(Baseline = true, Description = "Insert, no audit")]
        public int InsertPlain()
        {
            using var context = _db.CreatePlain();
            return Insert(context);
        }

        [Benchmark(Description = "Insert, audited")]
        public int InsertAudited()
        {
            using var context = _db.CreateAudited();
            return Insert(context);
        }

        [Benchmark(Description = "Insert, audited (async)")]
        public async Task<int> InsertAuditedAsync()
        {
            await using var context = _db.CreateAudited();
            for (var i = 0; i < Rows; i++)
            {
                context.Customers.Add(BenchmarkDb.NewCustomer(_next++));
            }

            return await context.SaveChangesAsync();
        }

        [Benchmark(Description = "Update, audited")]
        public int UpdateAudited()
        {
            using var context = _db.CreateAudited();
            var customers = context.Customers.OrderBy(c => c.Id).Take(Rows).ToList();
            if (customers.Count < Rows)
            {
                Insert(context);
                customers = context.Customers.OrderBy(c => c.Id).Take(Rows).ToList();
            }

            foreach (var customer in customers)
            {
                customer.Balance += 1;
                customer.Notes = "Updated " + _next++;
            }

            return context.SaveChanges();
        }

        private int Insert(BenchmarkContext context)
        {
            for (var i = 0; i < Rows; i++)
            {
                context.Customers.Add(BenchmarkDb.NewCustomer(_next++));
            }

            return context.SaveChanges();
        }
    }
}
