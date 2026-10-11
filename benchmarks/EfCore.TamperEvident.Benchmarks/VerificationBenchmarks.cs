using BenchmarkDotNet.Attributes;
using EfCore.TamperEvident.Services;

namespace EfCore.TamperEvident.Benchmarks
{
    /// <summary>Verifying a table with <see cref="Entries"/> audit entries.</summary>
    [MemoryDiagnoser]
    public class VerificationBenchmarks
    {
        private BenchmarkDb _db = null!;

        [Params(10_000)]
        public int Entries { get; set; }

        [GlobalSetup]
        public void Setup()
        {
            _db = new BenchmarkDb();
            for (var batch = 0; batch < Entries / 1000; batch++)
            {
                using var context = _db.CreateAudited();
                for (var i = 0; i < 1000; i++)
                {
                    context.Customers.Add(BenchmarkDb.NewCustomer(batch * 1000 + i));
                }

                context.SaveChanges();
            }
        }

        [GlobalCleanup]
        public void Cleanup() => _db.Dispose();

        [Benchmark(Description = "Full verification")]
        public async Task<bool> FullVerification()
        {
            await using var context = _db.CreatePlain();
            var result = await new AuditVerifier(context, _db.Options).VerifyTableIntegrityAsync("Customers");
            return result.IsValid ? true : throw new InvalidOperationException(result.Message);
        }
    }
}
