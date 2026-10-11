using EfCore.TamperEvident.Configuration;
using EfCore.TamperEvident.Extensions;
using EfCore.TamperEvident.Services;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace EfCore.TamperEvident.Cli.Tests
{
    public sealed class Customer
    {
        public int Id { get; set; }

        public required string Name { get; set; }

        public string? Email { get; set; }
    }

    public sealed class CliTestContext(DbContextOptions<CliTestContext> options) : DbContext(options)
    {
        public DbSet<Customer> Customers => Set<Customer>();

        protected override void OnModelCreating(ModelBuilder modelBuilder) => modelBuilder.ApplyTamperEvidentAudit();
    }

    /// <summary>
    /// Writes an audit trail (with anchors and a redaction) to a temporary directory and exports it as an evidence bundle,
    /// the way an auditor would receive it.
    /// </summary>
    public sealed class BundleFixture : IAsyncLifetime
    {
        public const string Secret = "cli-test-secret-0123456789-abcdefghijklmnop";

        public string Directory { get; } = Path.Combine(Path.GetTempPath(), "te-cli-" + Guid.NewGuid().ToString("N"));

        public string KeyFile => Path.Combine(Directory, "key.txt");

        public string Bundle => Path.Combine(Directory, "evidence.json");

        public string Anchors => Path.Combine(Directory, "anchors.jsonl");

        public string PathFor(string name) => Path.Combine(Directory, name);

        public async Task InitializeAsync()
        {
            System.IO.Directory.CreateDirectory(Directory);
            await File.WriteAllTextAsync(KeyFile, Secret + Environment.NewLine);

            var options = new TamperEvidentOptions
            {
                HmacSecretKey = Secret,
                AnchorThreshold = 2,
                AwaitAnchorDelivery = true,
                CustomAnchorPublisher = new FileAnchorPublisher(Anchors)
            };

            await using var connection = new SqliteConnection("DataSource=:memory:");
            await connection.OpenAsync();
            var dbOptions = new DbContextOptionsBuilder<CliTestContext>().UseSqlite(connection).UseTamperEvidentAudit(options).Options;

            await using (var db = new CliTestContext(dbOptions))
            {
                await db.Database.EnsureCreatedAsync();
                for (var i = 0; i < 5; i++)
                {
                    db.Customers.Add(new Customer { Name = "Customer " + i, Email = $"customer{i}@example.com" });
                    await db.SaveChangesAsync();
                }

                var first = await db.Customers.OrderBy(c => c.Id).FirstAsync();
                first.Name = "Renamed";
                await db.SaveChangesAsync();

                await db.RedactAuditTrailAsync(first, new AuditRedactionRequest { Reason = "Erasure request #1", Properties = ["Email"] });
            }

            await using (var db = new CliTestContext(dbOptions))
            await using (var file = File.Create(Bundle))
            {
                await AuditExporter.WriteEvidenceBundleAsync(file, db, new AuditVerifier(db, options));
            }
        }

        public Task DisposeAsync()
        {
            try
            {
                System.IO.Directory.Delete(Directory, recursive: true);
            }
            catch (IOException)
            {
                // A virus scanner may still hold a file; the directory is in the temp folder.
            }

            return Task.CompletedTask;
        }
    }
}
