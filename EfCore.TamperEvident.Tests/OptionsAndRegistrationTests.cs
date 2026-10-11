using EfCore.TamperEvident.Configuration;
using EfCore.TamperEvident.Extensions;
using EfCore.TamperEvident.Interceptors;
using EfCore.TamperEvident.Models;
using EfCore.TamperEvident.Services;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace EfCore.TamperEvident.Tests
{
    public class OptionsAndRegistrationTests
    {
        [Fact]
        public void MissingSecret_IsRefused()
        {
            var ex = Assert.Throws<InvalidOperationException>(() => new TamperEvidentOptions().Validate());
            Assert.Contains("HmacSecretKey", ex.Message);
        }

        [Fact]
        public void TheOldPublicDefaultKey_IsRefused()
        {
            var options = new TamperEvidentOptions { HmacSecretKey = TamperEvidentOptions.Version1DefaultKey };
            var ex = Assert.Throws<InvalidOperationException>(options.Validate);
            Assert.Contains("default key", ex.Message);
        }

        [Fact]
        public void ShortSecret_IsRefused()
        {
            Assert.Throws<InvalidOperationException>(() => new TamperEvidentOptions { HmacSecretKey = new string('x', 15) }.Validate());
            new TamperEvidentOptions { HmacSecretKey = new string('x', 16) }.Validate();
        }

        [Fact]
        public void InvalidKeyIds_AreRefused()
        {
            var tooLong = new TamperEvidentOptions { HmacSecretKey = Harness.SecretKey, HmacKeyId = new string('k', 65) };
            Assert.Throws<InvalidOperationException>(tooLong.Validate);

            var blankId = new TamperEvidentOptions { HmacSecretKey = Harness.SecretKey };
            blankId.AdditionalHmacKeys[" "] = "secret";
            Assert.Throws<InvalidOperationException>(blankId.Validate);

            var emptySecret = new TamperEvidentOptions { HmacSecretKey = Harness.SecretKey };
            emptySecret.AdditionalHmacKeys["old"] = string.Empty;
            Assert.Throws<InvalidOperationException>(emptySecret.Validate);
        }

        [Fact]
        public void AnchorAttempts_MustBePositive()
        {
            var options = new TamperEvidentOptions { HmacSecretKey = Harness.SecretKey, AnchorMaxAttempts = 0 };
            Assert.Throws<InvalidOperationException>(options.Validate);
        }

        [Fact]
        public void Defaults_AreSensible()
        {
            var options = new TamperEvidentOptions();

            Assert.Equal(DatabaseProvider.Auto, options.DbProvider);
            Assert.Equal(AuditOperation.All, options.TrackedOperations);
            Assert.Equal(1000, options.AnchorThreshold);
            Assert.Equal(587, options.SmtpPort);
            Assert.True(options.SmtpEnableSsl);
            Assert.Equal("System", options.DefaultUserId);
            Assert.Equal("IsDeleted", options.SoftDeleteColumnName);
        }

        [Fact]
        public void UseTamperEvidentAudit_ThrowsImmediately_ForAnInvalidConfiguration()
        {
            var builder = new DbContextOptionsBuilder<TestDbContext>().UseInMemoryDatabase("x");
            Assert.Throws<InvalidOperationException>(() => builder.UseTamperEvidentAudit(_ => { }));
        }

        [Fact]
        public void UseTamperEvidentAudit_KeepsTheTypedBuilder()
        {
            DbContextOptionsBuilder<TestDbContext> builder = new DbContextOptionsBuilder<TestDbContext>()
                .UseInMemoryDatabase("typed")
                .UseTamperEvidentAudit(o => o.HmacSecretKey = Harness.SecretKey);

            DbContextOptions<TestDbContext> options = builder.Options;
            Assert.NotNull(options);
        }

        [Fact]
        public async Task AddTamperEvident_RegistersOneSharedInterceptor_AndAVerifier()
        {
            using var connection = new SqliteConnection("DataSource=:memory:");
            connection.Open();

            var services = new ServiceCollection();
            services.AddTamperEvident(o =>
            {
                o.HmacSecretKey = Harness.SecretKey;
                o.UserIdProvider = _ => "di-user";
            });
            services.AddDbContext<TestDbContext>((sp, o) => o.UseSqlite(connection).UseTamperEvidentAudit(sp));
            services.AddTamperEvidentVerifier<TestDbContext>();

            await using var provider = services.BuildServiceProvider();
            Assert.Same(provider.GetRequiredService<TamperEvidentInterceptor>(), provider.GetRequiredService<TamperEvidentInterceptor>());

            await using (var scope = provider.CreateAsyncScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<TestDbContext>();
                await db.Database.EnsureCreatedAsync();
                db.Customers.Add(new Customer { Name = "via DI" });
                await db.SaveChangesAsync();
            }

            await using (var scope = provider.CreateAsyncScope())
            {
                var verifier = scope.ServiceProvider.GetRequiredService<AuditVerifier>();
                var result = await verifier.VerifyTableIntegrityAsync("Customers");
                Assert.True(result.IsValid, result.Message);

                var db = scope.ServiceProvider.GetRequiredService<TestDbContext>();
                Assert.Equal("di-user", (await db.AuditLogs.SingleAsync()).UserId);
            }
        }

        [Fact]
        public void AddTamperEvident_ValidatesAtRegistrationTime()
        {
            Assert.Throws<InvalidOperationException>(() => new ServiceCollection().AddTamperEvident(_ => { }));
        }

        [Fact]
        public void ProviderDetection_RecognisesTheSupportedProviders()
        {
            Assert.Equal(DatabaseProvider.SqlServer, Internal.ProviderDetector.Detect("Microsoft.EntityFrameworkCore.SqlServer"));
            Assert.Equal(DatabaseProvider.PostgreSql, Internal.ProviderDetector.Detect("Npgsql.EntityFrameworkCore.PostgreSQL"));
            Assert.Equal(DatabaseProvider.MySql, Internal.ProviderDetector.Detect("Pomelo.EntityFrameworkCore.MySql"));
            Assert.Equal(DatabaseProvider.MySql, Internal.ProviderDetector.Detect("MySql.EntityFrameworkCore"));
            Assert.Equal(DatabaseProvider.Sqlite, Internal.ProviderDetector.Detect("Microsoft.EntityFrameworkCore.Sqlite"));
            Assert.Equal(DatabaseProvider.InMemory, Internal.ProviderDetector.Detect("Microsoft.EntityFrameworkCore.InMemory"));
            Assert.Null(Internal.ProviderDetector.Detect("Oracle.EntityFrameworkCore"));
            Assert.Null(Internal.ProviderDetector.Detect(null));
        }

        [Fact]
        public async Task ProviderCommands_AreBuiltFromTheModel_ForEverySupportedDialect()
        {
            using var connection = new SqliteConnection("DataSource=:memory:");
            connection.Open();
            await using var db = new TestDbContext(new DbContextOptionsBuilder<TestDbContext>().UseSqlite(connection).Options);

            var sqlServer = Internal.AuditSqlCommands.Build(db, DatabaseProvider.SqlServer);
            Assert.Contains("WITH (UPDLOCK, ROWLOCK)", sqlServer.SelectForUpdate);
            Assert.Contains("WHERE NOT EXISTS", sqlServer.InsertIfMissing);
            Assert.Contains("HOLDLOCK", sqlServer.InsertIfMissing);
            Assert.Contains("BEGIN TRY", sqlServer.InsertIfMissing);

            var postgres = Internal.AuditSqlCommands.Build(db, DatabaseProvider.PostgreSql);
            Assert.EndsWith("FOR UPDATE", postgres.SelectForUpdate);
            Assert.Contains("ON CONFLICT", postgres.InsertIfMissing);
            Assert.Contains("DO NOTHING", postgres.InsertIfMissing);

            var mysql = Internal.AuditSqlCommands.Build(db, DatabaseProvider.MySql);
            Assert.EndsWith("FOR UPDATE", mysql.SelectForUpdate);
            Assert.StartsWith("INSERT IGNORE", mysql.InsertIfMissing);

            var sqlite = Internal.AuditSqlCommands.Build(db, DatabaseProvider.Sqlite);
            Assert.StartsWith("INSERT OR IGNORE", sqlite.InsertIfMissing);
            Assert.DoesNotContain("FOR UPDATE", sqlite.SelectForUpdate);

            foreach (var commands in new[] { sqlServer, postgres, mysql, sqlite })
            {
                // Everything is parameterized: the table name is only ever passed as a value.
                Assert.Contains("= {0}", commands.SelectForUpdate);
                Assert.Contains("WHERE", commands.UpdateChainState);
                Assert.Contains("{6}", commands.UpdateChainState);
                Assert.Contains("{" + (3 * Internal.AuditSqlCommands.LogColumnCount + 12) + "}", commands.InsertLogs(4));
                Assert.DoesNotContain("{" + (4 * Internal.AuditSqlCommands.LogColumnCount) + "}", commands.InsertLogs(4));
            }

            // Identifiers are delimited by the SQL generation helper of the context's own provider (here: SQLite).
            Assert.Contains("\"AuditChainStates\"", postgres.SelectForUpdate);
            Assert.Contains("\"AuditLogs\"", postgres.InsertLogs(1));
            Assert.Contains("\"TableName\" = {0}", postgres.SelectForUpdate);
        }

        [Fact]
        public async Task SqlCommands_UseCustomTableNames()
        {
            using var connection = new SqliteConnection("DataSource=:memory:");
            connection.Open();
            await using var db = new SchemaDbContext(new DbContextOptionsBuilder<SchemaDbContext>().UseSqlite(connection).Options);

            var postgres = Internal.AuditSqlCommands.Build(db, DatabaseProvider.PostgreSql);
            Assert.Contains("FROM \"chain_heads\"", postgres.SelectForUpdate);
            Assert.Contains("UPDATE \"chain_heads\"", postgres.UpdateChainState);
            Assert.Contains("INSERT INTO \"audit_trail\"", postgres.InsertLogs(1));
        }

        private sealed class SchemaDbContext : DbContext
        {
            public SchemaDbContext(DbContextOptions<SchemaDbContext> options) : base(options)
            {
            }

            protected override void OnModelCreating(ModelBuilder modelBuilder) =>
                modelBuilder.ApplyTamperEvidentAudit(auditLogTable: "audit_trail", chainStateTable: "chain_heads");
        }
    }
}
