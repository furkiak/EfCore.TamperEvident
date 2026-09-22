using Microsoft.EntityFrameworkCore;
using EfCore.TamperEvident.Models;
using EfCore.TamperEvident.Extensions;

namespace EfCore.TamperEvident.Tests
{
    public class TestEntity
    {
        public int Id { get; set; }
        public required string Name { get; set; }
        public decimal Price { get; set; }
        public bool IsDeleted { get; set; }
        public string? ApiKey { get; set; }
    }

    public class SalesEntry
    {
        public required string TenantId { get; set; }
        public required string ExternalId { get; set; }
        public required string Value { get; set; }
    }

    public class SupportEntry
    {
        public required string TenantId { get; set; }
        public required string ExternalId { get; set; }
        public required string Value { get; set; }
    }

    public class TestDbContext : DbContext
    {
        public DbSet<AuditLog> AuditLogs { get; set; }
        public DbSet<AuditChainState> AuditChainStates { get; set; }
        public DbSet<PendingAnchor> PendingAnchors { get; set; }
        public DbSet<TestEntity> TestEntities { get; set; }
        public DbSet<SalesEntry> SalesEntries { get; set; }
        public DbSet<SupportEntry> SupportEntries { get; set; }

        public TestDbContext(DbContextOptions<TestDbContext> options) : base(options) { }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            builder.Entity<SalesEntry>().ToTable("Entries", "sales")
                .HasKey(x => new { x.TenantId, x.ExternalId });
            builder.Entity<SupportEntry>().ToTable("Entries", "support")
                .HasKey(x => new { x.TenantId, x.ExternalId });
            builder.AddTamperEvidentModels();
        }
    }
}
