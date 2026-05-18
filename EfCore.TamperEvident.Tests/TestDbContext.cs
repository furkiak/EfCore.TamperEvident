using Microsoft.EntityFrameworkCore;
using EfCore.TamperEvident.Models;

namespace EfCore.TamperEvident.Tests
{
    public class TestEntity
    {
        public int Id { get; set; }
        public required string Name { get; set; }
        public decimal Price { get; set; }
        public bool IsDeleted { get; set; }
    }

    public class TestDbContext : DbContext
    {
        public DbSet<AuditLog> AuditLogs { get; set; }
        public DbSet<AuditChainState> AuditChainStates { get; set; }
        public DbSet<TestEntity> TestEntities { get; set; }

        public TestDbContext(DbContextOptions<TestDbContext> options) : base(options) { }
    }
}
