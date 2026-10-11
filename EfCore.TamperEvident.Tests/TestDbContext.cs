using EfCore.TamperEvident.Models;
using Microsoft.EntityFrameworkCore;

namespace EfCore.TamperEvident.Tests
{
    public class Customer
    {
        public int Id { get; set; }
        public required string Name { get; set; }
        public string? Email { get; set; }
        public decimal Balance { get; set; }
        public bool IsDeleted { get; set; }

        [AuditMask]
        public string? CardNumber { get; set; }

        [AuditIgnore]
        public string? PasswordHash { get; set; }

        public string? LastLoginIp { get; set; }
    }

    public class Document
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public required string Title { get; set; }
        public DateTime? DeletedAt { get; set; }
    }

    public class OrderLine
    {
        public int OrderId { get; set; }
        public int LineNo { get; set; }
        public required string Product { get; set; }
        public int Quantity { get; set; }
    }

    public class SystemLog
    {
        public int Id { get; set; }
        public required string Message { get; set; }
    }

    [AuditIgnore]
    public class ScratchPad
    {
        public int Id { get; set; }
        public required string Note { get; set; }
    }

    public class TestDbContext : DbContext
    {
        public DbSet<AuditLog> AuditLogs { get; set; } = null!;
        public DbSet<AuditChainState> AuditChainStates { get; set; } = null!;
        public DbSet<Customer> Customers { get; set; } = null!;
        public DbSet<Document> Documents { get; set; } = null!;
        public DbSet<OrderLine> OrderLines { get; set; } = null!;
        public DbSet<SystemLog> SystemLogs { get; set; } = null!;
        public DbSet<ScratchPad> ScratchPads { get; set; } = null!;

        public TestDbContext(DbContextOptions<TestDbContext> options) : base(options) { }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<OrderLine>().HasKey(x => new { x.OrderId, x.LineNo });
        }
    }
}
