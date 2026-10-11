using EfCore.TamperEvident;
using EfCore.TamperEvident.Extensions;
using Microsoft.EntityFrameworkCore;

namespace QuickStart;

public class Customer
{
    public int Id { get; set; }
    public required string Name { get; set; }
    public string? Email { get; set; }
    public string? Company { get; set; }
    public decimal CreditLimit { get; set; }
    public bool IsDeleted { get; set; }

    // Never copied into the audit trail.
    [AuditIgnore]
    public string? PasswordHash { get; set; }

    // Stored as a keyed fingerprint: provable that it changed, never readable.
    [AuditMask]
    public string? CardNumber { get; set; }
}

public class Invoice
{
    public int Id { get; set; }
    public int CustomerId { get; set; }
    public required string Number { get; set; }
    public decimal Amount { get; set; }
    public string Status { get; set; } = "Draft";
}

public class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options)
{
    public DbSet<Customer> Customers => Set<Customer>();
    public DbSet<Invoice> Invoices => Set<Invoice>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        // Adds the audit tables (AuditLogs, AuditChainStates) to the model - no DbSet properties needed.
        modelBuilder.ApplyTamperEvidentAudit();
    }
}
