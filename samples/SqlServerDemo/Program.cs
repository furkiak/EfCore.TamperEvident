using System.Security.Cryptography;
using EfCore.TamperEvident.Configuration;
using EfCore.TamperEvident.Extensions;
using EfCore.TamperEvident.Models;
using EfCore.TamperEvident.Services;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;

if (args is ["--dispatch-test-anchor"])
{
    // The SMTP integration test restarts the dispatcher as a separate process.
    var testConnection = Environment.GetEnvironmentVariable("AUDIT_DEMO_DISPATCH_CONNECTION")
        ?? throw new InvalidOperationException("The isolated dispatcher test connection is missing.");
    var parsed = new SqlConnectionStringBuilder(testConnection);
    if (!parsed.InitialCatalog.StartsWith("AuditIt_", StringComparison.Ordinal))
        throw new InvalidOperationException("The dispatcher test worker accepts only uniquely named AuditIt_ fixtures.");
    var testOptions = new TamperEvidentOptions
    {
        HmacSecretKey = Environment.GetEnvironmentVariable("AUDIT_DEMO_DISPATCH_KEY") ?? "",
        SmtpHost = "127.0.0.1", SmtpPort = int.Parse(Environment.GetEnvironmentVariable("AUDIT_DEMO_DISPATCH_PORT") ?? "0"),
        SmtpUser = "audit@example.test", AnchorEmailTo = "receiver@example.test",
        AllowUnencryptedLoopbackSmtp = true, SmtpTimeoutSeconds = 5
    };
    var workerOptions = new DbContextOptionsBuilder<DemoContext>().UseSqlServer(testConnection).Options;
    await using var worker = new DemoContext(workerOptions);
    var sent = await new AnchorDispatcher(worker, testOptions).DispatchPendingAsync();
    Console.WriteLine("Dispatched anchors: " + sent);
    return;
}

var server = Environment.GetEnvironmentVariable("EFCORE_AUDIT_SQLSERVER")
    ?? throw new InvalidOperationException("Set EFCORE_AUDIT_SQLSERVER to an isolated SQL Server test instance.");
var connection = new SqlConnectionStringBuilder(server)
{
    InitialCatalog = "AuditDemo_" + Guid.NewGuid().ToString("N"),
    TrustServerCertificate = true, ConnectTimeout = 10
}.ConnectionString;
// This disposable demo's key never leaves the process. A retained chain needs a retained secret-manager key.
var audit = new TamperEvidentOptions
{
    HmacSecretKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
    AnchorThreshold = 1, UserIdProvider = _ => "demo-user"
};
var optionsBuilder = new DbContextOptionsBuilder<DemoContext>().UseSqlServer(connection);
optionsBuilder.UseTamperEvidentAudit(x =>
    {
        x.HmacSecretKey = audit.HmacSecretKey;
        x.AnchorThreshold = audit.AnchorThreshold;
        x.UserIdProvider = audit.UserIdProvider;
    });
var options = optionsBuilder.Options;
await using var owner = new DemoContext(options);
try
{
    await owner.Database.EnsureCreatedAsync();
    owner.Customers.Add(new Customer { Name = "Synthetic Customer" });
    await owner.SaveChangesAsync();
    await using var check = new DemoContext(options);
    var row = await check.AuditLogs.SingleAsync();
    var pending = await check.PendingAnchors.SingleAsync();
    var result = await new AuditVerifier(check, audit).VerifyTableIntegrityAsync("Customers");
    if (!result.IsValid || row.UserId != "demo-user" || pending.DeliveredAtUtc != null)
        throw new InvalidOperationException("Demo verification failed.");
    Console.WriteLine("Business rows: 1; audit rows: 1; actor: demo-user; format: v2.");
    Console.WriteLine("Pending anchors: 1; delivered: 0 (no external receiver configured).");
    Console.WriteLine("Internal chain valid. No independently retained anchor was checked.");
}
finally
{
    await owner.Database.EnsureDeletedAsync();
    Console.WriteLine("Disposable AuditDemo database removed.");
}

public sealed class Customer
{
    public int Id { get; set; }
    public required string Name { get; set; }
}

public sealed class DemoContext(DbContextOptions<DemoContext> options) : DbContext(options)
{
    public DbSet<Customer> Customers => Set<Customer>();
    public DbSet<AuditLog> AuditLogs => Set<AuditLog>();
    public DbSet<PendingAnchor> PendingAnchors => Set<PendingAnchor>();
    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        builder.AddTamperEvidentModels();
    }
}
