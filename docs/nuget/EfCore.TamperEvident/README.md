![EF Core Tamper-Evident](https://raw.githubusercontent.com/furkiak/EfCore.TamperEvident/main/docs/assets/banner.jpg)

# EF Core Tamper-Evident Audit Trail

**Zero-trust audit logging for Entity Framework Core.** Every insert, update and delete is sealed into a per-table
**HMAC-SHA256 hash chain** inside the same transaction as the change itself. Rewrite a row, delete an entry, forge an
author or cut off the newest records, and the chain stops verifying, even if the person who did it is a database
administrator with full access to the server.

Personal data does not have to stay in the log forever: entries can be **redacted for GDPR/KVKK erasure requests without
breaking the chain**.

- 🔐 **HMAC hash chain with a signed head**: edits, insertions, deletions, reordering and removed newest entries are detected.
- 🛡 **Anchors**: publish the chain head to e-mail, a webhook or an append-only file, out of the database's reach.
- ⚛️ **Atomic and race-free**: written in your transaction; works with `EnableRetryOnFailure` and `TransactionScope`.
- 👤 **Who, why and from where**: user, reason, OpenTelemetry trace id, client IP and your own metadata are sealed.
- 🧽 **GDPR/KVKK redaction** that keeps every seal and anchor valid, and is itself recorded in the chain.
- 🕰 **History and time travel**: a readable change history per record, and any record as it was at any moment.
- ⚡ **Incremental verification**: re-check only what was appended since the last run.
- 📦 **Offline evidence bundles** that auditors verify without your database.
- 📈 **OpenTelemetry** traces and metrics.
- ✅ SQL Server, PostgreSQL, MySQL/MariaDB and SQLite; .NET 8, 9 and 10 with EF Core 8, 9 and 10.

## Quick start

```csharp
// 1. Add the audit tables to your model, then add a migration
protected override void OnModelCreating(ModelBuilder modelBuilder) => modelBuilder.ApplyTamperEvidentAudit();

// 2. Register it (keep the secret out of source control and out of the audited database)
builder.Services.AddTamperEvident((sp, audit) =>
{
    audit.HmacSecretKey = builder.Configuration["TamperEvident:SecretKey"]!;   // 32+ random characters
    audit.CustomAnchorPublisher = new FileAnchorPublisher("/mnt/worm/anchors.jsonl");
});
builder.Services.AddDbContext<AppDbContext>((sp, options) =>
    options.UseSqlServer(connectionString).UseTamperEvidentAudit(sp));

// 3. Use EF Core as always: the change and its sealed audit entry commit together
using (AuditScope.WithReason("Ticket #4711: corrected the billing address"))
{
    customer.City = "Ankara";
    await db.SaveChangesAsync();
}

// 4. Verify (inject AuditVerifier after services.AddTamperEvidentVerifier<AppDbContext>())
var report = await verifier.VerifyAllAsync();
if (!report.IsValid) logger.LogCritical("TAMPERING: {Message}", report.Message);
```

## Redaction, history and evidence

```csharp
await db.RedactAuditTrailAsync(customer, new AuditRedactionRequest
{
    Reason = "Erasure request #4711 (GDPR Art. 17)",
    Properties = ["Name", "Email", "Phone"]
});

foreach (var change in await db.GetAuditTrailAsync(order))
    Console.WriteLine($"{change.TimestampUtc:u} {change.UserId} {change.Action} {change.Reason}");

var asItWas = (await db.GetStateAsOfAsync(order, new DateTimeOffset(2026, 3, 1, 0, 0, 0, TimeSpan.Zero))).ToObject<Order>();

await AuditExporter.WriteEvidenceBundleAsync(file, db, verifier);   // verify offline with AuditEvidence or the CLI
```

## Packages

| Package | |
|---|---|
| `EfCore.TamperEvident` | The audit trail, verification, redaction, history and exports. |
| `EfCore.TamperEvident.AspNetCore` | A Liquid Glass dashboard, scheduled verification, a health check and HTTP user and request metadata. |
| `EfCore.TamperEvident.Cli` | The `tamper-evident` .NET tool: verify evidence bundles offline. |

## Documentation

- [Full documentation](https://github.com/furkiak/EfCore.TamperEvident#readme) · [Türkçe](https://github.com/furkiak/EfCore.TamperEvident/blob/main/README.tr.md)
- [Security model and limitations](https://github.com/furkiak/EfCore.TamperEvident#security-model-and-limitations)
- [Upgrading from 1.x](https://github.com/furkiak/EfCore.TamperEvident#upgrading-from-1x) (2.0 needs a migration and a real secret key)
- [Changelog](https://github.com/furkiak/EfCore.TamperEvident/blob/main/CHANGELOG.md) · [Issues](https://github.com/furkiak/EfCore.TamperEvident/issues)
